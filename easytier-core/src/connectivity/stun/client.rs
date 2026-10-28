//! Portable STUN clients and NAT classification.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::Context as _;
use bytecodec::{DecodeExt as _, EncodeExt as _};
use quanta::Instant;
use rand::seq::IteratorRandom as _;
use stun_codec::{Message, MessageClass, MessageDecoder, MessageEncoder};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _},
    sync::{Mutex, broadcast},
    task::JoinSet,
};
use tracing::{Instrument as _, Level};

use crate::{
    host::dns::{DnsQuery, DnsRecordResolver, DnsResolver},
    proto::common::NatType,
    socket::{
        IpVersion, SocketContext,
        tcp::{TcpBindOptions, TcpConnectOptions, VirtualTcpSocket, VirtualTcpSocketFactory},
        udp::{UdpBindOptions, VirtualUdpSocket, VirtualUdpSocketFactory},
    },
};

use crate::packet::stun::{Attribute, ChangeRequest, tid_to_u32, u32_to_tid};
use stun_codec::rfc5389::methods::BINDING;

pub trait StunSocketRuntime: VirtualUdpSocketFactory + VirtualTcpSocketFactory {}

impl<T> StunSocketRuntime for T where T: VirtualUdpSocketFactory + VirtualTcpSocketFactory {}

pub trait StunDnsRuntime: DnsResolver + DnsRecordResolver {}

impl<T> StunDnsRuntime for T where T: DnsResolver + DnsRecordResolver {}

pub(super) struct HostResolverIter<D: ?Sized> {
    dns: Arc<D>,
    context: SocketContext,
    hostnames: Vec<String>,
    ips: Vec<SocketAddr>,
    max_ip_per_domain: u32,
    use_ipv6: bool,
}

impl<D> HostResolverIter<D>
where
    D: StunDnsRuntime + ?Sized,
{
    pub(super) fn new(
        dns: Arc<D>,
        context: SocketContext,
        hostnames: Vec<String>,
        max_ip_per_domain: u32,
        use_ipv6: bool,
    ) -> Self {
        Self {
            dns,
            context,
            hostnames,
            ips: Vec::new(),
            max_ip_per_domain,
            use_ipv6,
        }
    }

    async fn get_txt_record(&self, domain_name: &str) -> anyhow::Result<Vec<String>> {
        let txt_data = self
            .dns
            .resolve_txt(DnsQuery::new(domain_name, self.context.clone()))
            .await?;
        Ok(txt_data.split_whitespace().map(str::to_owned).collect())
    }

    pub(super) async fn next(&mut self) -> Option<SocketAddr> {
        loop {
            if let Some(addr) = self.ips.pop() {
                return Some(addr);
            }

            if self.hostnames.is_empty() {
                return None;
            }

            let endpoint = self.hostnames.remove(0);
            if let Some(domain_name) = endpoint.strip_prefix("txt:") {
                match self.get_txt_record(domain_name).await {
                    Ok(hosts) => {
                        tracing::info!(
                            ?domain_name,
                            ?hosts,
                            "get txt record success when resolve stun server"
                        );
                        self.hostnames.splice(0..0, hosts);
                    }
                    Err(error) => {
                        tracing::warn!(
                            ?domain_name,
                            ?error,
                            "get txt record failed when resolve stun server"
                        );
                    }
                }
                continue;
            }

            if let Some(addr) = explicit_socket_addr(&endpoint) {
                if addr.is_ipv6() == self.use_ipv6 {
                    return Some(addr);
                }
                continue;
            }

            let Some((host, port)) = host_and_port(&endpoint) else {
                tracing::warn!(?endpoint, "invalid stun server endpoint");
                continue;
            };
            match self
                .dns
                .resolve(DnsQuery::new(host.clone(), self.context.clone()))
                .await
            {
                Ok(ips) => {
                    self.ips = ips
                        .into_iter()
                        .filter(|ip| ip.is_ipv6() == self.use_ipv6)
                        .map(|ip| SocketAddr::new(ip, port))
                        .choose_multiple(&mut rand::thread_rng(), self.max_ip_per_domain as usize);
                }
                Err(error) => {
                    tracing::warn!(?host, ?error, "lookup host for stun failed");
                }
            }
        }
    }
}

fn explicit_socket_addr(endpoint: &str) -> Option<SocketAddr> {
    if let Ok(addr) = endpoint.parse() {
        return Some(addr);
    }
    endpoint
        .parse::<IpAddr>()
        .ok()
        .map(|ip| SocketAddr::new(ip, 3478))
}

fn host_and_port(endpoint: &str) -> Option<(String, u16)> {
    match endpoint.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => {
            Some((host.to_owned(), port.parse::<u16>().ok()?))
        }
        _ => Some((endpoint.to_owned(), 3478)),
    }
}

#[derive(Debug, Clone)]
struct StunPacket {
    data: Vec<u8>,
    addr: SocketAddr,
}

type StunPacketReceiver = broadcast::Receiver<StunPacket>;

#[derive(Debug, Clone, Copy)]
pub(super) struct BindRequestResponse {
    pub(super) local_addr: SocketAddr,
    pub(super) stun_server_addr: SocketAddr,
    pub(super) recv_from_addr: SocketAddr,
    pub(super) mapped_socket_addr: Option<SocketAddr>,
    #[allow(dead_code)]
    changed_socket_addr: Option<SocketAddr>,
    #[allow(dead_code)]
    change_ip: bool,
    #[allow(dead_code)]
    change_port: bool,
    real_ip_changed: bool,
    real_port_changed: bool,
    #[allow(dead_code)]
    latency_us: u32,
}

#[derive(Debug, Clone)]
struct StunClient<S> {
    stun_server: SocketAddr,
    resp_timeout: Duration,
    req_repeat: u32,
    socket: Arc<S>,
    stun_packet_receiver: Arc<Mutex<StunPacketReceiver>>,
}

impl<S> StunClient<S>
where
    S: VirtualUdpSocket,
{
    fn new(
        stun_server: SocketAddr,
        socket: Arc<S>,
        stun_packet_receiver: StunPacketReceiver,
    ) -> Self {
        Self {
            stun_server,
            resp_timeout: Duration::from_millis(3000),
            req_repeat: 2,
            socket,
            stun_packet_receiver: Arc::new(Mutex::new(stun_packet_receiver)),
        }
    }

    async fn wait_stun_response(
        &self,
        tids: &[u32],
        stun_host: &SocketAddr,
    ) -> anyhow::Result<(Message<Attribute>, SocketAddr)> {
        let mut now = crate::foundation::time::Instant::now();
        let deadline = now + self.resp_timeout;

        while now < deadline {
            let mut receiver = self.stun_packet_receiver.lock().await;
            let packet =
                crate::foundation::time::timeout(deadline - now, receiver.recv()).await??;
            now = crate::foundation::time::Instant::now();

            if packet.data.len() < 20 {
                continue;
            }

            let mut decoder = MessageDecoder::<Attribute>::new();
            let Ok(message) = decoder
                .decode_from_bytes(&packet.data)
                .with_context(|| format!("decode stun message from {}", packet.addr))?
            else {
                continue;
            };

            tracing::trace!(
                data = ?packet.data,
                ?tids,
                remote_addr = ?packet.addr,
                ?stun_host,
                "recv stun response: {message:#?}"
            );

            if message.class() != MessageClass::SuccessResponse
                || message.method() != BINDING
                || !tids.contains(&tid_to_u32(&message.transaction_id()))
            {
                continue;
            }

            return Ok((message, packet.addr));
        }

        anyhow::bail!("timed out waiting for STUN response")
    }

    fn extract_mapped_addr(message: &Message<Attribute>) -> Option<SocketAddr> {
        message.attributes().find_map(|attribute| match attribute {
            Attribute::MappedAddress(addr) => Some(addr.address()),
            Attribute::XorMappedAddress(addr) => Some(addr.address()),
            _ => None,
        })
    }

    fn extract_changed_addr(message: &Message<Attribute>) -> Option<SocketAddr> {
        message.attributes().find_map(|attribute| match attribute {
            Attribute::OtherAddress(addr) => Some(addr.address()),
            Attribute::ChangedAddress(addr) => Some(addr.address()),
            _ => None,
        })
    }

    #[tracing::instrument(ret, level = Level::TRACE, skip(self))]
    async fn bind_request(
        self,
        change_ip: bool,
        change_port: bool,
    ) -> anyhow::Result<BindRequestResponse> {
        let stun_host = self.stun_server;
        let mut tids = Vec::new();
        for _ in 0..self.req_repeat {
            let tid = rand::random::<u32>();
            let mut message =
                Message::<Attribute>::new(MessageClass::Request, BINDING, u32_to_tid(tid));
            message.add_attribute(ChangeRequest::new(change_ip, change_port));
            let bytes = MessageEncoder::new()
                .encode_into_bytes(message.clone())
                .with_context(|| "encode stun message")?;
            tids.push(tid);
            tracing::trace!(?message, ?bytes, tid, "send stun request");
            self.socket.send_to(&bytes, stun_host).await?;
        }

        let now = Instant::now();
        let (message, recv_addr) = self.wait_stun_response(&tids, &stun_host).await?;
        let changed_socket_addr = Self::extract_changed_addr(&message);
        let response = BindRequestResponse {
            local_addr: self.socket.local_addr()?,
            stun_server_addr: stun_host,
            recv_from_addr: recv_addr,
            mapped_socket_addr: Self::extract_mapped_addr(&message),
            changed_socket_addr,
            change_ip,
            change_port,
            real_ip_changed: stun_host.ip() != recv_addr.ip(),
            real_port_changed: stun_host.port() != recv_addr.port(),
            latency_us: now.elapsed().as_micros() as u32,
        };

        tracing::trace!(
            ?stun_host,
            ?recv_addr,
            ?changed_socket_addr,
            "finish stun bind request"
        );
        Ok(response)
    }
}

struct StunClientBuilder<S>
where
    S: VirtualUdpSocket,
{
    socket: Arc<S>,
    tasks: JoinSet<()>,
    stun_packet_sender: broadcast::Sender<StunPacket>,
}

impl<S> StunClientBuilder<S>
where
    S: VirtualUdpSocket,
{
    fn new(socket: Arc<S>) -> Self {
        let (stun_packet_sender, _) = broadcast::channel(1024);
        let mut tasks = JoinSet::new();
        let listener_socket = socket.clone();
        let sender = stun_packet_sender.clone();
        tasks.spawn(
            async move {
                let mut buf = [0; 1620];
                tracing::trace!("start stun packet listener");
                loop {
                    let Ok((len, addr)) = listener_socket.recv_from(&mut buf).await else {
                        tracing::error!("udp recv_from error");
                        break;
                    };
                    let data = buf[..len].to_vec();
                    tracing::trace!(?addr, ?data, "recv udp stun packet");
                    let _ = sender.send(StunPacket { data, addr });
                }
            }
            .instrument(tracing::info_span!("stun_packet_listener")),
        );
        Self {
            socket,
            tasks,
            stun_packet_sender,
        }
    }

    fn new_stun_client(&self, stun_server: SocketAddr) -> StunClient<S> {
        StunClient::new(
            stun_server,
            self.socket.clone(),
            self.stun_packet_sender.subscribe(),
        )
    }

    async fn stop(&mut self) {
        self.tasks.shutdown().await;
    }
}

impl<S> Drop for StunClientBuilder<S>
where
    S: VirtualUdpSocket,
{
    fn drop(&mut self) {
        self.tasks.abort_all();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunTransport {
    Udp,
    Tcp,
}

#[derive(Debug, Clone)]
pub struct StunNatTypeDetectResult {
    transport: StunTransport,
    source_addr: SocketAddr,
    pub(super) stun_resps: Vec<BindRequestResponse>,
    pub(super) extra_bind_test: Option<BindRequestResponse>,
    /// Whether repeating a probe to the same STUN server returned the same
    /// mapped address. `None` when no repeat probe completed.
    ///
    /// A multi-WAN CPE that hashes each flow once keeps this stable; one that
    /// spreads packets of a single flow across WANs does not, and no amount of
    /// port prediction can punch through it.
    pub(super) repeatable: Option<bool>,
}

/// One distinct underlay egress, identified by the public IP the CPE maps this
/// socket to when it picks that egress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressGroup {
    pub public_ip: IpAddr,
    ports: BTreeSet<u16>,
    stun_servers: BTreeSet<SocketAddr>,
}

impl EgressGroup {
    pub fn min_port(&self) -> Option<u16> {
        self.ports.iter().next().copied()
    }

    pub fn max_port(&self) -> Option<u16> {
        self.ports.iter().next_back().copied()
    }

    pub fn port_count(&self) -> usize {
        self.ports.len()
    }

    /// Endpoint-independent mapping on this egress: every destination probed
    /// through it saw the same public port.
    ///
    /// A single destination proves nothing about mapping independence, so one
    /// server is only trusted when a repeat probe showed the same flow is
    /// mapped stably — that rules out per-packet egress selection, which is the
    /// only way a stable single port could still be a mirage.
    fn is_cone(&self, flow_is_stable: bool) -> bool {
        self.ports.len() == 1 && (self.stun_servers.len() >= 2 || flow_is_stable)
    }

    /// The port to advertise for this egress, or `None` when no peer could
    /// usefully punch at it.
    ///
    /// A per-destination egress has no single port to name, and advertising
    /// the lowest one would send peers to a port the CPE only opens for
    /// *someone else's* destination. Such an egress is simply not offered.
    pub fn punch_port(&self) -> Option<u16> {
        if self.ports.len() == 1 {
            self.ports.iter().next().copied()
        } else {
            None
        }
    }
}

impl StunNatTypeDetectResult {
    fn new(
        transport: StunTransport,
        source_addr: SocketAddr,
        stun_resps: Vec<BindRequestResponse>,
    ) -> Self {
        Self {
            transport,
            source_addr,
            stun_resps,
            extra_bind_test: None,
            repeatable: None,
        }
    }

    /// Responses grouped by the public IP they were mapped to, one group per
    /// underlay egress. A single-egress host yields exactly one group.
    pub fn egress_groups(&self) -> Vec<EgressGroup> {
        let mut groups: BTreeMap<IpAddr, EgressGroup> = BTreeMap::new();
        for resp in &self.stun_resps {
            let Some(mapped) = resp.mapped_socket_addr else {
                continue;
            };
            let group = groups.entry(mapped.ip()).or_insert_with(|| EgressGroup {
                public_ip: mapped.ip(),
                ports: BTreeSet::new(),
                stun_servers: BTreeSet::new(),
            });
            group.ports.insert(mapped.port());
            group.stun_servers.insert(resp.stun_server_addr);
        }
        groups.into_values().collect()
    }

    /// True when more than one underlay egress was observed, i.e. the host sits
    /// behind a multi-WAN CPE that selects an egress per destination.
    pub fn is_multi_egress(&self) -> bool {
        self.egress_groups().len() > 1
    }

    pub fn has_ip_changed_resp(&self) -> bool {
        self.stun_resps.iter().any(|resp| resp.real_ip_changed)
    }

    pub fn has_port_changed_resp(&self) -> bool {
        self.stun_resps.iter().any(|resp| resp.real_port_changed)
    }

    fn is_open_internet(&self) -> bool {
        self.stun_resps
            .iter()
            .any(|resp| resp.mapped_socket_addr == Some(self.source_addr))
    }

    fn is_no_pat(&self) -> bool {
        self.stun_resps.iter().any(|resp| {
            resp.mapped_socket_addr.map(|addr| addr.port()) == Some(self.source_addr.port())
        })
    }

    fn stun_server_count(&self) -> usize {
        self.stun_resps
            .iter()
            .map(|resp| resp.recv_from_addr)
            .collect::<BTreeSet<_>>()
            .len()
    }

    /// Every destination we probed saw the same single mapping.
    fn is_cone(&self) -> bool {
        self.stun_resps
            .iter()
            .filter_map(|resp| resp.mapped_socket_addr)
            .collect::<BTreeSet<_>>()
            .len()
            == 1
    }

    fn nat_type_udp(&self) -> NatType {
        if self.stun_server_count() < 2 {
            return NatType::Unknown;
        }

        // A CPE that spreads one flow's packets over several WANs breaks the
        // port prediction every symmetric-NAT strategy relies on. Nothing can
        // punch through it, so say so instead of letting the grouping below
        // mistake the resulting port spread for a per-destination mapping.
        if self.repeatable == Some(false) {
            return NatType::Symmetric;
        }

        if self.is_multi_egress() {
            return self.nat_type_multi_egress_udp();
        }

        if self.is_cone() {
            if self.has_ip_changed_resp() {
                if self.is_open_internet() {
                    NatType::OpenInternet
                } else if self.is_no_pat() {
                    NatType::NoPat
                } else {
                    NatType::FullCone
                }
            } else if self.has_port_changed_resp() {
                NatType::Restricted
            } else {
                NatType::PortRestricted
            }
        } else if !self.stun_resps.is_empty() {
            if self.usable_stun_resp_count() <= 1 || self.max_port() - self.min_port() > 15 {
                NatType::Symmetric
            } else if let Some(extra_bind_mapped) = self
                .extra_bind_test
                .as_ref()
                .and_then(|extra| extra.mapped_socket_addr)
            {
                let extra_port = extra_bind_mapped.port();
                let max_port_diff = extra_port.saturating_sub(self.max_port());
                let min_port_diff = self.min_port().saturating_sub(extra_port);
                if max_port_diff != 0 && max_port_diff < 100 {
                    NatType::SymmetricEasyInc
                } else if min_port_diff != 0 && min_port_diff < 100 {
                    NatType::SymmetricEasyDec
                } else {
                    NatType::Symmetric
                }
            } else {
                NatType::Symmetric
            }
        } else {
            NatType::Unknown
        }
    }

    /// A per-destination egress selection makes the public IP vary with the
    /// destination, which the single-egress logic reads as a symmetric NAT.
    /// Judge each egress on its own instead: as long as one maps
    /// endpoint-independently, a peer has an address that reaches us, so the
    /// host is as punchable as any cone.
    fn nat_type_multi_egress_udp(&self) -> NatType {
        let flow_is_stable = self.repeatable == Some(true);
        let groups = self.egress_groups();
        // One predictable egress is enough to be reachable: a peer punches at
        // that address and the CPE routes it out the WAN that owns it. The
        // unpredictable egresses are still advertised — the peer tries every
        // address and keeps whichever answers — but they must not veto the
        // node, which would relay traffic that could have gone direct.
        if !groups.iter().any(|group| group.is_cone(flow_is_stable)) {
            return NatType::Symmetric;
        }

        if self.is_open_internet() {
            NatType::OpenInternet
        } else if self.is_no_pat() {
            NatType::NoPat
        } else if self.has_port_changed_resp() {
            NatType::Restricted
        } else {
            NatType::PortRestricted
        }
    }

    fn nat_type_tcp(&self) -> NatType {
        if self.is_open_internet() {
            return NatType::OpenInternet;
        }
        if self.stun_server_count() < 2 || self.stun_resps.is_empty() {
            return NatType::Unknown;
        }
        if self.repeatable == Some(false) {
            return NatType::Symmetric;
        }
        if self.is_cone() {
            if self.is_no_pat() {
                NatType::NoPat
            } else {
                NatType::FullCone
            }
        } else {
            NatType::Symmetric
        }
    }

    pub fn nat_type(&self) -> NatType {
        match self.transport {
            StunTransport::Udp => self.nat_type_udp(),
            StunTransport::Tcp => self.nat_type_tcp(),
        }
    }

    pub fn public_ips(&self) -> Vec<IpAddr> {
        self.stun_resps
            .iter()
            .filter_map(|resp| resp.mapped_socket_addr.map(|addr| addr.ip()))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn collect_available_stun_server(&self) -> Vec<SocketAddr> {
        let mut servers = Vec::new();
        for response in &self.stun_resps {
            if !servers.contains(&response.stun_server_addr) {
                servers.push(response.stun_server_addr);
            }
        }
        servers
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.source_addr
    }

    pub fn extend_result(&mut self, other: Self) {
        self.stun_resps.extend(other.stun_resps);
        // A flow that proved stable in either probe is stable; only report
        // instability when a probe actually observed it.
        self.repeatable = match (self.repeatable, other.repeatable) {
            (Some(false), _) | (_, Some(false)) => Some(false),
            (Some(true), _) | (_, Some(true)) => Some(true),
            _ => None,
        };
    }

    pub fn min_port(&self) -> u16 {
        self.stun_resps
            .iter()
            .filter_map(|response| response.mapped_socket_addr.map(|addr| addr.port()))
            .min()
            .unwrap_or(0)
    }

    pub fn max_port(&self) -> u16 {
        self.stun_resps
            .iter()
            .filter_map(|response| response.mapped_socket_addr.map(|addr| addr.port()))
            .max()
            .unwrap_or(u16::MAX)
    }

    pub fn usable_stun_resp_count(&self) -> usize {
        self.stun_resps
            .iter()
            .filter(|response| response.mapped_socket_addr.is_some())
            .count()
    }
}

pub struct UdpNatTypeDetector<R, D: ?Sized> {
    runtime: Arc<R>,
    dns: Arc<D>,
    socket_context: SocketContext,
    stun_server_hosts: Vec<String>,
    max_ip_per_domain: u32,
}

impl<R, D> UdpNatTypeDetector<R, D>
where
    R: StunSocketRuntime,
    D: StunDnsRuntime + ?Sized,
{
    pub fn new(
        runtime: Arc<R>,
        dns: Arc<D>,
        socket_context: SocketContext,
        stun_server_hosts: Vec<String>,
        max_ip_per_domain: u32,
    ) -> Self {
        Self {
            runtime,
            dns,
            socket_context,
            stun_server_hosts,
            max_ip_per_domain,
        }
    }

    pub(super) async fn get_extra_bind_result(
        &self,
        source_port: u16,
        stun_server: SocketAddr,
    ) -> anyhow::Result<BindRequestResponse> {
        let socket = self
            .runtime
            .bind_udp(stun_udp_bind_options(
                self.socket_context.clone(),
                IpVersion::V4,
                SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), source_port),
            ))
            .await?;
        udp_bind_request(socket, stun_server).await
    }

    pub async fn detect_nat_type(
        &self,
        source_port: u16,
    ) -> anyhow::Result<StunNatTypeDetectResult> {
        let socket = self
            .runtime
            .bind_udp(stun_udp_bind_options(
                self.socket_context.clone(),
                IpVersion::V4,
                SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), source_port),
            ))
            .await?;
        self.detect_nat_type_with_socket(socket).await
    }

    #[tracing::instrument(skip(self, socket))]
    pub async fn detect_nat_type_with_socket(
        &self,
        socket: Arc<<R as VirtualUdpSocketFactory>::Socket>,
    ) -> anyhow::Result<StunNatTypeDetectResult> {
        let mut resolver = HostResolverIter::new(
            self.dns.clone(),
            self.socket_context.clone().with_ip_version(IpVersion::V4),
            self.stun_server_hosts.clone(),
            self.max_ip_per_domain,
            false,
        );
        let mut stun_servers = Vec::new();
        while let Some(addr) = resolver.next().await {
            stun_servers.push(addr);
        }

        let client_builder = StunClientBuilder::new(socket.clone());
        let mut tasks = JoinSet::new();
        for stun_server in stun_servers {
            tasks.spawn(
                client_builder
                    .new_stun_client(stun_server)
                    .bind_request(false, false),
            );
            tasks.spawn(
                client_builder
                    .new_stun_client(stun_server)
                    .bind_request(false, true),
            );
            tasks.spawn(
                client_builder
                    .new_stun_client(stun_server)
                    .bind_request(true, true),
            );
        }

        let mut responses = Vec::new();
        while let Some(response) = tasks.join_next().await {
            if let Ok(Ok(response)) = response {
                responses.push(response);
            }
        }

        let mut result =
            StunNatTypeDetectResult::new(StunTransport::Udp, socket.local_addr()?, responses);
        result.repeatable =
            Self::probe_repeatability(&client_builder, &result.collect_available_stun_server())
                .await;
        Ok(result)
    }

    /// Re-probe the same STUN server from the same socket and check that every
    /// attempt is mapped to the same public address.
    ///
    /// This separates the two multi-WAN behaviours that a single probe cannot
    /// tell apart. A CPE that picks an egress per flow keeps the mapping
    /// stable, so port prediction still works. One that spreads packets of a
    /// single flow across WANs does not, and every symmetric-NAT strategy will
    /// punch at addresses the peer never sees. Returns `None` when no server
    /// answered all attempts.
    async fn probe_repeatability(
        builder: &StunClientBuilder<<R as VirtualUdpSocketFactory>::Socket>,
        servers: &[SocketAddr],
    ) -> Option<bool> {
        const ATTEMPTS: usize = 3;

        let mut conclusive = false;
        for server in servers.iter().take(2) {
            let mut mapped = Vec::with_capacity(ATTEMPTS);
            for _ in 0..ATTEMPTS {
                match builder
                    .new_stun_client(*server)
                    .bind_request(false, false)
                    .await
                {
                    Ok(response) => mapped.push(response.mapped_socket_addr),
                    // A dropped probe says nothing about stability.
                    Err(_) => break,
                }
                crate::foundation::time::sleep(Duration::from_millis(50)).await;
            }

            if mapped.len() < ATTEMPTS {
                continue;
            }
            if mapped.windows(2).any(|pair| pair[0] != pair[1]) {
                tracing::debug!(
                    ?server,
                    ?mapped,
                    "repeated STUN probes disagree, egress is chosen per packet"
                );
                return Some(false);
            }
            conclusive = true;
        }

        conclusive.then_some(true)
    }
}

pub(super) async fn udp_bind_request<S>(
    socket: Arc<S>,
    stun_server: SocketAddr,
) -> anyhow::Result<BindRequestResponse>
where
    S: VirtualUdpSocket,
{
    let mut clients = StunClientBuilder::new(socket);
    let result = clients
        .new_stun_client(stun_server)
        .bind_request(false, false)
        .await;
    clients.stop().await;
    result
}

/// Probes several STUN servers at once over one socket.
///
/// Each probe must not build its own `StunClientBuilder`: every builder spawns
/// its own `recv_from` loop on the socket, and the kernel delivers each UDP
/// datagram to exactly one of those loops. Concurrent builders therefore steal
/// each other's responses, and the losers report no mapping at all — which is
/// worse than not probing, because the caller cannot tell a failed probe from a
/// host with a single egress. One builder feeds a broadcast channel, so every
/// client sees every datagram and matches it against its own transaction ids.
pub(super) async fn udp_bind_requests<S>(
    socket: Arc<S>,
    stun_servers: Vec<SocketAddr>,
) -> Vec<(SocketAddr, anyhow::Result<BindRequestResponse>)>
where
    S: VirtualUdpSocket,
{
    let mut builder = StunClientBuilder::new(socket);
    let requests = stun_servers.into_iter().map(|stun_server| {
        let client = builder.new_stun_client(stun_server);
        async move {
            let result = client.bind_request(false, false).await;
            (stun_server, result)
        }
    });
    let results = futures::future::join_all(requests).await;
    builder.stop().await;
    results
}

pub(super) fn stun_udp_bind_options(
    context: SocketContext,
    ip_version: IpVersion,
    local_addr: SocketAddr,
) -> UdpBindOptions {
    UdpBindOptions::stun_probe()
        .with_context(context.with_ip_version(ip_version))
        .with_local_addr(Some(local_addr))
}

struct TcpStunClient<R> {
    runtime: Arc<R>,
    socket_context: SocketContext,
    stun_server: SocketAddr,
    conn_timeout: Duration,
    io_timeout: Duration,
    source_port: u16,
}

impl<R> TcpStunClient<R>
where
    R: StunSocketRuntime,
{
    fn new(
        runtime: Arc<R>,
        socket_context: SocketContext,
        stun_server: SocketAddr,
        source_port: u16,
    ) -> Self {
        Self {
            runtime,
            socket_context,
            stun_server,
            conn_timeout: Duration::from_millis(1500),
            io_timeout: Duration::from_millis(3000),
            source_port,
        }
    }

    fn extract_mapped_addr(message: &Message<Attribute>) -> Option<SocketAddr> {
        message.attributes().find_map(|attribute| match attribute {
            Attribute::MappedAddress(addr) => Some(addr.address()),
            Attribute::XorMappedAddress(addr) => Some(addr.address()),
            _ => None,
        })
    }

    fn message_size_from_header(header: &[u8; 20]) -> anyhow::Result<usize> {
        if (header[0] & 0b1100_0000) != 0 {
            anyhow::bail!("invalid stun message type")
        }
        let message_len = u16::from_be_bytes([header[2], header[3]]) as usize;
        if !message_len.is_multiple_of(4) {
            anyhow::bail!("invalid stun message length")
        }
        let total = 20usize
            .checked_add(message_len)
            .context("invalid stun message size")?;
        if total > 4096 {
            anyhow::bail!("stun message too large")
        }
        Ok(total)
    }

    async fn tcp_read_stun_message<S>(
        stream: &mut S,
        timeout: Duration,
    ) -> anyhow::Result<Message<Attribute>>
    where
        S: AsyncRead + Unpin,
    {
        let mut header = [0u8; 20];
        crate::foundation::time::timeout(timeout, stream.read_exact(&mut header)).await??;
        let total_size = Self::message_size_from_header(&header)?;
        let mut buf = vec![0u8; total_size];
        buf[..20].copy_from_slice(&header);
        if total_size > 20 {
            crate::foundation::time::timeout(timeout, stream.read_exact(&mut buf[20..])).await??;
        }

        let mut decoder = MessageDecoder::<Attribute>::new();
        let Ok(message) = decoder
            .decode_from_bytes(&buf)
            .with_context(|| "decode tcp stun message")?
        else {
            anyhow::bail!("invalid stun message")
        };
        Ok(message)
    }

    async fn connect(&self) -> anyhow::Result<<R as VirtualTcpSocketFactory>::Socket> {
        let (bind_addr, ip_version) = match self.stun_server {
            SocketAddr::V4(_) => (
                SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), self.source_port),
                IpVersion::V4,
            ),
            SocketAddr::V6(_) => (
                SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), self.source_port),
                IpVersion::V6,
            ),
        };
        let bind = TcpBindOptions::default()
            .with_context(self.socket_context.clone().with_ip_version(ip_version))
            .with_local_addr(Some(bind_addr))
            .with_reuse_addr(true)
            .with_reuse_port(true)
            .with_only_v6(bind_addr.is_ipv6());
        crate::foundation::time::timeout(
            self.conn_timeout,
            self.runtime.connect_tcp(
                TcpConnectOptions::stun_probe(self.stun_server, bind_addr).with_bind(bind),
            ),
        )
        .await?
    }

    #[tracing::instrument(ret, level = Level::TRACE, skip(self))]
    async fn bind_request(self) -> anyhow::Result<BindRequestResponse> {
        let mut stream = self.connect().await?;
        let local_addr = stream.local_addr()?;
        let stun_host = self.stun_server;
        let tid = rand::random::<u32>();
        let message = Message::<Attribute>::new(MessageClass::Request, BINDING, u32_to_tid(tid));
        let bytes = MessageEncoder::new()
            .encode_into_bytes(message)
            .with_context(|| "encode tcp stun message")?;
        crate::foundation::time::timeout(self.io_timeout, stream.write_all(&bytes)).await??;

        let now = Instant::now();
        let message = Self::tcp_read_stun_message(&mut stream, self.io_timeout).await?;
        if message.class() != MessageClass::SuccessResponse
            || message.method() != BINDING
            || tid_to_u32(&message.transaction_id()) != tid
        {
            anyhow::bail!("unexpected stun response")
        }

        Ok(BindRequestResponse {
            local_addr,
            stun_server_addr: stun_host,
            recv_from_addr: stun_host,
            mapped_socket_addr: Self::extract_mapped_addr(&message),
            changed_socket_addr: None,
            change_ip: false,
            change_port: false,
            real_ip_changed: false,
            real_port_changed: false,
            latency_us: now.elapsed().as_micros() as u32,
        })
    }
}

pub(super) async fn tcp_bind_request<R>(
    runtime: Arc<R>,
    socket_context: SocketContext,
    stun_server: SocketAddr,
    source_port: u16,
) -> anyhow::Result<BindRequestResponse>
where
    R: StunSocketRuntime,
{
    TcpStunClient::new(runtime, socket_context, stun_server, source_port)
        .bind_request()
        .await
}

pub struct TcpNatTypeDetector<R, D: ?Sized> {
    runtime: Arc<R>,
    dns: Arc<D>,
    socket_context: SocketContext,
    stun_server_hosts: Vec<String>,
    max_ip_per_domain: u32,
}

impl<R, D> TcpNatTypeDetector<R, D>
where
    R: StunSocketRuntime,
    D: StunDnsRuntime + ?Sized,
{
    pub fn new(
        runtime: Arc<R>,
        dns: Arc<D>,
        socket_context: SocketContext,
        stun_server_hosts: Vec<String>,
        max_ip_per_domain: u32,
    ) -> Self {
        Self {
            runtime,
            dns,
            socket_context,
            stun_server_hosts,
            max_ip_per_domain,
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn detect_nat_type(
        &self,
        source_port: u16,
    ) -> anyhow::Result<StunNatTypeDetectResult> {
        let mut resolver = HostResolverIter::new(
            self.dns.clone(),
            self.socket_context.clone().with_ip_version(IpVersion::V4),
            self.stun_server_hosts.clone(),
            self.max_ip_per_domain,
            false,
        );
        let mut stun_servers = Vec::new();
        while let Some(addr) = resolver.next().await {
            stun_servers.push(addr);
        }

        let mut responses = Vec::new();
        let mut source_addr = None;
        let mut selected_source_port = (source_port != 0).then_some(source_port);
        for server in stun_servers {
            let response = TcpStunClient::new(
                self.runtime.clone(),
                self.socket_context.clone(),
                server,
                selected_source_port.unwrap_or(0),
            )
            .bind_request()
            .await;
            if let Ok(response) = response {
                if selected_source_port.is_none() {
                    selected_source_port = Some(response.local_addr.port());
                }
                source_addr.get_or_insert(response.local_addr);
                responses.push(response);
                if responses.len() >= 3 {
                    break;
                }
            }
        }

        let source_addr = source_addr.context("no TCP STUN response")?;
        Ok(StunNatTypeDetectResult::new(
            StunTransport::Tcp,
            source_addr,
            responses,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use async_trait::async_trait;

    use crate::host::dns::{DnsQuery, DnsRecordResolver, DnsResolver, DnsSrvRecord};

    use super::*;

    struct EmptyDns;

    #[async_trait]
    impl DnsResolver for EmptyDns {
        async fn resolve(&self, _query: DnsQuery) -> anyhow::Result<Vec<IpAddr>> {
            Ok(Vec::new())
        }
    }

    #[async_trait]
    impl DnsRecordResolver for EmptyDns {
        async fn resolve_txt(&self, _query: DnsQuery) -> anyhow::Result<String> {
            Ok(String::new())
        }

        async fn resolve_srv(&self, _query: DnsQuery) -> anyhow::Result<Vec<DnsSrvRecord>> {
            Ok(Vec::new())
        }
    }

    /// One socket, several destinations, a CPE that maps each destination to a
    /// different public address: every probe must come back with its own
    /// mapping. Building a client per probe instead makes them race for the
    /// single receive loop, and the losers report no mapping at all.
    #[tokio::test]
    async fn concurrent_probes_on_one_socket_do_not_steal_each_others_responses() {
        let socket = Arc::new(PerDestinationStunSocket::new(vec![
            (
                "192.0.2.1:3478".parse().unwrap(),
                "60.12.249.167:9527".parse().unwrap(),
            ),
            (
                "192.0.2.2:3478".parse().unwrap(),
                "122.224.109.114:47699".parse().unwrap(),
            ),
            (
                "192.0.2.3:3478".parse().unwrap(),
                "122.224.109.114:6374".parse().unwrap(),
            ),
        ]));

        let results = udp_bind_requests(
            socket,
            vec![
                "192.0.2.1:3478".parse().unwrap(),
                "192.0.2.2:3478".parse().unwrap(),
                "192.0.2.3:3478".parse().unwrap(),
            ],
        )
        .await;

        let mut mappings: Vec<SocketAddr> = results
            .into_iter()
            .map(|(server, result)| {
                let response = result.unwrap_or_else(|error| panic!("{server} failed: {error}"));
                response
                    .mapped_socket_addr
                    .unwrap_or_else(|| panic!("{server} reported no mapping"))
            })
            .collect();
        mappings.sort();

        assert_eq!(
            mappings,
            vec![
                "60.12.249.167:9527".parse::<SocketAddr>().unwrap(),
                "122.224.109.114:6374".parse().unwrap(),
                "122.224.109.114:47699".parse().unwrap(),
            ]
        );
    }

    /// Maps each STUN server to its own public address, like a multi-WAN CPE
    /// that picks an egress per destination.
    struct PerDestinationStunSocket {
        local_addr: SocketAddr,
        mappings: Vec<(SocketAddr, SocketAddr)>,
        pending: Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
        ready: tokio::sync::Notify,
    }

    impl PerDestinationStunSocket {
        fn new(mappings: Vec<(SocketAddr, SocketAddr)>) -> Self {
            Self {
                local_addr: "0.0.0.0:40000".parse().unwrap(),
                mappings,
                pending: Mutex::new(VecDeque::new()),
                ready: tokio::sync::Notify::new(),
            }
        }
    }

    #[async_trait]
    impl VirtualUdpSocket for PerDestinationStunSocket {
        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            Ok(self.local_addr)
        }

        async fn send_to(&self, data: &[u8], addr: SocketAddr) -> std::io::Result<usize> {
            let request = MessageDecoder::<Attribute>::new()
                .decode_from_bytes(data)
                .map_err(|error| std::io::Error::other(format!("{error:?}")))?
                .map_err(|error| std::io::Error::other(format!("{error:?}")))?;
            let mapped = self
                .mappings
                .iter()
                .find(|(server, _)| *server == addr)
                .map(|(_, mapped)| *mapped)
                .ok_or_else(|| std::io::Error::other(format!("unexpected stun server {addr}")))?;
            let mut response = Message::<Attribute>::new(
                MessageClass::SuccessResponse,
                BINDING,
                request.transaction_id(),
            );
            response.add_attribute(Attribute::XorMappedAddress(
                stun_codec::rfc5389::attributes::XorMappedAddress::new(mapped),
            ));
            let bytes = MessageEncoder::new()
                .encode_into_bytes(response)
                .map_err(std::io::Error::other)?;
            self.pending.lock().await.push_back((bytes, addr));
            self.ready.notify_one();
            Ok(data.len())
        }

        async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
            loop {
                if let Some((bytes, addr)) = self.pending.lock().await.pop_front() {
                    buf[..bytes.len()].copy_from_slice(&bytes);
                    return Ok((bytes.len(), addr));
                }
                self.ready.notified().await;
            }
        }
    }

    #[test]
    fn explicit_endpoints_keep_ports_and_default_bare_ips() {
        assert_eq!(
            explicit_socket_addr("127.0.0.1:5555"),
            Some("127.0.0.1:5555".parse().unwrap())
        );
        assert_eq!(
            explicit_socket_addr("[::1]:5555"),
            Some("[::1]:5555".parse().unwrap())
        );
        assert_eq!(
            explicit_socket_addr("2001:db8::1"),
            Some("[2001:db8::1]:3478".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn invalid_endpoint_does_not_hide_later_servers() {
        let mut resolver = HostResolverIter::new(
            Arc::new(EmptyDns),
            SocketContext::default(),
            vec![
                "bad.example:not-a-port".to_owned(),
                "127.0.0.1:3478".to_owned(),
            ],
            1,
            false,
        );

        assert_eq!(
            resolver.next().await,
            Some("127.0.0.1:3478".parse().unwrap())
        );
    }

    #[test]
    fn stun_udp_bind_request_preserves_context_and_family() {
        let context = SocketContext::default()
            .with_socket_mark(Some(0))
            .with_netns(Some(crate::socket::NetNamespace::new("instance-a")));
        let local_addr = "0.0.0.0:0".parse().unwrap();

        let options = stun_udp_bind_options(context, IpVersion::V4, local_addr);

        assert_eq!(options.context.ip_version, IpVersion::V4);
        assert_eq!(options.context.socket_mark, Some(0));
        assert_eq!(
            options.context.netns.as_ref().map(|netns| netns.token()),
            Some("instance-a")
        );
        assert_eq!(options.local_addr, Some(local_addr));
        assert_eq!(
            options.purpose,
            crate::socket::udp::UdpSocketPurpose::StunProbe
        );
    }

    fn response(stun_server: &str, mapped: Option<&str>) -> BindRequestResponse {
        let stun_server: SocketAddr = stun_server.parse().unwrap();
        BindRequestResponse {
            local_addr: "192.168.1.10:5000".parse().unwrap(),
            stun_server_addr: stun_server,
            recv_from_addr: stun_server,
            mapped_socket_addr: mapped.map(|addr| addr.parse().unwrap()),
            changed_socket_addr: None,
            change_ip: false,
            change_port: false,
            real_ip_changed: false,
            real_port_changed: false,
            latency_us: 0,
        }
    }

    fn udp_result(responses: Vec<BindRequestResponse>) -> StunNatTypeDetectResult {
        StunNatTypeDetectResult::new(
            StunTransport::Udp,
            "192.168.1.10:5000".parse().unwrap(),
            responses,
        )
    }

    #[test]
    fn single_egress_cone_classification_is_unchanged() {
        let result = udp_result(vec![
            response("1.1.1.1:3478", Some("203.0.113.1:5000")),
            response("2.2.2.2:3478", Some("203.0.113.1:5000")),
        ]);

        assert_eq!(result.nat_type(), NatType::PortRestricted);
        assert!(!result.is_multi_egress());
        assert_eq!(result.egress_groups().len(), 1);
    }

    #[test]
    fn per_destination_egress_selection_is_not_symmetric() {
        // A policy-routing CPE picks a WAN per destination, so each STUN server
        // sees a different public IP while each egress maps this socket to a
        // single port. That is punchable, and the old single-egress logic
        // mistook the IP spread for a symmetric NAT.
        //
        // Each egress here was only reached by one server, which on its own
        // cannot separate a cone from a symmetric NAT. The repeat probe is what
        // supplies the missing evidence: the same flow keeps its mapping, so
        // the egress is not rehashing per packet.
        let mut result = udp_result(vec![
            response("1.1.1.1:3478", Some("203.0.113.1:6000")),
            response("2.2.2.2:3478", Some("198.51.100.1:6001")),
        ]);
        result.repeatable = Some(true);

        assert!(result.is_multi_egress());
        assert_eq!(result.nat_type(), NatType::PortRestricted);
    }

    #[test]
    fn multi_egress_without_stability_evidence_stays_conservative() {
        // Same observation as above but no repeat probe completed. One server
        // per egress cannot prove endpoint-independent mapping, and guessing
        // wrong means punching at a port the peer's NAT drops. Relay instead.
        let result = udp_result(vec![
            response("1.1.1.1:3478", Some("203.0.113.1:5000")),
            response("2.2.2.2:3478", Some("198.51.100.1:5001")),
        ]);

        assert!(result.is_multi_egress());
        assert_eq!(result.nat_type(), NatType::Symmetric);
    }

    #[test]
    fn multi_egress_confirmed_by_two_servers_needs_no_repeat_probe() {
        // When an egress is reached through two destinations and both map to
        // the same port, that is endpoint-independent mapping on its own.
        let result = udp_result(vec![
            response("1.1.1.1:3478", Some("203.0.113.1:6000")),
            response("2.2.2.2:3478", Some("203.0.113.1:6000")),
            response("3.3.3.3:3478", Some("198.51.100.1:6001")),
            response("4.4.4.4:3478", Some("198.51.100.1:6001")),
        ]);

        assert!(result.is_multi_egress());
        assert_eq!(result.nat_type(), NatType::PortRestricted);
    }

    #[test]
    fn one_predictable_egress_is_enough_even_if_another_is_not() {
        // Real dual-WAN CPE: WAN1 keeps one port, WAN2 rehashes per destination.
        // A peer can still reach WAN1's address, so the node is punchable. The
        // unpredictable WAN must not veto the node.
        let mut result = udp_result(vec![
            response("1.1.1.1:3478", Some("203.0.113.1:7000")),
            response("2.2.2.2:3478", Some("203.0.113.1:8000")),
            response("3.3.3.3:3478", Some("198.51.100.1:7001")),
        ]);
        // WAN2 was reached by one server only; the repeat probe is what lets a
        // single-server egress count as predictable.
        result.repeatable = Some(true);

        assert!(result.is_multi_egress());
        assert_eq!(result.nat_type(), NatType::PortRestricted);

        // Both egresses are still offered to peers: the unpredictable one may
        // answer if the CPE happens to pick the port we named.
        let groups = result.egress_groups();
        assert_eq!(groups.len(), 2);
        assert!(groups.iter().any(|group| group.punch_port() == Some(7001)));
        assert!(
            groups
                .iter()
                .any(|group| group.punch_port().is_none() && group.port_count() > 1)
        );
    }

    #[test]
    fn all_egresses_unpredictable_is_symmetric() {
        // Nothing survives the filter, so no address can be advertised.
        let result = udp_result(vec![
            response("1.1.1.1:3478", Some("203.0.113.1:5000")),
            response("2.2.2.2:3478", Some("203.0.113.1:6000")),
            response("3.3.3.3:3478", Some("198.51.100.1:5001")),
            response("4.4.4.4:3478", Some("198.51.100.1:6002")),
        ]);

        assert!(result.is_multi_egress());
        assert_eq!(result.nat_type(), NatType::Symmetric);
        assert!(
            result
                .egress_groups()
                .iter()
                .all(|group| group.punch_port().is_none())
        );
    }

    #[test]
    fn unstable_flow_is_symmetric_regardless_of_grouping() {
        // A CPE that spreads one flow's packets over WANs produces a stable
        // per-egress port only by accident; no port prediction can hit it.
        let mut result = udp_result(vec![
            response("1.1.1.1:3478", Some("203.0.113.1:5000")),
            response("2.2.2.2:3478", Some("198.51.100.1:5001")),
        ]);
        result.repeatable = Some(false);

        assert!(result.is_multi_egress());
        assert_eq!(result.nat_type(), NatType::Symmetric);
    }

    #[test]
    fn unstable_flow_overrides_an_apparently_conic_single_egress() {
        let mut result = udp_result(vec![
            response("1.1.1.1:3478", Some("203.0.113.1:5000")),
            response("2.2.2.2:3478", Some("203.0.113.1:5000")),
        ]);
        result.repeatable = Some(false);

        assert_eq!(result.nat_type(), NatType::Symmetric);
    }

    #[test]
    fn egress_groups_carry_per_egress_port_range() {
        let result = udp_result(vec![
            response("1.1.1.1:3478", Some("203.0.113.1:5000")),
            response("2.2.2.2:3478", Some("198.51.100.1:6001")),
            response("3.3.3.3:3478", Some("198.51.100.1:6002")),
        ]);

        let groups = result.egress_groups();
        assert_eq!(groups.len(), 2);
        assert_eq!(
            groups[0].public_ip,
            "198.51.100.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(groups[0].min_port(), Some(6001));
        assert_eq!(groups[0].max_port(), Some(6002));
        assert_eq!(groups[1].min_port(), Some(5000));
    }

    #[test]
    fn extend_result_keeps_an_observed_instability() {
        let mut stable = udp_result(vec![response("1.1.1.1:3478", Some("203.0.113.1:5000"))]);
        stable.repeatable = Some(true);
        let mut unstable = udp_result(vec![response("2.2.2.2:3478", Some("203.0.113.1:5001"))]);
        unstable.repeatable = Some(false);

        stable.extend_result(unstable);

        assert_eq!(stable.repeatable, Some(false));
        assert_eq!(stable.nat_type(), NatType::Symmetric);
    }
}
