use std::{collections::BTreeSet, net::SocketAddr};

use quanta::Instant;

pub const MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReusableUdpPunchListener {
    pub running: bool,
    pub mapped_addr: SocketAddr,
    /// Every public address this listener is reachable at, one per underlay
    /// egress. Empty when the caller did not report them, which readers treat
    /// as just `mapped_addr`.
    pub mapped_addrs: Vec<SocketAddr>,
    pub has_port_mapping_lease: bool,
    pub last_active_time: Instant,
}

impl ReusableUdpPunchListener {
    fn egress_ips(&self) -> BTreeSet<std::net::IpAddr> {
        if self.mapped_addrs.is_empty() {
            std::iter::once(self.mapped_addr.ip()).collect()
        } else {
            self.mapped_addrs.iter().map(SocketAddr::ip).collect()
        }
    }
}

pub fn can_reuse_public_listener(listener: &ReusableUdpPunchListener) -> bool {
    listener.running && !listener.mapped_addr.ip().is_unspecified()
}

pub fn can_reuse_port_mapping_listener(listener: &ReusableUdpPunchListener) -> bool {
    can_reuse_public_listener(listener) && listener.has_port_mapping_lease
}

/// Picks the listener whose egress set adds the most addresses the listeners
/// already handed out do not cover, breaking ties by recent activity.
///
/// Behind a multi-WAN CPE each listener may be mapped to a different subset of
/// egresses, and a peer can only punch at addresses we advertise. Returning the
/// most recently used listener every time would advertise the same egress
/// repeatedly and leave the others unreachable. `already_selected` holds the
/// egress IPs covered by listeners selected earlier in this round.
pub fn select_listener_covering_new_egress(
    listeners: &[ReusableUdpPunchListener],
    already_selected: &BTreeSet<std::net::IpAddr>,
    accept: impl Fn(&ReusableUdpPunchListener) -> bool,
) -> Option<usize> {
    listeners
        .iter()
        .enumerate()
        .filter(|(_, listener)| accept(listener))
        .max_by_key(|(_, listener)| {
            let new_egress = listener.egress_ips().difference(already_selected).count();
            (new_egress, listener.last_active_time)
        })
        .map(|(idx, _)| idx)
}

/// Decides whether `select_listener` should bind yet another listener.
///
/// `prefer_port_mapping` must not by itself justify a new listener. When the
/// gateway offers no UPnP/NAT-PMP the lease is always absent, so a request that
/// keeps asking for one used to create a listener on every call. Each creation
/// binds a fresh local port and resolves it through STUN, so the advertised
/// address changed every time, and the listener was evicted again after 30s of
/// idling — a steady stream of addresses no peer could punch at. The first
/// listener (count 0) is still created with the caller's `prefer_port_mapping`,
/// so the mapping attempt happens exactly once per environment.
pub fn should_create_public_listener(
    current_listener_count: usize,
    has_reusable_listener: bool,
    _has_port_mapping_listener: bool,
    force_new_listener: bool,
    _prefer_port_mapping: bool,
) -> bool {
    if current_listener_count >= MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS {
        return false;
    }

    if current_listener_count == 0 {
        return true;
    }

    if force_new_listener {
        return true;
    }

    !has_reusable_listener
}

/// Whether a failed selection may retry with `force_new_listener`.
///
/// Retrying only helps while the listener cap leaves room. `prefer_port_mapping`
/// used to force one extra round even at the cap, which could never succeed
/// because `should_create_public_listener` refuses to create there.
pub fn should_retry_public_listener_selection(
    force_new_listener: bool,
    current_listener_count: usize,
    _prefer_port_mapping: bool,
    _has_port_mapping_listener: bool,
) -> bool {
    !force_new_listener && current_listener_count < MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        net::{Ipv4Addr, SocketAddr, SocketAddrV4},
        time::Duration,
    };

    use super::*;

    fn listener(
        port: u16,
        running: bool,
        has_port_mapping_lease: bool,
        active_age: Duration,
    ) -> ReusableUdpPunchListener {
        ReusableUdpPunchListener {
            running,
            mapped_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
            mapped_addrs: Vec::new(),
            has_port_mapping_lease,
            last_active_time: Instant::now() - active_age,
        }
    }

    fn multi_egress_listener(
        public_ips: &[&str],
        port: u16,
        active_age: Duration,
    ) -> ReusableUdpPunchListener {
        let addrs: Vec<SocketAddr> = public_ips
            .iter()
            .map(|ip| SocketAddr::V4(SocketAddrV4::new(ip.parse().unwrap(), port)))
            .collect();
        ReusableUdpPunchListener {
            running: true,
            mapped_addr: addrs[0],
            mapped_addrs: addrs,
            has_port_mapping_lease: false,
            last_active_time: Instant::now() - active_age,
        }
    }

    #[test]
    fn listener_selection_prefers_an_uncovered_egress_over_recency() {
        // The newest listener only reaches an egress already covered; the older
        // one reaches a second WAN. Advertising only the newest would leave the
        // second WAN unreachable.
        let listeners = vec![
            multi_egress_listener(&["203.0.113.1"], 1000, Duration::from_secs(60)),
            multi_egress_listener(
                &["203.0.113.1", "198.51.100.1"],
                2000,
                Duration::from_secs(1),
            ),
            multi_egress_listener(&["203.0.113.1"], 3000, Duration::from_secs(0)),
        ];
        let covered: BTreeSet<_> = std::iter::once("203.0.113.1".parse().unwrap()).collect();

        let idx =
            select_listener_covering_new_egress(&listeners, &covered, can_reuse_public_listener);
        assert_eq!(idx, Some(1));
    }

    #[test]
    fn listener_selection_falls_back_to_recency_when_no_new_egress() {
        let listeners = vec![
            multi_egress_listener(&["203.0.113.1"], 1000, Duration::from_secs(60)),
            multi_egress_listener(&["203.0.113.1"], 2000, Duration::from_secs(1)),
        ];
        let covered: BTreeSet<_> = std::iter::once("203.0.113.1".parse().unwrap()).collect();

        let idx =
            select_listener_covering_new_egress(&listeners, &covered, can_reuse_public_listener);
        assert_eq!(idx, Some(1));
    }

    #[test]
    fn single_egress_listener_reports_its_mapped_addr_as_the_egress() {
        let single = listener(1000, true, false, Duration::from_secs(1));
        assert_eq!(
            single.egress_ips(),
            std::iter::once(Ipv4Addr::LOCALHOST.into()).collect()
        );
    }

    #[test]
    fn listener_selection_prefers_reuse_before_cap() {
        assert!(!should_create_public_listener(1, true, true, false, false));
        assert!(!should_create_public_listener(
            MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS,
            true,
            true,
            false,
            false
        ));
    }

    #[test]
    fn listener_selection_creates_when_empty_or_no_reusable_listener() {
        assert!(should_create_public_listener(0, false, false, false, false));
        assert!(should_create_public_listener(1, false, false, false, false));
    }

    #[test]
    fn listener_selection_force_new_respects_cap() {
        assert!(should_create_public_listener(1, true, true, true, false));
        assert!(!should_create_public_listener(
            MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS,
            true,
            true,
            true,
            false
        ));
    }

    #[test]
    fn listener_selection_reuses_listener_when_port_mapping_is_unavailable() {
        // Without UPnP/NAT-PMP the lease never appears. Asking for a mapped
        // listener must not bind a new one each time: every bind moves the
        // advertised public port, which is what kept the peer punching at
        // addresses that no longer existed.
        assert!(!should_create_public_listener(1, true, false, false, true));
        assert!(!should_create_public_listener(1, true, false, false, false));
        // The first listener is still created, and it carries the mapping
        // attempt, so the gateway gets probed exactly once.
        assert!(should_create_public_listener(0, false, false, false, true));
    }

    #[test]
    fn listener_selection_retry_respects_cap() {
        assert!(should_retry_public_listener_selection(
            false, 1, false, false
        ));
        assert!(!should_retry_public_listener_selection(
            false,
            MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS,
            false,
            false
        ));
        assert!(!should_retry_public_listener_selection(
            true, 1, false, false
        ));
        // At the cap a retry can never create anything, whatever the caller
        // prefers, so it must not spin.
        assert!(!should_retry_public_listener_selection(
            false,
            MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS,
            true,
            false
        ));
    }

    #[test]
    fn selects_most_recent_reusable_public_listener() {
        let listeners = vec![
            listener(1000, true, false, Duration::from_secs(10)),
            listener(1001, false, false, Duration::from_secs(1)),
            listener(1002, true, false, Duration::from_secs(2)),
        ];

        assert_eq!(
            select_listener_covering_new_egress(
                &listeners,
                &BTreeSet::new(),
                can_reuse_public_listener
            ),
            Some(2)
        );
    }

    #[test]
    fn selects_most_recent_reusable_port_mapping_listener() {
        let listeners = vec![
            listener(1000, true, false, Duration::from_secs(1)),
            listener(1001, true, true, Duration::from_secs(10)),
            listener(1002, true, true, Duration::from_secs(2)),
        ];

        assert_eq!(
            select_listener_covering_new_egress(
                &listeners,
                &BTreeSet::new(),
                can_reuse_port_mapping_listener
            ),
            Some(2)
        );
    }

    #[test]
    fn unspecified_addr_is_not_reusable() {
        let mut listener = listener(1000, true, true, Duration::ZERO);
        listener.mapped_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 1000));

        assert!(!can_reuse_public_listener(&listener));
        assert!(!can_reuse_port_mapping_listener(&listener));
    }
}
