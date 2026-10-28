# 多 WAN 出口 P2P 打洞：改动说明与故障交接

本文交接给在 HZ-NET27（Windows）上继续排查的同学。

分两部分：

- **第一部分**是已经改完并验证的代码，可以当设计文档读。
- **第二部分**是还没解决的问题——HZ-NET27 到中继的连接每 8~13 秒断一次。
  这个**不是**第一部分的代码能修的，证据和下一步都在这里。

阅读顺序建议：先看 §2 的结论，再看 §5 的证据，最后按 §7 动手。

---

## 1. 背景：多 WAN 为什么会影响 P2P

一台设备挂在多 WAN 路由器后面时，路由器会按目的地址给每条流选一个出口。
从 EasyTier 的角度看，同一个本地 socket 对不同的 STUN 服务器会得到**不同的公网地址**。

这类 CPE（Customer Premises Equipment，这里指那台多 WAN 路由器）分两种：

| 类型 | 行为 | 能否打洞 |
|---|---|---|
| 按流固定出口 | 同一条流（五元组）始终走同一个 WAN，端口可预测 | 能，只要把所有出口都告诉对端 |
| 按包分散出口 | 同一条流的不同包被分到不同 WAN | **不能**，任何端口都只对一部分包有效 |

区分这两者**不能**靠单轮 STUN 探测——单轮只能看到一组地址。必须对同一个
STUN 服务器重复探测，看映射是否稳定。这就是 `egress_mapping_stable` 的由来。

改动前代码的假设是「一个节点只有一个 `mapped_addr`」。在多 WAN 下这个假设
直接导致：对端只往其中一个出口打洞，而 CPE 把这条流从另一个出口送出去，
于是永远打不通，只能走中继。

---

## 2. 结论先行

### 2.1 代码层修好了什么（已验证）

| 问题 | 状态 |
|---|---|
| listener 反复重建，公网端口不断变化 | **已修**，实测 25 个端口/21 分钟 → 2 次/2 分钟 |
| 单 socket 上并发 STUN 探测互相抢包 | **已修**，有专门的回归测试 |
| 只上报一个出口，多 WAN 下打洞必然失败 | **已修**，改为逐出口上报 + 逐出口打洞 |
| 心跳 32 秒过长，NAT 映射被提前回收 | **已改** 5 秒（仅 `UdpHolePunch` / `Listener` / `Direct`） |
| 连接断开时看不出死因 | **已加**日志：`exit_reason` / `rx_packets` / `last_loss_counter` |

### 2.2 HZ-NET27 的问题**不在**这些代码里

用**与 HZ-NET27 完全相同的参数**在 Linux 上起对照实例，接同一个中继：

| 实例 | 协议 | 运行时长 | 断开次数 |
|---|---|---|---|
| Linux 对照（参数与 HZ 一致） | UDP | 10 分 57 秒 | **0** |
| Linux 对照 | QUIC | 14 分 49 秒 | **0** |
| **HZ-NET27** | UDP | — | 每 10~13 秒 |
| **HZ-NET27** | QUIC | — | 每 8~13 秒 |
| **HZ-NET27**（更早） | TCP | — | 每 ~7 秒 |

同一份代码、同一个中继、同一个网络，对照实例稳定，HZ 一直断。
所以问题在 HZ 的运行环境或链路上。

**当前状态（2026-10-28 12:40）**：HZ 已改用 QUIC 接入，仍在断，间隔 8 秒。

---

## 3. 代码改动（7 个提交）

分支 `feat/multi-wan-egress`，基于 fork 最新 `main`（`48ccc56`），
`cargo test -p easytier-core --lib` → **892 passed, 0 failed**。

| SHA | 内容 |
|---|---|
| `c5da0b3` | proto：`StunInfo` 新增 `egress_count` / `egress_endpoints` / `multi_egress_udp_nat_type`；`PeerFeatureFlag` 新增 `multi_egress_v1` |
| `c5a3acd` | STUN：单 socket 并发探测 + 逐出口分类 + 稳定出口优先排序 |
| `cf78080` | 打洞：`mapped_addrs` 多出口 + listener 按"新出口覆盖数"选择 + 修 listener 抖动 |
| `862cfdd` | peers：心跳间隔、退出原因日志、路由查找诊断 |
| `28fd4ca` | CLI：新增 `easytier-cli egress` |
| `e834667` | build：`fast` profile + Windows 交叉编译文档 |
| `abedf7a` | peers：声明 `multi_egress_v1` 能力 |

### 3.1 proto 层（`c5da0b3`）

`common.proto` 的 `StunInfo` 新增三个字段，全部是**新增**，protobuf 向后兼容：

- `egress_count`：观测到的出口总数。0 表示"未上报"，读方要当成单出口处理。
- `egress_endpoints`：**只包含可打洞的**出口（每个出口一个稳定端口）。
  按目的分配端口的出口会被省略——给这种出口一个端口号，会把对端引到一个
  为其他目的打开的端口上。
- `multi_egress_udp_nat_type`：逐出口判定的 NAT 类型。

关键设计：`udp_nat_type` 的语义**保持不变**——只要没有一个出口可打洞，
它就仍然是 `Symmetric`。这样旧版本节点会继续走中继，而不是朝一个不可能
成功的地址打洞。

`peer_rpc.proto` 新增 `SendPunchPacketHardSym.target_endpoints`，逐出口带端口。
非空时取代 `public_ips` + 共享端口的老形式。旧发送方留空，行为不变。

### 3.2 STUN 探测（`c5a3acd`）

**这里有一个隐蔽的 bug，值得单独说明。**

旧实现是「每个探测各自建一个 `StunClientBuilder`」。每个 builder 都会起一个
`recv_from` 循环读同一个 UDP socket。N 个探测 = N 个循环抢同一个 socket 的
报文——谁抢到算谁的，其余的等到超时。

改法是**一个 builder + N 个 client**：builder 持有唯一的接收循环，把报文
广播出去，各 client 按自己的 transaction id 过滤。

配套测试 `concurrent_probes_on_one_socket_do_not_steal_each_others_responses`
用 `PerDestinationStunSocket` mock 复现了这个问题。

另外 `prefer_stable_egress` 把端口稳定的出口排到首位——主地址必须是可预测的，
否则对端拿到地址时那个端口已经失效了。

### 3.3 打洞（`cf78080`）

`ReusableUdpPunchListener` 增加 `mapped_addrs`，选择逻辑改为
「优先选能贡献**新**出口的 listener」。原来的实现是"永远返回最近活跃的那个"，
结果每次都通告同一个出口，其余出口永远不可达。

**顺带修了 listener 抖动**，这是改动前最影响实测体验的 bug：

```rust
// 修复前
if prefer_port_mapping && !has_port_mapping_listener { return true; }
// 修复后
!has_reusable_listener
```

原逻辑在 `--disable-upnp` 下，`has_port_mapping_listener` 恒为 `false`，
于是**每次** `select_punch_listener` 都新建 listener。每次新建 = 绑新端口 +
STUN 解析 + 通告，然后 30 秒空闲后被回收。

实测一台主机 21 分钟内创建了 **25 个 listener / 25 个不同端口**，对端拿到的
地址永远在变。修复后 2 分钟内只创建 2 次。

### 3.4 心跳与诊断（`862cfdd`）

`max_ping_interval` 原来除 TCP 打洞外一律 32 秒。多 WAN CPE 回收空闲会话
比这更快，映射会在两次心跳之间过期。现在：

| origin | 间隔 |
|---|---|
| `TcpHolePunch` | 1s |
| `UdpHolePunch` | **5s** |
| `Listener` / `Direct` | **5s** |
| `Manual` / `Attached` | 32s（保持） |

退避仍从 1s 起翻倍，健康链路不会因此多发多少包。`Manual`/`Attached` 是
配置出来的链路，不是 NAT 映射，保持 32s。

诊断日志：接收循环和 pingpong 循环**都以 `notify_close()` 收尾**，原来连接
消失时完全看不出是哪边先死。现在两边都记录退出原因，接收循环额外报
`rx_packets` 和 `already_closed`。

### 3.5 CLI（`28fd4ca`）

```
$ easytier-cli egress
Egresses: 2 (multi-WAN CPE detected), 1 directly punchable
| # | Public IP       | Ports       | Port mapping                        |
|---|-----------------|-------------|-------------------------------------|
| 1 | 60.12.249.167   | 32840       | endpoint-independent            |
| 2 | 122.224.109.114 | 30651-30661 | per-destination (tried, unreliable) |

Per-egress NAT type: PortRestricted
Legacy NAT type (older peers): PortRestricted
Mapping stability: stable (repeated probes to the same server agreed, so the CPE
does not spread one flow across WANs)

P2P: punchable. Peers are given all 2 addresses and try each in turn, so the 1
endpoint-independent egress(es) carry the connection. The per-destination ones
are still offered in case the CPE happens to pick the port we named.
```

单出口时输出会短很多：`Egresses: 1`，没有 `(multi-WAN CPE detected)`，
最后一行只有 `P2P: punchable.`。

`Mapping stability` 是新增的关键判据：

- `stable` → 按流固定出口，可打洞
- `UNSTABLE` → 单条流被分散到多个 WAN，**永远打不通**，只能中继
- `not measured` → 重复探测没完成

---

## 4. 环境信息

### 4.1 中继节点

| 项 | 值 |
|---|---|
| 登录 | `ssh -p 34724 nas@nas.ypwq.fun`（用户 `nas`，属 docker 组） |
| 部署目录 | `/share/docker/ghomeserver/clawbench/data/root/code/easytier/` |
| 容器 | `easytier`（镜像 `easytier/easytier:latest`，实际 2.6.4-8428a89d） |
| 公网入口 | `geasytierw.ypwq.fun` → `124.160.240.92` |
| 虚拟 IP | `10.126.126.102` |
| RPC portal | `127.0.0.1:15888`（容器内） |

实际监听（`netstat` 实测，外部可达性另测）：

| 端口 | 协议 | 外部可达 |
|---|---|---|
| 14349 | tcp + udp | 是 |
| 14350 | tcp + udp | **否** |
| 14351 | tcp + udp（QUIC） | 是 |
| 14352 | — | **否** |

所以可用入口只有 `14349`（tcp/udp）和 `14351`（quic）。

**抓包方法**（宿主 tcpdump 无权限，必须用容器）：

```bash
docker run --rm --net=container:easytier nicolaka/netshoot:latest \
  timeout 60 tcpdump -i any -nn -q -tt 'udp and host 60.12.249.167 and port 14351'
```

**看 peer 状态**：

```bash
docker exec easytier easytier-cli -p 127.0.0.1:15888 peer
```

### 4.2 网络标识

```
network_name   = 8H8nz447B83B6w63Qo45-pve
network_secret = （见 HZ 启动命令，不要外传）
```

### 4.3 节点

| 节点 | peer_id | 公网 IP | NAT | 虚拟 IP |
|---|---|---|---|---|
| 中继 | 2642693511 | 124.160.240.92 | PortRestricted | 10.126.126.102 |
| **HZ-NET27** | 3348707118（会变） | 60.12.249.167（WAN1）/ 122.224.109.114（WAN2） | PortRestricted | 10.126.126.202 |
| pve-mi | 782487322 | 36.28.5.77 | Symmetric | 10.126.126.3 |
| Linux 测试端 | 111286203 / 3148642408 | 39.174.90.44 | PortRestricted | 10.126.126.204~206 |

HZ 的 peer_id 每次重启都变，排查时以公网 IP 定位，不要用 peer_id。

---

## 5. HZ-NET27 断连：已掌握的证据

### 5.1 三种协议全断，断开间隔不同

| 协议 | 间隔 | 中继侧观测 |
|---|---|---|
| TCP | ~7s | 收到伪造 RST |
| UDP | 10~13s | 握手后 HZ 零发包 |
| QUIC | 8~13s | 同上，keepalive 5s 也发不出 |

### 5.2 中继侧抓包：回程严重丢包

同样 60 秒窗口，QUIC：

| | 中继收到 | 中继发出 | 比值 |
|---|---|---|---|
| **HZ** | 50 | **193** | 1 : 3.9 |
| Linux 对照 | 58 | 60 | 1 : 1.03 |

我的实例收发 1:1，HZ 是 1:3.9——中继每收到 1 个包要重传约 3 次，
即**中继→HZ 方向丢包 70%+**。

典型片段（时间戳为 Unix 秒）：

```
t+0.0  In  :60644  ← 握手
t+0.0  In  :15844  ← 同一时刻第二个 socket
t+1.0  In  :15844
t+2.0  In  :15844  ← 此后 HZ 一个包都不再发
t+3~11 Out ×9      ← 中继单方向打心跳，HZ 全不回
t+12   换 :48389 重建
```

### 5.3 已排除的原因

以下都查过，**不是**原因，不要重复：

| 假设 | 排除依据 |
|---|---|
| 链路不通 | `ping` 中继 30ms 0% 丢包；HZ WAN1 14ms 0%；WAN2 7.7ms 0% |
| MTU 问题 | 中继→HZ 用 `-M do` 测 1100/1200/1250/1300/1400 全部通过 |
| 第二出口捣乱 | 近 60 分钟 `122.224.109.114` 出现 **0 次**，HZ 一直在用 WAN1 |
| 协议本身 | TCP/UDP/QUIC 三种全断 |
| 心跳间隔过长 | 32s→5s 改过，断开间隔反而从 22s 缩到 5~11s |
| `--disable-upnp` | 加过，无变化 |
| `--disable-p2p` | 去掉后 HZ 开始参与打洞，但中继连接照断 |
| `private_mode` / `--relay-network-whitelist` | 中继侧日志显示 HZ 是**同网络**接入，不走 foreign network 分支 |
| `send_secret_digest` 判定 | 自定义 `PartialEq` 只比 digest，逻辑正确 |
| listener 端口漂移 | **确实是 bug，已修**，但修完 HZ 照断——不是本次断连的原因 |
| 参数差异 | 用与 HZ **完全相同**的命令行起 Linux 实例，稳定 10 分 57 秒 |

### 5.4 当前最可能的原因

**路由器对 UDP 突发流量的限制**（限速 / QoS / NAT 会话数上限）。

推理链：`ping` 是小包、低频、0% 丢包；EasyTier 握手和 keepalive 是连续小包
突发，被丢。丢包**与包速率相关**而不是与连通性相关——这解释了为什么
`ping` 正常但应用层一直断。

另一个待查项：HZ 每次重连会**同时**打开两个本地端口（`:60644` + `:15844`），
而对照实例只开一个。中继只接受一个，另一个 5 秒后 `Timeout error: deadline
has elapsed`。这个双开行为还没解释。

---

## 6. 工具：用新加的日志定位

代码已加诊断日志，排查时直接看日志就能知道是哪一侧先死。

### 6.1 打开 debug 日志

```cmd
set RUST_LOG=info,easytier_core::connectivity=debug,easytier_core::peers=debug
easytier-core.exe --network-name ... --network-secret ... ^
  --rpc-portal 127.0.0.1:15888 ^
  --peers quic://geasytierw.ypwq.fun:14351 ^
  --need-p2p -i 10.126.126.202 --no-tun
```

### 6.2 关键日志

连接正常建立：

```
new peer connection added ... tunnel_type: "quic"
start recving peer conn packet
```

连接死亡时会看到（**这是本次新增的**）：

```
WARN end recving peer conn packet exit_reason="stream ended" rx_packets=42 already_closed=false
WARN pingpong loop exited last_loss_counter=5
```

判读：

| 现象 | 含义 |
|---|---|
| `exit_reason="stream ended"` + `rx_packets` 很小 | 传输层先死（对端或中间设备断开） |
| `exit_reason="stream error"` | 收到明确的传输错误 |
| `already_closed=true` | 另一条路径先触发了关闭，这条是跟随退出 |
| `last_loss_counter=5` | pingpong 连续 5 次失败触发关闭（**说明是我方主动断的**） |
| 两个都出现 | 对比时间戳，先出现的是根因 |

### 6.3 看出口分类

```cmd
easytier-cli.exe -p 127.0.0.1:15888 egress
```

重点看 `Mapping stability`：如果是 `UNSTABLE`，说明这台 CPE 把单条流分散到
多个 WAN，**打洞永远不可能成功**，只能靠中继，此时应该去路由器改负载均衡策略。

### 6.4 看对端状态

```cmd
easytier-cli.exe -p 127.0.0.1:15888 peer
```

`tunnel` 列显示 `quic` / `udp` / `tcp` 表示直连成功，空表示走中继。

---

## 7. 下一步：请在 HZ 上做的事

按顺序做，每一步都能独立排除一个假设。

### 第 1 步：丢包是否随包速率变化（最重要）

在 HZ 的 cmd 里：

```cmd
ping -n 20 124.160.240.92
ping -n 200 -l 1000 124.160.240.92
```

| 结果 | 结论 | 下一步 |
|---|---|---|
| 第一条 0%，第二条大量丢包 | **限速/QoS 确认** | 去路由器关流控，或换链路 |
| 两条都 0% | 排除限速 | 做第 2 步 |
| 两条都丢包 | 上行链路本身有问题 | 换链路 |

### 第 2 步：查双开端口

```cmd
netstat -ano | findstr 14351
```

看是不是每次重连都有两个本地端口。如果确认，记录两个端口的进程 PID 是否相同。

### 第 3 步：确认出口数和稳定性

```cmd
easytier-cli.exe -p 127.0.0.1:15888 egress
```

把完整输出贴出来。重点：`Egresses:` 是几个，`Mapping stability:` 是什么。

### 第 4 步：路由器

需要看的三项（型号未知，按常见菜单给）：

1. **多 WAN 负载均衡策略** — 找"会话保持 / Session Affinity / 源地址哈希"。
   改成按源 IP 哈希，通常能解决单流被分散的问题。
2. **QoS / 带宽控制 / 流控** — 关掉试试。
3. **NAT 会话数上限 / 连接数限制** — 看有没有配得很低。

### 第 5 步：换单 WAN 对照

用手机热点跑 2 分钟，`--peers quic://geasytierw.ypwq.fun:14351`：

- 热点下稳定 → 确认是多 WAN 路由器的问题
- 热点下也断 → 问题在 Windows 侧或运营商，继续查

---

## 8. 代码怎么用

```bash
git fetch origin
git checkout feat/multi-wan-egress
```

Windows 上编译（MSVC，原生）：

```cmd
cargo build --release --package=easytier --features=mimalloc
```

Linux 交叉编译见 `docs/local-windows-cross-build.md`。

跑测试：

```bash
cargo test -p easytier-core --lib
```

---

## 9. 已知限制

1. **`multi_egress_v1` 无条件声明为 true**。这个 build 一定理解新字段，
   但意味着与旧版本节点混跑时，旧节点不会收到 `endpoints`（正确），
   而新节点会尝试用 `target_endpoints`（旧节点不认识该字段，会走老路径）。
   已在 proto 层保证向后兼容，但没有做过混版本实网验证。

2. **只支持 IPv4**。`egress_endpoints` 的 `public_ip` 是 string，理论上可放
   IPv6，但探测路径只走了 v4。

3. **`Mapping stability` 需要重复探测**。只跑一轮探测时显示
   `not measured`，这是"未知"不是"不稳定"，两者不能混。

4. **HZ 的问题没解决**。本文档只能把范围缩小到"链路层 + 路由器"，
   真正的修复在路由器配置或换链路，不在代码。

---

## 10. 排查过程中踩过的坑（省时间用）

这些都是我判断错过的，记录下来避免重犯：

1. **误判 `--relay-network-whitelist` 引号被 shell 吃掉** — 实际
   `/proc/1/cmdline` 证明是完整单参数。
2. **误判 UDP 端口漂移导致断连** — 改成 TCP 后仍断，而且更快。
3. **误判心跳 32s 过长是根因** — 降到 5s 后连接寿命从 22s 变 5~11s。
4. **误判 `suppressed_peer_ids`** — `route dump` 显示为空。
5. **误判测试节点与 HZ 同 NAT** — HZ 是 60.12.249.167，不同网络。
6. **误判「HZ 21010 端口不可达是故障」** — NAT 内不可达是正常预期。
7. **误判 QUIC 能解决问题** — 基于我自己的 Linux 实例得出，对 HZ 不成立。
   换 QUIC 后 HZ 仍然 8 秒断一次。**教训：对照实例的结论不能直接套到目标机。**
8. **误判「第二出口在捣乱」** — 实测近 60 分钟第二出口出现 0 次。

方法论上最有用的一条：**用 `easytier-cli -o json route dump` 直接读内部状态，
不要靠反复加日志猜**。日志改一次要重编译 + 换二进制 + 等复现，成本极高。
