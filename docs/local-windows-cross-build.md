# 本地交叉编译 Windows 产物（Linux → windows-gnu）

本文记录在 Linux 上交叉编译 EasyTier Windows 产物的可用配置、实测耗时，
以及两个已经踩过的坑。适用于「改代码 → 出 exe → 拷到 Windows 实测」的
开发循环。

> **与官方 CI 的区别**：`.github/workflows/core.yml` 使用
> `x86_64-pc-windows-msvc`，在 `windows-latest` 上**原生**编译。本文的
> mingw 交叉方案是本仓库开发机上的本地路径，产物格式为 PE/COFF，可正常
> 在 Windows 运行，但**不是发布路径**。发布请走 CI。

## 1. 工具链前提

| 组件 | 用途 | 本机验证状态 |
|---|---|---|
| `rustc` / `cargo` 1.95.0 | 编译 | `~/.cargo/bin`，不在默认 PATH |
| `x86_64-w64-mingw32-gcc` (GCC 14-win32) | 链接器 / cc | 正常 |
| `/usr/lib/llvm-19/bin/clang` (19.1.7) | bindgen 解析 C 头 | 见 §4.1，**易被替换** |
| `/usr/bin/ld.lld` (LLD 19.1.7) | 可选，加速链接 | 正常 |
| `/opt/winlibs/libPacket.a` | WinDivert 静态库 | 存在 |

`cargo` 不在默认 PATH，所有命令前需 `export PATH="$HOME/.cargo/bin:$PATH"`。

## 2. 构建命令

### 2.1 日常开发（推荐）

```bash
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc
export CC_x86_64_pc_windows_gnu=x86_64-w64-mingw32-gcc
export AR_x86_64_pc_windows_gnu=x86_64-w64-mingw32-ar
export RUSTFLAGS="-L /opt/winlibs"
export BINDGEN_EXTRA_CLANG_ARGS_x86_64_pc_windows_gnu="--target=x86_64-w64-mingw32"

cargo build --profile fast \
  --target x86_64-pc-windows-gnu \
  --package=easytier --features=mimalloc
```

产物：`target/x86_64-pc-windows-gnu/fast/{easytier-core,easytier-cli}.exe`

### 2.2 发布级（慢，但产物小）

把 `--profile fast` 换成 `--release`。注意仓库 `[profile.release]` 是
`lto = true` + `codegen-units = 1`，全量约 **6 分 45 秒**。

如需临时提速又不想改仓库配置，可用环境变量覆盖（实测 Windows 全量 3m01s，
Linux 单包 `easytier-core` 1m08s）：

```bash
export CARGO_PROFILE_RELEASE_LTO=thin
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16
```

再加 `-C link-arg=-fuse-ld=lld` 到 `RUSTFLAGS` 可略微缩短链接（实测收益
< 1%，CGU 32 相比 16 也无收益，说明瓶颈已转移到前端单线程）。

注意环境变量覆盖**不会**修改 `Cargo.toml`，只影响当前 shell。改回默认值
需要 `unset CARGO_PROFILE_RELEASE_LTO CARGO_PROFILE_RELEASE_CODEGEN_UNITS`，
否则后续所有构建都沿用覆盖值。

## 3. profile 说明

`Cargo.toml` 中新增的 `fast` profile：

```toml
[profile.fast]
inherits = "dev"
opt-level = 1
debug = 0
strip = "symbols"
incremental = true
```

各参数的作用：

- **`opt-level = 1`** — 只做廉价优化（小函数内联、删死代码），不做循环展开
  和自动向量化。这是编译速度与运行性能的平衡点。**不要降到 0**：未优化的
  打洞/加密逻辑会慢到超时，测不出真实连通性。
- **`debug = 0`** — 不生成 `-g` 符号，显著缩短链接时间。
- **`strip = "symbols"`** — 剥离符号。不加这项产物会从 45MB 膨胀到 71MB。
- **`incremental = true`** — 增量编译，改一个函数只重编对应单元。
- **不设 `lto`** — 继承 `dev` 的 `false`。fat LTO 需要合并全部 crate 的
  LLVM IR 再整体优化，**无法并行**，是 release 最慢的环节。

### 实测数据（40 核 / 125GB，2026-10-27）

| 场景 | release（仓库默认） | fast |
|---|---|---|
| 全量冷编译 | 6m45s | 3m36s |
| 改代码后增量（touch `easytier-core/src/lib.rs`） | 未单独测量（含 fat LTO 重跑，预计 5m 以上） | **30s** |
| 无改动重跑 | < 1s | < 1s |
| `easytier-core.exe` | 31MB | 45MB |
| `easytier-cli.exe` | 9.5MB | 48MB |

运行性能：`opt-level=1` 相对 `opt-level=3` 的差距**未做基准测量**，粗略预期
在 release 的 60–80% 区间。对验证连通性、NAT 类型、打洞行为足够；**不要
用 fast 产物评估吞吐或延迟指标**。

### 为什么并行度上不去

用 `cargo build --timings` 分析 666 个编译单元：

```
t=  0s  42 并发   ← 依赖阶段，能吃满 40 核
t= 20s   9 并发
t=100s   1 并发   ← easytier-core 单 crate 独占 74s
t=140s   2 并发   ← easytier 上层
t=180s   0
```

`easytier-core`(74s) → `easytier` lib(38s) → `easytier` bin(41s) 构成串行链。
`codegen-units` 只能拆分**代码生成**阶段，前端（类型检查、借用检查、
单态化）始终单线程。所以 `CGU 32` 不比 `CGU 16` 快。

若要进一步压缩，唯一有效手段是拆分 `easytier-core` 为多个子 crate 让其
并行编译，属于结构性改动，未实施。

## 4. 已知坑

### 4.1 clang 被替换成自递归脚本（曾导致构建卡死 24 分钟）

**症状**：`cargo build` 卡住不动，`ps` 中可见一个 99% CPU 的
`/bin/bash /usr/lib/llvm-19/bin/clang --driver-mode=cl ...`，`/proc/PID/cmdline`
参数数量异常膨胀（曾达 22751 个），`etimes` 持续增长但永不结束。

**原因**：`/usr/lib/llvm-19/bin/clang` 曾被替换为 shell 脚本：

```bash
#!/bin/bash
args=()
for a in "$@"; do ... done
exec /usr/lib/llvm-19/bin/clang --driver-mode=cl "${args[@]}"   # ← exec 自己
```

`exec` 的目标是脚本自身，每次调用都让 `--driver-mode=cl` 多叠加一层，形成
无限递归。同时 `/usr/local/bin/clang-cl` 是指向同一文件的符号链接，按
`argv[0]` 判定为 CL 模式，同样中招。

**判定方法**：

```bash
head -3 /usr/lib/llvm-19/bin/clang        # 应是 ELF，不是 #!/bin/bash
md5sum /usr/lib/llvm-19/bin/clang         # 应为 f36f25d1189f045abacf91ed5db79801
dpkg -V clang-19                          # 无输出 = 未被篡改
```

**修复**：

```bash
cd /tmp && apt-get download clang-19
dpkg-deb -x clang-19_*.deb /tmp/debx
cp /tmp/debx/usr/lib/llvm-19/bin/clang /usr/lib/llvm-19/bin/clang
chmod 755 /usr/lib/llvm-19/bin/clang
dpkg -V clang-19 && echo OK
```

不要手工重写这个 wrapper——`clang-cl` 通过符号链接按 `argv[0]` 自动进入
CL 模式，不需要包装脚本。

### 4.2 bindgen 头文件重复定义

还原真 clang 后，若沿用旧参数会报：

```
/usr/lib/gcc/x86_64-w64-mingw32/14-win32/include/stddef.h:437:3:
error: typedef redefinition with different types ('struct max_align_t' ...)
```

**原因**：同时传入 gcc 的 include 目录和 mingw 的 sysroot，导致 `stddef.h`
被两个路径各解析一次。

**修复**：`BINDGEN_EXTRA_CLANG_ARGS` 只传 target，让 clang 自己找头文件：

```bash
export BINDGEN_EXTRA_CLANG_ARGS_x86_64_pc_windows_gnu="--target=x86_64-w64-mingw32"
```

不要手工追加 `-I/usr/lib/gcc/x86_64-w64-mingw32/14-win32/include` 等路径。

### 4.3 `cargo clean -p <crate>` 会触发完整重编

清理单个包会连带使其下游全部重编。`cargo clean -p kcp-sys` 之后整条链
（含 `easytier-core`、`easytier`）都要重跑，约 3–6 分钟。非必要不要 clean。

## 5. 打包

```bash
rm -rf /tmp/etpkg && mkdir -p /tmp/etpkg/easytier-windows-x86_64
cp target/x86_64-pc-windows-gnu/fast/easytier-{core,cli}.exe \
   /tmp/etpkg/easytier-windows-x86_64/
cp easytier/third_party/x86_64/{Packet.dll,wintun.dll,WinDivert64.sys} \
   /tmp/etpkg/easytier-windows-x86_64/
cd /tmp/etpkg && zip -r -9 <输出路径>.zip easytier-windows-x86_64/
```

Windows 端运行必须与 `Packet.dll`、`wintun.dll`、`WinDivert64.sys` 同目录。

## 6. 验证清单

改动构建配置后，用以下步骤确认没有破坏原生编译路径：

```bash
cargo fmt --check
cargo test -p easytier-core --lib      # 基线：874 passed
```

`[profile.fast]` 是新增 profile，不继承也不影响 `dev`/`release`/`mini`，
对 CI 和原生构建无副作用。

## 7. 快速排障

| 现象 | 首要怀疑 | 检查 |
|---|---|---|
| 构建卡住 > 10 分钟，无输出 | clang 自递归（§4.1） | `ps -eo pid,etimes,%cpu,args \| grep driver-mode`，看 `etimes` 是否持续增长 |
| `typedef redefinition ... max_align_t` | bindgen 头文件冲突（§4.2） | `BINDGEN_EXTRA_CLANG_ARGS` 是否只传了 `--target` |
| 构建只有 1 个核在跑 | 已进入单 crate 串行段，正常 | `cargo build --timings` 看是否在 `easytier-core` 阶段 |
| `error: linker ... not found` | 环境变量未设置 | 确认 §2.1 六个 export 全部生效 |
| 产物拷到 Windows 起不来 | 缺 DLL | 确认同目录有 `Packet.dll`/`wintun.dll`/`WinDivert64.sys` |

判断「是否真的卡死」而不是「正在编译」：

```bash
# 卡死时 etimes 持续增长但 CPU 恒定 100%，且 cmdline 参数异常膨胀
cat /proc/<pid>/cmdline | tr '\0' '\n' | wc -l    # 正常应 < 100
```

