# RealiTLScanner

[English](README.md)

高性能 TLS 证书扫描器，集成 Reality 协议域名可用性评估功能。扫描 IP/CIDR/域名目标的 TLS 证书，通过多种检测器评估域名可行性（CDN、GFW、重定向、热门网站等）。

## 功能特性

- TLS 证书扫描（IP、CIDR、域名），支持 context 取消
- 可配置并发数的高速扫描
- GeoIP 地理位置查询（数据目录可配置）
- **域名可用性检测**：CDN、GFW、TLS 验证（SAN 优先 + 通配符 `VerifyHostname`）、热门网站、重定向、HTTP 状态
- **后量子探测（PQC）**：握手时优先 offer `X25519MLKEM768`（不支持则回落 X25519，crypto/tls 对两者都发 key_share，无 HRR 罚时），记录协商曲线；支持 PQC 的目标行为与当代 Chrome 一致，是更优质的偷邻居信号——计入星级并在「备注」列标记
- **去伪黑名单**：一票否决代理关键词域名、代理面板（通过 `Server` 头识别 x-ui / sing-box 等）、动态DNS / NAS 后缀；廉价 TLD 作为软信号（扣 1 星）——结果体现在「备注」列
- **SSRF 安全防护**：redirect/status 探测器拒绝 loopback / private / link-local / 云元数据地址
- **偷邻居发现（`-bgp`）**：为单个 `-addr` IP 智能选段——一台主机常同时落在多个重叠的已通告前缀下（如 /24、/21、/20），故枚举它们（Team Cymru 种子 + RIPEstat `routing-status`）并挑出 `/20`–`/24` 甜点段（中心 `/21`），再清点 bgp.tools 在该段实际见过多少活跃邻居，超过 `-max-hosts`（默认 4096）则中止，除非 `-yes`
- **两段式扫描（`-probe-first`）**：先用高并发 TCP 探活筛掉死/防火墙主机，再对存活主机做完整 TLS 扫描；`-bgp` 和 CIDR 段扫描时自动开启
- **星级评分**（0-6 星）：综合握手时间、CDN、热门度、证书有效期、后量子支持
- **格式化彩色表格输出**（非 TTY 或 `NO_COLOR` 自动关闭着色）
- **扫描统计**：summary 输出 `attempted / tls_failed / dropped` 计数
- **优雅中断**：scan 模式下按 Ctrl+C 可中断扫描阶段，立即使用已收集的域名进行检测
- **并发安全的数据管理**：`singleflight` 去重下载 + 大小限制（默认 200 MiB）
- Docker 支持

## 编译

要求：Go 1.26+

```bash
make build
# 或
go build -o RealiTLScanner ./cmd/realitlscanner

# 去除调试信息的可复现构建：
go build -trimpath -ldflags='-s -w' -o RealiTLScanner ./cmd/realitlscanner
```

### 交叉编译

```bash
# Linux x86_64
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o RealiTLScanner-linux-amd64 ./cmd/realitlscanner

# Linux ARM64
GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o RealiTLScanner-linux-arm64 ./cmd/realitlscanner

# Windows
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o RealiTLScanner-windows-amd64.exe ./cmd/realitlscanner
```

## 使用方法

### 基础扫描

扫描 IP 段中的域名，输出到 CSV 文件：

```bash
# 扫描指定 IP、CIDR 或域名：
./RealiTLScanner -addr 1.2.3.0/24

# 从文件读取目标：
./RealiTLScanner -in targets.txt

# 从 URL 抓取域名列表：
./RealiTLScanner -url https://launchpad.net/ubuntu/+archivemirrors

# 自定义端口、线程数、超时：
./RealiTLScanner -addr 107.172.1.0/24 -port 443 -thread 10 -timeout 5

# 指定输出文件（默认：out.csv）：
./RealiTLScanner -addr 1.2.3.0/24 -out results.csv

# 从单个 IP/域名向外持续扫描相邻 IP（默认只扫这一个主机）：
./RealiTLScanner -addr 1.2.3.4 -infinite

# 下载失败时继续运行：
./RealiTLScanner -addr 1.2.3.0/24 -skip-download
```

首次运行时会自动下载 `Country.mmdb`（GeoIP 数据库）。下载失败默认停止运行，使用 `-skip-download` 可跳过。

### 域名检测（`scan` 命令）

扫描域名并评估可用性，以格式化表格输出到终端：

```bash
# 扫描 IP 段，自动检测并展示结果：
./RealiTLScanner scan -addr 1.2.3.0/24

# 从之前扫描生成的 CSV 文件读取域名：
./RealiTLScanner scan -csv results.csv

# 直接指定域名：
./RealiTLScanner scan apple.com www.tesla.com example.com

# 同时输出到文件：
./RealiTLScanner scan -csv results.csv -out report.txt

# 自定义线程数和超时：
./RealiTLScanner scan -addr 1.2.3.0/24 -thread 16 -timeout 10

# 下载失败时继续运行：
./RealiTLScanner scan -addr 1.2.3.0/24 -skip-download
```

`scan` 命令首次运行时会自动下载 `gfwlist.conf` 和 `Country.mmdb`。下载失败默认停止，使用 `-skip-download` 可在检测能力受限的情况下继续运行。

#### 输出示例

```
------------------------------------------------------------------------------------------------------------------------------
最终域名                           基础条件     握手时间       证书时间       CDN      热门     推荐     页面状态     备注
------------------------------------------------------------------------------------------------------------------------------
cdn77.akamai-edge.net              ✓            142ms          312天          无       -        ******   200          PQC
shop.bingserve.com                 ✓            274ms          83天           无       -        ****     200
blog.example.xyz                   ✓            210ms          120天          无       -        ****     200          廉价/PQC
vless.cheapvps.top                 ✗            156ms          88天           无       -                 200          代理
sub.host-panel.net                 ✗            203ms          41天           无       -                 200          面板
home.duckdns.org                   ✗            318ms          60天           无       -                 -            动态DNS

------------------------------------------------------------------------------------------------------------------------------
检测完成: 6 个域名, 3 个适合 (50.0%), 耗时 12.9s
扫描统计: attempted=256  tls_failed=210  dropped=15
```

当输出被重定向到文件 / 管道（非 TTY）或环境变量 `NO_COLOR` 已设置时，颜色输出自动关闭。

| 列名 | 说明 |
|------|------|
| 最终域名 | TLS 证书中的域名(列宽自适应最长域名,不再截断) |
| 基础条件 | TLS 1.3 + H2 + 有效证书 + 签发者（✓/✗） |
| 握手时间 | TLS 握手延迟（绿色 ≤200ms，黄色 ≤500ms，红色 >500ms） |
| 证书时间 | 证书剩余有效天数（绿色 ≥60天，黄色 ≥30天，红色 <30天） |
| CDN | CDN 检测级别（无/low/medium/high） |
| 热门 | 热门网站标记（✓ = 热门，- = 非热门） |
| 推荐 | 星级评分 0-6，综合评估质量 |
| 页面状态 | HTTP 状态码 |
| 备注 | 命中的标记按 `/` 叠加显示（如 `代理/廉价/PQC`）。硬否决：代理（域名含代理关键词）、面板（`Server` 头识别 x-ui 等）、动态DNS、NAS；软信号：廉价（廉价 TLD）；加分：PQC（协商了后量子密钥交换）。为空表示干净 |

#### 星级评分标准

| 条件 | 星数 |
|------|------|
| 基础条件通过（TLS 1.3 + H2 + SNI 匹配） | +1 |
| 握手时间 ≤ 200ms | +1 |
| 未检测到 CDN | +1 |
| 非热门网站 | +1 |
| 证书有效期 ≥ 60 天 | +1 |
| 后量子密钥交换（X25519MLKEM768） | +1 |

> **去伪一票否决**（blocklist 检测器）：硬命中——域名含代理关键词、`Server` 头是代理面板（x-ui / sing-box / …）、或动态DNS / NAS 后缀——直接否决候选（`✗`，分数清零）。廉价 TLD（`.xyz` / `.top` / `.win` / …）只是软信号：仍判可用，但扣 1 星。

### 偷邻居发现（BGP 前缀展开）

不用猜 CIDR、也不用 `-infinite` 一个个试邻居——`-bgp` 直接把单个 IP 展开成其源 AS 宣告的前缀来扫，这正是「偷邻居」的天然范围。基础模式和 `scan` 模式都支持。

```bash
# 为单个 IP 智能选出最佳覆盖前缀并整段扫描：
./RealiTLScanner -addr 104.249.172.234 -bgp
./RealiTLScanner scan -addr 104.249.172.234 -bgp

# 若 bgp.tools 显示的活跃邻居数超过上限则拒绝，除非强制放行：
./RealiTLScanner -addr 1.2.3.4 -bgp -max-hosts 1024          # 活跃邻居 >1024 即拒绝
./RealiTLScanner -addr 1.2.3.4 -bgp -yes                     # 强制越过上限

# 两段式扫描：先做便宜的 TCP 探活，再做完整 TLS 扫描
# （跳过死/防火墙主机，免得它们各自耗满 -timeout）。
# -bgp 和 CIDR 扫描时自动开启；对 -in 文件(含 IP 段)可手动加：
./RealiTLScanner -in ranges.txt -probe-first
```

**智能选段。** 一个 IP 通常被多个重叠的已通告前缀覆盖——在 bgp.tools 上同一台主机可能同时落在 `/24`、`/21`、`/20` 下。`-bgp` 把它们枚举出来（Team Cymru 种子 + RIPEstat `routing-status`，后者已自动剔除近乎不可见的路由），并朝以 `/21` 为中心的 `/20`–`/24` 甜点段排序：邻居够多能找到好目标，又不至于扫到 `/14` 那么大。无需 API key。

**活跃邻居清点。** 选定前缀后，`-bgp` 会拉取 bgp.tools 的热力图并清点该段中 bgp.tools 实际见过多少地址——一个快速的事前估算（它反映的是 bgp.tools 的 ping 视角，不能替代随后真正的 TCP/TLS 探测）。若这个数超过 `-max-hosts` 则中止，除非加 `-yes`。`/20`–`/24` 段永远不可能超过默认的 4096，所以这道闸门只有当该 IP 仅被通告为更大的段时才真正起作用。

| 标志 | 作用 | 默认 |
|------|------|------|
| `-bgp` | 为 `-addr <ip>` 智能选出最佳覆盖 BGP 前缀（`/20`–`/24`）并扫描 | 关 |
| `-max-hosts N` | 若 bgp.tools 显示选中段的活跃邻居数超过 N 则中止；可用 `-yes` 覆盖 | 4096 |
| `-yes` | 强制越过 `-max-hosts` 活跃邻居上限 | 关 |
| `-probe-first` | 两段式扫描：完整 TLS 扫描前先做 TCP 探活预筛 | 关（`-bgp` / CIDR `-addr` 时自动开） |
| `-infinite` | 从单个 IP/域名向外遍历相邻 IP（基础模式） | 关 |

### 单域名检测（`check` 命令）

```bash
# 对单个域名做完整检测（TLS + 所有检测器）：
./RealiTLScanner check example.com

# 自定义端口 / 超时 / 数据目录：
./RealiTLScanner check example.com -port 443 -timeout 5 -data-dir /opt/realitls

# 数据文件下载失败时继续：
./RealiTLScanner check example.com -skip-download
```

`check` 失败时返回非零 exit code，便于脚本判断：

| Exit | 含义 |
|------|------|
| 0 | 成功 |
| 1 | 未提供 domain 参数或 DNS 解析失败 |
| 2 | TLS 扫描失败（dial / handshake / 无证书） |
| 3 | 数据文件下载失败（可加 `-skip-download` 容忍） |

### 版本信息

```bash
./RealiTLScanner version
```

### Docker

```bash
# 构建：
docker build -t realitlscanner .

# 运行：
docker run --rm realitlscanner -addr 1.1.1.0/24
docker run --rm realitlscanner scan -addr 1.1.1.0/24
docker run --rm realitlscanner scan apple.com www.tesla.com
```

## 资源文件

运行时所需的资源文件会**自动下载**：

| 文件 | 使用场景 | 用途 | 来源 |
|------|---------|------|------|
| `Country.mmdb` | 基础 + Scan | GeoIP 查询 | [Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip/releases) |
| `gfwlist.conf` | 仅 Scan | GFW 封锁检测 | [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules) |
| `cdn_keywords.txt` | 仅 Scan | CDN 检测 | 内置（编译嵌入） |
| `hot_websites.txt` | 仅 Scan | 热门网站检测 | 内置（编译嵌入） |
| `blocklist_keywords.txt` | 仅 Scan | 去伪黑名单（代理/动态DNS/NAS/廉价TLD） | 内置（编译嵌入） |

- 基础模式下载：`Country.mmdb`
- Scan 模式下载：`Country.mmdb` + `gfwlist.conf`
- CDN 关键词和热门网站列表已嵌入二进制文件（无需下载）
- 使用 `-skip-download` 可在下载失败时继续运行

### GitHub 下载失败时自动回退公益中转

直连 `raw.githubusercontent.com` 失败（超时、被墙、限流、非 200）时，会依次改用公益中转重试，成功即停：

| 顺序 | 地址 |
|------|------|
| 1 | 直连 `raw.githubusercontent.com` |
| 2 | `https://ghfast.top` |
| 3 | `https://gh-proxy.com` |

中转地址由环境变量 `REALITLS_GH_MIRRORS` 覆盖（逗号分隔，按序尝试），设为空值即完全关闭回退：

```bash
# 换成自己的中转
REALITLS_GH_MIRRORS=https://my-mirror.example ./RealiTLScanner scan -addr 1.2.3.0/24

# 只走直连，不用中转
REALITLS_GH_MIRRORS= ./RealiTLScanner scan -addr 1.2.3.0/24
```

拼接方式是把完整原始 URL 追加到中转地址后面，例如 `https://ghfast.top/https://raw.githubusercontent.com/...`。单次尝试超时 90 秒；所有地址都失败才算下载失败（此时 `-skip-download` 仍可放行）。

## 项目结构

```
cmd/realitlscanner/     CLI 入口（子命令路由 + url-fetch 超时/大小限制）
internal/
  types/                共享类型（Host、ScanResult、TLSInfo、CertValidResult）
  scanner/              TLS 扫描（ctx-aware）+ CSV 域名解析 + StrictDomainName 校验
                        + BGP 智能选段（Cymru/RIPEstat）+ bgp.tools 邻居清点 + TCP 探活预筛
  detector/             检测器接口 + CDN/GFW/HotSite/Location/Redirect/Status/TLSCheck/Blocklist + 评分
                        + 安全目标网关（拒绝 loopback / private / 元数据地址）
  pipeline/             基于 Channel 的 扫描→检测→输出 流水线，带 attempted/tls_failed/dropped 统计
  output/               输出器（CSV、JSON、JSONL、表格）
  data/                 资源文件管理（嵌入 + singleflight 去重下载 + 大小限制）
  geo/                  GeoIP 查询（路径可配置）
```

## 测试

```bash
make test
# 或
go test -race ./...
```

## 安全说明

- **扫描器使用 `InsecureSkipVerify=true`**：这是有意的设计 — 目标是发现 Reality 可用服务器，而非验证 PKI。`CertValidResult.Valid` 仅反映基础可行性（TLS 1.3 + h2 ALPN + 非空 CertDomain/Issuer）；`CertValidResult.SNIMatch` 使用 `x509.VerifyHostname`（支持通配符）。需要真正验证的下游必须自行 verify 链。
- **Redirect / Status 检测器**：HTTP 探测仅对公网可路由域名运行。Loopback、link-local（`127.0.0.0/8`、`::1`、`169.254.0.0/16`）、私网（`10/8`、`172.16/12`、`192.168/16`、ULA）、云元数据（`169.254.169.254` 等）地址在发请求前即被拒绝。
- **数据下载**：限制 200 MiB（先校验 `Content-Length`，再 `LimitReader` 兜底）；`singleflight` 避免并发重复下载。
- **代理清理**：所有子命令启动时清空 upper/lower-case 代理环境变量（`HTTP_PROXY` / `http_proxy` / ...）。

## 致谢

- [XTLS/RealiTLScanner](https://github.com/XTLS/RealiTLScanner) - 原始项目
- [V2RaySSR/RealityChecker](https://github.com/V2RaySSR/RealityChecker) - 域名检测逻辑参考
