# RealiTLScanner

[English](README.md)

高性能 TLS 证书扫描器，集成 Reality 协议域名可用性评估功能。扫描 IP/CIDR/域名目标的 TLS 证书，通过多种检测器评估域名可行性（CDN、GFW、重定向、热门网站等）。

## 功能特性

- TLS 证书扫描（IP、CIDR、域名），支持 context 取消
- 可配置并发数的高速扫描
- GeoIP 地理位置查询（数据目录可配置）
- **域名可用性检测**：CDN、GFW、TLS 验证（SAN 优先 + 通配符 `VerifyHostname`）、热门网站、重定向、HTTP 状态
- **去伪黑名单**：一票否决代理关键词域名、代理面板（通过 `Server` 头识别 x-ui / sing-box 等）、动态DNS / NAS 后缀；廉价 TLD 作为软信号（扣 1 星）——结果体现在「备注」列
- **SSRF 安全防护**：redirect/status 探测器拒绝 loopback / private / link-local / 云元数据地址
- **偷邻居发现（`-bgp`）**：把单个 `-addr` IP 展开成其所属 AS 宣告的 BGP 前缀（Team Cymru 主 + RIPEstat 兜底）整段扫描，受 `-max-hosts` 上限保护（默认 4096，超限需 `-yes`）
- **两段式扫描（`-probe-first`）**：先用高并发 TCP 探活筛掉死/防火墙主机，再对存活主机做完整 TLS 扫描；`-bgp` 时自动开启
- **星级评分**（0-5 星）：综合握手时间、CDN、热门度、证书有效期
- **格式化彩色表格输出**（非 TTY 或 `NO_COLOR` 自动关闭着色）
- **扫描统计**：summary 输出 `attempted / tls_failed / dropped` 计数
- **优雅中断**：scan 模式下按 Ctrl+C 可中断扫描阶段，立即使用已收集的域名进行检测
- **并发安全的数据管理**：`singleflight` 去重下载 + 大小限制（默认 200 MiB）
- Docker 支持

## 编译

要求：Go 1.21+

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
cdn77.akamai-edge.net              ✓            142ms          312天          无       -        *****    200
shop.bingserve.com                 ✓            274ms          83天           无       -        ****     200
blog.example.xyz                   ✓            210ms          120天          无       -        ***      200          廉价
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
| 最终域名 | TLS 证书中的域名 |
| 基础条件 | TLS 1.3 + H2 + 有效证书 + 签发者（✓/✗） |
| 握手时间 | TLS 握手延迟（绿色 ≤200ms，黄色 ≤500ms，红色 >500ms） |
| 证书时间 | 证书剩余有效天数（绿色 ≥60天，黄色 ≥30天，红色 <30天） |
| CDN | CDN 检测级别（无/low/medium/high） |
| 热门 | 热门网站标记（✓ = 热门，- = 非热门） |
| 推荐 | 星级评分 0-5，综合评估质量 |
| 页面状态 | HTTP 状态码 |
| 备注 | 去伪标记：代理（域名含代理关键词）/ 面板（`Server` 头识别 x-ui 等）/ 动态DNS / NAS / 廉价（廉价 TLD，软信号）；为空表示干净 |

#### 星级评分标准

| 条件 | 星数 |
|------|------|
| 基础条件通过（TLS 1.3 + H2 + SNI 匹配） | +1 |
| 握手时间 ≤ 200ms | +1 |
| 未检测到 CDN | +1 |
| 非热门网站 | +1 |
| 证书有效期 ≥ 60 天 | +1 |

> **去伪一票否决**（blocklist 检测器）：硬命中——域名含代理关键词、`Server` 头是代理面板（x-ui / sing-box / …）、或动态DNS / NAS 后缀——直接否决候选（`✗`，分数清零）。廉价 TLD（`.xyz` / `.top` / `.win` / …）只是软信号：仍判可用，但扣 1 星。

### 偷邻居发现（BGP 前缀展开）

不用猜 CIDR、也不用 `-infinite` 一个个试邻居——直接把单个 IP 展开成其源 AS 宣告的精确前缀来扫，这正是「偷邻居」的天然范围。基础模式和 `scan` 模式都支持。

```bash
# 把单个 IP 展开成其 BGP 公告前缀，整段扫描：
./RealiTLScanner -addr 104.249.172.234 -bgp
./RealiTLScanner scan -addr 104.249.172.234 -bgp

# 展开后主机数超过上限（默认 4096）会拒绝，除非显式确认：
./RealiTLScanner -addr 1.2.3.4 -bgp -max-hosts 1024          # 超过 1024 即拒绝
./RealiTLScanner -addr 1.2.3.4 -bgp -yes                     # 放行超限展开

# 两段式扫描：先做便宜的 TCP 探活，再做完整 TLS 扫描
# （跳过死/防火墙主机，免得它们各自耗满 -timeout）。
# -bgp 时自动开启；任意 IP/CIDR 扫描也可手动开启：
./RealiTLScanner -addr 1.2.3.0/24 -probe-first
```

覆盖前缀来自公共路由采集器，经 Team Cymru 的 whois 服务解析（RIPEstat 兜底），因此可能是 `/22`、`/23` 或 `/24`，取决于该 AS 如何宣告其地址块——无需 API key。

| 标志 | 作用 | 默认 |
|------|------|------|
| `-bgp` | 把 `-addr <ip>` 展开成其公告前缀，整段扫描 | 关 |
| `-max-hosts N` | 展开前缀时的主机数上限，超限则中止，除非加 `-yes` | 4096 |
| `-yes` | 展开超过 `-max-hosts` 时确认放行 | 关 |
| `-probe-first` | 两段式扫描：完整 TLS 扫描前先做 TCP 探活预筛 | 关（`-bgp` 时自动开） |
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

## 项目结构

```
cmd/realitlscanner/     CLI 入口（子命令路由 + url-fetch 超时/大小限制）
internal/
  types/                共享类型（Host、ScanResult、TLSInfo、CertValidResult）
  scanner/              TLS 扫描（ctx-aware）+ CSV 域名解析 + StrictDomainName 校验
                        + BGP 前缀解析（Cymru/RIPEstat）+ TCP 探活预筛
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
