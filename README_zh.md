# RealiTLScanner

[English](README.md)

高性能 TLS 证书扫描器，集成 Reality 协议域名可用性评估功能。扫描 IP/CIDR/域名目标的 TLS 证书，通过多种检测器评估域名可行性（CDN、GFW、重定向、热门网站等）。

## 功能特性

- TLS 证书扫描（IP、CIDR、域名）
- 可配置并发数的高速扫描
- GeoIP 地理位置查询
- **域名可用性检测**：CDN、GFW、TLS 验证、热门网站、重定向、HTTP 状态
- **星级评分**（0-5 星）：综合握手时间、CDN、热门度、证书有效期
- **格式化彩色表格输出**
- **实时进度显示**
- **优雅中断**：scan 模式下按 Ctrl+C 可中断扫描阶段，立即使用已收集的域名进行检测
- Docker 支持

## 编译

要求：Go 1.21+

```bash
make build
# 或
go build -o RealiTLScanner ./cmd/realitlscanner
```

### 交叉编译

```bash
# Linux x86_64
GOOS=linux GOARCH=amd64 go build -o RealiTLScanner ./cmd/realitlscanner

# Linux ARM64
GOOS=linux GOARCH=arm64 go build -o RealiTLScanner ./cmd/realitlscanner

# Windows
GOOS=windows GOARCH=amd64 go build -o RealiTLScanner.exe ./cmd/realitlscanner
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
------------------------------------------------------------------------------------------------
最终域名                           基础条件     握手时间       证书时间       CDN      热门     推荐     页面状态
------------------------------------------------------------------------------------------------
yz.iosjy.top                   ✓          341ms        69天         无       -      ****     200
blog.bingserve.xyz             ✓          447ms        83天         无       -      ****     200
yingyaozw.com                  ✓          439ms        246天        无       -      ****     200
code.memoncler.com             ✓          783ms        5天          无       -      ***      -
o03.cc                         ✗          1624ms       88天         无       -      ***      405

------------------------------------------------------------------------------------------------
检测完成: 31 个域名, 29 个适合 (93.5%), 耗时 12.9s
```

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

#### 星级评分标准

| 条件 | 星数 |
|------|------|
| 基础条件通过（TLS 1.3 + H2 + SNI 匹配） | +1 |
| 握手时间 ≤ 200ms | +1 |
| 未检测到 CDN | +1 |
| 非热门网站 | +1 |
| 证书有效期 ≥ 60 天 | +1 |

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

- 基础模式下载：`Country.mmdb`
- Scan 模式下载：`Country.mmdb` + `gfwlist.conf`
- CDN 关键词和热门网站列表已嵌入二进制文件（无需下载）
- 使用 `-skip-download` 可在下载失败时继续运行

## 项目结构

```
cmd/realitlscanner/     CLI 入口（子命令路由）
internal/
  types/                共享类型（Host、ScanResult）
  scanner/              TLS 扫描 + CSV 域名解析
  detector/             检测器接口 + 实现 + 评分器
  pipeline/             基于 Channel 的 扫描→检测→输出 流水线
  output/               输出器（CSV、JSON、表格）+ 进度显示
  data/                 资源文件管理（嵌入 + 下载）
  geo/                  GeoIP 查询
```

## 测试

```bash
make test
# 或
go test -race ./...
```

## 致谢

- [XTLS/RealiTLScanner](https://github.com/XTLS/RealiTLScanner) - 原始项目
- [V2RaySSR/RealityChecker](https://github.com/V2RaySSR/RealityChecker) - 域名检测逻辑参考
