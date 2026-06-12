package main

import (
	"flag"
	"fmt"
)

// printMainUsage documents the whole tool — subcommands plus the basic-scan
// flags — and is wired to the bare-invocation FlagSet's Usage so `-h` reflects
// the current feature set instead of a bare flag dump.
func printMainUsage(fs *flag.FlagSet) {
	w := fs.Output()
	fmt.Fprintf(w, "RealiTLScanner %s — TLS 证书扫描器 + Reality 偷邻居域名评估\n\n", version)
	fmt.Fprint(w, `用法:
  RealiTLScanner [flags]                 基础扫描:扫 IP/CIDR/域名,导出 CSV(默认 out.csv)
  RealiTLScanner scan [flags] [域名...]  扫描并检测,彩色表格输出(可用性/星级/备注)
  RealiTLScanner check <域名> [flags]    单域名完整检测,按结果返回 exit code
  RealiTLScanner version                 打印版本

基础扫描 flags:
`)
	fs.PrintDefaults()
	fmt.Fprint(w, `
示例:
  RealiTLScanner -addr 1.2.3.0/24                     扫一个 CIDR
  RealiTLScanner -addr 104.249.172.234 -bgp           展开到 BGP 前缀偷邻居
  RealiTLScanner -in targets.txt -out results.csv     从文件读目标
  RealiTLScanner scan -addr 1.2.3.0/24                扫描并检测可用性
  RealiTLScanner scan apple.com www.tesla.com         直接检测指定域名
  RealiTLScanner check example.com                    单域名检测

子命令各自的 flags 见: RealiTLScanner scan -h / RealiTLScanner check -h
`)
}

// printScanUsage documents the scan subcommand.
func printScanUsage(fs *flag.FlagSet) {
	w := fs.Output()
	fmt.Fprint(w, `RealiTLScanner scan — 扫描 + 检测,彩色表格输出(可用性 / 星级 / 备注)

用法:
  RealiTLScanner scan [flags] [域名...]

输入(下列三者择一,或直接给位置参数域名):
  -addr/-in/-url  扫 IP/CIDR/域名,边扫边检测
  -csv <file>     从上次扫描生成的 CSV 读取(取 CERT_DOMAIN 列)
  域名...         位置参数,直接检测这些域名

flags:
`)
	fs.PrintDefaults()
	fmt.Fprint(w, `
示例:
  RealiTLScanner scan -addr 1.2.3.0/24
  RealiTLScanner scan -addr 104.249.172.234 -bgp
  RealiTLScanner scan -csv results.csv -out report.txt
  RealiTLScanner scan apple.com www.tesla.com
`)
}

// printCheckUsage documents the check subcommand.
func printCheckUsage(fs *flag.FlagSet) {
	w := fs.Output()
	fmt.Fprint(w, `RealiTLScanner check — 单域名完整检测(TLS + 全部检测器)

用法:
  RealiTLScanner check <域名> [flags]

flags:
`)
	fs.PrintDefaults()
	fmt.Fprint(w, `
exit code: 0 成功 / 1 缺少域名或 DNS 解析失败 / 2 TLS 扫描失败 / 3 数据文件下载失败

示例:
  RealiTLScanner check example.com
  RealiTLScanner check example.com -port 443 -timeout 5 -data-dir /opt/realitls
`)
}
