# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A fork of XTLS/RealiTLScanner. It scans IPs/CIDRs/domains for TLS servers usable as a **Reality `dest` target** ("偷邻居"), then scores each candidate. Two layers: a *scan* layer (TLS handshake → cert domain) and a *detect* layer (CDN / GFW / hot-site / blocklist / redirect / status → 0–6 star rating).

User-facing output (table headers, progress lines, usage text) is Chinese; logs, code, and comments are English.

## Commands

```bash
make build          # go build -o RealiTLScanner ./cmd/realitlscanner
make test           # go test -race ./... -count=1
make vet            # go vet ./...
go test ./internal/output -run TestFormatNote_PQC -v      # single test
go test ./internal/scanner -run TestSelectPrefix          # single package + name prefix
```

Requires **Go 1.26+** (`go.mod` says `go 1.26`; the PQC curve `tls.X25519MLKEM768` needs it).

On Windows, `-race` needs cgo and a gcc on PATH — run tests from PowerShell with `C:\mingw64\bin` available, not from the Bash tool. Without gcc, drop `-race`.

Release builds inject the version: `go build -trimpath -ldflags="-s -w -X main.version=v2.6.0"` (the `var version` default in `cmd/realitlscanner/version.go` is only a dev placeholder). Cross-compile with `CGO_ENABLED=0` for linux-amd64 / linux-arm64 / windows-amd64; `gh release create` must pass `--repo leafxdd/RealiTLScanner`, since the default remote is the XTLS upstream.

## CLI surface

`main.go` routes on `os.Args[1]`: a first arg not starting with `-` is a subcommand (`scan` / `check` / `version`), anything else falls through to **legacy basic mode**. So there are two near-parallel flag sets — `runLegacy` (CSV output) and `runScan` (table output + detectors). **A new scan flag usually has to be added to both**, and to `reorderArgs`' `knownFlags` map if it takes a value (that map exists so positional domains can be mixed with flags in `scan`).

- basic mode → `output.CSVWriter`, downloads `Country.mmdb` only
- `scan` → `output.TableWriter`, downloads `Country.mmdb` + `gfwlist.conf`, runs all detectors
- `check <domain>` → single host, human-readable dump, meaningful exit codes (0/1/2/3)

`-h` output lives in `usage.go` and is hand-written — update it when flags change.

## Architecture

Flow: **host source → (optional TCP liveness pre-filter) → pipeline (scan workers) → detector.Runner → writer**.

`internal/pipeline` is the spine. `Pipeline.Run` fans `<-chan types.Host` across `ScanWorkers` goroutines calling `scanner.ScanTLS`, then optionally pipes through a `detector.Runner`. Everything is `*types.ScanResult` flowing over channels; detectors **mutate the result in place** rather than returning values.

Key wiring facts that aren't obvious from one file:

- **`PassAll`** — by default the pipeline drops non-feasible results. `scan` sets `PassAll: true` so unsuitable candidates still reach the table (rendered with ✗). Basic mode leaves it false.
- **`Feasible` is set in two places.** `ScanTLS` sets it from TLS 1.3 + h2 + non-empty cert domain/issuer; the blocklist and `vetoIfProxyServer` later *clear* it. Never assume it's final before detectors run.
- **Score is computed by the Runner**, not by detectors: `runner.processOne` calls `ComputeScore` after every detector. Adding a scoring signal means editing `detector/scorer.go` and the `备注` column in `output/table.go` together.
- **Three-phase Ctrl+C in `scan`.** Probe, scan, and detect each get their own `signal.NotifyContext`, so the first Ctrl+C ends probing, the second ends scanning and proceeds to detect the domains found so far. Don't collapse these into one context.

### Detectors (`internal/detector`)

Implement `Detector{Name, Detect, Available}` and register in `buildDetectors` in `main.go`. `Available()` gating is how a missing data file disables a detector instead of failing the run.

- Anything doing an outbound HTTP probe **must** go through `isSafeForProbe` (`safe_target.go`) — it rejects IP literals, localhost, and hostnames resolving to private/loopback/link-local/metadata addresses before a request is sent.
- `blocklist.go` parses a prefixed line format from the embedded list: `kw:` (substring, hard veto), `dyn:`/`nas:` (suffix, hard veto), `tld:` (cheap TLD, soft −1 star).
- `status.go` and `redirect.go` share `RedirectResult` — whichever runs first wins (`if result.Redirect != nil { return nil }`), and both feed the `Server` header into `vetoIfProxyServer`.

### Terminal output (`internal/output`)

Two independent TTY renderers that **must not be active at the same time** — overlapping cursor-control escapes corrupt each other's frames:

- `LiveLog` — fixed-height rolling window (scan/probe progress). Its `render()` maintains a strict invariant: cursor at column 0 of the region's top row on entry *and* exit. `Close()` parks the cursor below the region; call it before any other stderr write. `liveFilterBarrier` in `main.go` exists purely to enforce this ordering as a barrier.
- `TableWriter` — buffers **all** rows until `flush()` so the 最终域名 column can auto-fit the longest cert domain. It does not stream. A transient `检测中 N/M` line is drawn while buffering. All other columns are fixed-width; padding uses `stringVisualWidth` (CJK = 2 cells) and ignores ANSI escapes, so adding a column means updating the `col*W` constants, `renderRow`, and `headerRow` in lockstep.

Colour is off when stdout isn't a character device or `NO_COLOR` is set.

### Data files (`internal/data`)

`DataManager` unifies embedded and downloaded files behind one `GetPath`. Embedded lists (`cdn_keywords`, `hot_websites`, `blocklist`) are materialised to a temp file at construction. `gfwlist` and `geoip` download over HTTP with singleflight dedup, a 200 MiB cap, and atomic `.tmp` + rename. A file marked `Mirrored` retries through the public GitHub relays in `defaultGitHubMirrors` (override via `REALITLS_GH_MIRRORS`) when the direct fetch fails; `download` owns `f.State` across the whole attempt loop so a failed candidate doesn't mark the file Missing prematurely. `-skip-download` degrades to limited detection instead of aborting.

### BGP neighbour discovery (`internal/scanner/bgp*.go`)

`-bgp` expands a single IP to the best covering announced prefix: `bgp_select.go` enumerates candidates (Team Cymru seed + RIPEstat `routing-status`) and ranks toward the /20–/24 sweet spot centred on /21; `bgp_peek.go` counts active neighbours from bgp.tools' heatmap image and gates on `-max-hosts` (override with `-yes`). No API keys. `-bgp` and CIDR `-addr` auto-enable `-probe-first`.

## Conventions

- Proxy env vars are cleared at startup (`clearProxy`) for every subcommand — scans must not go through a proxy. Tests that need an HTTP client rely on this too.
- `ScanTLS` uses `InsecureSkipVerify: true` **by design**; `CertValidResult` is a feasibility heuristic plus `x509.VerifyHostname`, never a PKI verdict. Don't "fix" this.
- Tests use `httptest` servers throughout — no live network calls, nothing skipped in short mode. Detectors expose a `testInjected` field to bypass `isSafeForProbe` for `127.0.0.1` test servers.
- Commits are Chinese conventional-commit style (`feat(scanner): …`). Keep README.md and README_zh.md in sync when behaviour changes.

<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **RealiTLScanner** (715 symbols, 2190 relationships, 51 execution flows). Use the GitNexus MCP tools to understand code, assess impact, and navigate safely.

> Index stale? Run `node .gitnexus/run.cjs analyze` from the project root — it auto-selects an available runner. No `.gitnexus/run.cjs` yet? `npx gitnexus analyze` (npm 11 crash → `npm i -g gitnexus`; #1939).

## Always Do

- **MUST run impact analysis before editing any symbol.** Before modifying a function, class, or method, run `impact({target: "symbolName", direction: "upstream"})` and report the blast radius (direct callers, affected processes, risk level) to the user.
- **MUST run `detect_changes()` before committing** to verify your changes only affect expected symbols and execution flows. For regression review, compare against the default branch: `detect_changes({scope: "compare", base_ref: "main"})`.
- **MUST warn the user** if impact analysis returns HIGH or CRITICAL risk before proceeding with edits.
- When exploring unfamiliar code, use `query({search_query: "concept"})` to find execution flows instead of grepping. It returns process-grouped results ranked by relevance.
- When you need full context on a specific symbol — callers, callees, which execution flows it participates in — use `context({name: "symbolName"})`.
- For security review, `explain({target: "fileOrSymbol"})` lists taint findings (source→sink flows; needs `analyze --pdg`).

## Never Do

- NEVER edit a function, class, or method without first running `impact` on it.
- NEVER ignore HIGH or CRITICAL risk warnings from impact analysis.
- NEVER rename symbols with find-and-replace — use `rename` which understands the call graph.
- NEVER commit changes without running `detect_changes()` to check affected scope.

## Resources

| Resource | Use for |
|----------|---------|
| `gitnexus://repo/RealiTLScanner/context` | Codebase overview, check index freshness |
| `gitnexus://repo/RealiTLScanner/clusters` | All functional areas |
| `gitnexus://repo/RealiTLScanner/processes` | All execution flows |
| `gitnexus://repo/RealiTLScanner/process/{name}` | Step-by-step execution trace |

## CLI

| Task | Read this skill file |
|------|---------------------|
| Understand architecture / "How does X work?" | `.claude/skills/gitnexus/gitnexus-exploring/SKILL.md` |
| Blast radius / "What breaks if I change X?" | `.claude/skills/gitnexus/gitnexus-impact-analysis/SKILL.md` |
| Trace bugs / "Why is X failing?" | `.claude/skills/gitnexus/gitnexus-debugging/SKILL.md` |
| Rename / extract / split / refactor | `.claude/skills/gitnexus/gitnexus-refactoring/SKILL.md` |
| Tools, resources, schema reference | `.claude/skills/gitnexus/gitnexus-guide/SKILL.md` |
| Index, status, clean, wiki CLI commands | `.claude/skills/gitnexus/gitnexus-cli/SKILL.md` |

<!-- gitnexus:end -->
