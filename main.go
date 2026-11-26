package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/xhwarp/warp-client/internal/cache"
)

// register needs this too - its tunnel fallback registers through one of the
// sampled addresses.
func setupScan(opts options) (protoRun, []netip.Addr, error) {
	// -proto is the tunnel that crosses this network, which under -through is the
	// outer one; what gets scanned then runs inside it.
	proto := opts.proto
	if opts.through != "" {
		proto = opts.innerProto
	}
	run, err := parseProto(proto)
	if err != nil {
		return run, nil, err
	}

	pools = poolsFor(run, opts.ipv6)
	if len(opts.targets) > 0 {
		pools = opts.targets
	}
	// With -interface, interfaceAddr is the authoritative family check (per-interface,
	// precise error); the host-wide check only runs without it.
	if opts.iface != "" {
		if !deviceBindSupported {
			return run, nil, fmt.Errorf("-interface requires Linux (SO_BINDTODEVICE)")
		}
		ip, err := interfaceAddr(opts.iface, opts.ipv6)
		if err != nil {
			return run, nil, err
		}
		scanInterface = opts.iface
		scanSourceIP = ip
	} else if opts.through == "" && !haveAddrFamily(opts.ipv6) {
		// With -through the endpoints are dialled from inside the outer tunnel,
		// which carries both families whatever the host has.
		return run, nil, fmt.Errorf("no routable %s address on this host - nothing to scan", famName(opts.ipv6))
	}

	sample := opts.perSubnet
	if opts.full {
		sample = 0
	}
	return run, expandPools(sample), nil
}

func loadScanAccount(path string) error {
	a, err := loadAccount(path)
	if err != nil {
		return fmt.Errorf("no WARP account at %s: run \"xehn register\" first", path)
	}
	applyAccount(a)
	fmt.Fprintln(os.Stderr, errPal.dim(fmt.Sprintf("Using cached WARP account from %s", path)))
	if a.IPv6 == "" {
		fmt.Fprintln(os.Stderr, errPal.fail("this account file predates per-device addresses - IPv6 falls back to a constant that Cloudflare drops; run \"xehn register\" again"))
	}
	fmt.Fprintln(os.Stderr)
	return nil
}

func runRegisterCmd(ctx context.Context, opts options) error {
	if err := applyRelay(&opts); err != nil {
		return err
	}
	_, ips, err := setupScan(opts)
	if err != nil {
		return err
	}
	timeout := time.Duration(opts.timeoutSec) * time.Second

	var existing account
	if !opts.freshAccount {
		if existing, err = accountToRotate(opts.accountPath); err != nil {
			return err
		}
	}

	a, err := obtainAccount(ctx, opts, ips, timeout, existing)
	if err != nil {
		if opts.proxy == "" {
			return fmt.Errorf("registration failed: %v\ncould not register directly or through a WARP tunnel; retry with -proxy <http(s)/socks5 URL>", err)
		}
		return fmt.Errorf("registration failed: %v", err)
	}
	if err := saveAccount(opts.accountPath, a); err != nil {
		return fmt.Errorf("could not save account to %s: %v", opts.accountPath, err)
	}
	what := "Registered fresh WARP account"
	if a.ID == existing.ID {
		what = "Rotated the keys of the existing WARP account"
	}
	fmt.Fprintln(os.Stderr, errPal.ok(fmt.Sprintf("%s -> %s", what, opts.accountPath)))
	return nil
}

func validateThreshold(pct int) error {
	if pct < 1 || pct > 100 {
		return fmt.Errorf("-threshold (%d) must be between 1 and 100", pct)
	}
	return nil
}

func runFindJunkCmd(ctx context.Context, opts options) error {
	if err := validateThreshold(opts.threshold); err != nil {
		return err
	}
	if err := loadScanAccount(opts.accountPath); err != nil {
		return err
	}
	run, _, err := setupScan(opts)
	if err != nil {
		return err
	}
	return runFindJunk(ctx, opts, run, time.Duration(opts.timeoutSec)*time.Second)
}

func runFindSNICmd(ctx context.Context, opts options) error {
	validateSNIProto(opts)
	if err := validateThreshold(opts.threshold); err != nil {
		return err
	}
	if err := loadScanAccount(opts.accountPath); err != nil {
		return err
	}
	run, ips, err := setupScan(opts)
	if err != nil {
		return err
	}
	if masqueAcct == nil {
		return fmt.Errorf("%s holds no MASQUE device: run \"xehn register\" again", opts.accountPath)
	}
	return runFindSNI(ctx, opts, run, ips, time.Duration(opts.timeoutSec)*time.Second)
}

func runScanCmd(ctx context.Context, opts options) error {
	if err := loadScanAccount(opts.accountPath); err != nil {
		return err
	}
	run, ips, err := setupScan(opts)
	if err != nil {
		return err
	}
	if run.isMASQUE() && masqueAcct == nil {
		return fmt.Errorf("%s holds no MASQUE device: run \"xehn register\" again", opts.accountPath)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if opts.through != "" {
		n, err := dialOuter(ctx, opts, time.Duration(opts.timeoutSec)*time.Second)
		if err != nil {
			return err
		}
		defer n.tunnel.Close()
		outer = n
	}
	ph, err := runScanUI(ctx, cancel, opts, run, ips, time.Duration(opts.timeoutSec)*time.Second, "", "")
	if err != nil {
		// runScan already reported the failure through the emit seam.
		os.Exit(1)
	}

	if filtered(opts) {
		ph = applyFilters(ph, opts)
		pools = poolsWithHits(ph)
	}

	// Nothing to report: say so on stderr and fail, instead of leaving a report
	// file whose only content is "No working endpoints found".
	if !anyEndpoint(ph) {
		return fmt.Errorf("%s", noEndpointMsg(opts))
	}

	if (opts.speed || opts.bestBy == bestKeySpeed) && showsSpeed(opts) {
		if !opts.speed {
			fmt.Fprintln(os.Stderr, errPal.dim("\n-best-by speed ranks by throughput, so the speedtest phase runs even without -speed"))
		}
		runWithUI(opts, cancel, false, "", "q to skip the rest", func(emit emitter) {
			measureSpeed(ctx, ph, time.Duration(opts.timeoutSec)*time.Second, emit)
		})
	}

	// Persist the sweep for connect: its endpoint pick, rotation and dead-marking
	// all read this entry, and until now a standalone scan never healed a stale
	// cache (scanTTL is hours, so connects kept rotating through corpse
	// endpoints). Chained (-through) sweeps are skipped: those endpoints are
	// only proven through the outer tunnel.
	if opts.through == "" {
		if ces := projectCacheEndpoints(ph); len(ces) > 0 {
			if store, err := cache.Open(cache.Options{TTL: scanTTL}); err == nil {
				cs := cachedScan{Proto: opts.proto, IPv6: opts.ipv6, At: time.Now(), Results: ces}
				if raw, err := json.Marshal(cs); err == nil {
					_ = store.Put(scanCacheKey(opts.proto, opts.ipv6), raw)
					fmt.Fprintln(os.Stderr, errPal.dim(fmt.Sprintf("cached %d working endpoint(s) for later connects", len(ces))))
				}
			}
		}
	}

	// Held rather than returned: the scan itself succeeded, so the report file is
	// still written and only the exit status carries the failure.
	var outErr error
	switch {
	case opts.best:
		outErr = printBest(os.Stdout, ph)
	case opts.conf == confStdout:
	default:
		writeConsole(os.Stdout, ph, consoleRenderer(os.Stdout), opts.tunPingCheck)
	}

	if opts.conf != "" {
		if err := writeConfFile(opts, ph); outErr == nil {
			outErr = err
		}
	}

	if opts.noReport {
		return outErr
	}

	reportPath := opts.output
	if reportPath == "" && (opts.best || opts.conf == confStdout) {
		return outErr
	}
	if reportPath == "" {
		reportPath = fmt.Sprintf("warp-report-%s.txt", time.Now().Format("2006-01-02-150405"))
	}
	if err := writeToFile(reportPath, ph, opts.tunPingCheck); err != nil {
		fmt.Fprintln(os.Stderr, errPal.fail(fmt.Sprintf("failed to write %s: %v", reportPath, err)))
	} else {
		fmt.Fprintln(os.Stderr, errPal.dim(fmt.Sprintf("\nFull report written to %s", reportPath)))
	}
	return outErr
}

// wantMeta is what only scan sets, and only scan prints the tables that repeat
// the live feed endpoint for endpoint.
func tablesFollow(opts options) bool {
	return opts.wantMeta && !opts.best && opts.conf != confStdout
}

func showsSpeed(opts options) bool {
	if opts.bestBy == bestKeySpeed {
		return true
	}
	if !opts.best && opts.conf != confStdout {
		return true
	}
	return !opts.noReport && opts.output != ""
}

func measureSpeed(ctx context.Context, ph phaseResult, timeout time.Duration, emit emitter) {
	picks := speedTargets(ph.results)
	const label = "Speedtest phase: measuring picked endpoints one at a time"
	emit(barBeginMsg{label: label, total: len(picks)})

	prevGC := debug.SetGCPercent(speedGCPercent)
	defer debug.SetGCPercent(prevGC)

	tn, err := newTunnel(ph.run)
	if err != nil {
		emit(stepMsg{fail: true, summary: fmt.Sprintf("speedtest failed: %v", err)})
		return
	}
	defer closeAfterDrain(tn)

	speeds := make(map[string]float64, len(picks))
	for _, p := range picks {
		if ctx.Err() != nil {
			break
		}
		speeds[p.endpoint] = endpointSpeed(ctx, tn, p.endpoint, timeout)
		emit(speedMsg{endpoint: p.endpoint, mbps: speeds[p.endpoint]})
		emit(probedMsg{})
	}
	for i, r := range ph.results {
		ph.results[i].speed = speeds[r.endpoint]
	}

	emit(barEndMsg{label: label, summary: fastestNote(speeds)})
	emit(doneMsg{})
}

func fastestNote(speeds map[string]float64) string {
	var endpoint string
	var best float64
	for ep, mbps := range speeds {
		if mbps > best {
			best, endpoint = mbps, ep
		}
	}
	if endpoint == "" {
		return "nothing measured"
	}
	return fmt.Sprintf("fastest %s at %s", speedStr(best), endpoint)
}

func closeAfterDrain(tn tunnel) {
	time.Sleep(speedDrain)
	tn.Close()
}

func endpointSpeed(ctx context.Context, tn tunnel, endpoint string, timeout time.Duration) float64 {
	for attempt := 0; attempt < max(tn.attempts(), 1); attempt++ {
		if ctx.Err() != nil {
			break
		}
		if !tn.handshake(ctx, endpoint, timeout) {
			continue
		}
		if mbps, ok := tn.stack().speedTest(ctx); ok {
			return mbps
		}
	}
	return 0
}

func anyEndpoint(ph phaseResult) bool {
	for _, r := range ph.results {
		if r.ok {
			return true
		}
	}
	return false
}

func filtered(opts options) bool {
	return len(opts.colos)+len(opts.countries)+len(opts.dropColos)+len(opts.dropCountries) > 0
}

func applyFilters(ph phaseResult, opts options) phaseResult {
	for _, f := range []struct {
		list []string
		want bool
		by   func(phaseResult, []string, bool) phaseResult
	}{
		{opts.colos, true, filterByColo},
		{opts.countries, true, filterByCountry},
		{opts.dropColos, false, filterByColo},
		{opts.dropCountries, false, filterByCountry},
	} {
		if len(f.list) > 0 {
			ph = f.by(ph, f.list, f.want)
		}
	}
	return ph
}

func noEndpointMsg(opts options) string {
	var filters []string
	if len(opts.colos) > 0 {
		filters = append(filters, "node "+strings.Join(opts.colos, ", "))
	}
	if len(opts.countries) > 0 {
		filters = append(filters, "country "+strings.Join(opts.countries, ", "))
	}
	if len(filters) > 0 {
		return "no endpoint landed on " + strings.Join(filters, " and ")
	}
	if len(opts.dropColos) > 0 {
		filters = append(filters, "node "+strings.Join(opts.dropColos, ", "))
	}
	if len(opts.dropCountries) > 0 {
		filters = append(filters, "country "+strings.Join(opts.dropCountries, ", "))
	}
	if len(filters) > 0 {
		return "every endpoint was excluded by " + strings.Join(filters, " and ")
	}
	if opts.proto == protoMASQUE || opts.proto == protoMASQUEH2 {
		return masqueBlockedMsg
	}
	if opts.genI1 == "" {
		if opts.proto == protoAWG {
			return "no working endpoints found - try -gen-i1 quic"
		}
		return "no working endpoints found - try -p awg -gen-i1 quic"
	}
	return "no working endpoints found"
}

const (
	noWorkingMsg     = "every matching endpoint was torn down mid-stream"
	masqueBlockedMsg = "no MASQUE endpoint passed data - this network blocks it, try -p awg"
)

func writeConfFile(opts options, ph phaseResult) error {
	best, ok := bestOverall(ph)
	if !ok {
		return fmt.Errorf("%s", noWorkingMsg)
	}
	// The separator goes to stderr: on a terminal it still splits the config off
	// the progress lines, and "-conf - > file" stays free of a leading blank line.
	if opts.conf == confStdout {
		fmt.Fprintln(os.Stderr)
	}
	if err := writeConf(opts, best.endpoint, ph.run); err != nil {
		return fmt.Errorf("failed to write %s: %v", opts.conf, err)
	}
	if opts.conf == confStdout {
		return nil
	}
	fmt.Fprintln(os.Stderr, errPal.dim(fmt.Sprintf("\n%s config for %s written to %s", ph.run.name, best.endpoint, opts.conf)))
	if outer != nil {
		note := fmt.Sprintf("  it holds both tunnels of the chain (outer %s) - split it in two before use", outer.label)
		if isMihomo(opts.confType) {
			note = fmt.Sprintf("  it chains through %s itself (dialer-proxy)", outer.label)
		}
		fmt.Fprintln(os.Stderr, errPal.dim(note))
	}
	if ph.run.isMASQUE() && !isMihomo(opts.confType) {
		if _, port, err := net.SplitHostPort(best.endpoint); err == nil {
			h2 := ""
			if ph.run.isH2() {
				h2 = " --http2"
			}
			fmt.Fprintln(os.Stderr, errPal.dim(fmt.Sprintf(
				"  run it with: usque socks -c %s -P %s -s %s%s", opts.conf, port, masqueSNI, h2)))
		}
	}
	return nil
}

func bestOverall(ph phaseResult) (endpointResult, bool) {
	var best endpointResult
	found := false
	for _, r := range workingSorted(ph.results) {
		if !found || lessByLossRTT(r, best) {
			best, found = r, true
		}
	}
	return best, found
}

func printBest(w io.Writer, ph phaseResult) error {
	best, ok := bestOverall(ph)
	if !ok {
		return fmt.Errorf("%s", noWorkingMsg)
	}
	fmt.Fprintln(w, best.endpoint)
	return nil
}

func runScanUI(ctx context.Context, cancel context.CancelFunc, opts options, run protoRun, ips []netip.Addr, timeout time.Duration, header, quitHint string) (phaseResult, error) {
	var ph phaseResult
	var scanErr error
	if err := runWithUI(opts, cancel, opts.tunPingCheck, header, quitHint, func(emit emitter) {
		ph, scanErr = runScan(ctx, opts, run, ips, timeout, emit)
	}); err != nil {
		return phaseResult{}, err
	}
	return ph, scanErr
}

func runWithUI(opts options, cancel context.CancelFunc, ping bool, header, quitHint string, work func(emitter)) error {
	if usePlainOutput(opts) {
		work(plainEmit)
		return nil
	}

	m := newScanModel(cancel, ping)
	m.header = header
	m.dropLists = tablesFollow(opts)
	if quitHint != "" {
		m.quitHint = quitHint
	}
	p := tea.NewProgram(m, tea.WithOutput(os.Stderr))
	defer enableVirtualTerminal()

	// A terminal the TUI cannot drive is not a reason to fail the run.
	// Fall back to the plain emitter and keep scanning.
	var uiFailed atomic.Bool
	emit := func(msg tea.Msg) {
		if uiFailed.Load() {
			plainEmit(msg)
			return
		}
		p.Send(msg)
	}

	workDone := make(chan struct{})
	go func() {
		work(emit)
		// Only doneMsg quits the program, and an error path returns without one:
		// without this the TUI spins on forever under the failure it just printed.
		emit(doneMsg{})
		close(workDone)
	}()
	if _, err := p.Run(); err != nil {
		uiFailed.Store(true)
		fmt.Fprintln(os.Stderr, errPal.fail("live output unavailable: "+err.Error()))
	}
	<-workDone
	return nil
}

func usePlainOutput(opts options) bool {
	return opts.plain || os.Getenv("NO_COLOR") != "" || !isTerminal(os.Stderr)
}

func runScan(ctx context.Context, opts options, run protoRun, ips []netip.Addr, timeout time.Duration, emit emitter) (phaseResult, error) {
	if scanSourceIP.IsValid() {
		emit(stepMsg{done: true, label: "Interface", summary: fmt.Sprintf("%s (%s)", opts.iface, scanSourceIP)})
	}
	if outer != nil {
		emit(stepMsg{done: true, label: "Through", summary: outer.label})
	}
	ports := masqueEndpointPorts
	if opts.port != 0 {
		ports = []int{opts.port}
		warpPorts = ports
		emit(stepMsg{done: true, label: "Port", summary: fmt.Sprintf("%d (pinned, phase 1 skipped)", opts.port)})
	}
	if opts.sweepPorts == sweepAll {
		warpPorts = allWarpPorts()
		emit(stepMsg{done: true, label: "Ports", summary: fmt.Sprintf("sweeping all %d known ports (phase 1 skipped)", len(warpPorts))})
	}
	if !run.isMASQUE() && opts.port == 0 && opts.sweepPorts != sweepAll {
		open, err := reachablePorts(ctx, run, ips, timeout, portProbeSample, opts.tunnelParallel, emit)
		if err != nil {
			emit(stepMsg{fail: true, summary: fmt.Sprintf("phase 1 failed: %v", err)})
			return phaseResult{}, err
		}
		if len(open) == 0 {
			emit(stepMsg{fail: true, summary: "no WARP port is reachable on this network"})
			return phaseResult{}, fmt.Errorf("no reachable WARP port")
		}
		warpPorts = open
	}

	if !run.isMASQUE() {
		ports = warpPorts
	}
	results, err := runPhase2(ctx, opts, run, ips, ports, timeout, emit)
	if err != nil {
		return phaseResult{}, err
	}
	// Phase 1 stops on the first IP that answers any port: if that IP only
	// answered a DPI-dropped port (commonly UDP 2408) or timeout_sec was too
	// tight for the full in-tunnel HTTPS meta round-trip, retry once with the
	// remaining primary ports (putting 500/1701/4500 ahead of 2408) and at
	// least 4s per-probe budget before declaring 0 working endpoints.
	if retryPorts, retryTimeout, reason, ok := phase2FallbackPlan(run, opts, ports, timeout, results); ok && ctx.Err() == nil {
		if reason == "missing_primary_ports" {
			stageMsg(fmt.Sprintf("[%s] 端口 %v 数据面未通过，补扫其余主端口 %v（超时 %ds）…",
				protoLabel(run.name), ports, retryPorts, int(retryTimeout.Seconds())))
		} else {
			stageMsg(fmt.Sprintf("[%s] %ds 超时下无可用端点，放宽至 %ds 重试主端口 %v…",
				protoLabel(run.name), int(timeout.Seconds()), int(retryTimeout.Seconds()), retryPorts))
		}
		warpPorts = retryPorts
		retryResults, rerr := runPhase2(ctx, opts, run, ips, retryPorts, retryTimeout, emit)
		if rerr != nil {
			return phaseResult{}, rerr
		}
		results = retryResults
	}

	// ISPs often let standard WARP ports (2408/500/1701/4500) complete the
	// initial WG/AWG handshake in Phase 1 while dropping real data in Phase 2,
	// which previously skipped extendedWarpPorts altogether. Sweep the 50
	// alternate ports whenever all primary ports fail data-plane verification.
	if needsExtendedPortFallback(run, opts, ports, results) && ctx.Err() == nil {
		stageMsg(fmt.Sprintf("[%s] 主端口均无法传输数据，正在探测 50 个冷门备用端口…", protoLabel(run.name)))
		extOpen, eerr := probePorts(ctx, run, sampleAddrs(ips, portProbeSample), extendedWarpPorts, timeout, opts.tunnelParallel, emit, "Phase 1b: sweeping alternate WARP ports")
		if eerr == nil && len(extOpen) > 0 {
			if len(extOpen) > 4 {
				extOpen = extOpen[:4]
			}
			extTimeout := max(timeout, scanRetryMinTimeout)
			stageMsg(fmt.Sprintf("[%s] 发现可达备用端口 %v，正在验证数据面…", protoLabel(run.name), extOpen))
			warpPorts = extOpen
			if extResults, rerr := runPhase2(ctx, opts, run, ips, extOpen, extTimeout, emit); rerr == nil {
				results = extResults
			}
		}
	}

	emit(doneMsg{})
	return phaseResult{run, results}, nil
}

// needsExtendedPortFallback reports whether an empty Phase 2 sweep only tried
// primary ports and should still probe extendedWarpPorts before giving up.
func needsExtendedPortFallback(run protoRun, opts options, lastUsedPorts []int, results []endpointResult) bool {
	if run.isMASQUE() || opts.port != 0 || opts.sweepPorts == sweepAll {
		return false
	}
	if len(workingSorted(results)) > 0 {
		return false
	}
	extSet := make(map[int]bool, len(extendedWarpPorts))
	for _, p := range extendedWarpPorts {
		extSet[p] = true
	}
	for _, p := range lastUsedPorts {
		if extSet[p] {
			return false
		}
	}
	return true
}

const scanRetryMinTimeout = 4 * time.Second

// fallbackPrimaryWarpPorts prefers alternate primary UDP ports ahead of 2408,
// which is the default WARP port most frequently targeted by ISP QoS/DPI.
var fallbackPrimaryWarpPorts = []int{500, 1701, 4500, 2408}

// missingPrimaryPorts returns the primary WARP ports that were not already
// covered by used, ordered with 500/1701/4500 ahead of 2408.
func missingPrimaryPorts(used []int) []int {
	seen := make(map[int]bool, len(used))
	for _, p := range used {
		seen[p] = true
	}
	var out []int
	for _, p := range fallbackPrimaryWarpPorts {
		if !seen[p] {
			out = append(out, p)
		}
	}
	return out
}

// phase2FallbackPlan decides whether an empty Phase 2 sweep warrants one
// fallback pass over missing primary ports or a wider per-probe timeout.
func phase2FallbackPlan(run protoRun, opts options, usedPorts []int, timeout time.Duration, results []endpointResult) (ports []int, retryTimeout time.Duration, reason string, ok bool) {
	if run.isMASQUE() || opts.port != 0 || opts.sweepPorts == sweepAll {
		return nil, 0, "", false
	}
	if len(workingSorted(results)) > 0 {
		return nil, 0, "", false
	}
	retryTimeout = timeout
	if retryTimeout < scanRetryMinTimeout {
		retryTimeout = scanRetryMinTimeout
	}
	if missing := missingPrimaryPorts(usedPorts); len(missing) > 0 {
		return missing, retryTimeout, "missing_primary_ports", true
	}
	if timeout < scanRetryMinTimeout {
		return append([]int(nil), fallbackPrimaryWarpPorts...), retryTimeout, "tight_timeout", true
	}
	return nil, 0, "", false
}

func runPhase2(ctx context.Context, opts options, run protoRun, ips []netip.Addr, ports []int, timeout time.Duration, emit emitter) ([]endpointResult, error) {
	targets := probeTargets(run, opts.sweepPorts != "", ips, ports)
	results := make([]endpointResult, len(targets))
	pings := opts.tunPingCount
	label := fmt.Sprintf("Phase 2: verifying tunnels (proto=%s)", run.name)
	emit(barBeginMsg{label: label, total: len(targets)})
	// Early stop: a connect needs one working endpoint, not all of them, and the
	// user is waiting on this scan. Once enough are verified the remaining jobs
	// return immediately, so the pool drains fast instead of paying a full
	// handshake per candidate. Only the connect path sets earlyStop; a plain
	// `scan` (and the GUI's endpoint list) still measures everything.
	var goodCount int32
	earlyStop := opts.earlyStop
	work := func(tn tunnel, i int) {
		defer emit(probedMsg{})
		if earlyStop > 0 && atomic.LoadInt32(&goodCount) >= int32(earlyStop) {
			return
		}
		ip := targets[i].ip
		r := endpointResult{ip: ip}
		if t, endpoint, ok, rtt, loss, torn := tunnelProbe(ctx, tn, targets[i], timeout, pings, opts.wantMeta); ok {
			r.exit, r.endpoint, r.ok, r.durable = t, endpoint, true, true
			if pings > 0 {
				r.tunPing, r.loss, r.measured, r.durable = rtt, loss, true, !torn
			}
			// Host ICMP measures the direct path, which a nested run does not take;
			// from inside the outer tunnel the same echo walks the real one.
			if outer == nil {
				if hrtt, pok := pingHost(ip, timeout); pok {
					r.epPing = hrtt
				}
			} else if hrtt, pok := outer.pingTo(ip, timeout); pok {
				r.epPing = hrtt
			}
			found := foundMsg{endpoint: endpoint, epPing: r.epPing, tunPing: r.tunPing, loss: r.loss, measured: r.measured, torn: !r.durable}
			if opts.wantMeta {
				found.exit, found.colo = exitRegion(t), exitColo(t)
			}
			emit(found)
		}
		if r.durable {
			atomic.AddInt32(&goodCount, 1)
		}
		results[i] = r
	}
	if err := runTunnelPool(opts.tunnelParallel, run, len(targets), work); err != nil {
		emit(stepMsg{fail: true, summary: err.Error()})
		return nil, err
	}
	emit(barEndMsg{label: label, summary: "done"})
	return results, nil
}
