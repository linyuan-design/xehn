package engine

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/xhwarp/android-engine/warp"
)

func TestAndroidHealthGuardDetectsDeadAndHalfDeadTunnels(t *testing.T) {
	now := time.Now()
	g := newAndroidHealthGuard(now)

	// Three consecutive probe failures (without real bidirectional flow) trigger recovery.
	if a := g.observe(now, false, 0, false); a.recoverNow {
		t.Fatal("1st failure must not immediately recover")
	}
	if a := g.observe(now.Add(2*time.Second), false, 0, false); a.recoverNow {
		t.Fatal("2nd failure must not immediately recover")
	}
	if a := g.observe(now.Add(4*time.Second), false, 0, false); !a.recoverNow {
		t.Fatal("3rd failure must trigger NeedRecover")
	}

	// Half-dead tunnel: slow probe + 2 consecutive <30 KB/s throughput checks triggers recovery.
	g2 := newAndroidHealthGuard(now)
	_ = g2.observe(now, true, 3400, false)
	if !g2.shouldProbeSpeed(now.Add(50*time.Second), true, 3400, false, 45*time.Second) {
		t.Fatal("expected slow latency to schedule throughput verification")
	}
	if a := g2.observeSpeed(now.Add(50*time.Second), 12*1024, nil); a.recoverNow {
		t.Fatal("1st low-speed sample should confirm once more before rotating")
	}
	if a := g2.observeSpeed(now.Add(65*time.Second), 15*1024, errors.New("timeout")); !a.recoverNow {
		t.Fatal("2nd low-speed/failed sample must trigger NeedRecover")
	}

	// Active bidirectional traffic suppresses false alarms.
	g3 := newAndroidHealthGuard(now)
	_ = g3.observe(now, false, 0, false)
	if a := g3.observe(now.Add(2*time.Second), false, 0, true); a.recoverNow || !a.recovered {
		t.Fatalf("bidirectional traffic should decay trouble: %+v", a)
	}
}

func TestMergeVPNGateCachePrioritizesLiveAndTCPAndUncrowded(t *testing.T) {
	now := time.Now()
	prev := &warp.VPNGateCache{
		FetchedAt: now.Add(-40 * time.Minute).UnixMilli(),
		Nodes: []warp.VPNGateNode{
			{ID: "us-198.51.100.10-443", CC: "US", IP: "198.51.100.10", Port: 443, Proto: "tcp", Class: "residential", SpeedBps: 800_000_000, Sessions: 3, PingMS: 15, Config: "ovpn-us"},
			{ID: "de-198.51.100.11-443", CC: "DE", IP: "198.51.100.11", Port: 443, Proto: "tcp", Class: "residential", SeenAt: now.Add(-3 * time.Hour).UnixMilli(), Config: "ovpn-de"},
		},
	}
	fresh := []warp.VPNGateNode{
		// Live UDP node
		{ID: "jp-198.51.100.20-1194", CC: "JP", IP: "198.51.100.20", Port: 1194, Proto: "udp", Class: "residential", SpeedBps: 900_000_000, Sessions: 5, PingMS: 10, Config: "ovpn-udp"},
		// Live crowded TCP node (110 sessions)
		{ID: "jp-198.51.100.21-443", CC: "JP", IP: "198.51.100.21", Port: 443, Proto: "tcp", Class: "residential", SpeedBps: 500_000_000, Sessions: 110, LatencyMS: 40, Config: "ovpn-crowded"},
		// Live uncrowded TCP node (8 sessions)
		{ID: "kr-198.51.100.22-995", CC: "KR", IP: "198.51.100.22", Port: 995, Proto: "tcp", Class: "residential", SpeedBps: 500_000_000, Sessions: 8, LatencyMS: 45, Config: "ovpn-fast"},
	}

	merged := warp.MergeVPNGateCache(prev, fresh, now)
	if len(merged.Nodes) != 4 {
		t.Fatalf("merged len = %d, want 4 (3 fresh + 1 unexpired US)", len(merged.Nodes))
	}
	if merged.Nodes[0].ID != "kr-198.51.100.22-995" {
		t.Fatalf("expected live uncrowded TCP relay first, got %s", merged.Nodes[0].ID)
	}
	if merged.Nodes[1].ID != "jp-198.51.100.21-443" {
		t.Fatalf("expected live TCP relay ahead of live UDP relay, got %s", merged.Nodes[1].ID)
	}
	if merged.Nodes[2].ID != "jp-198.51.100.20-1194" {
		t.Fatalf("expected live UDP relay ahead of stale US relay, got %s", merged.Nodes[2].ID)
	}
	if merged.Nodes[3].ID != "us-198.51.100.10-443" || !merged.Nodes[3].Stale {
		t.Fatalf("expected carried-over US relay last with Stale=true, got %+v", merged.Nodes[3])
	}
}

func TestUnderlayFallbacksOrder(t *testing.T) {
	got := warp.UnderlayFallbacks("awg")
	want := []string{"awg", "masque", "masque-h2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("UnderlayFallbacks(awg) = %v, want %v", got, want)
	}
}
