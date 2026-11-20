//go:build windows

package main

import (
	"testing"
	"time"
)

func TestVPNGateQualityRankingPrefersUncrowdedFastRelays(t *testing.T) {
	nodes := []vpnGateNode{
		// Crowded "1ms" JP headliners that used to win blindly
		{CountryShort: "JP", IP: "58.87.159.9", Port: 1605, Proto: "tcp", Class: "residential", Speed: 432_400_000, Sessions: 98, PingMS: 1},
		{CountryShort: "JP", IP: "58.87.159.114", Port: 1276, Proto: "tcp", Class: "residential", Speed: 897_600_000, Sessions: 109, PingMS: 1},
		{CountryShort: "JP", IP: "202.157.252.10", Port: 1734, Proto: "tcp", Class: "residential", Speed: 876_400_000, Sessions: 136, PingMS: 4},
		// Fast, much less crowded JP relays
		{CountryShort: "JP", IP: "106.167.59.85", Port: 1871, Proto: "tcp", Class: "residential", Speed: 329_600_000, Sessions: 16, PingMS: 6},
		{CountryShort: "JP", IP: "14.193.53.232", Port: 1932, Proto: "tcp", Class: "residential", Speed: 814_000_000, Sessions: 40, PingMS: 19},
	}
	sortVPNGateNodesByLatency(nodes)

	if nodes[0].IP != "14.193.53.232" || nodes[1].IP != "106.167.59.85" {
		t.Fatalf("expected uncrowded fast relays first, got %s, %s (all: %+v)", nodes[0].IP, nodes[1].IP, nodes)
	}
	if nodes[len(nodes)-1].IP != "58.87.159.9" {
		t.Fatalf("expected most crowded lowest-per-user relay last, got %s", nodes[len(nodes)-1].IP)
	}

	// Zero-session relays (often half-broken/firewalled volunteers) must rank
	// behind proven-active low-session relays of comparable speed.
	zeroVsActive := []vpnGateNode{
		{CountryShort: "KR", IP: "14.52.56.171", Port: 995, Proto: "tcp", Class: "residential", Speed: 300_000_000, Sessions: 0, PingMS: 30},
		{CountryShort: "KR", IP: "61.73.154.77", Port: 995, Proto: "tcp", Class: "residential", Speed: 300_000_000, Sessions: 3, PingMS: 30},
	}
	sortVPNGateNodesByLatency(zeroVsActive)
	if zeroVsActive[0].IP != "61.73.154.77" {
		t.Fatalf("expected active low-session relay ahead of 0-session relay, got %s", zeroVsActive[0].IP)
	}
}

func TestMergeVPNGateNodesPreservesRareCountriesAndUpdatesFresh(t *testing.T) {
	now := time.Now()
	existing := []vpnGateNode{
		{CountryShort: "US", IP: "198.51.100.10", Port: 443, Proto: "tcp", Profile: "p", SeenAt: now.Add(-1 * time.Hour)},
		{CountryShort: "DE", IP: "198.51.100.11", Port: 443, Proto: "tcp", Profile: "p", SeenAt: now.Add(-8 * time.Hour)}, // expired
		{CountryShort: "JP", IP: "198.51.100.12", Port: 443, Proto: "tcp", Profile: "old", Sessions: 99, SeenAt: now.Add(-30 * time.Minute)},
	}
	fresh := []vpnGateNode{
		{CountryShort: "JP", IP: "198.51.100.12", Port: 443, Proto: "tcp", Profile: "new", Sessions: 5},
		{CountryShort: "KR", IP: "198.51.100.13", Port: 995, Proto: "tcp", Profile: "p", Sessions: 3},
	}

	merged := mergeVPNGateNodes(existing, fresh, now.Add(-1*time.Hour), now)
	byID := map[string]vpnGateNode{}
	for _, n := range merged {
		byID[n.id()] = n
	}
	if len(merged) != 3 {
		t.Fatalf("merged len = %d, want 3 (fresh JP+KR + unexpired US)", len(merged))
	}
	if _, ok := byID["us-198.51.100.10-443"]; !ok {
		t.Fatal("unexpired US relay from previous slice was dropped")
	}
	if _, ok := byID["de-198.51.100.11-443"]; ok {
		t.Fatal("expired DE relay should have been pruned")
	}
	if jp := byID["jp-198.51.100.12-443"]; jp.Profile != "new" || jp.Sessions != 5 {
		t.Fatalf("fresh relay did not overwrite stale entry: %+v", jp)
	}
}

func TestVPNNodeMetricsLabel(t *testing.T) {
	got := vpnNodeMetricsLabel(vpnGateNode{
		Speed: 625_300_000, Sessions: 3, Proto: "tcp", LatencyMS: 82,
	})
	if want := "625M · 3人 · 82ms"; got != want {
		t.Fatalf("tcp label = %q, want %q", got, want)
	}
	gotUDP := vpnNodeMetricsLabel(vpnGateNode{
		Speed: 447_500_000, Sessions: 20, Proto: "udp", PingMS: 12, MeasuredBps: 420 * 1024,
	})
	if want := "实测420K/s · 447M · 20人 · UDP 12ms"; gotUDP != want {
		t.Fatalf("udp label = %q, want %q", gotUDP, want)
	}
}
