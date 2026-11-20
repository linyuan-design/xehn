package main

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/xhwarp/warp-client/internal/cache"
)

func TestOpenVPNBaseTrackerRotatesOnConsecutiveTimeouts(t *testing.T) {
	timeoutErr := &openvpnHandshakeTimeoutError{window: 22 * time.Second, err: errors.New("deadline exceeded")}

	var tr openvpnBaseTracker
	rot, clr, mark := tr.record("kr-1.1.1.1-995", timeoutErr, true)
	if rot || len(clr) != 0 || !mark {
		t.Fatalf("1st timeout: got rot=%v clr=%v mark=%v, want false [] true", rot, clr, mark)
	}
	rot, clr, mark = tr.record("kr-2.2.2.2-995", timeoutErr, true)
	if !rot || !reflect.DeepEqual(clr, []string{"kr-1.1.1.1-995"}) || mark {
		t.Fatalf("2nd timeout: got rot=%v clr=%v mark=%v, want true [kr-1.1.1.1-995] false", rot, clr, mark)
	}
}

func TestOpenVPNBaseTrackerStaysWhenBaseConfirmed(t *testing.T) {
	timeoutErr := &openvpnHandshakeTimeoutError{window: 22 * time.Second, err: errors.New("deadline exceeded")}
	authErr := errors.New("OpenVPN 出口认证被拒绝（AUTH_FAILED），立即换节点")

	var tr openvpnBaseTracker
	rot, clr, mark := tr.record("jp-1.1.1.1-443", authErr, true)
	if rot || len(clr) != 0 || !mark || !tr.confirmed {
		t.Fatalf("AUTH_FAILED should confirm base and mark relay failed: rot=%v clr=%v mark=%v confirmed=%v", rot, clr, mark, tr.confirmed)
	}
	for i, id := range []string{"jp-2.2.2.2-443", "jp-3.3.3.3-443", "jp-4.4.4.4-443"} {
		rot, clr, mark = tr.record(id, timeoutErr, true)
		if rot || len(clr) != 0 || !mark {
			t.Fatalf("timeout #%d on confirmed base: got rot=%v clr=%v mark=%v, want false [] true", i+1, rot, clr, mark)
		}
	}

	var trSlow openvpnBaseTracker
	rot, clr, mark = trSlow.record("kr-9.9.9.9-443", &slowRelayError{bps: 100 * 1024}, true)
	if rot || len(clr) != 0 || mark || !trSlow.confirmed {
		t.Fatalf("slowRelayError should confirm base without blacklisting: rot=%v clr=%v mark=%v confirmed=%v", rot, clr, mark, trSlow.confirmed)
	}
}

func TestOpenVPNBaseTrackerDoesNotRotateWhenLastBase(t *testing.T) {
	timeoutErr := &openvpnHandshakeTimeoutError{window: 22 * time.Second, err: errors.New("deadline exceeded")}
	var tr openvpnBaseTracker
	for _, id := range []string{"kr-1-995", "kr-2-995", "kr-3-995"} {
		rot, clr, mark := tr.record(id, timeoutErr, false)
		if rot || len(clr) != 0 || !mark {
			t.Fatalf("single base must not rotate: got rot=%v clr=%v mark=%v", rot, clr, mark)
		}
	}
}

func TestPutCachedScanDoesNotOverwriteWithEmpty(t *testing.T) {
	store, err := cache.Open(cache.Options{Path: filepath.Join(t.TempDir(), "cache.json"), TTL: time.Hour})
	if err != nil {
		t.Fatalf("open cache: %v", err)
	}
	key := scanCacheKey(protoAWG, false)
	good := cachedScan{
		Proto: protoAWG,
		At:    time.Now(),
		Results: []cachedEndpoint{
			{Endpoint: "8.35.211.32:500", IP: "8.35.211.32", Working: true},
		},
	}
	putCachedScan(store, key, good)

	// Empty sweep must not wipe out the working cache entry.
	putCachedScan(store, key, cachedScan{Proto: protoAWG, At: time.Now(), Results: nil})
	putCachedScan(store, key, cachedScan{Proto: protoAWG, At: time.Now(), Results: []cachedEndpoint{}})

	raw, ok := store.Get(key)
	if !ok {
		t.Fatal("cache entry disappeared after empty scan")
	}
	var got cachedScan
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Results) != 1 || got.Results[0].Endpoint != "8.35.211.32:500" {
		t.Fatalf("cache overwritten: got %+v", got.Results)
	}
}

func TestPhase2FallbackPlan(t *testing.T) {
	awg := mustParseProto(protoAWG)
	masque := mustParseProto(protoMASQUE)
	empty := []endpointResult{{ok: false}}
	working := []endpointResult{{ok: true, durable: true, endpoint: "8.35.211.32:500"}}

	// Case 1: Phase 1 locked to [2408] only -> fallback to [500, 1701, 4500] at >=4s.
	ports, rt, reason, ok := phase2FallbackPlan(awg, options{}, []int{2408}, 2*time.Second, empty)
	if !ok || reason != "missing_primary_ports" || rt != 4*time.Second || !reflect.DeepEqual(ports, []int{500, 1701, 4500}) {
		t.Fatalf("case 1: got ports=%v rt=%v reason=%q ok=%v", ports, rt, reason, ok)
	}

	// Case 2: All 4 primary ports tried at tight 2s timeout -> retry at 4s with 500 first.
	ports, rt, reason, ok = phase2FallbackPlan(awg, options{}, []int{2408, 500, 1701, 4500}, 2*time.Second, empty)
	if !ok || reason != "tight_timeout" || rt != 4*time.Second || !reflect.DeepEqual(ports, []int{500, 1701, 4500, 2408}) {
		t.Fatalf("case 2: got ports=%v rt=%v reason=%q ok=%v", ports, rt, reason, ok)
	}

	// Case 3: All 4 primary ports already tried at >=4s -> no redundant retry.
	if _, _, _, ok = phase2FallbackPlan(awg, options{}, []int{2408, 500, 1701, 4500}, 4*time.Second, empty); ok {
		t.Fatal("case 3: expected no fallback when all primary ports already tried at 4s")
	}

	// Case 4: Working endpoint found -> no fallback.
	if _, _, _, ok = phase2FallbackPlan(awg, options{}, []int{2408}, 2*time.Second, working); ok {
		t.Fatal("case 4: expected no fallback when working endpoint exists")
	}

	// Case 5: Pinned port, MASQUE, or sweepAll -> no fallback.
	if _, _, _, ok = phase2FallbackPlan(awg, options{port: 2408}, []int{2408}, 2*time.Second, empty); ok {
		t.Fatal("case 5a: pinned port must not fallback")
	}
	if _, _, _, ok = phase2FallbackPlan(masque, options{}, []int{443}, 2*time.Second, empty); ok {
		t.Fatal("case 5b: masque must not fallback")
	}
	if _, _, _, ok = phase2FallbackPlan(awg, options{sweepPorts: sweepAll}, []int{2408}, 2*time.Second, empty); ok {
		t.Fatal("case 5c: sweepAll must not fallback")
	}
}
