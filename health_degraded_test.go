package main

import (
	"errors"
	"testing"
	"time"
)

func TestHealthMonitorRotatesOnLowThroughputStreak(t *testing.T) {
	t0 := time.Now()
	mon := newHealthMonitor(t0)

	// Immediately after session start, periodic throughput probe is not due yet.
	if mon.needsThroughputCheck(t0.Add(5*time.Second), true, 400*time.Millisecond, 0) {
		t.Fatal("should not run periodic throughput probe 5s after connect")
	}

	// At +31s idle, periodic check runs and detects 10 KB/s (<35 KB/s): 1st strike, no repair yet.
	t1 := t0.Add(31 * time.Second)
	if !mon.needsThroughputCheck(t1, true, 400*time.Millisecond, 0) {
		t.Fatal("expected periodic throughput probe at +31s")
	}
	act := mon.observeThroughput(t1, 10*1024, nil)
	if act.repair || !act.degraded {
		t.Fatalf("1st slow sample should warn without rotating: %+v", act)
	}

	// Confirmation probe waits at least healthSpeedConfirmWait (6s), then triggers rotation on 2nd low reading.
	if mon.needsThroughputCheck(t1.Add(2*time.Second), true, 400*time.Millisecond, 0) {
		t.Fatal("confirmation probe must respect minimum confirm gap")
	}
	t2 := t1.Add(8 * time.Second)
	if !mon.needsThroughputCheck(t2, true, 400*time.Millisecond, 0) {
		t.Fatal("expected confirmation probe at +8s after first slow sample")
	}
	act = mon.observeThroughput(t2, 8*1024, nil)
	if !act.repair || !act.degraded || act.measuredBps != 8*1024 {
		t.Fatalf("2nd consecutive slow sample must trigger rotation: %+v", act)
	}
}

func TestHealthMonitorCatchesIntermittentZombiePacketLoss(t *testing.T) {
	now := time.Now()
	mon := newHealthMonitor(now)
	timeoutErr := errors.New("context deadline exceeded")

	// Fail (+2), Fail (+2), then 1 lucky slow 4.2s squeak (+1 -> 5) must rotate instead of resetting to 0!
	if act := mon.observeProbe(now, false, 5*time.Second, timeoutErr, 0); act.repair {
		t.Fatal("rotated on 1st failure")
	}
	if act := mon.observeProbe(now, false, 5*time.Second, timeoutErr, 0); act.repair {
		t.Fatal("rotated on 2nd failure")
	}
	act := mon.observeProbe(now, true, 4200*time.Millisecond, nil, 0)
	if !act.repair || !act.degraded {
		t.Fatalf("expected rotation after 2 timeouts + 4.2s struggling squeak, got %+v", act)
	}

	// Even if the lucky squeak is fast (decay 4 -> 3), one more failure (+2 -> 5) rotates.
	mon2 := newHealthMonitor(now)
	_ = mon2.observeProbe(now, false, 5*time.Second, timeoutErr, 0)
	_ = mon2.observeProbe(now, false, 5*time.Second, timeoutErr, 0)
	if act := mon2.observeProbe(now, true, 600*time.Millisecond, nil, 0); act.repair {
		t.Fatal("single fast recovery should decay, not rotate")
	}
	if act := mon2.observeProbe(now, false, 5*time.Second, timeoutErr, 0); !act.repair {
		t.Fatal("expected rotation on next failure after 2 fails + 1 lucky squeak")
	}
}

func TestHealthMonitorNeverInterruptsActiveUserDownload(t *testing.T) {
	now := time.Now()
	mon := newHealthMonitor(now)
	activeBps := int64(200 * 1024) // user actively downloading at 200 KB/s

	// Even if synthetic probes time out due to link saturation, active user traffic prevents false rotation.
	for i := 0; i < 5; i++ {
		tTick := now.Add(time.Duration(i*10) * time.Second)
		if act := mon.observeProbe(tTick, false, 5*time.Second, errors.New("timeout"), activeBps); act.repair {
			t.Fatalf("must not rotate while user traffic is actively flowing (%d B/s)", activeBps)
		}
		if mon.needsThroughputCheck(tTick, true, 5*time.Second, activeBps) {
			t.Fatal("must not run synthetic throughput check while user traffic is active")
		}
	}
}
