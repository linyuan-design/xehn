//go:build windows

package main

import (
	"runtime"
	"testing"
	"time"

	"github.com/lxn/walk"
	"github.com/lxn/win"
	"golang.org/x/sys/windows"
)

func currentGDICount(t *testing.T) uint32 {
	t.Helper()
	p := windows.NewLazySystemDLL("user32.dll").NewProc("GetGuiResources")
	h, err := windows.GetCurrentProcess()
	if err != nil {
		t.Fatalf("GetCurrentProcess: %v", err)
	}
	r, _, _ := p.Call(uintptr(h), 0) // GR_GDIOBJECTS
	return uint32(r)
}

func TestPaintDoesNotLeakGDIHandles(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	mw, err := walk.NewMainWindow()
	if err != nil {
		t.Fatalf("NewMainWindow: %v", err)
	}
	defer mw.Dispose()
	_ = mw.SetClientSizePixels(walk.Size{Width: 1080, Height: 734})

	u := &natUI{
		mw: mw,
		m:  newNatModel(),
		sp: make([]spot, 0, 128),
	}
	u.m.connected = true
	u.m.connecting = true
	u.m.connectAt = time.Now().Add(-15 * time.Second)
	u.m.status = clientState{
		Connected: true,
		ExitIP:    "27.130.206.228",
		Country:   "TH",
		Colo:      "BKK",
		Proto:     protoAWG,
		StartedAt: time.Now().Add(-5 * time.Minute).Format(time.RFC3339),
	}
	u.m.latency = 88
	u.m.upRates = []int64{1024, 4096, 8192, 16384, 32768, 12000}
	u.m.downRates = []int64{4096, 32768, 65536, 131072, 98000, 45000}
	u.m.logs = []natLog{
		{at: time.Now(), text: "test info line", lv: 0},
		{at: time.Now(), text: "test warn line", lv: 1},
		{at: time.Now(), text: "test err line", lv: 2},
	}

	u.fonts = []fontSpec{
		{&u.f.f8, uiFont, 9, 0},
		{&u.f.f9, uiFont, 10, 0},
		{&u.f.f10, uiFont, 11, 0},
		{&u.f.f10b, uiFont, 11, 0},
		{&u.f.f11b, uiFont, 11, 0},
		{&u.f.f12b, uiFont, 12, 0},
		{&u.f.f12, uiFont, 10, 0},
		{&u.f.f13, uiFont, 11, 0},
		{&u.f.f13b, uiFont, 12, 0},
		{&u.f.f15, uiFont, 12, 0},
		{&u.f.f15b, uiFont, 15, 0},
		{&u.f.f16b, uiFont, 13, 0},
		{&u.f.f17b, uiFont, 15, 0},
		{&u.f.f18b, uiFont, 17, 0},
		{&u.f.f22b, uiFont, 18, 0},
		{&u.f.f25b, uiFont, 20, 0},
		{&u.f.f30b, uiFont, 24, 0},
		{&u.f.fmono, "Consolas", 10, 0},
	}
	if err := u.rebuildFonts(1); err != nil {
		t.Fatalf("rebuildFonts: %v", err)
	}
	defer u.disposeFonts()
	defer disposeLogo()

	cw, err := walk.NewCustomWidgetPixels(mw, 0, u.paint)
	if err != nil {
		t.Fatalf("NewCustomWidgetPixels: %v", err)
	}
	defer cw.Dispose()
	cw.SetPaintMode(walk.PaintBuffered)
	cw.SetBoundsPixels(walk.Rectangle{Width: 1080, Height: 734})
	u.cw = cw

	pages := []string{pageHome, pageSettings, pageAbout, pageLogs}
	paintOneFrame := func() {
		// Trigger CustomWidget's real WM_PAINT -> bufferedPaint -> u.paint path
		// using a memory DC passed via WM_PRINTCLIENT (which CustomWidget forwards
		// straight to WM_PAINT with wParam = hdc, exercising bufferedPaint!).
		sdc := win.GetDC(cw.Handle())
		if sdc == 0 {
			t.Fatal("GetDC failed")
		}
		memdc := win.CreateCompatibleDC(sdc)
		hbmp := win.CreateCompatibleBitmap(sdc, 1080, 734)
		old := win.SelectObject(memdc, win.HGDIOBJ(hbmp))
		win.SendMessage(cw.Handle(), win.WM_PRINTCLIENT, uintptr(memdc), win.PRF_CLIENT)
		win.SelectObject(memdc, old)
		win.DeleteObject(win.HGDIOBJ(hbmp))
		win.DeleteDC(memdc)
		win.ReleaseDC(cw.Handle(), sdc)
	}

	// Warm up cached logo bitmap and fonts across all pages.
	for _, p := range pages {
		u.m.page = p
		paintOneFrame()
	}

	before := currentGDICount(t)
	const frames = 200
	for i := 0; i < frames; i++ {
		u.m.page = pages[i%len(pages)]
		u.m.spin = i
		paintOneFrame()
	}
	after := currentGDICount(t)

	t.Logf("GDI handles before=%d, after=%d (%d frames across all pages, delta=%d)",
		before, after, frames, int(after)-int(before))
	if after > before+2 {
		t.Fatalf("GDI handle leak detected: before=%d after=%d (delta=+%d over %d frames)",
			before, after, after-before, frames)
	}
}
