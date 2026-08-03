//go:build windows

package carrier

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Minimal cgo-free bindings to Npcap's wpcap.dll. Only the handful of libpcap
// entry points gfk needs are bound; BPF compilation is skipped (the client is
// low-volume and filtering happens in the carrier receive loop). On Windows
// amd64 there is a single native calling convention, so LazyProc.Call works for
// these cdecl functions directly.

const pcapErrbufSize = 256

var (
	wpcapOnce      sync.Once
	wpcapErr       error
	procOpenLive     *windows.LazyProc
	procNextEx       *windows.LazyProc
	procSendPacket   *windows.LazyProc
	procClose        *windows.LazyProc
	procSetMinToCopy *windows.LazyProc
)

func loadWpcap() error {
	wpcapOnce.Do(func() {
		// Npcap installs wpcap.dll (and its Packet.dll dependency) into
		// %SystemRoot%\System32\Npcap, which is not on the default search path.
		npcapDir := filepath.Join(os.Getenv("SystemRoot"), "System32", "Npcap")
		_ = windows.SetDllDirectory(npcapDir)

		dll := windows.NewLazyDLL("wpcap.dll")
		if err := dll.Load(); err != nil {
			wpcapErr = fmt.Errorf("cannot load wpcap.dll (is Npcap installed?): %w", err)
			return
		}
		procOpenLive = dll.NewProc("pcap_open_live")
		procNextEx = dll.NewProc("pcap_next_ex")
		procSendPacket = dll.NewProc("pcap_sendpacket")
		procClose = dll.NewProc("pcap_close")
		procSetMinToCopy = dll.NewProc("pcap_setmintocopy")
	})
	return wpcapErr
}

// pcapT is a pcap_t* handle.
type pcapT uintptr

func pcapOpenLive(device string, snaplen, promisc, toMs int) (pcapT, error) {
	if err := loadWpcap(); err != nil {
		return 0, err
	}
	dev, err := windows.BytePtrFromString(device)
	if err != nil {
		return 0, err
	}
	errbuf := make([]byte, pcapErrbufSize)
	r, _, _ := procOpenLive.Call(
		uintptr(unsafe.Pointer(dev)),
		uintptr(snaplen),
		uintptr(promisc),
		uintptr(toMs),
		uintptr(unsafe.Pointer(&errbuf[0])),
	)
	if r == 0 {
		return 0, fmt.Errorf("pcap_open_live(%s) failed: %s", device, cstr(errbuf))
	}
	return pcapT(r), nil
}

// nextEx returns (data, status). status: 1=packet, 0=timeout, <0=error/eof.
// The returned slice is a fresh copy owned by the caller.
func (p pcapT) nextEx() ([]byte, int) {
	var hdr unsafe.Pointer
	var data unsafe.Pointer
	r, _, _ := procNextEx.Call(uintptr(p), uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data)))
	status := int(int32(r))
	if status != 1 || hdr == nil || data == nil {
		return nil, status
	}
	// struct pcap_pkthdr { struct timeval ts; bpf_u_int32 caplen; bpf_u_int32 len; }
	// On Windows (LLP64) timeval is two 32-bit longs, so caplen is at offset 8.
	caplen := *(*uint32)(unsafe.Add(hdr, 8))
	out := make([]byte, caplen)
	copy(out, unsafe.Slice((*byte)(data), int(caplen)))
	return out, 1
}

// setMinToCopy sets the kernel->userspace copy threshold in bytes. 0 means
// deliver each packet as soon as it arrives, instead of batching until ~16 KB
// accumulate — critical for low capture latency on low-rate flows.
func (p pcapT) setMinToCopy(n int) error {
	if procSetMinToCopy == nil {
		return fmt.Errorf("pcap_setmintocopy unavailable")
	}
	r, _, _ := procSetMinToCopy.Call(uintptr(p), uintptr(n))
	if int(int32(r)) != 0 {
		return fmt.Errorf("pcap_setmintocopy failed (%d)", int32(r))
	}
	return nil
}

func (p pcapT) sendPacket(buf []byte) error {
	if len(buf) == 0 {
		return nil
	}
	r, _, _ := procSendPacket.Call(uintptr(p), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if int(int32(r)) != 0 {
		return fmt.Errorf("pcap_sendpacket failed (%d)", int32(r))
	}
	return nil
}

func (p pcapT) close() {
	if p != 0 && procClose != nil {
		procClose.Call(uintptr(p))
	}
}

// cstr trims a NUL-terminated C string out of a byte buffer.
func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
