//go:build windows

package carrier

import (
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/sys/windows"
)

// GetAdaptersAddresses flags (not all are exported by x/sys/windows).
const (
	gaaFlagSkipAnycast     = 0x0002
	gaaFlagSkipMulticast   = 0x0004
	gaaFlagSkipDNSServer   = 0x0008
	gaaFlagIncludeGateways = 0x0080
)

// windowsIO captures/injects via Npcap. It injects at L2 (Ethernet), so it
// needs the source (NIC) MAC and the gateway MAC, resolved once at startup.
type windowsIO struct {
	h      pcapT
	srcMAC net.HardwareAddr
	dstMAC net.HardwareAddr
	sbuf   gopacket.SerializeBuffer
}

func newPacketIO(p ioParams) (packetIO, error) {
	ai, err := adapterForIP(p.localIP)
	if err != nil {
		return nil, err
	}
	// promisc=1 so return traffic addressed to us post-NAT is still delivered.
	// to_ms=10 + setMinToCopy(0) deliver captured packets immediately instead of
	// batching in the kernel buffer (Npcap's ~16 KB default batch adds up to
	// hundreds of ms of latency on low-rate flows like ping).
	h, err := pcapOpenLive(ai.device, p.snapLen, 1, 10)
	if err != nil {
		return nil, err
	}
	_ = h.setMinToCopy(0) // best-effort: minimise capture latency
	dstMAC, err := resolveGatewayMAC(h, ai.srcMAC, p.localIP, ai.gwIP)
	if err != nil {
		h.close()
		return nil, fmt.Errorf("resolve gateway MAC: %w", err)
	}
	return &windowsIO{
		h:      h,
		srcMAC: ai.srcMAC,
		dstMAC: dstMAC,
		sbuf:   gopacket.NewSerializeBuffer(),
	}, nil
}

func (w *windowsIO) Capture() ([]byte, error) {
	for {
		data, status := w.h.nextEx()
		if status == 0 {
			continue // timeout
		}
		if status < 0 {
			return nil, fmt.Errorf("pcap_next_ex returned status %d", status)
		}
		if len(data) < 14 {
			continue
		}
		// Ethernet II; keep only IPv4 (0x0800), strip the 14-byte header.
		if data[12] != 0x08 || data[13] != 0x00 {
			continue
		}
		return data[14:], nil
	}
}

func (w *windowsIO) Inject(ipPacket []byte) error {
	eth := &layers.Ethernet{
		SrcMAC:       w.srcMAC,
		DstMAC:       w.dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	w.sbuf.Clear()
	if err := gopacket.SerializeLayers(w.sbuf, gopacket.SerializeOptions{}, eth, gopacket.Payload(ipPacket)); err != nil {
		return err
	}
	return w.h.sendPacket(w.sbuf.Bytes())
}

func (w *windowsIO) Close() error {
	w.h.close()
	return nil
}

// adapterInfo is what we need about the outgoing NIC.
type adapterInfo struct {
	device string // \Device\NPF_{GUID}
	srcMAC net.HardwareAddr
	gwIP   net.IP
}

func adapterForIP(localIP net.IP) (adapterInfo, error) {
	flags := uint32(gaaFlagIncludeGateways | gaaFlagSkipAnycast | gaaFlagSkipMulticast | gaaFlagSkipDNSServer)
	size := uint32(15000)
	var buf []byte
	for i := 0; i < 4; i++ {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0,
			(*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		return adapterInfo{}, fmt.Errorf("GetAdaptersAddresses: %w", err)
	}

	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); aa != nil; aa = aa.Next {
		matched := false
		for ua := aa.FirstUnicastAddress; ua != nil; ua = ua.Next {
			if ip := sockaddrToIP(ua.Address.Sockaddr); ip != nil && ip.Equal(localIP) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}

		info := adapterInfo{device: `\Device\NPF_` + windows.BytePtrToString(aa.AdapterName)}
		if aa.PhysicalAddressLength >= 6 {
			info.srcMAC = net.HardwareAddr(append([]byte(nil), aa.PhysicalAddress[:6]...))
		} else {
			return info, fmt.Errorf("adapter for %s has no Ethernet MAC", localIP)
		}
		for ga := aa.FirstGatewayAddress; ga != nil; ga = ga.Next {
			if ip := sockaddrToIP(ga.Address.Sockaddr); ip != nil && ip.To4() != nil {
				info.gwIP = ip
				break
			}
		}
		if info.gwIP == nil {
			return info, fmt.Errorf("no IPv4 gateway on the adapter owning %s", localIP)
		}
		return info, nil
	}
	return adapterInfo{}, fmt.Errorf("no adapter owns local IP %s (set carrier.interface)", localIP)
}

func sockaddrToIP(rsa *syscall.RawSockaddrAny) net.IP {
	if rsa == nil {
		return nil
	}
	switch rsa.Addr.Family {
	case syscall.AF_INET:
		sa := (*syscall.RawSockaddrInet4)(unsafe.Pointer(rsa))
		return net.IPv4(sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3])
	case syscall.AF_INET6:
		sa := (*syscall.RawSockaddrInet6)(unsafe.Pointer(rsa))
		ip := make(net.IP, 16)
		copy(ip, sa.Addr[:])
		return ip
	}
	return nil
}

// resolveGatewayMAC ARPs for the gateway over the pcap handle. The handle has
// no BPF filter, so ARP replies are visible here.
func resolveGatewayMAC(h pcapT, srcMAC net.HardwareAddr, srcIP, gwIP net.IP) (net.HardwareAddr, error) {
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   srcMAC,
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      net.HardwareAddr{0, 0, 0, 0, 0, 0},
		DstProtAddress:    gwIP.To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, eth, arp); err != nil {
		return nil, err
	}
	req := buf.Bytes()

	deadline := time.Now().Add(3 * time.Second)
	var lastSend time.Time
	for time.Now().Before(deadline) {
		if time.Since(lastSend) > 400*time.Millisecond {
			if err := h.sendPacket(req); err != nil {
				return nil, err
			}
			lastSend = time.Now()
		}
		data, status := h.nextEx()
		if status != 1 {
			continue
		}
		pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
		al := pkt.Layer(layers.LayerTypeARP)
		if al == nil {
			continue
		}
		a := al.(*layers.ARP)
		if a.Operation == layers.ARPReply && net.IP(a.SourceProtAddress).Equal(gwIP.To4()) {
			return net.HardwareAddr(append([]byte(nil), a.SourceHwAddress...)), nil
		}
	}
	return nil, fmt.Errorf("timeout waiting for ARP reply from gateway %s", gwIP)
}
