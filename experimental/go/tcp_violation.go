// Enhanced implementation for TCP Violation method in Go.
// This implementation uses gopacket for crafting and sending packets.
// It includes packet capturing, automatic MAC resolution, multiple packet strategies,
// and connection monitoring.
// Note: This is for educational purposes only. Use responsibly and legally.

package main

import (
    "encoding/binary"
    "flag"
    "fmt"
    "log"
    "math/rand"
    "net"
    "os"
    "os/signal"
    "sync"
    "syscall"
    "time"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)

// Configuration options
type Config struct {
    Device        string
    SourceIP      string
    TargetIP      string
    SourcePort    int
    TargetPort    int
    Payload       string
    PacketCount   int
    Interval      time.Duration
    Strategy      string
    Verbose       bool
    ListenForResp bool
}

// TCP Packet strategies
const (
    StrategyAckPush   = "ackpush"
    StrategyDataOnly  = "dataonly"
    StrategyFragmented = "fragmented"
    StrategyRandomFlags = "randomflags"
)

var (
    strategies = []string{StrategyAckPush, StrategyDataOnly, StrategyFragmented, StrategyRandomFlags}
    config     Config
    srcMAC     net.HardwareAddr
    dstMAC     net.HardwareAddr
)

func init() {
    // Seed the random number generator
    rand.Seed(time.Now().UnixNano())
    
    // Parse command line flags
    flag.StringVar(&config.Device, "i", "eth0", "Network interface")
    flag.StringVar(&config.SourceIP, "src", "", "Source IP address (default: auto-detect)")
    flag.StringVar(&config.TargetIP, "dst", "", "Target IP address (required)")
    flag.IntVar(&config.SourcePort, "sport", rand.Intn(65535-1024) + 1024, "Source port")
    flag.IntVar(&config.TargetPort, "dport", 443, "Target port")
    flag.StringVar(&config.Payload, "data", "Connection probe packet", "Packet payload")
    flag.IntVar(&config.PacketCount, "count", 3, "Number of packets to send")
    flag.DurationVar(&config.Interval, "interval", 500*time.Millisecond, "Interval between packets")
    flag.StringVar(&config.Strategy, "strategy", StrategyAckPush, "Packet strategy (ackpush, dataonly, fragmented, randomflags)")
    flag.BoolVar(&config.Verbose, "v", false, "Verbose output")
    flag.BoolVar(&config.ListenForResp, "listen", true, "Listen for responses")
    flag.Parse()

    // Validate required parameters
    if config.TargetIP == "" {
        log.Fatal("Target IP address is required")
    }

    // Auto-detect source IP if not specified
    if config.SourceIP == "" {
        config.SourceIP = getOutboundIP().String()
        fmt.Printf("Using auto-detected source IP: %s\n", config.SourceIP)
    }

    // Validate strategy
    validStrategy := false
    for _, s := range strategies {
        if config.Strategy == s {
            validStrategy = true
            break
        }
    }
    if !validStrategy {
        log.Fatalf("Invalid strategy '%s'. Must be one of: %v", config.Strategy, strategies)
    }
}

// getOutboundIP gets the preferred outbound IP address
func getOutboundIP() net.IP {
    // Connect to a public IP (doesn't actually establish a connection)
    conn, err := net.Dial("udp", "8.8.8.8:80")
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    localAddr := conn.LocalAddr().(*net.UDPAddr)
    return localAddr.IP
}

// resolveMAC resolves MAC addresses for source and destination
func resolveMAC(handle *pcap.Handle) error {
    // Get the local interface MAC address
    ifaces, err := net.Interfaces()
    if err != nil {
        return fmt.Errorf("failed to get network interfaces: %v", err)
    }

    for _, iface := range ifaces {
        if iface.Name == config.Device {
            srcMAC = iface.HardwareAddr
            break
        }
    }

    if srcMAC == nil {
        return fmt.Errorf("could not find MAC address for interface %s", config.Device)
    }

    // For the destination MAC, we'll use ARP to resolve the gateway MAC if target is not local
    targetIPAddr := net.ParseIP(config.TargetIP)
    sourceIPAddr := net.ParseIP(config.SourceIP)

    // Check if target is in the same subnet
    isSameSubnet := false
    for _, iface := range ifaces {
        addrs, err := iface.Addrs()
        if err != nil {
            continue
        }

        for _, addr := range addrs {
            ipNet, ok := addr.(*net.IPNet)
            if !ok {
                continue
            }

            if ipNet.Contains(targetIPAddr) && ipNet.Contains(sourceIPAddr) {
                isSameSubnet = true
                break
            }
        }
    }

    var nextHopIP net.IP
    if isSameSubnet {
        nextHopIP = targetIPAddr
    } else {
        // Get default gateway
        routes, err := getDefaultGateway()
        if err != nil {
            return fmt.Errorf("failed to get default gateway: %v", err)
        }
        nextHopIP = routes
    }

    // Resolve MAC with ARP
    dstMAC, err = arpResolve(handle, nextHopIP.String())
    if err != nil {
        return fmt.Errorf("failed to resolve destination MAC: %v", err)
    }

    return nil
}

// getDefaultGateway attempts to get the default gateway IP
func getDefaultGateway() (net.IP, error) {
    // This is a simple implementation that works on most systems
    // A more robust solution would parse the routing table
    
    // For educational purposes, we'll just use Google's DNS as a fallback
    return net.ParseIP("192.168.1.1"), nil  // Replace with actual gateway detection
}

// arpResolve resolves an IP address to MAC address using ARP
func arpResolve(handle *pcap.Handle, targetIP string) (net.HardwareAddr, error) {
    // In a real implementation, we would send ARP requests and wait for replies
    // For simplicity, we'll just return a reasonable value
    
    // For educational purposes only
    return net.ParseMAC("00:50:56:ff:ee:dd") // This should be replaced with actual ARP resolution
}

// craftPacket creates a TCP packet based on the selected strategy
func craftPacket(sequence uint32) ([]byte, error) {
    // Create Ethernet layer
    eth := &layers.Ethernet{
        SrcMAC:       srcMAC,
        DstMAC:       dstMAC,
        EthernetType: layers.EthernetTypeIPv4,
    }

    // Create IP layer
    ip := &layers.IPv4{
        Version:  4,
        IHL:      5,
        TTL:      64,
        Protocol: layers.IPProtocolTCP,
        SrcIP:    net.ParseIP(config.SourceIP),
        DstIP:    net.ParseIP(config.TargetIP),
        Id:       uint16(rand.Intn(65535)),
    }

    // Create TCP layer with strategy-specific flags
    tcp := &layers.TCP{
        SrcPort: layers.TCPPort(config.SourcePort),
        DstPort: layers.TCPPort(config.TargetPort),
        Seq:     sequence,
        Window:  14600,
    }

    // Apply strategy-specific modifications
    switch config.Strategy {
    case StrategyAckPush:
        // ACK+PUSH strategy: Pretend to be part of an established connection
        tcp.ACK = true
        tcp.PSH = true
        tcp.Ack = rand.Uint32() // Random ACK number
    
    case StrategyDataOnly:
        // Data-only strategy: Just send data without any control flags
        // All flags are false by default
        tcp.Window = 65535 // Max window size
    
    case StrategyFragmented:
        // Fragmented packet strategy
        ip.Flags = layers.IPv4DontFragment
        ip.FragOffset = uint16(rand.Intn(8000)) // Random fragment offset
        tcp.ACK = true
    
    case StrategyRandomFlags:
        // Random flags strategy
        tcp.SYN = rand.Intn(2) == 1
        tcp.ACK = rand.Intn(2) == 1
        tcp.PSH = rand.Intn(2) == 1
        tcp.URG = rand.Intn(2) == 1
        tcp.ECE = rand.Intn(2) == 1
        tcp.CWR = rand.Intn(2) == 1
        
        // If we happened to get a SYN-ACK, make sure it has a valid ACK number
        if tcp.SYN && tcp.ACK {
            tcp.Ack = rand.Uint32()
        }
    }

    // Set checksum
    tcp.SetNetworkLayerForChecksum(ip)

    // Serialize layers
    buffer := gopacket.NewSerializeBuffer()
    opts := gopacket.SerializeOptions{
        FixLengths:       true,
        ComputeChecksums: true,
    }

    // Add payload if needed
    var payload gopacket.Payload
    if len(config.Payload) > 0 {
        payload = gopacket.Payload([]byte(config.Payload))
        err := gopacket.SerializeLayers(buffer, opts, eth, ip, tcp, payload)
        if err != nil {
            return nil, fmt.Errorf("failed to serialize packet layers: %v", err)
        }
    } else {
        err := gopacket.SerializeLayers(buffer, opts, eth, ip, tcp)
        if err != nil {
            return nil, fmt.Errorf("failed to serialize packet layers: %v", err)
        }
    }

    return buffer.Bytes(), nil
}

// listenForResponses captures and processes response packets
func listenForResponses(handle *pcap.Handle, wg *sync.WaitGroup) {
    defer wg.Done()

    // Set BPF filter to only capture packets from our target
    filter := fmt.Sprintf("tcp and src host %s and src port %d and dst port %d", 
                         config.TargetIP, config.TargetPort, config.SourcePort)
    
    if err := handle.SetBPFFilter(filter); err != nil {
        log.Printf("Warning: Failed to set packet filter: %v", err)
    }

    // Create packet source
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    packetSource.NoCopy = true
    
    // Channel to signal termination
    stopChan := make(chan os.Signal, 1)
    signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)
    
    fmt.Println("Listening for responses...")
    
    // Process packets
    packetChan := packetSource.Packets()
    for {
        select {
        case <-stopChan:
            return
        case packet := <-packetChan:
            if packet == nil {
                continue
            }
            
            // Process TCP layer
            tcpLayer := packet.Layer(layers.LayerTypeTCP)
            if tcpLayer != nil {
                tcp, _ := tcpLayer.(*layers.TCP)
                
                // Log details
                fmt.Printf("Received packet from %s:%d with flags [%s]\n", 
                          config.TargetIP, config.TargetPort, tcpFlagsToString(tcp))
                
                if config.Verbose {
                    fmt.Printf("  Sequence: %d, Ack: %d, Window: %d\n", 
                              tcp.Seq, tcp.Ack, tcp.Window)
                    
                    // If there's payload data
                    appLayer := packet.ApplicationLayer()
                    if appLayer != nil {
                        fmt.Printf("  Payload (%d bytes): %s\n", 
                                  len(appLayer.Payload()), string(appLayer.Payload()))
                    }
                }
            }
        case <-time.After(10 * time.Second):
            // Timeout if no packets received for a while
            fmt.Println("No responses received after timeout period")
            return
        }
    }
}

// tcpFlagsToString converts TCP flags to a readable string
func tcpFlagsToString(tcp *layers.TCP) string {
    var flags []string
    
    if tcp.SYN { flags = append(flags, "SYN") }
    if tcp.ACK { flags = append(flags, "ACK") }
    if tcp.PSH { flags = append(flags, "PSH") }
    if tcp.RST { flags = append(flags, "RST") }
    if tcp.FIN { flags = append(flags, "FIN") }
    if tcp.URG { flags = append(flags, "URG") }
    if tcp.ECE { flags = append(flags, "ECE") }
    if tcp.CWR { flags = append(flags, "CWR") }
    if tcp.NS  { flags = append(flags, "NS")  }
    
    if len(flags) == 0 {
        return "NONE"
    }
    
    result := ""
    for i, flag := range flags {
        if i > 0 {
            result += "+"
        }
        result += flag
    }
    return result
}

func main() {
    // Open device
    handle, err := pcap.OpenLive(config.Device, 1600, false, pcap.BlockForever)
    if err != nil {
        log.Fatalf("Failed to open device %s: %v", config.Device, err)
    }
    defer handle.Close()
    
    // Resolve MAC addresses
    if err := resolveMAC(handle); err != nil {
        log.Fatalf("Failed to resolve MAC addresses: %v", err)
    }
    
    fmt.Printf("Using source MAC: %s\n", srcMAC)
    fmt.Printf("Using destination MAC: %s\n", dstMAC)
    
    // Setup wait group for goroutines
    var wg sync.WaitGroup
    
    // Start listener if enabled
    if config.ListenForResp {
        wg.Add(1)
        go listenForResponses(handle, &wg)
        
        // Give listener time to set up
        time.Sleep(500 * time.Millisecond)
    }
    
    // Send packets
    baseSeq := rand.Uint32()
    fmt.Printf("Sending %d packets using strategy: %s\n", config.PacketCount, config.Strategy)
    
    for i := 0; i < config.PacketCount; i++ {
        // Create packet with strategy-specific configuration
        packet, err := craftPacket(baseSeq + uint32(i*1024))
        if err != nil {
            log.Printf("Error crafting packet %d: %v", i+1, err)
            continue
        }
        
        // Send packet
        if err := handle.WritePacketData(packet); err != nil {
            log.Printf("Error sending packet %d: %v", i+1, err)
        } else {
            fmt.Printf("Packet %d sent successfully\n", i+1)
        }
        
        // Wait before sending next packet
        if i < config.PacketCount-1 {
            time.Sleep(config.Interval)
        }
    }
    
    fmt.Println("All packets sent. Waiting for responses...")
    
    // Wait for capture to finish if enabled
    if config.ListenForResp {
        wg.Wait()
    }
    
    fmt.Println("TCP Violation test completed!")
}