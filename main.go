// main.go
package main

import (
    "bytes"
    _ "embed"
    "encoding/binary"
    "flag"
    "fmt"
    "log"
    "net"
    "os"
    "os/exec"
    "os/signal"
    "sort"
    "strconv"
    "strings"
    "sync"
    "syscall"
    "time"

    "github.com/cilium/ebpf"
    "github.com/vishvananda/netlink"
)

//go:embed flow.o
var embeddedBPF []byte

type FlowKey struct {
    Src uint32
    Dst uint32
}

type FlowStats struct {
    PacketsRx uint64
    PacketsTx uint64
    BytesRx   uint64
    BytesTx   uint64
    LastSeen  uint64
}

type Metrics struct {
    SrcIP, DstIP string
    PpsRx, PpsTx, MbpsRx, MbpsTx float64
    Banned bool
}

type GraphiteMetric struct {
    Name  string
    Value float64
}

type FlowData struct {
    key   FlowKey
    stats FlowStats
    perspective NetworkPerspective
    ppsRx, ppsTx, mbpsRx, mbpsTx float64
}

func (f *FlowData) getSrcIP() string {
    return u32ToIPString(f.key.Src)
}

func (f *FlowData) getDstIP() string {
    return u32ToIPString(f.key.Dst)
}

var (
    prevStats = make(map[FlowKey]FlowStats)
    lastUpdate = time.Now()
    bannedIPs = make(map[string]*Ban)
    bannedMu sync.RWMutex
    statsMu sync.RWMutex
    graphiteConn net.Conn
    graphiteMu sync.Mutex
    // IP cache for network filtering
    ipCache = make(map[uint32]bool)
    ipCacheMu sync.RWMutex
    // Goroutine management
)

type Config struct {
    Interface       string
    GraphiteHost    string
    GraphitePort    int
    Interval        time.Duration
    BpfObjectFile   string
    Verbose         bool
    ShowStats       bool
    ForceCleanup    bool
    CleanupOnly     bool
    Install         bool
    Networks        string
    AllowedNets     []*net.IPNet
    // Ban threshold settings
    BanPpsRx  float64
    BanPpsTx  float64
    BanMbpsRx float64
    BanMbpsTx float64
    BanTime         time.Duration
    BanScript       string
    // Minimum thresholds for flow and IP metrics in Graphite
    MinFlowPps  float64
    MinFlowMbps float64
    MinIPsPps   float64
    MinIPsMbps  float64
    // Performance settings
    IPCacheSize      int
}

type Ban struct {
    Start time.Time
    Duration time.Duration
}


func sanitizeIP(ip string) string {
    if strings.Contains(ip, ".") {
        return strings.ReplaceAll(ip, ".", "_")
    }
    return ip // IPv6 or already sanitized
}

type NetworkPerspective struct {
    srcInNetwork, dstInNetwork bool
}

func (np NetworkPerspective) applyPerspective(ppsRx, ppsTx, mbpsRx, mbpsTx float64) (float64, float64, float64, float64) {
    if np.srcInNetwork && !np.dstInNetwork {
        return 0, ppsRx + ppsTx, 0, mbpsRx + mbpsTx
    }
    if !np.srcInNetwork && np.dstInNetwork {
        return ppsRx + ppsTx, 0, mbpsRx + mbpsTx, 0
    }
    return ppsRx, ppsTx, mbpsRx, mbpsTx
}

func getNetworkPerspective(srcIP, dstIP uint32, allowedNets []*net.IPNet) NetworkPerspective {
    if len(allowedNets) == 0 {
        return NetworkPerspective{true, true}
    }
    return NetworkPerspective{
        srcInNetwork: isIPAllowed(srcIP, allowedNets),
        dstInNetwork: isIPAllowed(dstIP, allowedNets),
    }
}

func parseNetworks(networks string) ([]*net.IPNet, error) {
    if networks == "" {
        return nil, nil
    }

    var nets []*net.IPNet
    for _, network := range strings.Fields(networks) {
        _, ipnet, err := net.ParseCIDR(network)
        if err != nil {
            return nil, fmt.Errorf("invalid network %s: %v", network, err)
        }
        nets = append(nets, ipnet)
    }
    return nets, nil
}

// Fast IP filtering with cache
func isIPAllowed(ipU32 uint32, allowedNets []*net.IPNet) bool {
    if len(allowedNets) == 0 {
        return true // No filter means allow all
    }

    // Check cache first (read lock)
    ipCacheMu.RLock()
    if result, exists := ipCache[ipU32]; exists {
        ipCacheMu.RUnlock()
        return result
    }
    ipCacheMu.RUnlock()

    // Convert to IP and check networks (expensive operation)
    ip := u32ToIP(ipU32)
    allowed := false
    for _, ipnet := range allowedNets {
        if ipnet.Contains(ip) {
            allowed = true
            break
        }
    }

    // Cache the result (write lock)
    ipCacheMu.Lock()
    ipCache[ipU32] = allowed
    ipCacheMu.Unlock()

    return allowed
}


// Clear IP cache when it gets too large
func clearIPCacheIfNeeded(maxSize int) {
    ipCacheMu.Lock()
    if len(ipCache) > maxSize {
        log.Printf("IP cache cleared (size: %d)", len(ipCache))
        ipCache = make(map[uint32]bool)
    }
    ipCacheMu.Unlock()
}

func cleanupExistingFilters(linkIndex int, verbose bool, forceCleanup bool) {
    var removed int

    // First try to remove filters from both ingress and egress
    parents := []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS}

    for _, parent := range parents {
        parentName := "ingress"
        if parent == netlink.HANDLE_MIN_EGRESS {
            parentName = "egress"
        }

        log.Printf("Checking %s filters on interface index %d", parentName, linkIndex)

        // List all filters for this parent
        filters, err := netlink.FilterList(nil, uint32(linkIndex))

        if err != nil {
            log.Printf("Could not list %s filters: %v", parentName, err)
            continue
        }

        if verbose {
            log.Printf("Found %d %s filters", len(filters), parentName)
        }

        // Remove each filter
        for _, filter := range filters {
            if bpfFilter, ok := filter.(*netlink.BpfFilter); ok {
                shouldRemove := forceCleanup || bpfFilter.Name == "count_flows_ingress" || bpfFilter.Name == "count_flows_egress"

                if shouldRemove {
                    if verbose {
                        log.Printf("Removing %s filter: %s (handle: %x, parent: %x)", parentName, bpfFilter.Name, bpfFilter.Handle, bpfFilter.Parent)
                    }

                    if err := netlink.FilterDel(bpfFilter); err != nil {
                        log.Printf("Failed to remove %s filter: %v", parentName, err)
                    } else {
                        removed++
                        log.Printf("Successfully removed %s filter", parentName)
                    }
                }
            } else {
                // Try to remove non-BPF filters if force cleanup
                if forceCleanup {
                    log.Printf("Removing non-BPF %s filter", parentName)
                    if err := netlink.FilterDel(filter); err == nil {
                        removed++
                    }
                }
            }
        }
    }

    // Also try to remove by our specific handles (fallback)
    knownFilters := []struct {
        parent uint32
        handle uint32
        name   string
    }{
        {netlink.HANDLE_MIN_INGRESS, netlink.MakeHandle(0, 1), "ingress"},
        {netlink.HANDLE_MIN_EGRESS, netlink.MakeHandle(0, 2), "egress"},
    }

    for _, known := range knownFilters {
        filter := &netlink.BpfFilter{
            FilterAttrs: netlink.FilterAttrs{
                LinkIndex: linkIndex,
                Parent:    known.parent,
                Handle:    known.handle,
            },
        }

        if verbose {
            log.Printf("Attempting to remove known %s filter (handle: %x)", known.name, known.handle)
        }

        if err := netlink.FilterDel(filter); err == nil {
            removed++
            if verbose {
                log.Printf("Removed known %s filter", known.name)
            }
        } else {
            log.Printf("Could not remove known %s filter: %v", known.name, err)
        }
    }

    // If regular cleanup didn't work and force cleanup is enabled, try tc command
    if removed == 0 && forceCleanup {
        if verbose {
            log.Printf("Trying tc command fallback cleanup")
        }

        iface, err := net.InterfaceByIndex(linkIndex)
        if err == nil && iface != nil {
            // Try to remove clsact qdisc completely (this removes all filters)
            cmd := exec.Command("tc", "qdisc", "del", "dev", iface.Name, "clsact")
            if err := cmd.Run(); err == nil {
                removed++
                if verbose {
                    log.Printf("Removed clsact qdisc using tc command")
                }
            } else {
                log.Printf("tc command failed: %v", err)
            }
        }
    }

    if removed > 0 {
        log.Printf("Cleaned up %d existing filter(s)", removed)
    } else if verbose {
        log.Printf("No filters found to remove")
    }
}


func addFilterWithRetry(filter *netlink.BpfFilter, name string, iface *net.Interface) error {
    if err := netlink.FilterAdd(filter); err != nil {
        if strings.Contains(err.Error(), "file exists") {
            log.Printf("%s filter conflict detected, attempting cleanup...", name)
            cleanupExistingFilters(iface.Index, true, true)

            if err2 := netlink.FilterAdd(filter); err2 != nil {
                return fmt.Errorf("FilterAdd %s failed after cleanup: %v\nTry running: sudo ./cleanup-filters.sh %s", name, err2, iface.Name)
            }
        } else {
            log.Printf("FilterAdd %s with handle failed: %v, trying without handle", name, err)
            filter.Handle = 0
            if err2 := netlink.FilterAdd(filter); err2 != nil {
                return fmt.Errorf("FilterAdd %s failed: original=%v, retry=%v\nTry running: sudo ./cleanup-filters.sh %s", name, err, err2, iface.Name)
            }
        }
    }
    return nil
}

func installSystemdService(config *Config) error {
    execPath, err := os.Executable()
    if err != nil {
        return fmt.Errorf("failed to get executable path: %v", err)
    }

    // Use all current args except remove -install
    argsStr := strings.Join(os.Args[1:], " ")
    argsStr = strings.ReplaceAll(argsStr, "-install", "")
    argsStr = strings.TrimSpace(argsStr)
    if argsStr != "" {
        argsStr = " " + argsStr
    }

    serviceContent := fmt.Sprintf(`[Unit]
Description=FastFlowIPs - eBPF Network Flow Collector
After=network.target

[Service]
Type=simple
User=root
ExecStart=%s%s
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`, execPath, argsStr)

    servicePath := "/etc/systemd/system/fastflowips.service"
    if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
        return fmt.Errorf("failed to write service file: %v", err)
    }

    cmds := [][]string{
        {"systemctl", "daemon-reload"},
        {"systemctl", "enable", "fastflowips.service"},
        {"systemctl", "restart", "fastflowips.service"},
    }

    for _, cmd := range cmds {
        if err := exec.Command(cmd[0], cmd[1:]...).Run(); err != nil {
            return fmt.Errorf("failed to run %s: %v", strings.Join(cmd, " "), err)
        }
    }

    log.Printf("Service installed: journalctl -u fastflowips.service -f")
    return nil
}

func runScript(script, action, ip string) {
    if script != "" {
        go func() {
            if err := exec.Command(script, action, ip).Run(); err != nil {
                log.Printf("%s script error for %s: %v", action, ip, err)
            }
        }()
    }
}

func banIP(ip string, duration time.Duration, script string) {
    bannedMu.Lock()
    defer bannedMu.Unlock()

    if _, exists := bannedIPs[ip]; exists {
        return
    }

    bannedIPs[ip] = &Ban{Start: time.Now(), Duration: duration}
    log.Printf("BANNED IP: %s for %v", ip, duration)
    runScript(script, "ban", ip)
}

func unbanIP(ip, script string) {
    bannedMu.Lock()
    defer bannedMu.Unlock()

    if _, exists := bannedIPs[ip]; !exists {
        return
    }

    delete(bannedIPs, ip)
    log.Printf("UNBANNED IP: %s", ip)
    runScript(script, "unban", ip)
}

func checkExpiredBans(script string) {
    bannedMu.Lock()
    defer bannedMu.Unlock()

    now := time.Now()
    for ip, ban := range bannedIPs {
        if now.Sub(ban.Start) >= ban.Duration {
            delete(bannedIPs, ip)
            log.Printf("UNBANNED IP (expired): %s", ip)
            runScript(script, "unban", ip)
        }
    }
}


func meetsFlowThresholds(ppsRx, ppsTx, mbpsRx, mbpsTx float64, cfg *Config) bool {
    totalPps, totalMbps := ppsRx+ppsTx, mbpsRx+mbpsTx
    return (totalPps > 0 || totalMbps > 0) &&
           (cfg.MinFlowPps <= 0 || totalPps >= cfg.MinFlowPps) &&
           (cfg.MinFlowMbps <= 0 || totalMbps >= cfg.MinFlowMbps)
}

func meetsIPThresholds(ppsRx, ppsTx, mbpsRx, mbpsTx float64, cfg *Config) bool {
    totalPps, totalMbps := ppsRx+ppsTx, mbpsRx+mbpsTx
    return (totalPps > 0 || totalMbps > 0) &&
           (cfg.MinIPsPps <= 0 || totalPps >= cfg.MinIPsPps) &&
           (cfg.MinIPsMbps <= 0 || totalMbps >= cfg.MinIPsMbps)
}

func checkThresholds(ip string, ppsRx, ppsTx, mbpsRx, mbpsTx float64, cfg *Config) bool {
    if (cfg.BanPpsRx > 0 && ppsRx > cfg.BanPpsRx) ||
       (cfg.BanPpsTx > 0 && ppsTx > cfg.BanPpsTx) ||
       (cfg.BanMbpsRx > 0 && mbpsRx > cfg.BanMbpsRx) ||
       (cfg.BanMbpsTx > 0 && mbpsTx > cfg.BanMbpsTx) {

        log.Printf("THRESHOLD VIOLATION: %s (%.1f/%.1f pps, %.2f/%.2f mbps)",
            ip, ppsRx, ppsTx, mbpsRx, mbpsTx)
        banIP(ip, cfg.BanTime, cfg.BanScript)
        return true
    }
    return false
}

func parseFlags() *Config {
    config := &Config{}

    flag.StringVar(&config.Interface, "interface", "eth0", "Network interface to monitor")
    flag.StringVar(&config.GraphiteHost, "graphite-host", "", "Graphite server hostname (empty disables Graphite export)")
    flag.IntVar(&config.GraphitePort, "graphite-port", 2003, "Graphite server port")
    flag.DurationVar(&config.Interval, "interval", 5*time.Second, "Statistics collection interval")
    flag.StringVar(&config.BpfObjectFile, "bpf-object", "flow.o", "Path to compiled eBPF object file")
    flag.BoolVar(&config.Verbose, "verbose", false, "Enable verbose logging")
    flag.BoolVar(&config.ShowStats, "show-stats", false, "Show periodic detailed flow statistics")
    flag.BoolVar(&config.ForceCleanup, "force-cleanup", false, "Force cleanup of existing eBPF filters on startup")
    flag.BoolVar(&config.CleanupOnly, "cleanup-only", false, "Only cleanup existing filters and exit (no monitoring)")
    flag.BoolVar(&config.Install, "install", false, "Install as systemd service using current arguments and exit")
    flag.StringVar(&config.Networks, "networks", "", "Filter IPs to specific networks in CIDR notation (e.g., '192.168.1.0/24 10.0.0.0/8')")

    // Threshold and ban settings
    flag.Float64Var(&config.BanPpsRx, "ban-pps-rx", 0, "PPS RX threshold for banning (0 = disabled)")
    flag.Float64Var(&config.BanPpsTx, "ban-pps-tx", 0, "PPS TX threshold for banning (0 = disabled)")
    flag.Float64Var(&config.BanMbpsRx, "ban-mbps-rx", 0, "Mbps RX threshold for banning (0 = disabled)")
    flag.Float64Var(&config.BanMbpsTx, "ban-mbps-tx", 0, "Mbps TX threshold for banning (0 = disabled)")
    flag.DurationVar(&config.BanTime, "ban-time", 300*time.Second, "Duration to ban IPs that exceed thresholds")
    flag.StringVar(&config.BanScript, "ban-script", "", "Script to execute on ban/unban actions (e.g., /path/to/script.sh)")

    // Minimum thresholds for Graphite flow and IP metrics
    flag.Float64Var(&config.MinFlowPps, "min-flow-pps", 0, "Minimum PPS threshold for flow-based Graphite metrics (0 = export all flows)")
    flag.Float64Var(&config.MinFlowMbps, "min-flow-mbps", 0, "Minimum Mbps threshold for flow-based Graphite metrics (0 = export all flows)")
    flag.Float64Var(&config.MinIPsPps, "min-ips-pps", 0, "Minimum PPS threshold for IP-based Graphite metrics (0 = export all IPs)")
    flag.Float64Var(&config.MinIPsMbps, "min-ips-mbps", 0, "Minimum Mbps threshold for IP-based Graphite metrics (0 = export all IPs)")

    // Performance settings
    flag.IntVar(&config.IPCacheSize, "ip-cache-size", 100000, "Maximum IP cache size before clearing (higher = better performance, more memory)")

    flag.Usage = func() {
        fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n\n", os.Args[0])
        fmt.Fprintf(os.Stderr, "FastFlowIPs - Fast eBPF Network Flow Collector - Monitor per-IP traffic with eBPF\n\n")
        fmt.Fprintf(os.Stderr, "Options:\n")
        flag.PrintDefaults()
        fmt.Fprintf(os.Stderr, "\nExamples:\n")
        fmt.Fprintf(os.Stderr, "  %s -show-stats -graphite-host localhost\n", os.Args[0])
        fmt.Fprintf(os.Stderr, "  %s -ban-pps-rx 1000 -ban-script ./ban.sh\n", os.Args[0])
        fmt.Fprintf(os.Stderr, "  sudo %s -install -interface eth0\n", os.Args[0])
        fmt.Fprintf(os.Stderr, "\nRequires root privileges. Ban script args: <action> <ip>\n")
    }

    flag.Parse()

    // Parse networks if provided
    if config.Networks != "" {
        nets, err := parseNetworks(config.Networks)
        if err != nil {
            log.Fatalf("Error parsing networks: %v", err)
        }
        config.AllowedNets = nets
    }

    return config
}

func main() {
    config := parseFlags()

    // Handle install mode
    if config.Install {
        if os.Geteuid() != 0 {
            log.Fatalf("Installation requires root privileges. Run with: sudo %s -install ...", os.Args[0])
        }
        if err := installSystemdService(config); err != nil {
            log.Fatalf("Failed to install service: %v", err)
        }
        return
    }

		log.Printf("Starting FastFlowIPs collector with config: %+v", config)
		if len(config.AllowedNets) > 0 {
				log.Printf("Network filter enabled - monitoring %d network(s):", len(config.AllowedNets))
				for _, net := range config.AllowedNets {
						log.Printf("  - %s", net.String())
				}
		} else {
				log.Printf("Network filter disabled - monitoring all IPs")
		}

    // Get interface index first (needed for cleanup)
    iface, err := net.InterfaceByName(config.Interface)
    if err != nil {
        log.Fatalf("Interface %s: %v", config.Interface, err)
    }

    if config.Verbose {
        log.Printf("Found interface %s with index %d", config.Interface, iface.Index)
    }

    // Clean up any existing filters first (always try, but be more aggressive if force-cleanup is set)
    cleanupExistingFilters(iface.Index, config.Verbose, config.ForceCleanup || config.CleanupOnly)

    // If cleanup-only mode, exit after cleanup
    if config.CleanupOnly {
        log.Printf("Cleanup completed. Exiting.")
        return
    }

    var spec *ebpf.CollectionSpec

    if config.BpfObjectFile != "flow.o" {
        // Load from custom file if specified
        spec, err = ebpf.LoadCollectionSpec(config.BpfObjectFile)
        if err != nil {
            log.Fatalf("load spec from %s: %v", config.BpfObjectFile, err)
        }
    } else {
        // Use embedded eBPF object
        spec, err = ebpf.LoadCollectionSpecFromReader(bytes.NewReader(embeddedBPF))
        if err != nil {
            log.Fatalf("load embedded eBPF spec: %v", err)
        }
    }

    coll, err := ebpf.NewCollection(spec)
    if err != nil {
        log.Fatalf("new collection: %v", err)
    }
    defer coll.Close()

    progIngress := coll.Programs["count_flows_ingress"]
    if progIngress == nil {
        log.Fatalf("BPF program 'count_flows_ingress' not found")
    }

    progEgress := coll.Programs["count_flows_egress"]
    if progEgress == nil {
        log.Fatalf("BPF program 'count_flows_egress' not found")
    }

    flowMap := coll.Maps["flow_cnt"]
    if flowMap == nil {
        log.Fatalf("BPF map 'flow_cnt' not found")
    }

    // Ensure clsact qdisc exists
    qdisc := &netlink.GenericQdisc{
        QdiscAttrs: netlink.QdiscAttrs{
            LinkIndex: iface.Index,
            Handle:    netlink.MakeHandle(0xffff, 0),
            Parent:    netlink.HANDLE_CLSACT,
        },
        QdiscType: "clsact",
    }
    if err := netlink.QdiscAdd(qdisc); err != nil {
        // It's fine if it already exists
        if !os.IsExist(err) {
            log.Printf("QdiscAdd: %v (often safe to ignore if 'file exists')", err)
        }
    }

    // Use timestamp-based handles to avoid conflicts
    timestamp := uint16(time.Now().Unix() & 0xFFFF)
    ingressHandle := netlink.MakeHandle(timestamp, 1)
    egressHandle := netlink.MakeHandle(timestamp, 2)

    if config.Verbose {
        log.Printf("Using handles: ingress=%x, egress=%x", ingressHandle, egressHandle)
    }

    // Attach BPF to TC ingress using netlink directly
    filterIngress := &netlink.BpfFilter{
        FilterAttrs: netlink.FilterAttrs{
            LinkIndex: iface.Index,
            Parent:    netlink.HANDLE_MIN_INGRESS,
            Handle:    ingressHandle,
            Protocol:  syscall.ETH_P_ALL,
            Priority:  1,
        },
        Fd:           progIngress.FD(),
        Name:         "count_flows_ingress",
        DirectAction: true,
    }

    if err := addFilterWithRetry(filterIngress, "ingress", iface); err != nil {
        log.Fatalf("%v", err)
    }

    // Attach BPF to TC egress
    filterEgress := &netlink.BpfFilter{
        FilterAttrs: netlink.FilterAttrs{
            LinkIndex: iface.Index,
            Parent:    netlink.HANDLE_MIN_EGRESS,
            Handle:    egressHandle,
            Protocol:  syscall.ETH_P_ALL,
            Priority:  1,
        },
        Fd:           progEgress.FD(),
        Name:         "count_flows_egress",
        DirectAction: true,
    }

    if err := addFilterWithRetry(filterEgress, "egress", iface); err != nil {
        log.Fatalf("%v", err)
    }

    log.Printf("Attached TC eBPF classifiers on %s ingress/egress", config.Interface)

    // Cleanup function
    defer func() {
        log.Printf("Cleaning up eBPF programs...")
        netlink.FilterDel(filterIngress)
        netlink.FilterDel(filterEgress)
        if graphiteConn != nil {
            graphiteConn.Close()
        }
        log.Printf("eBPF programs unloaded")
    }()

    // Periodically dump statistics
    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

    ticker := time.NewTicker(config.Interval)
    defer ticker.Stop()

    if config.ShowStats {
        log.Printf("Starting with periodic statistics display (interval: %v)", config.Interval)
    } else {
        log.Printf("Starting silent monitoring mode (interval: %v)", config.Interval)
    }

    log.Printf("Starting collection loop with %v interval", config.Interval)

    for {
        select {
        case <-ticker.C:
            checkExpiredBans(config.BanScript)
            processMap(flowMap, config)
        case <-sigCh:
            log.Println("Exiting...")
            return
        }
    }
}

func cleanupStats(currentFlowData map[FlowKey]FlowStats) {
    statsMu.Lock()
    defer statsMu.Unlock()
    for k := range prevStats {
        if _, exists := currentFlowData[k]; !exists {
            delete(prevStats, k)
        }
    }
}

func calculateFlowMetrics(current, prev FlowStats, deltaTime float64) (float64, float64, float64, float64) {
    var pktRxDelta, pktTxDelta, bytesRxDelta, bytesTxDelta uint64

    if current.PacketsRx >= prev.PacketsRx {
        pktRxDelta = current.PacketsRx - prev.PacketsRx
    } else {
        pktRxDelta = current.PacketsRx
    }

    if current.PacketsTx >= prev.PacketsTx {
        pktTxDelta = current.PacketsTx - prev.PacketsTx
    } else {
        pktTxDelta = current.PacketsTx
    }

    if current.BytesRx >= prev.BytesRx {
        bytesRxDelta = current.BytesRx - prev.BytesRx
    } else {
        bytesRxDelta = current.BytesRx
    }

    if current.BytesTx >= prev.BytesTx {
        bytesTxDelta = current.BytesTx - prev.BytesTx
    } else {
        bytesTxDelta = current.BytesTx
    }

    ppsRx := float64(pktRxDelta) / deltaTime
    ppsTx := float64(pktTxDelta) / deltaTime
    mbpsRx := float64(bytesRxDelta) * 8 / (deltaTime * 1000000)
    mbpsTx := float64(bytesTxDelta) * 8 / (deltaTime * 1000000)

    return ppsRx, ppsTx, mbpsRx, mbpsTx
}

func collectFlowData(m *ebpf.Map, cfg *Config, deltaTime float64) ([]FlowData, map[FlowKey]FlowStats) {
    currentFlowData := make(map[FlowKey]FlowStats)
    flows := make([]FlowData, 0, 64) // Pre-allocate with reasonable capacity

    it := m.Iterate()
    var k FlowKey
    var v FlowStats

    statsMu.RLock()
    for it.Next(&k, &v) {
        currentFlowData[k] = v

        prev, exists := prevStats[k]
        if !exists {
            continue
        }

        if !(isIPAllowed(k.Src, cfg.AllowedNets) || isIPAllowed(k.Dst, cfg.AllowedNets)) {
            continue
        }

        ppsRx, ppsTx, mbpsRx, mbpsTx := calculateFlowMetrics(v, prev, deltaTime)
        perspective := getNetworkPerspective(k.Src, k.Dst, cfg.AllowedNets)

        flows = append(flows, FlowData{
            key:         k,
            stats:       v,
            perspective: perspective,
            ppsRx:       ppsRx,
            ppsTx:       ppsTx,
            mbpsRx:      mbpsRx,
            mbpsTx:      mbpsTx,
        })
    }
    statsMu.RUnlock()

    return flows, currentFlowData
}

type IPStatsMap map[string]struct{ ppsRx, ppsTx, mbpsRx, mbpsTx float64 }

func (ips IPStatsMap) addStats(ip string, ppsRx, ppsTx, mbpsRx, mbpsTx float64) {
    stats := ips[ip]
    stats.ppsRx += ppsRx
    stats.ppsTx += ppsTx
    stats.mbpsRx += mbpsRx
    stats.mbpsTx += mbpsTx
    ips[ip] = stats
}

func aggregateIPStats(flows []FlowData, cfg *Config) IPStatsMap {
    ipStats := make(IPStatsMap)
    hasNetworkFilter := len(cfg.AllowedNets) > 0

    for _, flow := range flows {
        ipPpsRx, ipPpsTx, ipMbpsRx, ipMbpsTx := flow.perspective.applyPerspective(flow.ppsRx, flow.ppsTx, flow.mbpsRx, flow.mbpsTx)

        if flow.perspective.srcInNetwork {
            srcIP := flow.getSrcIP()
            if hasNetworkFilter && !flow.perspective.dstInNetwork {
                ipStats.addStats(srcIP, 0, ipPpsTx, 0, ipMbpsTx)
            } else {
                ipStats.addStats(srcIP, ipPpsRx, ipPpsTx, ipMbpsRx, ipMbpsTx)
            }
        }

        if flow.perspective.dstInNetwork {
            dstIP := flow.getDstIP()
            if hasNetworkFilter && !flow.perspective.srcInNetwork {
                ipStats.addStats(dstIP, ipPpsRx, 0, ipMbpsRx, 0)
            } else {
                ipStats.addStats(dstIP, ipPpsRx, ipPpsTx, ipMbpsRx, ipMbpsTx)
            }
        }
    }

    return ipStats
}

func getBannedIPs() map[string]bool {
    bannedMu.RLock()
    defer bannedMu.RUnlock()
    banned := make(map[string]bool, len(bannedIPs))
    for ip := range bannedIPs {
        banned[ip] = true
    }
    return banned
}

func generateDisplayMetrics(flows []FlowData, cfg *Config) []Metrics {
    if !cfg.ShowStats {
        return nil
    }

    metrics := make([]Metrics, 0, len(flows))
    banned := getBannedIPs()

    for _, flow := range flows {
        flowPpsRx, flowPpsTx, flowMbpsRx, flowMbpsTx := flow.perspective.applyPerspective(flow.ppsRx, flow.ppsTx, flow.mbpsRx, flow.mbpsTx)

        srcIP := flow.getSrcIP()
        metrics = append(metrics, Metrics{
            SrcIP: srcIP, DstIP: flow.getDstIP(),
            PpsRx: flowPpsRx, PpsTx: flowPpsTx,
            MbpsRx: flowMbpsRx, MbpsTx: flowMbpsTx,
            Banned: banned[srcIP],
        })
    }

    return metrics
}

func generateGraphiteMetrics(flows []FlowData, ipStats IPStatsMap, cfg *Config) ([]GraphiteMetric, GraphiteStats) {
    if cfg.GraphiteHost == "" {
        return nil, GraphiteStats{}
    }

    var gMetrics []GraphiteMetric
    var gStats GraphiteStats

    for _, flow := range flows {
        if !meetsFlowThresholds(flow.ppsRx, flow.ppsTx, flow.mbpsRx, flow.mbpsTx, cfg) {
            continue
        }

        graphitePpsRx, graphitePpsTx, graphiteMbpsRx, graphiteMbpsTx := flow.perspective.applyPerspective(flow.ppsRx, flow.ppsTx, flow.mbpsRx, flow.mbpsTx)

        srcSan := sanitizeIP(flow.getSrcIP())
        dstSan := sanitizeIP(flow.getDstIP())
        base := "network.flows." + srcSan + "_to_" + dstSan

        var flowMetrics []GraphiteMetric
        if cfg.MinFlowPps == 0 || graphitePpsRx >= cfg.MinFlowPps {
            flowMetrics = append(flowMetrics, GraphiteMetric{base + ".pps.rx", graphitePpsRx})
        }
        if cfg.MinFlowPps == 0 || graphitePpsTx >= cfg.MinFlowPps {
            flowMetrics = append(flowMetrics, GraphiteMetric{base + ".pps.tx", graphitePpsTx})
        }
        if cfg.MinFlowMbps == 0 || graphiteMbpsRx >= cfg.MinFlowMbps {
            flowMetrics = append(flowMetrics, GraphiteMetric{base + ".mbps.rx", graphiteMbpsRx})
        }
        if cfg.MinFlowMbps == 0 || graphiteMbpsTx >= cfg.MinFlowMbps {
            flowMetrics = append(flowMetrics, GraphiteMetric{base + ".mbps.tx", graphiteMbpsTx})
        }

        if len(flowMetrics) > 0 {
            gMetrics = append(gMetrics, flowMetrics...)
            gStats.FlowCount++
            if cfg.MinFlowPps == 0 || graphitePpsRx >= cfg.MinFlowPps {
                gStats.FlowPpsRx += graphitePpsRx
            }
            if cfg.MinFlowPps == 0 || graphitePpsTx >= cfg.MinFlowPps {
                gStats.FlowPpsTx += graphitePpsTx
            }
            if cfg.MinFlowMbps == 0 || graphiteMbpsRx >= cfg.MinFlowMbps {
                gStats.FlowMbpsRx += graphiteMbpsRx
            }
            if cfg.MinFlowMbps == 0 || graphiteMbpsTx >= cfg.MinFlowMbps {
                gStats.FlowMbpsTx += graphiteMbpsTx
            }
        }
    }

    for ip, stats := range ipStats {
        if !meetsIPThresholds(stats.ppsRx, stats.ppsTx, stats.mbpsRx, stats.mbpsTx, cfg) {
            continue
        }

        ipSan := sanitizeIP(ip)
        var ipMetrics []GraphiteMetric

        baseIP := "network.ips." + ipSan
        if cfg.MinIPsPps == 0 || stats.ppsRx >= cfg.MinIPsPps {
            ipMetrics = append(ipMetrics, GraphiteMetric{baseIP + ".pps.rx", stats.ppsRx})
        }
        if cfg.MinIPsPps == 0 || stats.ppsTx >= cfg.MinIPsPps {
            ipMetrics = append(ipMetrics, GraphiteMetric{baseIP + ".pps.tx", stats.ppsTx})
        }
        if cfg.MinIPsMbps == 0 || stats.mbpsRx >= cfg.MinIPsMbps {
            ipMetrics = append(ipMetrics, GraphiteMetric{baseIP + ".mbps.rx", stats.mbpsRx})
        }
        if cfg.MinIPsMbps == 0 || stats.mbpsTx >= cfg.MinIPsMbps {
            ipMetrics = append(ipMetrics, GraphiteMetric{baseIP + ".mbps.tx", stats.mbpsTx})
        }

        if len(ipMetrics) > 0 {
            gMetrics = append(gMetrics, ipMetrics...)
            gStats.IPCount++
            if cfg.MinIPsPps == 0 || stats.ppsRx >= cfg.MinIPsPps {
                gStats.IPPpsRx += stats.ppsRx
            }
            if cfg.MinIPsPps == 0 || stats.ppsTx >= cfg.MinIPsPps {
                gStats.IPPpsTx += stats.ppsTx
            }
            if cfg.MinIPsMbps == 0 || stats.mbpsRx >= cfg.MinIPsMbps {
                gStats.IPMbpsRx += stats.mbpsRx
            }
            if cfg.MinIPsMbps == 0 || stats.mbpsTx >= cfg.MinIPsMbps {
                gStats.IPMbpsTx += stats.mbpsTx
            }
        }
    }

    return gMetrics, gStats
}

func processMap(m *ebpf.Map, cfg *Config) {
    now := time.Now()
    deltaTime := now.Sub(lastUpdate).Seconds()
    if deltaTime <= 0 {
        return
    }

    flows, currentFlowData := collectFlowData(m, cfg, deltaTime)

    // Update prevStats for ALL flows in current iteration
    statsMu.Lock()
    for k, v := range currentFlowData {
        prevStats[k] = v
    }
    statsMu.Unlock()

    ipStats := aggregateIPStats(flows, cfg)
    banned := getBannedIPs()

    networkInfo := ""
    if len(cfg.AllowedNets) > 0 {
        networkInfo = " (monitored)"
    }

    for ip, stats := range ipStats {
        if cfg.Verbose && meetsIPThresholds(stats.ppsRx, stats.ppsTx, stats.mbpsRx, stats.mbpsTx, cfg) {
            log.Printf("IP %s%s stats: PPS RX=%.1f TX=%.1f, Mbps RX=%.2f TX=%.2f", ip, networkInfo, stats.ppsRx, stats.ppsTx, stats.mbpsRx, stats.mbpsTx)
        }

        if !banned[ip] {
            checkThresholds(ip, stats.ppsRx, stats.ppsTx, stats.mbpsRx, stats.mbpsTx, cfg)
        }
    }

    lastUpdate = now
    cleanupStats(currentFlowData)
    clearIPCacheIfNeeded(cfg.IPCacheSize)

    gMetrics, gStats := generateGraphiteMetrics(flows, ipStats, cfg)
    if len(gMetrics) > 0 {
        go sendBatch(gMetrics, cfg.GraphiteHost, cfg.GraphitePort, now.Unix(), cfg.Verbose, &gStats)
    }

    if cfg.ShowStats {
        metrics := generateDisplayMetrics(flows, cfg)
        displayStats(metrics, now)
    }
}

type GraphiteStats struct {
    FlowCount int
    IPCount   int
    FlowPpsRx, FlowPpsTx, FlowMbpsRx, FlowMbpsTx float64
    IPPpsRx, IPPpsTx, IPMbpsRx, IPMbpsTx float64
}

func sendBatch(metrics []GraphiteMetric, host string, port int, timestamp int64, verbose bool, stats *GraphiteStats) {
    if len(metrics) == 0 {
        return
    }

    // Build batch message
    var batch strings.Builder
    batch.Grow(len(metrics) * 50) // Pre-allocate approximate space

    for _, m := range metrics {
        fmt.Fprintf(&batch, "%s %.6f %d\n", m.Name, m.Value, timestamp)
    }

    // Send entire batch in one TCP write
    graphiteMu.Lock()
    defer graphiteMu.Unlock()

    if graphiteConn == nil {
        conn, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
        if err != nil {
            log.Printf("Failed to connect to Graphite: %v", err)
            return
        }
        graphiteConn = conn
    }

    _, err := graphiteConn.Write([]byte(batch.String()))
    if err != nil {
        log.Printf("Failed to send batch (%d metrics): %v", len(metrics), err)
        graphiteConn.Close()
        graphiteConn = nil
    } else if verbose {
        log.Printf("Sent %d metrics to Graphite: %d flows (%.1f/%.1f PPS RX/TX, %.2f/%.2f Mbps RX/TX), %d IPs (%.1f/%.1f PPS RX/TX, %.2f/%.2f Mbps RX/TX)",
            len(metrics), stats.FlowCount, stats.FlowPpsRx, stats.FlowPpsTx, stats.FlowMbpsRx, stats.FlowMbpsTx,
            stats.IPCount, stats.IPPpsRx, stats.IPPpsTx, stats.IPMbpsRx, stats.IPMbpsTx)
    }
}

func displayStats(metrics []Metrics, now time.Time) {
    sort.Slice(metrics, func(i, j int) bool {
        return metrics[i].PpsRx+metrics[i].PpsTx > metrics[j].PpsRx+metrics[j].PpsTx
    })

    fmt.Printf("\n%s ---- Flow Statistics ----\n", now.Format("15:04:05"))

    bannedMu.RLock()
    if count := len(bannedIPs); count > 0 {
        fmt.Printf("Banned IPs: %d\n", count)
    }
    bannedMu.RUnlock()

    fmt.Printf("%-20s %-20s %8s %8s %8s %8s %6s\n",
        "SRC IP", "DST IP", "PPS RX", "PPS TX", "Mbps RX", "Mbps TX", "STATUS")
    fmt.Printf("%s\n", "---------------------------------------------------------------------")

    for _, m := range metrics {
        status := "OK"
        if m.Banned {
            status = "BAN"
        }

        fmt.Printf("%-20s %-20s %8.1f %8.1f %8.2f %8.2f %6s\n",
            m.SrcIP, m.DstIP, m.PpsRx, m.PpsTx, m.MbpsRx, m.MbpsTx, status)
    }
    fmt.Printf("%s\n", "---------------------------------------------------------------------")
}



func u32ToIP(v uint32) net.IP {
    // IP addresses from eBPF are in network byte order, but we need to convert
    // them to host byte order for proper display
    b := make([]byte, 4)
    binary.LittleEndian.PutUint32(b, v)
    return net.IP(b)
}

func u32ToIPString(v uint32) string {
    // Direct conversion to string without intermediate allocations
    var buf [4]byte
    binary.LittleEndian.PutUint32(buf[:], v)
    return fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
}

