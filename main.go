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
	"net/http"
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
	PacketsRx    uint64
	PacketsTx    uint64
	BytesRx      uint64
	BytesTx      uint64
	LastSeen     uint64
	SrcMonitored uint8
	DstMonitored uint8
	Pad          [6]byte // Padding to match eBPF struct alignment
}

type Metrics struct {
	srcIP, dstIP                 string
	ppsRx, ppsTx, mbpsRx, mbpsTx float64
	banned                       bool
}

type FlowData struct {
	key                          FlowKey
	stats                        FlowStats
	ppsRx, ppsTx, mbpsRx, mbpsTx float64
	srcMonitored, dstMonitored   bool
}

func (f *FlowData) getSrcIP() string {
	return u32ToIPString(f.key.Src)
}

func (f *FlowData) getDstIP() string {
	return u32ToIPString(f.key.Dst)
}

var (
	prevStats    = make(map[FlowKey]FlowStats)
	lastUpdate   = time.Now()
	bannedIPs    = make(map[string]*Ban)
	bannedMu     sync.RWMutex
	statsMu      sync.RWMutex
	graphiteConn net.Conn
	graphiteMu   sync.Mutex
	// Goroutine management
)

type Config struct {
	Interface     string
	GraphiteHost  string
	GraphitePort  int
	InfluxURL     string
	InfluxDB      string
	InfluxUser    string
	InfluxPass    string
	Interval      time.Duration
	BpfObjectFile string
	Verbose       bool
	ShowStats     bool
	ForceCleanup  bool
	CleanupOnly   bool
	Install       bool
	Networks      string
	AllowedNets   []*net.IPNet
	// Ban threshold settings
	BanPpsRx  float64
	BanPpsTx  float64
	BanMbpsRx float64
	BanMbpsTx float64
	BanTime   time.Duration
	BanScript string
	// Minimum thresholds for flow and IP metrics
	MinFlowPps  float64
	MinFlowMbps float64
	MinIPsPps   float64
	MinIPsMbps  float64
	// Performance settings
	IPCacheSize int
	DebugFlows  bool
}

type Ban struct {
	Start    time.Time
	Duration time.Duration
}

func sanitizeIP(ip string) string {
	if strings.Contains(ip, ".") {
		return strings.ReplaceAll(ip, ".", "_")
	}
	return ip // IPv6 or already sanitized
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

	// Use all current args except -install, preserving quotes for args with spaces
	var filteredArgs []string
	for _, arg := range os.Args[1:] {
		if arg != "-install" {
			// Quote argument if it contains spaces and isn't already quoted
			if strings.Contains(arg, " ") && !strings.HasPrefix(arg, "'") && !strings.HasPrefix(arg, "\"") {
				filteredArgs = append(filteredArgs, fmt.Sprintf("'%s'", arg))
			} else {
				filteredArgs = append(filteredArgs, arg)
			}
		}
	}
	argsStr := strings.Join(filteredArgs, " ")
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

func banIP(ip string, duration time.Duration, script string, ppsRx, ppsTx, mbpsRx, mbpsTx float64) {
	bannedMu.Lock()
	defer bannedMu.Unlock()

	if _, exists := bannedIPs[ip]; exists {
		return
	}

	bannedIPs[ip] = &Ban{Start: time.Now(), Duration: duration}
	log.Printf("BANNED IP: %s for %v (%.1f/%.1f pps, %.2f/%.2f mbps)", ip, duration, ppsRx, ppsTx, mbpsRx, mbpsTx)
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
	totalPps := ppsRx + ppsTx
	totalMbps := mbpsRx + mbpsTx

	if totalPps == 0 && totalMbps == 0 {
		return false
	}

	return (cfg.MinFlowPps <= 0 || totalPps >= cfg.MinFlowPps) &&
		(cfg.MinFlowMbps <= 0 || totalMbps >= cfg.MinFlowMbps)
}

func meetsIPThresholds(ppsRx, ppsTx, mbpsRx, mbpsTx float64, cfg *Config) bool {
	totalPps := ppsRx + ppsTx
	totalMbps := mbpsRx + mbpsTx

	if totalPps == 0 && totalMbps == 0 {
		return false
	}

	return (cfg.MinIPsPps <= 0 || totalPps >= cfg.MinIPsPps) &&
		(cfg.MinIPsMbps <= 0 || totalMbps >= cfg.MinIPsMbps)
}

func parseFlags() *Config {
	config := &Config{}

	flag.StringVar(&config.Interface, "interface", "eth0", "Network interface to monitor")
	flag.StringVar(&config.GraphiteHost, "graphite-host", "", "Graphite server hostname (empty disables Graphite export)")
	flag.IntVar(&config.GraphitePort, "graphite-port", 2003, "Graphite server port")
	flag.StringVar(&config.InfluxURL, "influx-url", "", "InfluxDB URL (e.g., http://localhost:8086) (empty disables InfluxDB export)")
	flag.StringVar(&config.InfluxDB, "influx-db", "fastflowips", "InfluxDB database name")
	flag.StringVar(&config.InfluxUser, "influx-user", "", "InfluxDB username")
	flag.StringVar(&config.InfluxPass, "influx-pass", "", "InfluxDB password")
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

	// Minimum thresholds for flow/ip metrics reporting
	flag.Float64Var(&config.MinFlowPps, "min-flow-pps", 0, "Minimum PPS threshold for flow-based metrics (0 = export all flows)")
	flag.Float64Var(&config.MinFlowMbps, "min-flow-mbps", 0, "Minimum Mbps threshold for flow-based metrics (0 = export all flows)")
	flag.Float64Var(&config.MinIPsPps, "min-ips-pps", 0, "Minimum PPS threshold for IP-based metrics (0 = export all IPs)")
	flag.Float64Var(&config.MinIPsMbps, "min-ips-mbps", 0, "Minimum Mbps threshold for IP-based metrics (0 = export all IPs)")

	// Performance settings
	flag.IntVar(&config.IPCacheSize, "ip-cache-size", 100000, "Maximum IP cache size before clearing (legacy option, no longer used)")
	flag.BoolVar(&config.DebugFlows, "debug-flows", false, "Log raw eBPF flow entries and computed metrics each interval")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "FastFlowIPs - Fast eBPF Network Flow Collector - Monitor per-IP traffic with eBPF\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "\t%s -interface eth2 -show-stats\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\t%s -graphite-host localhost\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\t%s -influx-url http://localhost:8086 -influx-db fastflowips\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\t%s -ban-pps-rx 1000 -ban-script ./ban.sh\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\t%s -interface eth0 -graphite-host localhost -install\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nRequires root privileges.\nBan script args: <action> <ip>\n")
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

func populateNetworksMap(coll *ebpf.Collection, allowedNets []*net.IPNet) error {
	networksMap := coll.Maps["monitored_networks"]
	if networksMap == nil {
		return fmt.Errorf("BPF map 'monitored_networks' not found")
	}

	countMap := coll.Maps["network_count"]
	if countMap == nil {
		return fmt.Errorf("BPF map 'network_count' not found")
	}

	// Set network count for optimization
	countKey := uint32(0)
	networkCount := uint32(len(allowedNets))
	if err := countMap.Put(countKey, networkCount); err != nil {
		return fmt.Errorf("failed to set network count: %v", err)
	}

	// Clear the networks map first
	for i := 0; i < 32; i++ {
		key := uint32(i)
		emptyNet := struct {
			Addr uint32
			Mask uint32
		}{0, 0}
		networksMap.Put(key, emptyNet)
	}

	// Populate with actual networks
	for i, ipnet := range allowedNets {
		if i >= 32 {
			log.Printf("Warning: Only first 32 networks will be used in eBPF filter")
			break
		}

		key := uint32(i)
		netAddr := binary.BigEndian.Uint32(ipnet.IP.To4())
		netMask := binary.BigEndian.Uint32(ipnet.Mask)

		network := struct {
			Addr uint32
			Mask uint32
		}{
			Addr: netAddr & netMask, // Apply mask to get network address
			Mask: netMask,
		}

		if err := networksMap.Put(key, network); err != nil {
			return fmt.Errorf("failed to update network %d: %v", i, err)
		}

		if log.Printf != nil {
			log.Printf("eBPF network filter: %s (addr=0x%08x, mask=0x%08x)",
				ipnet.String(), network.Addr, network.Mask)
		}
	}

	log.Printf("eBPF optimization: network_count=%d", networkCount)
	return nil
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

	// Populate monitored networks map in eBPF
	if err := populateNetworksMap(coll, config.AllowedNets); err != nil {
		log.Fatalf("Failed to populate networks map: %v", err)
	}

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
	ebpfFlowCount := 0
	debugLogged := 0
	const debugLogLimit = 20
	for it.Next(&k, &v) {
		ebpfFlowCount++
		currentFlowData[k] = v

		prev, exists := prevStats[k]
		var rawPpsRx, rawPpsTx, rawMbpsRx, rawMbpsTx float64

		if exists {
			rawPpsRx, rawPpsTx, rawMbpsRx, rawMbpsTx = calculateFlowMetrics(v, prev, deltaTime)
		}
		// If no previous stats, rates will be 0 (which is correct for first iteration)

		// eBPF already handles network filtering, so accept all flows we receive
		flowEntry := FlowData{
			key:          k,
			stats:        v,
			ppsRx:        rawPpsRx,
			ppsTx:        rawPpsTx,
			mbpsRx:       rawMbpsRx,
			mbpsTx:       rawMbpsTx,
			srcMonitored: v.SrcMonitored != 0,
			dstMonitored: v.DstMonitored != 0,
		}

		flows = append(flows, flowEntry)

		if cfg.DebugFlows && debugLogged < debugLogLimit {
			srcIP := flowEntry.getSrcIP()
			dstIP := flowEntry.getDstIP()
			log.Printf("[flow-debug] raw flow src=%s dst=%s packets(rx/tx)=%d/%d bytes(rx/tx)=%d/%d last_seen=%dns monitored(src/dst)=%t/%t prev_exists=%t -> pps(rx/tx)=%.2f/%.2f mbps(rx/tx)=%.4f/%.4f",
				srcIP, dstIP,
				v.PacketsRx, v.PacketsTx,
				v.BytesRx, v.BytesTx,
				v.LastSeen,
				flowEntry.srcMonitored, flowEntry.dstMonitored,
				exists,
				rawPpsRx, rawPpsTx,
				rawMbpsRx, rawMbpsTx)
			debugLogged++
		}
	}
	statsMu.RUnlock()

	if err := it.Err(); err != nil {
		log.Printf("Flow map iteration error: %v", err)
	} else if cfg.DebugFlows {
		log.Printf("[flow-debug] iteration summary: ebpf_flows=%d processed=%d delta_time=%.3fs", ebpfFlowCount, len(flows), deltaTime)
	}

	if cfg.Verbose {
		log.Printf("eBPF flows: %d, processed flows: %d", ebpfFlowCount, len(flows))
	}

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

	for _, flow := range flows {
		// If no networks configured, aggregate both IPs (legacy behavior)
		if len(cfg.AllowedNets) == 0 {
			ipStats.addStats(flow.getSrcIP(), flow.ppsRx, flow.ppsTx, flow.mbpsRx, flow.mbpsTx)
			ipStats.addStats(flow.getDstIP(), flow.ppsRx, flow.ppsTx, flow.mbpsRx, flow.mbpsTx)
		} else {
			// Only aggregate stats for IPs that belong to monitored networks
			if flow.srcMonitored {
				ipStats.addStats(flow.getSrcIP(), flow.ppsRx, flow.ppsTx, flow.mbpsRx, flow.mbpsTx)
			}

			if flow.dstMonitored {
				ipStats.addStats(flow.getDstIP(), flow.ppsRx, flow.ppsTx, flow.mbpsRx, flow.mbpsTx)
			}
		}
	}

	if cfg.DebugFlows {
		log.Printf("[flow-debug] aggregated %d IP entries", len(ipStats))
	}

	return ipStats
}

func isIPBanned(ip string) bool {
	bannedMu.RLock()
	defer bannedMu.RUnlock()
	_, banned := bannedIPs[ip]
	return banned
}

func generateDisplayMetrics(flows []FlowData, ipStats IPStatsMap, cfg *Config) {
	metrics := make([]Metrics, 0, len(flows)+len(ipStats))

	for _, flow := range flows {
		if !meetsFlowThresholds(flow.ppsRx, flow.ppsTx, flow.mbpsRx, flow.mbpsTx, cfg) {
			continue
		}

		metrics = append(metrics, Metrics{
			srcIP:  flow.getSrcIP(),
			dstIP:  flow.getDstIP(),
			ppsRx:  flow.ppsRx,
			ppsTx:  flow.ppsTx,
			mbpsRx: flow.mbpsRx,
			mbpsTx: flow.mbpsTx,
			banned: isIPBanned(flow.getSrcIP()),
		})
	}

	// Add IP metrics (aggregated stats per IP)
	for ip, stats := range ipStats {
		if !meetsIPThresholds(stats.ppsRx, stats.ppsTx, stats.mbpsRx, stats.mbpsTx, cfg) {
			continue
		}

		metrics = append(metrics, Metrics{
			srcIP: ip, dstIP: "[TOTAL]", // Mark as IP total
			ppsRx: stats.ppsRx, ppsTx: stats.ppsTx,
			mbpsRx: stats.mbpsRx, mbpsTx: stats.mbpsTx,
			banned: isIPBanned(ip),
		})
	}

	// display stats
	sort.Slice(metrics, func(i, j int) bool {
		return metrics[i].ppsRx+metrics[i].ppsTx > metrics[j].ppsRx+metrics[j].ppsTx
	})

	bannedMu.RLock()
	if count := len(bannedIPs); count > 0 {
		fmt.Printf("Banned IPs: %d\n", count)
	}
	bannedMu.RUnlock()

	if len(metrics) > 0 {
		fmt.Printf("%-20s %-20s %8s %8s %8s %8s %6s\n", "srcIP", "dstIP", "ppsRX", "ppsTX", "mbpsRX", "mbpsTX", "status")
		fmt.Printf("%s\n", "____________________________________________________________________________________")

		for _, m := range metrics {
			status := "OK"
			if m.banned {
				status = "BAN"
			}

			fmt.Printf("%-20s %-20s %8.1f %8.1f %8.2f %8.2f %6s\n", m.srcIP, m.dstIP, m.ppsRx, m.ppsTx, m.mbpsRx, m.mbpsTx, status)
		}
		fmt.Printf("%s\n\n", "____________________________________________________________________________________")
	} else {
		fmt.Printf("%s\n", "-- no metrics --")
	}
}

func generateGraphiteMetrics(flows []FlowData, ipStats IPStatsMap, cfg *Config, timestamp int64) {
	var gMetrics []string

	for _, flow := range flows {
		if !meetsFlowThresholds(flow.ppsRx, flow.ppsTx, flow.mbpsRx, flow.mbpsTx, cfg) {
			continue
		}

		srcSan := sanitizeIP(flow.getSrcIP())
		dstSan := sanitizeIP(flow.getDstIP())

		// eBPF provides correct RX/TX values
		gMetrics = append(gMetrics,
			fmt.Sprintf("fastflowips.flows.%s_to_%s.pps.rx %.6f %d", dstSan, srcSan, flow.ppsRx, timestamp),
			fmt.Sprintf("fastflowips.flows.%s_to_%s.pps.tx %.6f %d", srcSan, dstSan, flow.ppsTx, timestamp),
			fmt.Sprintf("fastflowips.flows.%s_to_%s.mbps.rx %.6f %d", dstSan, srcSan, flow.mbpsRx, timestamp),
			fmt.Sprintf("fastflowips.flows.%s_to_%s.mbps.tx %.6f %d", srcSan, dstSan, flow.mbpsTx, timestamp),
		)
	}

	for ip, stats := range ipStats {
		if !meetsIPThresholds(stats.ppsRx, stats.ppsTx, stats.mbpsRx, stats.mbpsTx, cfg) {
			continue
		}

		ipSan := sanitizeIP(ip)

		gMetrics = append(gMetrics,
			fmt.Sprintf("fastflowips.ips.%s.pps.rx %.6f %d", ipSan, stats.ppsRx, timestamp),
			fmt.Sprintf("fastflowips.ips.%s.pps.tx %.6f %d", ipSan, stats.ppsTx, timestamp),
			fmt.Sprintf("fastflowips.ips.%s.mbps.rx %.6f %d", ipSan, stats.mbpsRx, timestamp),
			fmt.Sprintf("fastflowips.ips.%s.mbps.tx %.6f %d", ipSan, stats.mbpsTx, timestamp),
		)
	}

	if len(gMetrics) > 0 {
		go sendGraphiteBatch(gMetrics, cfg)
	}
}

func generateInfluxMetrics(flows []FlowData, ipStats IPStatsMap, cfg *Config, timestamp int64) {
	var gMetrics []string
	ts := fmt.Sprintf("%d", timestamp*1000000000)

	for _, flow := range flows {
		if !meetsFlowThresholds(flow.ppsRx, flow.ppsTx, flow.mbpsRx, flow.mbpsTx, cfg) {
			continue
		}

		srcSan := sanitizeIP(flow.getSrcIP())
		dstSan := sanitizeIP(flow.getDstIP())

		// eBPF provides correct RX/TX values
		gMetrics = append(gMetrics,
			fmt.Sprintf("fastflowips_flows,src=%s,dst=%s,type=pps,direction=rx value=%.6f %s", srcSan, dstSan, flow.ppsRx, ts),
			fmt.Sprintf("fastflowips_flows,src=%s,dst=%s,type=pps,direction=tx value=%.6f %s", srcSan, dstSan, flow.ppsTx, ts),
			fmt.Sprintf("fastflowips_flows,src=%s,dst=%s,type=mbps,direction=rx value=%.6f %s", srcSan, dstSan, flow.mbpsRx, ts),
			fmt.Sprintf("fastflowips_flows,src=%s,dst=%s,type=mbps,direction=tx value=%.6f %s", srcSan, dstSan, flow.mbpsTx, ts),
		)
	}

	for ip, stats := range ipStats {
		if !meetsIPThresholds(stats.ppsRx, stats.ppsTx, stats.mbpsRx, stats.mbpsTx, cfg) {
			continue
		}

		ipSan := sanitizeIP(ip)

		gMetrics = append(gMetrics,
			fmt.Sprintf("fastflowips_ips,ip=%s,type=%s,direction=%s value=%.6f %s", ipSan, "pps", "rx", stats.ppsRx, ts),
			fmt.Sprintf("fastflowips_ips,ip=%s,type=%s,direction=%s value=%.6f %s", ipSan, "pps", "tx", stats.ppsTx, ts),
			fmt.Sprintf("fastflowips_ips,ip=%s,type=%s,direction=%s value=%.6f %s", ipSan, "mbps", "rx", stats.mbpsRx, ts),
			fmt.Sprintf("fastflowips_ips,ip=%s,type=%s,direction=%s value=%.6f %s", ipSan, "mbps", "tx", stats.mbpsTx, ts),
		)
	}

	if len(gMetrics) > 0 {
		go sendInfluxBatch(gMetrics, cfg)
	}
}

func processMap(m *ebpf.Map, cfg *Config) {
	now := time.Now()
	deltaTime := now.Sub(lastUpdate).Seconds()
	if deltaTime <= 0 {
		return
	}

	flows, currentFlowData := collectFlowData(m, cfg, deltaTime)

	if cfg.DebugFlows && len(flows) == 0 {
		log.Printf("[flow-debug] no flows returned from eBPF map this interval (delta=%.3fs)", deltaTime)
	}

	// Update prevStats for ALL flows in current iteration
	statsMu.Lock()
	for k, v := range currentFlowData {
		prevStats[k] = v
	}
	statsMu.Unlock()

	ipStats := aggregateIPStats(flows, cfg)

	if cfg.DebugFlows && len(ipStats) == 0 {
		log.Printf("[flow-debug] aggregated IP stats is empty (flows=%d)", len(flows))
	}

	for ip, stats := range ipStats {
		if cfg.Verbose && meetsIPThresholds(stats.ppsRx, stats.ppsTx, stats.mbpsRx, stats.mbpsTx, cfg) {
			log.Printf("IP %s stats: PPS RX=%.1f TX=%.1f, Mbps RX=%.2f TX=%.2f", ip, stats.ppsRx, stats.ppsTx, stats.mbpsRx, stats.mbpsTx)
		}

		if !isIPBanned(ip) && ((cfg.BanPpsRx > 0 && stats.ppsRx > cfg.BanPpsRx) ||
			(cfg.BanPpsTx > 0 && stats.ppsTx > cfg.BanPpsTx) ||
			(cfg.BanMbpsRx > 0 && stats.mbpsRx > cfg.BanMbpsRx) ||
			(cfg.BanMbpsTx > 0 && stats.mbpsTx > cfg.BanMbpsTx)) {
			banIP(ip, cfg.BanTime, cfg.BanScript, stats.ppsRx, stats.ppsTx, stats.mbpsRx, stats.mbpsTx)
		}
	}

	lastUpdate = now
	cleanupStats(currentFlowData)

	if cfg.GraphiteHost != "" {
		generateGraphiteMetrics(flows, ipStats, cfg, now.Unix())
	}
	if cfg.InfluxURL != "" {
		generateInfluxMetrics(flows, ipStats, cfg, now.Unix())
	}
	if cfg.ShowStats {
		generateDisplayMetrics(flows, ipStats, cfg)
	}
}

func sendGraphiteBatch(metrics []string, cfg *Config) {
	// Build batch message
	var batch strings.Builder
	batch.Grow(len(metrics) * 50) // Pre-allocate approximate space

	for _, metric := range metrics {
		batch.WriteString(metric)
		batch.WriteByte('\n')
	}

	// Send entire batch in one TCP write with thread-safe connection management
	graphiteMu.Lock()
	defer graphiteMu.Unlock()

	// Check if connection is nil or closed, establish new connection if needed
	if graphiteConn == nil {
		conn, err := net.Dial("tcp", net.JoinHostPort(cfg.GraphiteHost, strconv.Itoa(cfg.GraphitePort)))
		if err != nil {
			log.Printf("Failed to connect to Graphite: %v", err)
			return
		}
		graphiteConn = conn
	}

	// Defensive check to ensure connection is still valid
	if graphiteConn == nil {
		log.Printf("Graphite connection is unexpectedly nil")
		return
	}

	_, err := graphiteConn.Write([]byte(batch.String()))
	if err != nil {
		log.Printf("Failed to send batch (%d metrics): %v", len(metrics), err)
		// Safely close and reset connection
		if graphiteConn != nil {
			graphiteConn.Close()
			graphiteConn = nil
		}
	} else if cfg.Verbose {
		log.Printf("Sent %d metrics to Graphite", len(metrics))
	}
}

func sendInfluxBatch(metrics []string, cfg *Config) {
	// Build InfluxDB batch message
	var batch strings.Builder
	batch.Grow(len(metrics) * 60) // Pre-allocate approximate space

	for _, metric := range metrics {
		batch.WriteString(metric)
		batch.WriteByte('\n')
	}

	// Create HTTP request
	writeURL := cfg.InfluxURL + "/write?db=" + cfg.InfluxDB
	if cfg.InfluxUser != "" {
		writeURL += "&u=" + cfg.InfluxUser + "&p=" + cfg.InfluxPass
	}

	resp, err := http.Post(writeURL, "application/octet-stream", strings.NewReader(batch.String()))
	if err != nil {
		log.Printf("Failed to send InfluxDB batch (%d metrics): %v", len(metrics), err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("InfluxDB write failed with status %d: %s", resp.StatusCode, resp.Status)
		return
	}

	if cfg.Verbose {
		log.Printf("Sent %d metrics to InfluxDB", len(metrics))
	}
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
