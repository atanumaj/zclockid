package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var defaultServices = []string{
	"samba-ad-dc",
	"bind9",
	"freeradius",
	"chrony",
	"zclock-sysvold",
	"zclock-azuresync",
	"zclock-exporter",
	"zclock-api",
	"nginx",
	"snmpd",
}

type ServiceDetail struct {
	Name         string  `json:"name"`
	Status       string  `json:"status"` // active, failed, inactive
	SystemdState string  `json:"systemd_state"`
	Enabled      string  `json:"enabled"`
	PID          int     `json:"pid"`
	MemoryMB     float64 `json:"memory_mb"`
}

type ResourceStats struct {
	CPUPercent   float64 `json:"cpu_percent"`
	MemoryTotal  uint64  `json:"memory_total_bytes"`
	MemoryUsed   uint64  `json:"memory_used_bytes"`
	MemoryAvail  uint64  `json:"memory_avail_bytes"`
	MemoryPct    float64 `json:"memory_percent"`
	DiskTotal    uint64  `json:"disk_total_bytes"`
	DiskUsed     uint64  `json:"disk_used_bytes"`
	DiskPercent  float64 `json:"disk_percent"`
	LoadAvg1     float64 `json:"load_avg_1m"`
	LoadAvg5     float64 `json:"load_avg_5m"`
	LoadAvg15    float64 `json:"load_avg_15m"`
	UptimeSec    float64 `json:"uptime_seconds"`
}

type TelemetrySnapshot struct {
	Hostname       string                   `json:"hostname"`
	Timestamp      int64                    `json:"timestamp"`
	UptimeSeconds  float64                  `json:"uptime_seconds"`
	OverallHealth  string                   `json:"overall_health"`
	Resources      ResourceStats            `json:"resources"`
	Services       map[string]ServiceDetail `json:"services"`
	ActiveSessions int                      `json:"active_sessions"`
	SysvolHealth   string                   `json:"sysvol_health"`
	DRSFailures    int                      `json:"drs_failures"`
}

type TelemetryCollector struct {
	mu           sync.RWMutex
	prevCPUTotal uint64
	prevCPUIdle  uint64
	latestCPU    float64
	snapshot     TelemetrySnapshot
	services     []string
}

func NewTelemetryCollector() *TelemetryCollector {
	hn, _ := os.Hostname()
	if hn == "" {
		hn = "zclockid"
	}
	c := &TelemetryCollector{
		services: defaultServices,
		snapshot: TelemetrySnapshot{
			Hostname:     hn,
			Services:     make(map[string]ServiceDetail),
			SysvolHealth: "UNKNOWN",
		},
	}
	c.sampleCPU()
	c.collectAll()
	return c
}

// Read Linux /proc/stat to compute non-blocking CPU percentage
func (c *TelemetryCollector) sampleCPU() {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 5 && fields[0] == "cpu" {
			var total, idle uint64
			for i := 1; i < len(fields); i++ {
				val, _ := strconv.ParseUint(fields[i], 10, 64)
				total += val
				if i == 4 || i == 5 { // idle + iowait
					idle += val
				}
			}

			if c.prevCPUTotal > 0 && total > c.prevCPUTotal {
				totalDiff := total - c.prevCPUTotal
				idleDiff := idle - c.prevCPUIdle
				if totalDiff > 0 {
					cpuPct := (1.0 - float64(idleDiff)/float64(totalDiff)) * 100.0
					if cpuPct < 0 {
						cpuPct = 0
					} else if cpuPct > 100 {
						cpuPct = 100
					}
					c.latestCPU = mathRound(cpuPct, 1)
				}
			}
			c.prevCPUTotal = total
			c.prevCPUIdle = idle
		}
	}
}

func mathRound(val float64, decimals int) float64 {
	pow := 1.0
	for i := 0; i < decimals; i++ {
		pow *= 10.0
	}
	return float64(int(val*pow+0.5)) / pow
}

func getMemoryStats() (total, used, avail uint64, pct float64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, 0, 0
	}
	defer f.Close()

	var memTotal, memAvail uint64
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[0] == "MemTotal:" {
			kb, _ := strconv.ParseUint(fields[1], 10, 64)
			memTotal = kb * 1024
		} else if fields[0] == "MemAvailable:" {
			kb, _ := strconv.ParseUint(fields[1], 10, 64)
			memAvail = kb * 1024
		}
	}

	if memTotal > 0 {
		used = memTotal - memAvail
		pct = mathRound((float64(used)/float64(memTotal))*100.0, 1)
	}
	return memTotal, used, memAvail, pct
}

func getDiskStats(path string) (total, used uint64, pct float64) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, 0, 0
	}
	total = stat.Blocks * uint64(stat.Bsize)
	free := stat.Bavail * uint64(stat.Bsize)
	used = total - free
	if total > 0 {
		pct = mathRound((float64(used)/float64(total))*100.0, 1)
	}
	return total, used, pct
}

func getLoadAverages() (l1, l5, l15 float64) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0
	}
	fields := strings.Fields(string(data))
	if len(fields) >= 3 {
		l1, _ = strconv.ParseFloat(fields[0], 64)
		l5, _ = strconv.ParseFloat(fields[1], 64)
		l15, _ = strconv.ParseFloat(fields[2], 64)
	}
	return
}

func getSystemUptime() float64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) > 0 {
		up, _ := strconv.ParseFloat(fields[0], 64)
		return up
	}
	return 0
}

// Queries all managed systemd services in a single systemctl batch call
func (c *TelemetryCollector) queryServicesBatch() map[string]ServiceDetail {
	res := make(map[string]ServiceDetail)
	for _, s := range c.services {
		res[s] = ServiceDetail{
			Name:         s,
			Status:       "inactive",
			SystemdState: "unknown",
			Enabled:      "unknown",
		}
	}

	args := append([]string{"show"}, c.services...)
	args = append(args, "-p", "Id,ActiveState,MainPID,MemoryCurrent,UnitFileState")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "systemctl", args...)
	out, err := cmd.Output()
	if err != nil {
		return res
	}

	blocks := strings.Split(string(out), "\n\n")
	for _, block := range blocks {
		lines := strings.Split(strings.TrimSpace(block), "\n")
		var id, activeState, unitFileState string
		var pid int
		var memMB float64

		for _, line := range lines {
			if strings.HasPrefix(line, "Id=") {
				id = strings.TrimPrefix(line, "Id=")
				id = strings.TrimSuffix(id, ".service")
			} else if strings.HasPrefix(line, "ActiveState=") {
				activeState = strings.TrimPrefix(line, "ActiveState=")
			} else if strings.HasPrefix(line, "UnitFileState=") {
				unitFileState = strings.TrimPrefix(line, "UnitFileState=")
			} else if strings.HasPrefix(line, "MainPID=") {
				pStr := strings.TrimPrefix(line, "MainPID=")
				pid, _ = strconv.Atoi(pStr)
			} else if strings.HasPrefix(line, "MemoryCurrent=") {
				mStr := strings.TrimPrefix(line, "MemoryCurrent=")
				if b, err := strconv.ParseUint(mStr, 10, 64); err == nil && b > 0 && b < 1e14 {
					memMB = mathRound(float64(b)/(1024*1024), 1)
				}
			}
		}

		if id != "" {
			st := "inactive"
			if activeState == "active" {
				st = "active"
			} else if activeState == "failed" {
				st = "failed"
			}
			res[id] = ServiceDetail{
				Name:         id,
				Status:       st,
				SystemdState: activeState,
				Enabled:      unitFileState,
				PID:          pid,
				MemoryMB:     memMB,
			}
		}
	}

	return res
}

func getSysvolHealthCached() string {
	paths := []string{"/var/run/zclock-sysvol.health"}
	for _, p := range paths {
		if data, err := os.ReadFile(p); err == nil {
			lines := strings.Split(string(data), "\n")
			for _, l := range lines {
				if strings.HasPrefix(l, "STATUS=") {
					return strings.TrimPrefix(l, "STATUS=")
				}
			}
		}
	}
	return "UNKNOWN"
}

func getActiveSessionsCount() int {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "smbstatus", "-b")
	out, err := cmd.Output()
	if err != nil {
		return 0
	}
	lines := strings.Split(string(out), "\n")
	count := 0
	if len(lines) > 4 {
		for _, l := range lines[4:] {
			if strings.TrimSpace(l) != "" {
				count++
			}
		}
	}
	return count
}

func getDRSFailures() int {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "samba-tool", "drs", "showrepl")
	out, err := cmd.Output()
	if err != nil {
		return 0
	}
	total := 0
	lines := strings.Split(string(out), "\n")
	for _, l := range lines {
		if strings.Contains(strings.ToLower(l), "consecutive failure") {
			fields := strings.Fields(l)
			if len(fields) > 0 {
				if n, err := strconv.Atoi(fields[0]); err == nil {
					total += n
				}
			}
		}
	}
	return total
}

func (c *TelemetryCollector) collectAll() {
	c.sampleCPU()

	memTotal, memUsed, memAvail, memPct := getMemoryStats()
	diskTotal, diskUsed, diskPct := getDiskStats("/")
	l1, l5, l15 := getLoadAverages()
	uptime := getSystemUptime()
	services := c.queryServicesBatch()
	sysvolH := getSysvolHealthCached()
	activeS := getActiveSessionsCount()

	activeCount := 0
	for _, s := range services {
		if s.Status == "active" {
			activeCount++
		}
	}

	overallH := "DEGRADED"
	if activeCount >= 5 {
		overallH = "HEALTHY"
	} else if activeCount >= 3 {
		overallH = "INITIALIZING"
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.snapshot = TelemetrySnapshot{
		Hostname:      c.snapshot.Hostname,
		Timestamp:     time.Now().Unix(),
		UptimeSeconds: uptime,
		OverallHealth: overallH,
		Resources: ResourceStats{
			CPUPercent:  c.latestCPU,
			MemoryTotal: memTotal,
			MemoryUsed:  memUsed,
			MemoryAvail: memAvail,
			MemoryPct:   memPct,
			DiskTotal:   diskTotal,
			DiskUsed:    diskUsed,
			DiskPercent: diskPct,
			LoadAvg1:    l1,
			LoadAvg5:    l5,
			LoadAvg15:   l15,
			UptimeSec:   uptime,
		},
		Services:       services,
		ActiveSessions: activeS,
		SysvolHealth:   sysvolH,
		DRSFailures:    0,
	}
}

func (c *TelemetryCollector) Run(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	drsTicker := time.NewTicker(45 * time.Second)
	defer drsTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.collectAll()
		case <-drsTicker.C:
			fails := getDRSFailures()
			c.mu.Lock()
			c.snapshot.DRSFailures = fails
			c.mu.Unlock()
		}
	}
}

// ------------------- HTTP Handlers -------------------

func (c *TelemetryCollector) HandleMetrics(w http.ResponseWriter, r *http.Request) {
	c.mu.RLock()
	snap := c.snapshot
	c.mu.RUnlock()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	fmt.Fprintf(w, "# HELP zclock_cpu_percent Total system CPU utilization percentage\n")
	fmt.Fprintf(w, "# TYPE zclock_cpu_percent gauge\n")
	fmt.Fprintf(w, "zclock_cpu_percent %.2f\n", snap.Resources.CPUPercent)

	fmt.Fprintf(w, "# HELP zclock_memory_total_bytes Total physical memory in bytes\n")
	fmt.Fprintf(w, "# TYPE zclock_memory_total_bytes gauge\n")
	fmt.Fprintf(w, "zclock_memory_total_bytes %d\n", snap.Resources.MemoryTotal)

	fmt.Fprintf(w, "# HELP zclock_memory_used_bytes Used physical memory in bytes\n")
	fmt.Fprintf(w, "# TYPE zclock_memory_used_bytes gauge\n")
	fmt.Fprintf(w, "zclock_memory_used_bytes %d\n", snap.Resources.MemoryUsed)

	fmt.Fprintf(w, "# HELP zclock_disk_total_bytes Total root filesystem capacity in bytes\n")
	fmt.Fprintf(w, "# TYPE zclock_disk_total_bytes gauge\n")
	fmt.Fprintf(w, "zclock_disk_total_bytes %d\n", snap.Resources.DiskTotal)

	fmt.Fprintf(w, "# HELP zclock_disk_used_bytes Used root filesystem capacity in bytes\n")
	fmt.Fprintf(w, "# TYPE zclock_disk_used_bytes gauge\n")
	fmt.Fprintf(w, "zclock_disk_used_bytes %d\n", snap.Resources.DiskUsed)

	fmt.Fprintf(w, "# HELP zclock_uptime_seconds System uptime in seconds\n")
	fmt.Fprintf(w, "# TYPE zclock_uptime_seconds counter\n")
	fmt.Fprintf(w, "zclock_uptime_seconds %.0f\n", snap.UptimeSeconds)

	fmt.Fprintf(w, "# HELP zclock_load_average System load average\n")
	fmt.Fprintf(w, "# TYPE zclock_load_average gauge\n")
	fmt.Fprintf(w, "zclock_load_average{period=\"1m\"} %.2f\n", snap.Resources.LoadAvg1)
	fmt.Fprintf(w, "zclock_load_average{period=\"5m\"} %.2f\n", snap.Resources.LoadAvg5)
	fmt.Fprintf(w, "zclock_load_average{period=\"15m\"} %.2f\n", snap.Resources.LoadAvg15)

	fmt.Fprintf(w, "# HELP zclock_service_active Systemd service operational status (1=active, 0=inactive)\n")
	fmt.Fprintf(w, "# TYPE zclock_service_active gauge\n")
	for name, s := range snap.Services {
		act := 0
		if s.Status == "active" {
			act = 1
		}
		fmt.Fprintf(w, "zclock_service_active{service=\"%s\"} %d\n", name, act)
		fmt.Fprintf(w, "zclock_service_memory_mb{service=\"%s\"} %.1f\n", name, s.MemoryMB)
	}

	fmt.Fprintf(w, "# HELP zclock_active_sessions Active SMB connections to Domain Controller\n")
	fmt.Fprintf(w, "# TYPE zclock_active_sessions gauge\n")
	fmt.Fprintf(w, "zclock_active_sessions %d\n", snap.ActiveSessions)

	fmt.Fprintf(w, "# HELP zclock_drs_failures Consecutive DRS directory replication failures\n")
	fmt.Fprintf(w, "# TYPE zclock_drs_failures gauge\n")
	fmt.Fprintf(w, "zclock_drs_failures %d\n", snap.DRSFailures)
}

func (c *TelemetryCollector) HandleStats(w http.ResponseWriter, r *http.Request) {
	c.mu.RLock()
	snap := c.snapshot
	c.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(snap)
}

func (c *TelemetryCollector) HandleHealth(w http.ResponseWriter, r *http.Request) {
	c.mu.RLock()
	health := c.snapshot.OverallHealth
	c.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  health,
		"engine":  "zclock-exporter-go",
		"version": "1.2.7",
	})
}

// ------------------- CLI Subcommand Mode -------------------

func runCLISubcommand(cmd string) {
	switch cmd {
	case "ad_status":
		out, err := exec.Command("systemctl", "is-active", "--quiet", "samba-ad-dc").CombinedOutput()
		_ = out
		if err == nil {
			fmt.Println("HEALTHY")
		} else {
			fmt.Println("CRITICAL")
		}
	case "drs_health":
		fmt.Println(getDRSFailures())
	case "active_sessions":
		fmt.Println(getActiveSessionsCount())
	case "sysvol_health":
		h := getSysvolHealthCached()
		if h == "HEALTHY" {
			fmt.Println("HEALTHY")
		} else if h == "ERROR" {
			fmt.Println("ACL_MISMATCH")
		} else {
			fmt.Println(h)
		}
	case "radius_auths":
		if err := exec.Command("systemctl", "is-active", "--quiet", "freeradius").Run(); err == nil {
			fmt.Println("ACTIVE")
		} else {
			fmt.Println("INACTIVE")
		}
	case "stats", "json":
		c := NewTelemetryCollector()
		data, _ := json.MarshalIndent(c.snapshot, "", "  ")
		fmt.Println(string(data))
	default:
		fmt.Printf("Usage: %s {daemon|ad_status|drs_health|active_sessions|sysvol_health|radius_auths|stats}\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}
}

func main() {
	// If invoked with a CLI subcommand argument, execute CLI mode and exit
	if len(os.Args) > 1 && os.Args[1] != "daemon" && !strings.HasPrefix(os.Args[1], "-") {
		runCLISubcommand(os.Args[1])
		return
	}

	port := os.Getenv("EXPORTER_PORT")
	if port == "" {
		port = "9101"
	}

	collector := NewTelemetryCollector()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go collector.Run(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", collector.HandleMetrics)
	mux.HandleFunc("/stats", collector.HandleStats)
	mux.HandleFunc("/health", collector.HandleHealth)

	server := &http.Server{
		Addr:    fmt.Sprintf("0.0.0.0:%s", port),
		Handler: mux,
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("[zclock-exporter] Starting Go Prometheus & Telemetry Exporter on port %s...", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[zclock-exporter] Listener failed: %v", err)
		}
	}()

	<-sigChan
	log.Println("[zclock-exporter] Shutting down telemetry server...")
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)
	log.Println("[zclock-exporter] Exited cleanly.")
}
