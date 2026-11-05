package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var managedServices = []string{
	"samba-ad-dc",
	"bind9",
	"freeradius",
	"chrony",
	"zclock-sysvold",
	"zclock-azuresync",
	"zclock-api",
	"nginx",
	"snmpd",
}

type SystemStats struct {
	CPUPercent   float64            `json:"cpu_percent"`
	MemoryTotal  uint64             `json:"memory_total_bytes"`
	MemoryUsed   uint64             `json:"memory_used_bytes"`
	DiskTotal    uint64             `json:"disk_total_bytes"`
	DiskUsed     uint64             `json:"disk_used_bytes"`
	LoadAvg1     float64            `json:"load_avg_1m"`
	LoadAvg5     float64            `json:"load_avg_5m"`
	LoadAvg15    float64            `json:"load_avg_15m"`
	ServiceState map[string]int     `json:"services_active"`
	Timestamp    int64              `json:"timestamp"`
}

func getMemoryInfo() (total uint64, available uint64) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[0] == "MemTotal:" {
			kb, _ := strconv.ParseUint(fields[1], 10, 64)
			total = kb * 1024
		} else if fields[0] == "MemAvailable:" {
			kb, _ := strconv.ParseUint(fields[1], 10, 64)
			available = kb * 1024
		}
	}
	return total, available
}

func getLoadAvg() (load1, load5, load15 float64) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0
	}
	fields := strings.Fields(string(data))
	if len(fields) >= 3 {
		load1, _ = strconv.ParseFloat(fields[0], 64)
		load5, _ = strconv.ParseFloat(fields[1], 64)
		load15, _ = strconv.ParseFloat(fields[2], 64)
	}
	return
}

func getDiskUsage(path string) (total uint64, used uint64) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, 0
	}
	total = stat.Blocks * uint64(stat.Bsize)
	free := stat.Bfree * uint64(stat.Bsize)
	used = total - free
	return total, used
}

func checkServiceActive(name string) int {
	cmd := exec.Command("systemctl", "is-active", "--quiet", name)
	if err := cmd.Run(); err == nil {
		return 1
	}
	return 0
}

func collectStats() SystemStats {
	memTotal, memAvail := getMemoryInfo()
	memUsed := memTotal - memAvail
	diskTotal, diskUsed := getDiskUsage("/")
	load1, load5, load15 := getLoadAvg()

	services := make(map[string]int)
	for _, s := range managedServices {
		services[s] = checkServiceActive(s)
	}

	return SystemStats{
		CPUPercent:   load1 * 10.0, // rough indicator without interval
		MemoryTotal:  memTotal,
		MemoryUsed:   memUsed,
		DiskTotal:    diskTotal,
		DiskUsed:     diskUsed,
		LoadAvg1:     load1,
		LoadAvg5:     load5,
		LoadAvg15:    load15,
		ServiceState: services,
		Timestamp:    time.Now().Unix(),
	}
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	stats := collectStats()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP zclock_memory_total_bytes Total system physical memory in bytes\n")
	fmt.Fprintf(w, "# TYPE zclock_memory_total_bytes gauge\n")
	fmt.Fprintf(w, "zclock_memory_total_bytes %d\n", stats.MemoryTotal)

	fmt.Fprintf(w, "# HELP zclock_memory_used_bytes Used system physical memory in bytes\n")
	fmt.Fprintf(w, "# TYPE zclock_memory_used_bytes gauge\n")
	fmt.Fprintf(w, "zclock_memory_used_bytes %d\n", stats.MemoryUsed)

	fmt.Fprintf(w, "# HELP zclock_disk_total_bytes Total root filesystem capacity in bytes\n")
	fmt.Fprintf(w, "# TYPE zclock_disk_total_bytes gauge\n")
	fmt.Fprintf(w, "zclock_disk_total_bytes %d\n", stats.DiskTotal)

	fmt.Fprintf(w, "# HELP zclock_disk_used_bytes Used root filesystem capacity in bytes\n")
	fmt.Fprintf(w, "# TYPE zclock_disk_used_bytes gauge\n")
	fmt.Fprintf(w, "zclock_disk_used_bytes %d\n", stats.DiskUsed)

	fmt.Fprintf(w, "# HELP zclock_load_average System load average\n")
	fmt.Fprintf(w, "# TYPE zclock_load_average gauge\n")
	fmt.Fprintf(w, "zclock_load_average{period=\"1m\"} %.2f\n", stats.LoadAvg1)
	fmt.Fprintf(w, "zclock_load_average{period=\"5m\"} %.2f\n", stats.LoadAvg5)
	fmt.Fprintf(w, "zclock_load_average{period=\"15m\"} %.2f\n", stats.LoadAvg15)

	fmt.Fprintf(w, "# HELP zclock_service_active Systemd service operational status (1=active, 0=inactive)\n")
	fmt.Fprintf(w, "# TYPE zclock_service_active gauge\n")
	for svc, state := range stats.ServiceState {
		fmt.Fprintf(w, "zclock_service_active{service=\"%s\"} %d\n", svc, state)
	}
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	stats := collectStats()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "UP",
		"engine": "zclock-exporter-go",
	})
}

func main() {
	port := os.Getenv("EXPORTER_PORT")
	if port == "" {
		port = "9101"
	}

	http.HandleFunc("/metrics", metricsHandler)
	http.HandleFunc("/stats", statsHandler)
	http.HandleFunc("/health", healthHandler)

	addr := fmt.Sprintf("0.0.0.0:%s", port)
	log.Printf("[zclock-exporter] Starting Go Prometheus & Telemetry Exporter on %s...", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("[zclock-exporter] Failed to listen: %v", err)
	}
}

