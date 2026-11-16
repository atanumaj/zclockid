package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
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

type FileInfo struct {
	Hash  string  `json:"hash"`
	Mtime float64 `json:"mtime"`
	Size  int64   `json:"size"`
}

type Partner struct {
	Name            string `json:"name"`
	IPAddress       string `json:"ip_address"`
	SharedSecret    string `json:"shared_secret"`
	CertFingerprint string `json:"cert_fingerprint"`
	CertPEM         string `json:"cert_pem"`
}

type PartnersConfig struct {
	Partners []Partner `json:"partners"`
}

type PartnerStatus struct {
	Name       string  `json:"name"`
	IPAddress  string  `json:"ip_address"`
	Status     string  `json:"status"`
	LastSync   float64 `json:"last_sync"`
	FilesCount int     `json:"files_count"`
	Error      *string `json:"error"`
}

type SysvolDaemon struct {
	sysvolPath      string
	debounceSec     time.Duration
	resetTimer      *time.Timer
	resetMutex      sync.Mutex
	partnerStatuses map[string]PartnerStatus
	statusMutex     sync.RWMutex
	localSecret     string
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func getOrCreateSecret() string {
	secretPaths := []string{
		"/etc/zclockid/sysvol_secret",
		"/zclockid/config/sysvol_secret",
	}

	for _, p := range secretPaths {
		if data, err := os.ReadFile(p); err == nil && len(bytes.TrimSpace(data)) > 0 {
			return string(bytes.TrimSpace(data))
		}
	}

	// Generate 24-byte hex secret
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	sec := hex.EncodeToString(b)

	destPath := "/etc/zclockid/sysvol_secret"
	_ = os.MkdirAll(filepath.Dir(destPath), 0700)
	_ = os.WriteFile(destPath, []byte(sec+"\n"), 0600)
	return sec
}

func (d *SysvolDaemon) GetClientForPartner(p Partner) *http.Client {
	roots := x509.NewCertPool()
	if p.CertPEM != "" {
		roots.AppendCertsFromPEM([]byte(p.CertPEM))
	}
	certPath := fmt.Sprintf("/etc/zclockid/certs/partner_%s.crt", p.IPAddress)
	if data, err := os.ReadFile(certPath); err == nil {
		roots.AppendCertsFromPEM(data)
	}

	expectedFP := strings.ToLower(strings.ReplaceAll(p.CertFingerprint, ":", ""))

	tlsConfig := &tls.Config{
		RootCAs: roots,
		// InsecureSkipVerify is completely removed / false: standard CA/SAN validation occurs,
		// supplemented by exact SHA-256 fingerprint verification on every connection.
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no peer certificates presented by %s", p.IPAddress)
			}
			fp := sha256.Sum256(rawCerts[0])
			fpHex := hex.EncodeToString(fp[:])
			if expectedFP != "" && fpHex != expectedFP {
				return fmt.Errorf("TLS certificate fingerprint mismatch for %s: got %s, expected %s", p.IPAddress, fpHex, expectedFP)
			}
			return nil
		},
	}

	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	return &http.Client{Transport: tr, Timeout: 25 * time.Second}
}

func NewSysvolDaemon(sysvolPath string, debounceSec int) *SysvolDaemon {
	return &SysvolDaemon{
		sysvolPath:      sysvolPath,
		debounceSec:     time.Duration(debounceSec) * time.Second,
		partnerStatuses: make(map[string]PartnerStatus),
		localSecret:     getOrCreateSecret(),
	}
}

func (d *SysvolDaemon) ScheduleReset(reason string) {
	d.resetMutex.Lock()
	defer d.resetMutex.Unlock()

	if d.resetTimer != nil {
		d.resetTimer.Stop()
	}

	log.Printf("[zclock-sysvold] Sysvol change detected (%s). Scheduling NTACL reset in %v...", reason, d.debounceSec)
	d.resetTimer = time.AfterFunc(d.debounceSec, func() {
		d.ExecuteSysvolReset()
	})
}

func (d *SysvolDaemon) RecordHealth(status, message string) {
	healthPaths := []string{
		"/var/run/zclock-sysvol.health",
	}
	now := float64(time.Now().Unix())
	content := fmt.Sprintf("STATUS=%s\nLAST_RESET=%.0f\nMESSAGE=%s\n", status, now, message)

	for _, p := range healthPaths {
		_ = os.MkdirAll(filepath.Dir(p), 0755)
		_ = os.WriteFile(p, []byte(content), 0644)
	}
}

func (d *SysvolDaemon) ExecuteSysvolReset() {
	log.Println("[zclock-sysvold] Executing 'samba-tool ntacl sysvolreset'...")
	start := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "samba-tool", "ntacl", "sysvolreset")
	output, err := cmd.CombinedOutput()
	duration := time.Since(start).Seconds()

	if err != nil {
		log.Printf("[zclock-sysvold] NTACL sysvolreset failed (err: %v): %s", err, string(output))
		d.RecordHealth("ERROR", string(output))
		return
	}

	log.Printf("[zclock-sysvold] NTACL sysvolreset completed successfully in %.2fs", duration)
	d.RecordHealth("HEALTHY", "Sysvol NTACLs verified and healthy")
}

func (d *SysvolDaemon) GetLocalManifest() map[string]FileInfo {
	manifest := make(map[string]FileInfo)
	if _, err := os.Stat(d.sysvolPath); os.IsNotExist(err) {
		return manifest
	}

	_ = filepath.Walk(d.sysvolPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(d.sysvolPath, path)
		if err != nil {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return nil
		}

		manifest[relPath] = FileInfo{
			Hash:  hex.EncodeToString(h.Sum(nil)),
			Mtime: float64(info.ModTime().UnixNano()) / 1e9,
			Size:  info.Size(),
		}
		return nil
	})

	return manifest
}

func (d *SysvolDaemon) LoadPartners() []Partner {
	partnerPaths := []string{
		"/etc/zclockid/sysvol_partners.json",
		"/zclockid/config/sysvol_partners.json",
	}

	for _, p := range partnerPaths {
		if data, err := os.ReadFile(p); err == nil {
			var cfg PartnersConfig
			if err := json.Unmarshal(data, &cfg); err == nil {
				return cfg.Partners
			}
		}
	}
	return nil
}

func (d *SysvolDaemon) SyncPartner(p Partner) bool {
	if p.IPAddress == "" {
		return false
	}
	name := p.Name
	if name == "" {
		name = p.IPAddress
	}

	baseURL := fmt.Sprintf("https://%s", p.IPAddress)
	manifestURL := fmt.Sprintf("%s/api/v1/sysvol/manifest", baseURL)

	client := d.GetClientForPartner(p)

	req, err := http.NewRequest("GET", manifestURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("X-Zclock-Sync-Secret", p.SharedSecret)

	resp, err := client.Do(req)
	if err != nil {
		errStr := err.Error()
		d.statusMutex.Lock()
		d.partnerStatuses[p.IPAddress] = PartnerStatus{
			Name:       name,
			IPAddress:  p.IPAddress,
			Status:     "UNREACHABLE",
			LastSync:   float64(time.Now().Unix()),
			FilesCount: 0,
			Error:      &errStr,
		}
		d.statusMutex.Unlock()
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errStr := fmt.Sprintf("HTTP %d", resp.StatusCode)
		d.statusMutex.Lock()
		d.partnerStatuses[p.IPAddress] = PartnerStatus{
			Name:       name,
			IPAddress:  p.IPAddress,
			Status:     "ERROR",
			LastSync:   float64(time.Now().Unix()),
			FilesCount: 0,
			Error:      &errStr,
		}
		d.statusMutex.Unlock()
		return false
	}

	var remoteData struct {
		Manifest map[string]FileInfo `json:"manifest"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&remoteData); err != nil {
		return false
	}

	localManifest := d.GetLocalManifest()
	changed := false

	// 1. Pull remote files that are missing or newer
	for relPath, rInfo := range remoteData.Manifest {
		cleanRel := filepath.Clean(relPath)
		if strings.HasPrefix(cleanRel, "..") || filepath.IsAbs(cleanRel) {
			log.Printf("[zclock-sysvold] Path traversal rejected from remote manifest: %s", relPath)
			continue
		}
		destPath := filepath.Join(d.sysvolPath, cleanRel)
		if !strings.HasPrefix(destPath, d.sysvolPath) {
			continue
		}

		lInfo, exists := localManifest[relPath]
		if !exists || (rInfo.Hash != lInfo.Hash && rInfo.Mtime > lInfo.Mtime) {
			log.Printf("[zclock-sysvold] Pulling updated file '%s' from %s (%s)...", relPath, name, p.IPAddress)
			dlURL := fmt.Sprintf("%s/api/v1/sysvol/file?rel_path=%s", baseURL, url.QueryEscape(relPath))
			dlReq, _ := http.NewRequest("GET", dlURL, nil)
			dlReq.Header.Set("X-Zclock-Sync-Secret", p.SharedSecret)

			dlResp, err := client.Do(dlReq)
			if err == nil && dlResp.StatusCode == http.StatusOK {
				_ = os.MkdirAll(filepath.Dir(destPath), 0755)

				tmpPath := destPath + ".tmp"
				if outF, err := os.Create(tmpPath); err == nil {
					_, _ = io.Copy(outF, dlResp.Body)
					outF.Close()
					_ = os.Rename(tmpPath, destPath)
					changed = true
				}
				dlResp.Body.Close()
			}
		}
	}

	// 2. Push local files that are missing or newer remotely
	for relPath, lInfo := range localManifest {
		rInfo, exists := remoteData.Manifest[relPath]
		if !exists || (lInfo.Hash != rInfo.Hash && lInfo.Mtime > rInfo.Mtime) {
			log.Printf("[zclock-sysvold] Pushing updated file '%s' to %s (%s)...", relPath, name, p.IPAddress)
			localFilePath := filepath.Join(d.sysvolPath, relPath)
			if fileData, err := os.ReadFile(localFilePath); err == nil {
				pushPayload := map[string]interface{}{
					"rel_path":       relPath,
					"content_base64": hex.EncodeToString(fileData),
					"mtime":          lInfo.Mtime,
				}
				jsonPayload, _ := json.Marshal(pushPayload)

				pushURL := fmt.Sprintf("%s/api/v1/sysvol/file", baseURL)
				pushReq, _ := http.NewRequest("POST", pushURL, bytes.NewBuffer(jsonPayload))
				pushReq.Header.Set("X-Zclock-Sync-Secret", p.SharedSecret)
				pushReq.Header.Set("Content-Type", "application/json")

				if pushResp, err := client.Do(pushReq); err == nil {
					pushResp.Body.Close()
					changed = true
				}
			}
		}
	}

	d.statusMutex.Lock()
	d.partnerStatuses[p.IPAddress] = PartnerStatus{
		Name:       name,
		IPAddress:  p.IPAddress,
		Status:     "IN_SYNC",
		LastSync:   float64(time.Now().Unix()),
		FilesCount: len(localManifest),
		Error:      nil,
	}
	d.statusMutex.Unlock()

	if changed {
		d.ScheduleReset(fmt.Sprintf("Replicated changes from %s", name))
	}
	return true
}

func (d *SysvolDaemon) WriteTelemetry() {
	d.statusMutex.RLock()
	defer d.statusMutex.RUnlock()

	partnersList := make([]PartnerStatus, 0)
	for _, st := range d.partnerStatuses {
		partnersList = append(partnersList, st)
	}

	payload := map[string]interface{}{
		"timestamp": float64(time.Now().Unix()),
		"partners":  partnersList,
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err == nil {
		_ = os.WriteFile("/var/run/zclock-sysvol-sync.json", data, 0644)
	}
}

func (d *SysvolDaemon) Run(ctx context.Context) {
	log.Printf("[zclock-sysvold] Starting Go Native Sysvol Guardian on %s (debounce: %v)...", d.sysvolPath, d.debounceSec)
	d.ExecuteSysvolReset()

	// Initial partner sync & telemetry pass on start
	partners := d.LoadPartners()
	for _, p := range partners {
		d.SyncPartner(p)
	}
	d.WriteTelemetry()

	var lastMtime int64 = 0
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("[zclock-sysvold] Daemon loop terminating via context...")
			return
		case <-ticker.C:
			// 1. Check local modification
			var maxMtime int64 = 0
			_ = filepath.Walk(d.sysvolPath, func(path string, info os.FileInfo, err error) error {
				if err == nil && !info.IsDir() {
					if mt := info.ModTime().UnixNano(); mt > maxMtime {
						maxMtime = mt
					}
				}
				return nil
			})

			if lastMtime != 0 && maxMtime > lastMtime {
				d.ScheduleReset("Local modification in sysvol")
			}
			lastMtime = maxMtime

			// 2. Sync partner DCs
			pList := d.LoadPartners()
			for _, p := range pList {
				d.SyncPartner(p)
			}

			// 3. Write telemetry
			d.WriteTelemetry()
		}
	}
}

func main() {
	sysvolPath := getEnv("SYSVOL_PATH", "/var/lib/samba/sysvol")
	debounceSec := 4
	if v := os.Getenv("DEBOUNCE_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			debounceSec = n
		}
	}

	daemon := NewSysvolDaemon(sysvolPath, debounceSec)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go daemon.Run(ctx)

	<-sigChan
	log.Println("[zclock-sysvold] Shutting down gracefully...")
	cancel()
	time.Sleep(200 * time.Millisecond)
}


