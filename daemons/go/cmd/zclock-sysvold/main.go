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
	"sort"
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

type Tombstone struct {
	RelPath      string  `json:"rel_path"`
	DeletedAt    float64 `json:"deleted_at"`
	HashAtDelete string  `json:"hash_at_delete"`
}

type SysvolSettings struct {
	MassDeleteMinFiles int     `json:"mass_delete_min_files"`
	MassDeletePct      float64 `json:"mass_delete_pct"`
	MassDeleteMaxFiles int     `json:"mass_delete_max_files"`
}

type MassDeletePending struct {
	PartnerIP  string   `json:"partner_ip"`
	Paths      []string `json:"paths"`
	DetectedAt float64  `json:"detected_at"`
}

type MassDeleteApproved struct {
	PartnerIP  string   `json:"partner_ip"`
	Paths      []string `json:"paths"`
	DetectedAt float64  `json:"detected_at"`
}

type SysvolState struct {
	Files              map[string]FileInfo  `json:"files"`
	Tombstones         map[string]Tombstone `json:"tombstones"`
	MassDeleteTripped  bool                 `json:"mass_delete_tripped"`
	PendingMassDelete  *MassDeletePending   `json:"pending_mass_delete,omitempty"`
	ApprovedMassDelete *MassDeleteApproved  `json:"approved_mass_delete,omitempty"`
}

type PartnersConfig struct {
	Partners []Partner       `json:"partners"`
	Settings *SysvolSettings `json:"settings,omitempty"`
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
	statePath       string
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
			_ = os.Chmod(p, 0600)
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

func (d *SysvolDaemon) LoadState() SysvolState {
	st := SysvolState{
		Files:      make(map[string]FileInfo),
		Tombstones: make(map[string]Tombstone),
	}
	if data, err := os.ReadFile(d.statePath); err == nil {
		_ = json.Unmarshal(data, &st)
		if st.Files == nil {
			st.Files = make(map[string]FileInfo)
		}
		if st.Tombstones == nil {
			st.Tombstones = make(map[string]Tombstone)
		}
	}
	return st
}

func (d *SysvolDaemon) SaveState(st SysvolState) {
	_ = os.MkdirAll(filepath.Dir(d.statePath), 0700)
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return
	}
	tmpPath := d.statePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err == nil {
		_ = os.Chmod(tmpPath, 0600)
		_ = os.Rename(tmpPath, d.statePath)
	}
}

func (d *SysvolDaemon) UpdateLocalStateOnScan(localManifest map[string]FileInfo, state *SysvolState) {
	now := float64(time.Now().Unix())

	// 1. Expire tombstones older than 30 days
	cutoff := now - (30 * 86400)
	for p, t := range state.Tombstones {
		if t.DeletedAt <= cutoff {
			delete(state.Tombstones, p)
		}
	}

	// 2. Detect local deletions compared to state.Files
	for p, prev := range state.Files {
		if _, exists := localManifest[p]; !exists {
			if _, alreadyTomb := state.Tombstones[p]; !alreadyTomb {
				state.Tombstones[p] = Tombstone{
					RelPath:      p,
					DeletedAt:    now,
					HashAtDelete: prev.Hash,
				}
				log.Printf("[zclock-sysvold] Local deletion detected for '%s' (hash: %s)", p, prev.Hash)
			}
		}
	}

	// 3. Remove tombstones for files present locally
	for p := range localManifest {
		delete(state.Tombstones, p)
	}

	state.Files = localManifest
}

func VerifyHash(content []byte, expectedHash string) bool {
	h := sha256.Sum256(content)
	actualHash := hex.EncodeToString(h[:])
	return strings.EqualFold(actualHash, strings.TrimSpace(expectedHash))
}

func MergeTombstones(localManifest map[string]FileInfo, remoteTombstones []Tombstone, state *SysvolState, partnerIP string, settings *SysvolSettings) (toDelete []string, conflictCount int, tripped bool) {
	totalFiles := len(localManifest)
	candidates := make([]string, 0)

	for _, rt := range remoteTombstones {
		lInfo, exists := localManifest[rt.RelPath]
		if !exists {
			if state != nil {
				if existing, has := state.Tombstones[rt.RelPath]; !has || rt.DeletedAt > existing.DeletedAt {
					state.Tombstones[rt.RelPath] = rt
				}
			}
			continue
		}

		if lInfo.Hash == rt.HashAtDelete {
			candidates = append(candidates, rt.RelPath)
		} else if lInfo.Mtime > rt.DeletedAt {
			log.Printf("[zclock-sysvold] Conflict for '%s': locally modified after remote deletion (mtime %.0f > deleted_at %.0f). Keeping local copy.", rt.RelPath, lInfo.Mtime, rt.DeletedAt)
			conflictCount++
		} else {
			candidates = append(candidates, rt.RelPath)
		}
	}

	sort.Strings(candidates)

	// Check if an approval exists
	if state != nil && state.ApprovedMassDelete != nil && len(state.ApprovedMassDelete.Paths) > 0 {
		partnerMatch := partnerIP == "" || state.ApprovedMassDelete.PartnerIP == "" || state.ApprovedMassDelete.PartnerIP == partnerIP
		if partnerMatch {
			approvedMap := make(map[string]bool)
			for _, p := range state.ApprovedMassDelete.Paths {
				approvedMap[p] = true
			}
			isSubset := true
			for _, c := range candidates {
				if !approvedMap[c] {
					isSubset = false
					break
				}
			}

			if isSubset {
				log.Printf("[zclock-sysvold] Mass deletion of %d files approved. Proceeding with deletion.", len(candidates))
				state.ApprovedMassDelete = nil
				state.PendingMassDelete = nil
				state.MassDeleteTripped = false
				return candidates, conflictCount, false
			} else {
				log.Printf("[zclock-sysvold] Candidates contain unapproved paths. Invalidating prior approval and re-tripping safety brake.")
				state.ApprovedMassDelete = nil
			}
		}
	}

	minFiles := 10
	pct := 20.0
	maxFiles := 50
	if settings != nil {
		if settings.MassDeleteMinFiles > 0 {
			minFiles = settings.MassDeleteMinFiles
		}
		if settings.MassDeletePct > 0 {
			pct = settings.MassDeletePct
		}
		if settings.MassDeleteMaxFiles > 0 {
			maxFiles = settings.MassDeleteMaxFiles
		}
	}

	numToDelete := len(candidates)
	trippedCond := numToDelete > maxFiles || (totalFiles > 0 && numToDelete > minFiles && float64(numToDelete) > (pct/100.0)*float64(totalFiles))

	if trippedCond {
		if state != nil {
			state.MassDeleteTripped = true
			now := float64(time.Now().Unix())
			pathsMatch := false
			if state.PendingMassDelete != nil && state.PendingMassDelete.PartnerIP == partnerIP && len(state.PendingMassDelete.Paths) == len(candidates) {
				candMap := make(map[string]bool)
				for _, c := range candidates {
					candMap[c] = true
				}
				matchAll := true
				for _, p := range state.PendingMassDelete.Paths {
					if !candMap[p] {
						matchAll = false
						break
					}
				}
				if matchAll {
					pathsMatch = true
				}
			}

			if !pathsMatch {
				state.PendingMassDelete = &MassDeletePending{
					PartnerIP:  partnerIP,
					Paths:      candidates,
					DetectedAt: now,
				}
			}
		}
		return nil, conflictCount, true
	}

	if state != nil {
		state.MassDeleteTripped = false
		state.PendingMassDelete = nil
	}
	return candidates, conflictCount, false
}

func (d *SysvolDaemon) CleanupEmptyDirs(filePath string) {
	dir := filepath.Dir(filePath)
	cleanSysvol := filepath.Clean(d.sysvolPath)

	for {
		cleanDir := filepath.Clean(dir)
		if cleanDir == cleanSysvol || !strings.HasPrefix(cleanDir, cleanSysvol) {
			break
		}

		relDir, err := filepath.Rel(cleanSysvol, cleanDir)
		if err != nil || relDir == "." || relDir == "" {
			break
		}

		parts := strings.Split(filepath.ToSlash(relDir), "/")
		// Never remove SYSVOL root, <domain>, <domain>/Policies, or <domain>/scripts
		if len(parts) <= 1 {
			break
		}
		if len(parts) == 2 && (strings.EqualFold(parts[1], "Policies") || strings.EqualFold(parts[1], "scripts")) {
			break
		}

		entries, err := os.ReadDir(cleanDir)
		if err != nil || len(entries) > 0 {
			break
		}

		if err := os.Remove(cleanDir); err != nil {
			break
		}
		log.Printf("[zclock-sysvold] Cleaned up empty directory: %s", relDir)
		dir = filepath.Dir(cleanDir)
	}
}

func (d *SysvolDaemon) GetClientForPartner(p Partner) (*http.Client, error) {
	expectedFP := strings.ToLower(strings.ReplaceAll(p.CertFingerprint, ":", ""))
	if expectedFP == "" {
		return nil, fmt.Errorf("no pinned certificate fingerprint for partner %s: sync refused", p.IPAddress)
	}

	roots := x509.NewCertPool()
	if p.CertPEM != "" {
		roots.AppendCertsFromPEM([]byte(p.CertPEM))
	}
	certPath := fmt.Sprintf("/etc/zclockid/certs/partner_%s.crt", p.IPAddress)
	if data, err := os.ReadFile(certPath); err == nil {
		roots.AppendCertsFromPEM(data)
	}

	tlsConfig := &tls.Config{
		RootCAs: roots,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no peer certificates presented by %s", p.IPAddress)
			}
			fp := sha256.Sum256(rawCerts[0])
			fpHex := hex.EncodeToString(fp[:])
			if fpHex != expectedFP {
				return fmt.Errorf("certificate changed: re-pin required (got %s, expected %s)", fpHex, expectedFP)
			}
			return nil
		},
	}

	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	return &http.Client{Transport: tr, Timeout: 25 * time.Second}, nil
}

func NewSysvolDaemon(sysvolPath string, debounceSec int) *SysvolDaemon {
	statePath := getEnv("ZCLOCKID_SYSVOL_STATE", "/var/lib/zclockid/sysvol_state.json")
	return &SysvolDaemon{
		sysvolPath:      sysvolPath,
		statePath:       statePath,
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

func (d *SysvolDaemon) LoadConfig() (PartnersConfig, error) {
	partnerPaths := []string{
		"/etc/zclockid/sysvol_partners.json",
		"/zclockid/config/sysvol_partners.json",
	}

	for _, p := range partnerPaths {
		if data, err := os.ReadFile(p); err == nil {
			var cfg PartnersConfig
			if err := json.Unmarshal(data, &cfg); err == nil {
				return cfg, nil
			}
		}
	}
	return PartnersConfig{}, fmt.Errorf("no partners config found")
}

func (d *SysvolDaemon) LoadPartners() []Partner {
	cfg, err := d.LoadConfig()
	if err == nil {
		return cfg.Partners
	}
	return nil
}

func (d *SysvolDaemon) LoadSettings() SysvolSettings {
	cfg, err := d.LoadConfig()
	defaults := SysvolSettings{
		MassDeleteMinFiles: 10,
		MassDeletePct:      20.0,
		MassDeleteMaxFiles: 50,
	}
	if err == nil && cfg.Settings != nil {
		if cfg.Settings.MassDeleteMinFiles > 0 {
			defaults.MassDeleteMinFiles = cfg.Settings.MassDeleteMinFiles
		}
		if cfg.Settings.MassDeletePct > 0 {
			defaults.MassDeletePct = cfg.Settings.MassDeletePct
		}
		if cfg.Settings.MassDeleteMaxFiles > 0 {
			defaults.MassDeleteMaxFiles = cfg.Settings.MassDeleteMaxFiles
		}
	}
	return defaults
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

	client, err := d.GetClientForPartner(p)
	if err != nil {
		errStr := err.Error()
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
		log.Printf("[zclock-sysvold] Peer %s client error: %v", p.IPAddress, err)
		return false
	}

	req, err := http.NewRequest("GET", manifestURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("X-Zclock-Sync-Secret", p.SharedSecret)

	resp, err := client.Do(req)
	if err != nil {
		errStr := err.Error()
		status := "UNREACHABLE"
		if strings.Contains(errStr, "re-pin required") || strings.Contains(errStr, "fingerprint mismatch") {
			status = "ERROR"
			errStr = "certificate changed: re-pin required"
		}
		d.statusMutex.Lock()
		d.partnerStatuses[p.IPAddress] = PartnerStatus{
			Name:       name,
			IPAddress:  p.IPAddress,
			Status:     status,
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
		Manifest   map[string]FileInfo `json:"manifest"`
		Tombstones []Tombstone         `json:"tombstones"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&remoteData); err != nil {
		return false
	}

	state := d.LoadState()
	localManifest := d.GetLocalManifest()
	d.UpdateLocalStateOnScan(localManifest, &state)
	changed := false

	// Build map of remote tombstones
	remoteTombMap := make(map[string]Tombstone)
	for _, t := range remoteData.Tombstones {
		if t.RelPath != "" {
			remoteTombMap[t.RelPath] = t
		}
	}

	// 1. Process deletions via Tombstones
	settings := d.LoadSettings()
	hadApproval := state.ApprovedMassDelete != nil
	candidatesToDelete, _, tripped := MergeTombstones(localManifest, remoteData.Tombstones, &state, p.IPAddress, &settings)
	if tripped {
		cnt := 0
		if state.PendingMassDelete != nil {
			cnt = len(state.PendingMassDelete.Paths)
		}
		d.RecordHealth("ERROR", fmt.Sprintf("Mass deletion brake tripped: attempted to delete %d files (>%.0f%% of %d or >%d files). Confirmation required.", cnt, settings.MassDeletePct, len(localManifest), settings.MassDeleteMaxFiles))
		log.Printf("[zclock-sysvold] Mass deletion brake tripped! Deletion aborted.")
		d.SaveState(state)
	} else {
		if hadApproval && state.ApprovedMassDelete == nil {
			d.RecordHealth("HEALTHY", "Operating normally (mass deletion approved and executed)")
		}
		if len(candidatesToDelete) > 0 {
			for _, relPath := range candidatesToDelete {
				targetPath := filepath.Join(d.sysvolPath, filepath.Clean(relPath))
				if err := os.Remove(targetPath); err == nil {
					log.Printf("[zclock-sysvold] Deleted local file per peer tombstone: %s", relPath)
					d.CleanupEmptyDirs(targetPath)
					changed = true
					delete(localManifest, relPath)
					delete(state.Files, relPath)
					if rt, ok := remoteTombMap[relPath]; ok {
						state.Tombstones[relPath] = rt
					}
				}
			}
		}
	}

	// 2. Pull remote files that are missing or newer
	const MaxSysvolFileSize = 50 * 1024 * 1024 // 50 MB
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

		// Never pull a file listed in your own tombstones unless remote copy is newer and hash differs
		if localTomb, hasTomb := state.Tombstones[relPath]; hasTomb {
			if !(rInfo.Mtime > localTomb.DeletedAt && rInfo.Hash != localTomb.HashAtDelete) {
				continue
			}
			delete(state.Tombstones, relPath)
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
				if outF, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644); err == nil {
					hasher := sha256.New()
					multiOut := io.MultiWriter(outF, hasher)
					limitedReader := io.LimitReader(dlResp.Body, MaxSysvolFileSize+1)
					written, cErr := io.Copy(multiOut, limitedReader)
					outF.Close()

					if cErr != nil || written > MaxSysvolFileSize {
						_ = os.Remove(tmpPath)
						log.Printf("[zclock-sysvold] File %s exceeds 50 MB cap or download error (%v). Aborting.", relPath, cErr)
					} else {
						downloadedHash := hex.EncodeToString(hasher.Sum(nil))
						if !strings.EqualFold(downloadedHash, rInfo.Hash) {
							_ = os.Remove(tmpPath)
							log.Printf("[zclock-sysvold] Content integrity check failed for '%s': got %s, expected %s. Download discarded.", relPath, downloadedHash, rInfo.Hash)
						} else {
							if err := os.Rename(tmpPath, destPath); err == nil {
								if rInfo.Mtime > 0 {
									sec := int64(rInfo.Mtime)
									nsec := int64((rInfo.Mtime - float64(sec)) * 1e9)
									mtime := time.Unix(sec, nsec)
									_ = os.Chtimes(destPath, mtime, mtime)
								}
								delete(state.Tombstones, relPath)
								changed = true
							}
						}
					}
				}
				dlResp.Body.Close()
			}
		}
	}

	// 3. Push local files that are missing or newer remotely
	for relPath, lInfo := range localManifest {
		// Do not push if remote partner has a tombstone for this file, unless local file was modified after deletion
		if rTomb, hasRTomb := remoteTombMap[relPath]; hasRTomb {
			if !(lInfo.Mtime > rTomb.DeletedAt && lInfo.Hash != rTomb.HashAtDelete) {
				continue
			}
		}

		// Do not push if local state has a tombstone for this file, unless local file was modified after deletion
		if lTomb, hasLTomb := state.Tombstones[relPath]; hasLTomb {
			if !(lInfo.Mtime > lTomb.DeletedAt && lInfo.Hash != lTomb.HashAtDelete) {
				continue
			}
		}

		rInfo, exists := remoteData.Manifest[relPath]
		if !exists || (lInfo.Hash != rInfo.Hash && lInfo.Mtime > rInfo.Mtime) {
			localFilePath := filepath.Join(d.sysvolPath, relPath)
			if _, statErr := os.Stat(localFilePath); statErr != nil {
				continue
			}
			log.Printf("[zclock-sysvold] Pushing updated file '%s' to %s (%s)...", relPath, name, p.IPAddress)
			if fileData, err := os.ReadFile(localFilePath); err == nil {
				pushPayload := map[string]interface{}{
					"rel_path":       relPath,
					"content_base64": hex.EncodeToString(fileData),
					"sha256":         lInfo.Hash,
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

	// 4. Update local state files snapshot and save
	state.Files = d.GetLocalManifest()
	d.SaveState(state)

	d.statusMutex.Lock()
	d.partnerStatuses[p.IPAddress] = PartnerStatus{
		Name:       name,
		IPAddress:  p.IPAddress,
		Status:     "IN_SYNC",
		LastSync:   float64(time.Now().Unix()),
		FilesCount: len(state.Files),
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

	// Initial scan & partner sync pass on start
	initState := d.LoadState()
	initManifest := d.GetLocalManifest()
	d.UpdateLocalStateOnScan(initManifest, &initState)
	d.SaveState(initState)

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
			// 1. Scan and detect local file changes & deletions
			st := d.LoadState()
			currManifest := d.GetLocalManifest()
			d.UpdateLocalStateOnScan(currManifest, &st)
			d.SaveState(st)

			var maxMtime int64 = 0
			for _, info := range currManifest {
				if mt := int64(info.Mtime * 1e9); mt > maxMtime {
					maxMtime = mt
				}
			}

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


