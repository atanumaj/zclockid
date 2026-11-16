package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVerifyHash(t *testing.T) {
	content := []byte("test GPO policy content for integrity validation")
	h := sha256.Sum256(content)
	validHash := hex.EncodeToString(h[:])

	if !VerifyHash(content, validHash) {
		t.Errorf("Expected valid hash to match, but failed")
	}

	corruptedHash := "0000000000000000000000000000000000000000000000000000000000000000"
	if VerifyHash(content, corruptedHash) {
		t.Errorf("Expected corrupted hash to be rejected, but matched")
	}
}

func TestMergeTombstones_BasicDeletion(t *testing.T) {
	now := float64(time.Now().Unix())
	hashA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	localManifest := map[string]FileInfo{
		"cybertechie.net/Policies/{GUID-1}/gpt.ini": {
			Hash:  hashA,
			Mtime: now - 100,
			Size:  10,
		},
		"cybertechie.net/scripts/login.bat": {
			Hash:  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			Mtime: now - 100,
			Size:  20,
		},
	}

	remoteTombstones := []Tombstone{
		{
			RelPath:      "cybertechie.net/Policies/{GUID-1}/gpt.ini",
			DeletedAt:    now - 10,
			HashAtDelete: hashA,
		},
	}

	state := &SysvolState{
		Files:      make(map[string]FileInfo),
		Tombstones: make(map[string]Tombstone),
	}

	toDelete, conflicts, tripped := MergeTombstones(localManifest, remoteTombstones, state)

	if tripped {
		t.Fatalf("Did not expect mass-delete brake to trip for 1 file deletion")
	}
	if conflicts != 0 {
		t.Errorf("Expected 0 conflicts, got %d", conflicts)
	}
	if len(toDelete) != 1 || toDelete[0] != "cybertechie.net/Policies/{GUID-1}/gpt.ini" {
		t.Errorf("Expected deletion of {GUID-1}/gpt.ini, got %v", toDelete)
	}
}

func TestMergeTombstones_ModifiedBeatsDeleted(t *testing.T) {
	now := float64(time.Now().Unix())
	oldHash := "1111111111111111111111111111111111111111111111111111111111111111"
	newHash := "2222222222222222222222222222222222222222222222222222222222222222"

	// Local file was modified at now - 10 (AFTER deletion at now - 50)
	localManifest := map[string]FileInfo{
		"cybertechie.net/scripts/important.vbs": {
			Hash:  newHash,
			Mtime: now - 10,
			Size:  50,
		},
	}

	remoteTombstones := []Tombstone{
		{
			RelPath:      "cybertechie.net/scripts/important.vbs",
			DeletedAt:    now - 50,
			HashAtDelete: oldHash,
		},
	}

	state := &SysvolState{
		Files:      make(map[string]FileInfo),
		Tombstones: make(map[string]Tombstone),
	}

	toDelete, conflicts, tripped := MergeTombstones(localManifest, remoteTombstones, state)

	if tripped {
		t.Fatalf("Did not expect mass-delete brake to trip")
	}
	if conflicts != 1 {
		t.Errorf("Expected 1 conflict (modified beats deleted), got %d", conflicts)
	}
	if len(toDelete) != 0 {
		t.Errorf("Expected 0 files deleted (modified beats deleted), got %v", toDelete)
	}
}

func TestMergeTombstones_MassDeleteBrake(t *testing.T) {
	now := float64(time.Now().Unix())

	// Create 10 local files
	localManifest := make(map[string]FileInfo)
	for i := 0; i < 10; i++ {
		p := fmt.Sprintf("cybertechie.net/Policies/{GUID-%d}/gpt.ini", i)
		localManifest[p] = FileInfo{
			Hash:  fmt.Sprintf("%064d", i),
			Mtime: now - 500,
			Size:  10,
		}
	}

	// Remote sends tombstones for 3 files (3/10 = 30% > 20% limit)
	remoteTombstones := []Tombstone{
		{RelPath: "cybertechie.net/Policies/{GUID-0}/gpt.ini", DeletedAt: now - 10, HashAtDelete: fmt.Sprintf("%064d", 0)},
		{RelPath: "cybertechie.net/Policies/{GUID-1}/gpt.ini", DeletedAt: now - 10, HashAtDelete: fmt.Sprintf("%064d", 1)},
		{RelPath: "cybertechie.net/Policies/{GUID-2}/gpt.ini", DeletedAt: now - 10, HashAtDelete: fmt.Sprintf("%064d", 2)},
	}

	state := &SysvolState{
		Files:      make(map[string]FileInfo),
		Tombstones: make(map[string]Tombstone),
	}

	toDelete, _, tripped := MergeTombstones(localManifest, remoteTombstones, state)

	if !tripped {
		t.Errorf("Expected mass-delete brake to trip for 30%% deletion (>20%% limit)")
	}
	if len(toDelete) != 0 {
		t.Errorf("Expected no files returned for deletion when brake trips, got %v", toDelete)
	}
	if !state.MassDeleteTripped {
		t.Errorf("Expected state.MassDeleteTripped to be true")
	}
}

func TestCleanupEmptyDirs(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sysvol_cleanup_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	daemon := &SysvolDaemon{sysvolPath: tmpDir}

	// Create structure: <tmpDir>/cybertechie.net/Policies/{GUID-ABC}/Machine
	machineDir := filepath.Join(tmpDir, "cybertechie.net", "Policies", "{GUID-ABC}", "Machine")
	if err := os.MkdirAll(machineDir, 0755); err != nil {
		t.Fatal(err)
	}

	dummyFile := filepath.Join(machineDir, "registry.pol")
	if err := os.WriteFile(dummyFile, []byte("policy data"), 0644); err != nil {
		t.Fatal(err)
	}

	// Delete file
	_ = os.Remove(dummyFile)

	// Invoke directory cleanup
	daemon.CleanupEmptyDirs(dummyFile)

	// Machine and {GUID-ABC} should be removed since they are empty
	if _, err := os.Stat(machineDir); !os.IsNotExist(err) {
		t.Errorf("Expected empty Machine directory to be removed, but still exists")
	}
	guidDir := filepath.Join(tmpDir, "cybertechie.net", "Policies", "{GUID-ABC}")
	if _, err := os.Stat(guidDir); !os.IsNotExist(err) {
		t.Errorf("Expected empty GUID directory to be removed, but still exists")
	}

	// Policies and cybertechie.net and sysvol root MUST NOT be removed
	policiesDir := filepath.Join(tmpDir, "cybertechie.net", "Policies")
	if _, err := os.Stat(policiesDir); os.IsNotExist(err) {
		t.Errorf("Protected Policies directory was incorrectly removed!")
	}
	domainDir := filepath.Join(tmpDir, "cybertechie.net")
	if _, err := os.Stat(domainDir); os.IsNotExist(err) {
		t.Errorf("Protected domain root directory was incorrectly removed!")
	}
}
