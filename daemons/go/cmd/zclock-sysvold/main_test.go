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

	toDelete, conflicts, tripped := MergeTombstones(localManifest, remoteTombstones, state, "", nil)

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

	toDelete, conflicts, tripped := MergeTombstones(localManifest, remoteTombstones, state, "", nil)

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

func TestMergeTombstones_6of25_DoesNotTrip(t *testing.T) {
	now := float64(time.Now().Unix())

	// Create 25 local files
	localManifest := make(map[string]FileInfo)
	for i := 0; i < 25; i++ {
		p := fmt.Sprintf("cybertechie.net/Policies/{GUID-%02d}/gpt.ini", i)
		localManifest[p] = FileInfo{
			Hash:  fmt.Sprintf("%064d", i),
			Mtime: now - 500,
			Size:  10,
		}
	}

	// 6 deletions out of 25 (6 <= 10, does not trip)
	var remoteTombstones []Tombstone
	for i := 0; i < 6; i++ {
		p := fmt.Sprintf("cybertechie.net/Policies/{GUID-%02d}/gpt.ini", i)
		remoteTombstones = append(remoteTombstones, Tombstone{
			RelPath:      p,
			DeletedAt:    now - 10,
			HashAtDelete: fmt.Sprintf("%064d", i),
		})
	}

	state := &SysvolState{
		Files:      make(map[string]FileInfo),
		Tombstones: make(map[string]Tombstone),
	}

	toDelete, _, tripped := MergeTombstones(localManifest, remoteTombstones, state, "192.168.180.44", nil)

	if tripped {
		t.Fatalf("Deleting 6 of 25 files should NOT trip the safety brake (threshold is >10 and >20%%)")
	}
	if len(toDelete) != 6 {
		t.Errorf("Expected 6 files approved for deletion, got %d", len(toDelete))
	}
	if state.MassDeleteTripped {
		t.Errorf("Expected state.MassDeleteTripped to be false")
	}
}

func TestMergeTombstones_15of25_Trips(t *testing.T) {
	now := float64(time.Now().Unix())

	// Create 25 local files
	localManifest := make(map[string]FileInfo)
	for i := 0; i < 25; i++ {
		p := fmt.Sprintf("cybertechie.net/Policies/{GUID-%02d}/gpt.ini", i)
		localManifest[p] = FileInfo{
			Hash:  fmt.Sprintf("%064d", i),
			Mtime: now - 500,
			Size:  10,
		}
	}

	// 15 deletions out of 25 (15 > 10 and 15 > 20% of 25 = 5.0 -> TRIPS)
	var remoteTombstones []Tombstone
	for i := 0; i < 15; i++ {
		p := fmt.Sprintf("cybertechie.net/Policies/{GUID-%02d}/gpt.ini", i)
		remoteTombstones = append(remoteTombstones, Tombstone{
			RelPath:      p,
			DeletedAt:    now - 10,
			HashAtDelete: fmt.Sprintf("%064d", i),
		})
	}

	state := &SysvolState{
		Files:      make(map[string]FileInfo),
		Tombstones: make(map[string]Tombstone),
	}

	toDelete, _, tripped := MergeTombstones(localManifest, remoteTombstones, state, "192.168.180.44", nil)

	if !tripped {
		t.Fatalf("Deleting 15 of 25 files MUST trip the safety brake")
	}
	if len(toDelete) != 0 {
		t.Errorf("Expected 0 files deleted when tripped, got %d", len(toDelete))
	}
	if !state.MassDeleteTripped {
		t.Errorf("Expected state.MassDeleteTripped to be true")
	}
	if state.PendingMassDelete == nil {
		t.Fatalf("Expected PendingMassDelete to be recorded")
	}
	if len(state.PendingMassDelete.Paths) != 15 {
		t.Errorf("Expected 15 pending paths, got %d", len(state.PendingMassDelete.Paths))
	}
	if state.PendingMassDelete.PartnerIP != "192.168.180.44" {
		t.Errorf("Expected partner IP 192.168.180.44, got %s", state.PendingMassDelete.PartnerIP)
	}
}

func TestMergeTombstones_ApprovalExecutes(t *testing.T) {
	now := float64(time.Now().Unix())

	localManifest := make(map[string]FileInfo)
	for i := 0; i < 25; i++ {
		p := fmt.Sprintf("cybertechie.net/Policies/{GUID-%02d}/gpt.ini", i)
		localManifest[p] = FileInfo{
			Hash:  fmt.Sprintf("%064d", i),
			Mtime: now - 500,
			Size:  10,
		}
	}

	var remoteTombstones []Tombstone
	var pendingPaths []string
	for i := 0; i < 15; i++ {
		p := fmt.Sprintf("cybertechie.net/Policies/{GUID-%02d}/gpt.ini", i)
		remoteTombstones = append(remoteTombstones, Tombstone{
			RelPath:      p,
			DeletedAt:    now - 10,
			HashAtDelete: fmt.Sprintf("%064d", i),
		})
		pendingPaths = append(pendingPaths, p)
	}

	state := &SysvolState{
		Files:             make(map[string]FileInfo),
		Tombstones:        make(map[string]Tombstone),
		MassDeleteTripped: true,
		PendingMassDelete: &MassDeletePending{
			PartnerIP:  "192.168.180.44",
			Paths:      pendingPaths,
			DetectedAt: now - 30,
		},
		ApprovedMassDelete: &MassDeleteApproved{
			PartnerIP:  "192.168.180.44",
			Paths:      pendingPaths,
			DetectedAt: now - 30,
		},
	}

	toDelete, _, tripped := MergeTombstones(localManifest, remoteTombstones, state, "192.168.180.44", nil)

	if tripped {
		t.Fatalf("Approved deletion should not trip")
	}
	if len(toDelete) != 15 {
		t.Fatalf("Expected exactly 15 files deleted on approval, got %d", len(toDelete))
	}
	if state.MassDeleteTripped {
		t.Errorf("Expected MassDeleteTripped to be reset to false")
	}
	if state.ApprovedMassDelete != nil {
		t.Errorf("Expected ApprovedMassDelete to be cleared")
	}
	if state.PendingMassDelete != nil {
		t.Errorf("Expected PendingMassDelete to be cleared")
	}
}

func TestMergeTombstones_UnapprovedNewFileTripsAgain(t *testing.T) {
	now := float64(time.Now().Unix())

	localManifest := make(map[string]FileInfo)
	for i := 0; i < 25; i++ {
		p := fmt.Sprintf("cybertechie.net/Policies/{GUID-%02d}/gpt.ini", i)
		localManifest[p] = FileInfo{
			Hash:  fmt.Sprintf("%064d", i),
			Mtime: now - 500,
			Size:  10,
		}
	}

	var remoteTombstones []Tombstone
	var approvedPaths []string
	for i := 0; i < 15; i++ {
		p := fmt.Sprintf("cybertechie.net/Policies/{GUID-%02d}/gpt.ini", i)
		remoteTombstones = append(remoteTombstones, Tombstone{
			RelPath:      p,
			DeletedAt:    now - 10,
			HashAtDelete: fmt.Sprintf("%064d", i),
		})
		approvedPaths = append(approvedPaths, p)
	}

	// A 16th file deletion appears that was NOT in the approved list!
	unapprovedPath := "cybertechie.net/Policies/{GUID-15}/gpt.ini"
	remoteTombstones = append(remoteTombstones, Tombstone{
		RelPath:      unapprovedPath,
		DeletedAt:    now - 5,
		HashAtDelete: fmt.Sprintf("%064d", 15),
	})

	state := &SysvolState{
		Files:             make(map[string]FileInfo),
		Tombstones:        make(map[string]Tombstone),
		MassDeleteTripped: true,
		ApprovedMassDelete: &MassDeleteApproved{
			PartnerIP:  "192.168.180.44",
			Paths:      approvedPaths,
			DetectedAt: now - 30,
		},
	}

	toDelete, _, tripped := MergeTombstones(localManifest, remoteTombstones, state, "192.168.180.44", nil)

	if !tripped {
		t.Fatalf("Expected brake to trip again when an unapproved file is present in candidate deletions")
	}
	if len(toDelete) != 0 {
		t.Fatalf("Expected NO files to be deleted when candidate list has unapproved files, got %d", len(toDelete))
	}
	if state.ApprovedMassDelete != nil {
		t.Errorf("Expected ApprovedMassDelete to be cleared on unapproved path mismatch")
	}
	if state.PendingMassDelete == nil || len(state.PendingMassDelete.Paths) != 16 {
		t.Errorf("Expected PendingMassDelete with all 16 paths, got %v", state.PendingMassDelete)
	}
}

func TestMergeTombstones_ApprovalZeroCandidatesNotConsumed(t *testing.T) {
	now := float64(time.Now().Unix())

	localManifest := map[string]FileInfo{
		"cybertechie.net/scripts/login.bat": {
			Hash:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Mtime: now - 500,
			Size:  10,
		},
	}

	state := &SysvolState{
		Files:      make(map[string]FileInfo),
		Tombstones: make(map[string]Tombstone),
		ApprovedMassDelete: &MassDeleteApproved{
			PartnerIP:  "192.168.180.44",
			Paths:      []string{"cybertechie.net/scripts/test1.bat", "cybertechie.net/scripts/test2.bat"},
			DetectedAt: now - 30,
		},
	}

	// 0 remote tombstones -> 0 candidates
	var remoteTombstones []Tombstone

	toDelete, conflicts, tripped := MergeTombstones(localManifest, remoteTombstones, state, "192.168.180.44", nil)

	if tripped {
		t.Fatalf("Did not expect trip with 0 candidates")
	}
	if len(toDelete) != 0 || conflicts != 0 {
		t.Fatalf("Expected 0 deletions, got %d", len(toDelete))
	}
	if state.ApprovedMassDelete == nil {
		t.Fatalf("Approval with 0 candidates MUST NOT be consumed!")
	}
	if len(state.ApprovedMassDelete.Paths) != 2 {
		t.Errorf("Expected 2 approved paths retained, got %d", len(state.ApprovedMassDelete.Paths))
	}
}

func TestMergeTombstones_Reject_NextCycleSkipsAndRestores(t *testing.T) {
	now := float64(time.Now().Unix())

	// Create 25 local files
	localManifest := make(map[string]FileInfo)
	for i := 0; i < 25; i++ {
		p := fmt.Sprintf("cybertechie.net/Policies/{GUID-%02d}/gpt.ini", i)
		localManifest[p] = FileInfo{
			Hash:  fmt.Sprintf("%064d", i),
			Mtime: now - 500,
			Size:  10,
		}
	}

	// Remote partner sends tombstones for 15 files
	var remoteTombstones []Tombstone
	for i := 0; i < 15; i++ {
		p := fmt.Sprintf("cybertechie.net/Policies/{GUID-%02d}/gpt.ini", i)
		remoteTombstones = append(remoteTombstones, Tombstone{
			RelPath:      p,
			DeletedAt:    now - 10,
			HashAtDelete: fmt.Sprintf("%064d", i),
		})
	}

	state := &SysvolState{
		Files:              make(map[string]FileInfo),
		Tombstones:         make(map[string]Tombstone),
		RejectedTombstones: make(map[string]RejectedTombstone),
	}

	// 1. Initial cycle: trips mass-delete brake
	toDelete, _, tripped := MergeTombstones(localManifest, remoteTombstones, state, "192.168.180.44", nil)
	if !tripped {
		t.Fatalf("Expected brake to trip on 15 of 25 files")
	}
	if len(toDelete) != 0 {
		t.Fatalf("Expected 0 files deleted when brake trips")
	}
	if state.PendingMassDelete == nil || len(state.PendingMassDelete.Tombstones) != 15 {
		t.Fatalf("Expected PendingMassDelete with 15 tombstones, got %v", state.PendingMassDelete)
	}

	// 2. Operator rejects: save rejected_tombstones using partner's tombstone deleted_at
	for p, delAt := range state.PendingMassDelete.Tombstones {
		state.RejectedTombstones[p] = RejectedTombstone{
			PartnerIP: "192.168.180.44",
			DeletedAt: delAt,
		}
		delete(state.Tombstones, p)
	}
	state.PendingMassDelete = nil
	state.ApprovedMassDelete = nil
	state.MassDeleteTripped = false

	// 3. Next cycle: partner STILL advertises unchanged tombstones
	toDelete2, _, tripped2 := MergeTombstones(localManifest, remoteTombstones, state, "192.168.180.44", nil)
	if tripped2 {
		t.Fatalf("Next cycle MUST NOT trip after rejection!")
	}
	if len(toDelete2) != 0 {
		t.Fatalf("Next cycle MUST NOT delete any files after rejection, got %v", toDelete2)
	}
	if len(state.Tombstones) != 0 {
		t.Fatalf("Rejected tombstones must NOT be merged into local state.Tombstones, got %v", state.Tombstones)
	}

	// 4. Verify push step selects those 15 files with restore=true even if Hash == HashAtDelete
	restoreCount := 0
	for relPath, lInfo := range localManifest {
		isRestore := false
		if state.RejectedTombstones != nil {
			if rej, hasRej := state.RejectedTombstones[relPath]; hasRej {
				if rej.PartnerIP == "" || rej.PartnerIP == "192.168.180.44" {
					isRestore = true
				}
			}
		}
		if isRestore {
			restoreCount++
			// Even though remote tombstone exists with matching hash, restore overrides skip
			if lInfo.Hash == "" {
				t.Errorf("Invalid hash for %s", relPath)
			}
		}
	}
	if restoreCount != 15 {
		t.Fatalf("Push step expected 15 files selected with restore=true, got %d", restoreCount)
	}
}

func TestMergeTombstones_RejectKeepsFiles(t *testing.T) {
	now := float64(time.Now().Unix())

	localManifest := make(map[string]FileInfo)
	for i := 0; i < 25; i++ {
		p := fmt.Sprintf("cybertechie.net/Policies/{GUID-%02d}/gpt.ini", i)
		localManifest[p] = FileInfo{
			Hash:  fmt.Sprintf("%064d", i),
			Mtime: now - 500,
			Size:  10,
		}
	}

	state := &SysvolState{
		Files:             make(map[string]FileInfo),
		Tombstones:        make(map[string]Tombstone),
		MassDeleteTripped: true,
		PendingMassDelete: &MassDeletePending{
			PartnerIP:  "192.168.180.44",
			Paths:      []string{"cybertechie.net/Policies/{GUID-00}/gpt.ini"},
			DetectedAt: now - 30,
		},
	}

	// Operator rejects: pending is cleared, approved is cleared, mass_delete_tripped is cleared, tombstones cleared
	state.PendingMassDelete = nil
	state.ApprovedMassDelete = nil
	state.MassDeleteTripped = false
	delete(state.Tombstones, "cybertechie.net/Policies/{GUID-00}/gpt.ini")

	if state.MassDeleteTripped {
		t.Errorf("Expected MassDeleteTripped to be false after rejection")
	}
	if state.PendingMassDelete != nil {
		t.Errorf("Expected PendingMassDelete to be nil after rejection")
	}
	if len(localManifest) != 25 {
		t.Errorf("Expected all 25 files kept, got %d", len(localManifest))
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
