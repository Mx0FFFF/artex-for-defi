package server

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

const (
	maxDraftFiles = 1000
	maxDraftBytes = 1 << 30
)

// A task can be created while an upload request is in flight. Serialize only
// draft file writes and their final move; ordinary task/session uploads do not
// take this lock.
var draftUploadMu sync.Mutex

func validateDraftUploads(dataDir, draftID string) error {
	draftUploadMu.Lock()
	defer draftUploadMu.Unlock()
	return inspectDraftUploads(dataDir, draftID)
}

func inspectDraftUploads(dataDir, draftID string) error {
	if len(draftID) > 64 || !safeChatID.MatchString(draftID) {
		return fmt.Errorf("invalid draft ID")
	}
	draftDir := filepath.Join(dataDir, "drafts", draftID)
	uploadDir := filepath.Join(draftDir, "uploads")
	for _, dir := range []string{draftDir, uploadDir} {
		info, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("draft path is not a directory: %s", dir)
		}
	}
	entries, err := os.ReadDir(uploadDir)
	if err != nil {
		return err
	}
	if len(entries) == 0 || len(entries) > maxDraftFiles {
		return fmt.Errorf("draft must contain 1..%d files", maxDraftFiles)
	}
	var total int64
	for _, entry := range entries {
		info, err := os.Lstat(filepath.Join(uploadDir, entry.Name()))
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("draft contains a non-regular file: %s", entry.Name())
		}
		total += info.Size()
		if total > maxDraftBytes {
			return fmt.Errorf("draft files exceed %d bytes", maxDraftBytes)
		}
	}
	return nil
}

// promoteDraftUploads moves the exact staged file set into the newly created
// task before launch. Both paths are below the same data directory, so rename is
// atomic on the supported local filesystem layout.
func promoteDraftUploads(dataDir, draftID, taskID string) error {
	draftUploadMu.Lock()
	defer draftUploadMu.Unlock()
	if err := inspectDraftUploads(dataDir, draftID); err != nil {
		return err
	}
	id, err := strconv.ParseInt(taskID, 10, 64)
	if err != nil || id <= 0 {
		return fmt.Errorf("invalid task ID")
	}
	taskDir := filepath.Join(dataDir, "tasks", taskID)
	if err := os.MkdirAll(taskDir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(taskDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("task path is not a directory")
	}
	destination := filepath.Join(taskDir, "uploads")
	if _, err := os.Lstat(destination); err == nil {
		return fmt.Errorf("task upload directory already exists")
	} else if !os.IsNotExist(err) {
		return err
	}
	source := filepath.Join(dataDir, "drafts", draftID, "uploads")
	if err := os.Rename(source, destination); err != nil {
		return err
	}
	if err := os.Chmod(destination, 0o700); err != nil {
		_ = os.Rename(destination, source)
		return err
	}
	// Keep a small tombstone so an upload request that parsed its body before this
	// move cannot recreate the same draft after it acquires draftUploadMu.
	if err := os.WriteFile(filepath.Join(filepath.Dir(source), ".consumed"), []byte(taskID), 0o600); err != nil {
		_ = os.Rename(destination, source)
		return err
	}
	return nil
}
