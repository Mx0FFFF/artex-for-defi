package server

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateTaskPromotesDraftBeforeLaunch(t *testing.T) {
	dataDir := t.TempDir()
	m, err := NewManager(dataDir, "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	uploadDir := filepath.Join(dataDir, "drafts", "draft_api", "uploads")
	if err := os.MkdirAll(uploadDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(uploadDir, "Vault.sol"), []byte("contract Vault {}"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newAdmissionTestServer(m, nil)
	request := httptest.NewRequest(http.MethodPost, "/api/tasks", bytes.NewBufferString(
		`{"description":"Review uploads/Vault.sol","goal":"review source","review_mode":"defi","draft_id":"draft_api"}`))
	response := httptest.NewRecorder()
	s.createTask(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("create task = %d: %s", response.Code, response.Body.String())
	}
	var task struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &task); err != nil || task.ID == "" {
		t.Fatalf("create task response = %s: %v", response.Body.String(), err)
	}
	defer m.DeleteTask(task.ID, DeleteTaskOptions{}) //nolint:errcheck
	content, err := os.ReadFile(filepath.Join(dataDir, "tasks", task.ID, "uploads", "Vault.sol"))
	if err != nil || string(content) != "contract Vault {}" {
		t.Fatalf("task upload = %q, %v", content, err)
	}
	if got, ok := m.Task(task.ID); !ok || !strings.Contains(got.Description, "uploads/Vault.sol") {
		t.Fatalf("task description lost uploaded source: %+v", got)
	}
}

func TestCreateCustomTaskKeepsModeWithRepositoryScope(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := newAdmissionTestServer(m, nil)
	request := httptest.NewRequest(http.MethodPost, "/api/tasks", bytes.NewBufferString(
		`{"description":"Review repository","goal":"inspect source","review_mode":"custom","scope":[{"kind":"repository","value":"https://github.com/example/protocol"}]}`))
	response := httptest.NewRecorder()
	s.createTask(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("create task = %d: %s", response.Code, response.Body.String())
	}
	var task struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &task); err != nil || task.ID == "" {
		t.Fatalf("create task response = %s: %v", response.Body.String(), err)
	}
	defer m.DeleteTask(task.ID, DeleteTaskOptions{}) //nolint:errcheck
	if got, ok := m.Task(task.ID); !ok || got.ReviewMode != "custom" {
		t.Fatalf("repository scope changed custom mode: %+v", got)
	}
}

func TestPromoteDraftUploadsMovesFilesIntoTask(t *testing.T) {
	dataDir := t.TempDir()
	uploadDir := filepath.Join(dataDir, "drafts", "draft_1", "uploads")
	if err := os.MkdirAll(uploadDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(uploadDir, "Vault.sol"), []byte("contract Vault {}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateDraftUploads(dataDir, "draft_1"); err != nil {
		t.Fatal(err)
	}
	if err := promoteDraftUploads(dataDir, "draft_1", "42"); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(dataDir, "tasks", "42", "uploads", "Vault.sol"))
	if err != nil || string(content) != "contract Vault {}" {
		t.Fatalf("promoted content = %q, %v", content, err)
	}
	if _, err := os.Lstat(uploadDir); !os.IsNotExist(err) {
		t.Fatalf("staged upload still exists: %v", err)
	}
	if marker, err := os.ReadFile(filepath.Join(dataDir, "drafts", "draft_1", ".consumed")); err != nil || string(marker) != "42" {
		t.Fatalf("draft consumption marker = %q, %v", marker, err)
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	file, err := writer.CreateFormFile("file", "late.sol")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("late")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/chat/upload?scope=staging&id=draft_1", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	response := httptest.NewRecorder()
	(&Server{m: &Manager{dir: dataDir}}).chatUpload(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("consumed draft accepted a late upload: %d %s", response.Code, response.Body.String())
	}
}

func TestPromoteDraftUploadsRejectsSymlinksAndExistingDestination(t *testing.T) {
	dataDir := t.TempDir()
	uploadDir := filepath.Join(dataDir, "drafts", "draft_2", "uploads")
	if err := os.MkdirAll(uploadDir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(dataDir, "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(uploadDir, "link.sol")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := validateDraftUploads(dataDir, "draft_2"); err == nil || !strings.Contains(err.Error(), "non-regular") {
		t.Fatalf("symlink accepted: %v", err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(uploadDir, "Vault.sol"), []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dataDir, "tasks", "43", "uploads")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := promoteDraftUploads(dataDir, "draft_2", "43"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing task upload directory overwritten: %v", err)
	}
	if _, err := os.Stat(filepath.Join(uploadDir, "Vault.sol")); err != nil {
		t.Fatalf("draft file lost after failed promotion: %v", err)
	}
}
