package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadConfigRestoresPersistedEnrollment(t *testing.T) {
	dataDir := t.TempDir()
	if err := savePersisted(agentConfig{
		BackendURL:   "https://staging.example.test",
		ResourceCode: "resource-1",
		AgentToken:   "amh_resource_persisted",
		PrivateKey:   "private-key",
		StoragePath:  "/srv/resource-data",
		DataDir:      dataDir,
	}); err != nil {
		t.Fatalf("savePersisted: %v", err)
	}

	t.Setenv("AMAHANE_AGENT_BACKEND_URL", "")
	t.Setenv("AMAHANE_AGENT_RESOURCE_CODE", "")
	t.Setenv("AMAHANE_AGENT_TOKEN", "")
	t.Setenv("AMAHANE_AGENT_PRIVATE_KEY", "")
	t.Setenv("AMAHANE_AGENT_DATA_DIR", dataDir)
	t.Setenv("AMAHANE_AGENT_INTERVAL", "1m")

	config, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if config.BackendURL != "https://staging.example.test" || config.ResourceCode != "resource-1" {
		t.Fatalf("persisted endpoint identity = %#v", config)
	}
	if config.AgentToken != "amh_resource_persisted" || config.PrivateKey != "private-key" || config.StoragePath != "/srv/resource-data" {
		t.Fatalf("persisted enrollment state = %#v", config)
	}
	if config.Interval != time.Minute {
		t.Fatalf("interval = %s, want 1m", config.Interval)
	}

	state, err := os.Stat(dataDir + "/agent.json")
	if err != nil {
		t.Fatalf("stat persisted state: %v", err)
	}
	if mode := state.Mode().Perm(); mode != 0o600 {
		t.Fatalf("persisted state mode = %o, want 600", mode)
	}
}

func TestParseCPUTimes(t *testing.T) {
	times, err := parseCPUTimes([]byte("cpu 100 20 30 400 50 6 7 8 9\ncpu0 1 2 3 4 5 6 7 8 9\n"))
	if err != nil {
		t.Fatalf("parseCPUTimes: %v", err)
	}
	if times.total != 630 || times.idle != 450 {
		t.Fatalf("parsed CPU times = %#v, want total=630 idle=450", times)
	}
}

func TestCPUPercentBetweenSnapshots(t *testing.T) {
	previous := cpuTimes{total: 1000, idle: 700}
	current := cpuTimes{total: 1200, idle: 750}
	if got := cpuPercentBetween(previous, current); got != 75 {
		t.Fatalf("cpuPercentBetween = %v, want 75", got)
	}
	if got := cpuPercentBetween(current, previous); got != 0 {
		t.Fatalf("backwards CPU sample = %v, want 0", got)
	}
}

func TestCPUSamplerDoesNotInventFirstInterval(t *testing.T) {
	if got := (&cpuSampler{}).percent(); got != 0 {
		t.Fatalf("first CPU sample = %v, want 0 without a previous interval", got)
	}
}

func TestValidPairingCode(t *testing.T) {
	for _, code := range []string{"ABCD-2345", "HJKM-NPQR"} {
		if !validPairingCode(code) {
			t.Errorf("rejected valid pairing code %q", code)
		}
	}
	for _, code := range []string{"FBLT-EE4", "ABCD-234\x00", "ABCD-23I5", "abcd-2345", "ABCD_2345"} {
		if validPairingCode(code) {
			t.Errorf("accepted invalid pairing code %q", code)
		}
	}
}

func TestBootstrapHelloPersistsAndUsesIssuedCredential(t *testing.T) {
	dataDir := t.TempDir()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	issuedToken := "amh_resource_key_bound"
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Helper()
		if r.Method != http.MethodPost || r.URL.Path != "/api/node-agent/hello" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusNotFound)
			return
		}
		var request struct {
			NodeID       string `json:"nodeId"`
			Token        string `json:"token"`
			AgentVersion string `json:"agentVersion"`
			Timestamp    string `json:"timestamp"`
			Signature    string `json:"signature"`
			PublicKey    string `json:"publicKey"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode hello request: %v", err)
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if request.AgentVersion != "1.1.0" {
			t.Errorf("agent version = %q, want 1.1.0", request.AgentVersion)
		}
		calls++
		w.Header().Set("Content-Type", "application/json")
		switch calls {
		case 1:
			if request.Token != "one_time_bootstrap" || request.Timestamp != "" || request.Signature != "" {
				t.Errorf("bootstrap request used unexpected credentials: %#v", request)
			}
			_, _ = io.WriteString(w, `{"sessionToken":"bootstrap-session","agentToken":"`+issuedToken+`","pairingCode":"ABCD-2345","storagePath":"/srv/amahane/backups"}`)
		case 2:
			if request.NodeID != "resource-1" || request.Token != issuedToken {
				t.Errorf("post-bootstrap request used wrong identity or credential: %#v", request)
			}
			if request.PublicKey != base64.RawURLEncoding.EncodeToString(publicKey) {
				t.Errorf("post-bootstrap request used wrong public key")
			}
			signature, decodeErr := base64.RawURLEncoding.DecodeString(request.Signature)
			message := request.Timestamp + ".resource-1." + agentVersion
			if decodeErr != nil || !ed25519.Verify(publicKey, []byte(message), signature) {
				t.Errorf("post-bootstrap request signature is invalid")
			}
			_, _ = io.WriteString(w, `{"sessionToken":"verified-session"}`)
		default:
			t.Errorf("unexpected hello request number %d", calls)
			http.Error(w, "too many requests", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	config := agentConfig{
		BackendURL:   server.URL,
		ResourceCode: "resource-1",
		AgentToken:   "one_time_bootstrap",
		DataDir:      dataDir,
	}
	client := client{config: config, http: server.Client()}
	bootstrapSession, err := client.hello(&config, publicKey, privateKey, true)
	if err != nil {
		t.Fatalf("bootstrap hello: %v", err)
	}
	if bootstrapSession != "bootstrap-session" || config.AgentToken != issuedToken || config.StoragePath != "/srv/amahane/backups" {
		t.Fatalf("bootstrap did not update caller config: session=%q config=%#v", bootstrapSession, config)
	}
	client.config = config

	session, err := client.hello(&config, publicKey, privateKey, false)
	if err != nil {
		t.Fatalf("key-bound hello after bootstrap: %v", err)
	}
	if session != "verified-session" || calls != 2 {
		t.Fatalf("post-bootstrap session/calls = %q/%d", session, calls)
	}

	persisted, err := loadPersisted(agentConfig{DataDir: dataDir})
	if err != nil {
		t.Fatalf("load persisted enrollment: %v", err)
	}
	if persisted.AgentToken != issuedToken || persisted.PrivateKey != base64.RawURLEncoding.EncodeToString(privateKey) || persisted.StoragePath != "/srv/amahane/backups" {
		t.Fatalf("persisted enrollment = %#v", persisted)
	}
}

func TestProvisionerSQLConstrainsPrivileges(t *testing.T) {
	password := "Abcdefghijklmno_23456789-ABCDEFG"
	postgres, err := provisionerSQL("postgres", "amh_provisioner", password)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"NOSUPERUSER", "NOREPLICATION", "NOBYPASSRLS"} {
		if !strings.Contains(postgres, forbidden) {
			t.Errorf("PostgreSQL provisioner must explicitly disable %s", forbidden)
		}
	}
	if !strings.Contains(postgres, "CREATEDB CREATEROLE") {
		t.Fatal("PostgreSQL provisioner is missing database management capabilities")
	}

	mariadb, err := provisionerSQL("mariadb", "amh_provisioner", password)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(mariadb, "ON *.*") || !strings.Contains(mariadb, "GRANT EXECUTE ON PROCEDURE amahane_control.amh_provision_database") {
		t.Fatal("MariaDB provisioner must receive only constrained stored-procedure grants")
	}
	if !strings.Contains(mariadb, "p_database NOT REGEXP '^amh_[a-f0-9]{8}$'") || !strings.Contains(mariadb, "p_username NOT REGEXP '^amh_[a-f0-9]{8}$'") {
		t.Fatal("MariaDB stored procedures must validate managed database identifiers")
	}
	procedureStart := strings.Index(mariadb, "DROP PROCEDURE IF EXISTS")
	procedureEnd := strings.Index(mariadb[procedureStart:], "DELIMITER ;")
	if procedureStart < 0 || procedureEnd < 0 {
		t.Fatal("MariaDB procedure definition block is missing")
	}
	procedureDefinitions := mariadb[procedureStart : procedureStart+procedureEnd]
	if strings.Contains(procedureDefinitions, password) {
		t.Fatal("MariaDB stored procedure definitions must not persist the provisioner password")
	}
}

func TestProvisionerCredentialValidation(t *testing.T) {
	for _, value := range []string{"amh_ok_1", "Aupper", "amh-space", "amh;drop"} {
		if validProvisionerUsername(value) != (value == "amh_ok_1") {
			t.Errorf("username %q validation mismatch", value)
		}
	}
	validPassword := "Abcdefghijklmno_23456789-ABCDEFG"
	for _, value := range []string{validPassword, "short", "contains space 123456", "contains'quote123456", "contains\\slash123456"} {
		if validProvisionerPassword(value) != (value == validPassword) {
			t.Errorf("password validation mismatch for input length %d", len(value))
		}
	}
}

func TestLoadConfigEnvironmentCredentialOverridesPersistedCredential(t *testing.T) {
	dataDir := t.TempDir()
	if err := savePersisted(agentConfig{
		BackendURL:   "https://staging.example.test",
		ResourceCode: "resource-1",
		AgentToken:   "amh_resource_old",
		PrivateKey:   "old-key",
		DataDir:      dataDir,
	}); err != nil {
		t.Fatalf("savePersisted: %v", err)
	}
	t.Setenv("AMAHANE_AGENT_BACKEND_URL", "")
	t.Setenv("AMAHANE_AGENT_RESOURCE_CODE", "")
	t.Setenv("AMAHANE_AGENT_TOKEN", "amh_resource_override")
	t.Setenv("AMAHANE_AGENT_PRIVATE_KEY", "new-key")
	t.Setenv("AMAHANE_AGENT_DATA_DIR", dataDir)
	t.Setenv("AMAHANE_AGENT_INTERVAL", "")

	config, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if config.AgentToken != "amh_resource_override" || config.PrivateKey != "new-key" {
		t.Fatalf("environment credentials did not override persisted values: %#v", config)
	}
}

func TestLoadConfigRequiresEndpointWhenNotEnrolled(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("AMAHANE_AGENT_BACKEND_URL", "")
	t.Setenv("AMAHANE_AGENT_RESOURCE_CODE", "resource-1")
	t.Setenv("AMAHANE_AGENT_TOKEN", "")
	t.Setenv("AMAHANE_AGENT_PRIVATE_KEY", "")
	t.Setenv("AMAHANE_AGENT_DATA_DIR", dataDir)
	t.Setenv("AMAHANE_AGENT_INTERVAL", "")

	if _, err := loadConfig(); err == nil {
		t.Fatal("loadConfig accepted an unenrolled agent without backend URL")
	}
}

func TestProbeBackupStorageVerifiesAndCleansTarget(t *testing.T) {
	root := t.TempDir()
	if err := probeBackupStorage(agentConfig{StoragePath: root}); err != nil {
		t.Fatalf("probeBackupStorage: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("backup probe left %d entries in the target directory", len(entries))
	}

	file, err := os.CreateTemp(t.TempDir(), "not-a-directory")
	if err != nil {
		t.Fatal(err)
	}
	if err := probeBackupStorage(agentConfig{StoragePath: file.Name()}); err == nil {
		t.Fatal("backup probe accepted a regular file")
	}
	if _, err := executeTask(agentConfig{StoragePath: root}, resourceTask{ID: "task-1", Type: "probe_backup_storage"}); err != nil {
		t.Fatalf("executeTask backup probe: %v", err)
	}
}

func TestDeleteBackupArchiveIsSafeAndIdempotent(t *testing.T) {
	root := t.TempDir()
	serviceID := "33333333-3333-4333-8333-333333333333"
	recordID := "22222222-2222-4222-8222-222222222222"
	taskID := "11111111-1111-4111-8111-111111111111"
	directory := filepath.Join(root, serviceID)
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, recordID+".tar.zst")
	if err := os.WriteFile(target, []byte("archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	task := resourceTask{ID: taskID, Type: "delete_backup_archive",
		ObjectKey: serviceID + "/" + recordID + ".tar.zst"}
	if result, err := executeTask(agentConfig{StoragePath: root}, task); err != nil || result != "backup_delete_ok" {
		t.Fatalf("delete backup archive = %q, %v", result, err)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted archive stat = %v, want not exist", err)
	}
	if result, err := executeTask(agentConfig{StoragePath: root}, task); err != nil || result != "backup_delete_ok" {
		t.Fatalf("repeated delete backup archive = %q, %v", result, err)
	}
}

func testPanelSnapshot(t *testing.T) []byte {
	t.Helper()
	var data bytes.Buffer
	gz := gzip.NewWriter(&data)
	archive := tar.NewWriter(gz)
	if err := archive.WriteHeader(&tar.Header{Name: "world.dat", Typeflag: tar.TypeReg, Mode: 0o600, Size: 5}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(archive, "world"); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return data.Bytes()
}

func TestDownloadAndArchiveBackupPublishesAtomically(t *testing.T) {
	snapshot := testPanelSnapshot(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Accept") != "application/octet-stream" {
			t.Errorf("backup request = %s Accept %q", r.Method, r.Header.Get("Accept"))
		}
		_, _ = w.Write(snapshot)
	}))
	defer server.Close()

	storagePath := t.TempDir()
	serviceID := "33333333-3333-4333-8333-333333333333"
	recordID := "22222222-2222-4222-8222-222222222222"
	taskID := "11111111-1111-4111-8111-111111111111"
	transfer := backupTransfer{URL: server.URL + "/snapshot", BackupRecordID: recordID,
		ObjectKey: serviceID + "/" + recordID + ".tar.zst", MaxInputBytes: int64(len(snapshot)) + 1,
		MaxSourceBytes: 1024, MaxArchiveBytes: 1 << 20}
	task := resourceTask{ID: taskID, BackupRecordID: recordID}
	if err := validateBackupTransfer(task, transfer); err != nil {
		t.Fatalf("validate backup transfer: %v", err)
	}
	result, err := downloadAndArchiveBackup(context.Background(), agentConfig{StoragePath: storagePath}, server.Client(), task, transfer, nil)
	if err != nil {
		t.Fatalf("download and archive backup: %v", err)
	}
	target := filepath.Join(storagePath, serviceID, recordID+".tar.zst")
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read published archive: %v", err)
	}
	digest := sha256.Sum256(data)
	if result.SizeBytes != int64(len(data)) || result.ChecksumSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("published archive result = %+v", result)
	}
	if result.SourceBytes != 5 {
		t.Fatalf("source bytes = %d, want 5", result.SourceBytes)
	}
	info, err := os.Stat(target)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("archive mode = %v, error %v; want 600", info, err)
	}
	entries, err := os.ReadDir(filepath.Dir(target))
	if err != nil || len(entries) != 1 || entries[0].Name() != recordID+".tar.zst" {
		t.Fatalf("service directory after publish = %#v, error %v", entries, err)
	}
}

func TestDownloadAndArchiveBackupRejectsRedirectAndLeaseLoss(t *testing.T) {
	redirected := false
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected = true
	}))
	defer target.Close()
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/snapshot", http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()
	snapshot := testPanelSnapshot(t)
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(snapshot)
	}))
	defer source.Close()

	storagePath := t.TempDir()
	serviceID := "33333333-3333-4333-8333-333333333333"
	recordID := "22222222-2222-4222-8222-222222222222"
	taskID := "11111111-1111-4111-8111-111111111111"
	transfer := backupTransfer{URL: redirector.URL + "/snapshot", BackupRecordID: recordID,
		ObjectKey: serviceID + "/" + recordID + ".tar.zst", MaxInputBytes: 1 << 20,
		MaxSourceBytes: 1 << 20, MaxArchiveBytes: 1 << 20}
	task := resourceTask{ID: taskID, BackupRecordID: recordID}
	_, err := downloadAndArchiveBackup(context.Background(), agentConfig{StoragePath: storagePath}, redirector.Client(), task, transfer, nil)
	if err == nil || redirected {
		t.Fatalf("redirect result = %v, redirected target reached = %v", err, redirected)
	}

	transfer.URL = source.URL + "/snapshot"
	_, err = downloadAndArchiveBackup(context.Background(), agentConfig{StoragePath: storagePath}, source.Client(), task, transfer,
		func() error { return errors.New("lease lost") })
	if err == nil {
		t.Fatal("backup was published after lease renewal failed")
	}
	serviceDir := filepath.Join(storagePath, serviceID)
	entries, readErr := os.ReadDir(serviceDir)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("files remained after rejected transfer: %#v, error %v", entries, readErr)
	}
}

func TestOpenBackupTargetRejectsSymlinksAndCleansOldPartials(t *testing.T) {
	storagePath := t.TempDir()
	outside := t.TempDir()
	serviceID := "33333333-3333-4333-8333-333333333333"
	recordID := "22222222-2222-4222-8222-222222222222"
	taskID := "11111111-1111-4111-8111-111111111111"
	objectKey := serviceID + "/" + recordID + ".tar.zst"
	if err := os.Symlink(outside, filepath.Join(storagePath, serviceID)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := openBackupTarget(storagePath, objectKey, taskID); err == nil {
		t.Fatal("backup target accepted a service-directory symlink")
	}
	if err := os.Remove(filepath.Join(storagePath, serviceID)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(storagePath, serviceID), 0o700); err != nil {
		t.Fatal(err)
	}
	serviceDir := filepath.Join(storagePath, serviceID)
	oldPartial := "." + recordID + ".aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa.partial"
	newPartial := "." + recordID + ".bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb.partial"
	unrelatedPartial := ".aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa.cccccccc-cccc-4ccc-8ccc-cccccccccccc.partial"
	for _, name := range []string{oldPartial, newPartial, unrelatedPartial} {
		if err := os.WriteFile(filepath.Join(serviceDir, name), []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	oldTime := time.Now().Add(-2 * backupPartialStaleAfter)
	if err := os.Chtimes(filepath.Join(serviceDir, oldPartial), oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	serviceRoot, _, _, err := openBackupTarget(storagePath, objectKey, taskID)
	if err != nil {
		t.Fatalf("open secure backup target: %v", err)
	}
	defer serviceRoot.Close()
	if _, err := serviceRoot.Lstat(oldPartial); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale partial still exists: %v", err)
	}
	for _, name := range []string{newPartial, unrelatedPartial} {
		if _, err := serviceRoot.Lstat(name); err != nil {
			t.Errorf("cleanup removed unrelated or fresh file %q: %v", name, err)
		}
	}
}

func TestPublishBackupFileDoesNotLeaveUntrackedArchiveAfterSyncFailure(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.WriteFile("pending.partial", []byte("archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	syncFailure := func(*os.Root) error { return errors.New("sync failed") }
	err = publishBackupFile(root, "pending.partial", "archive.tar.zst", syncFailure)
	if !errors.Is(err, errBackupArchivePublishUncertain) {
		t.Fatalf("publish error = %v, want uncertain publish", err)
	}
	if _, err := root.Lstat("archive.tar.zst"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("untracked archive remained after failed sync: %v", err)
	}
}

func TestExecuteTaskRejectsUnknownAndIncompleteTasks(t *testing.T) {
	if code, err := executeTask(agentConfig{}, resourceTask{}); code != "task_invalid" || err == nil {
		t.Fatalf("missing task = %q, %v; want task_invalid", code, err)
	}
	if code, err := executeTask(agentConfig{}, resourceTask{ID: "task-1", Type: "run_shell"}); code != "task_type_invalid" || err == nil {
		t.Fatalf("unknown task = %q, %v; want task_type_invalid", code, err)
	}
}
