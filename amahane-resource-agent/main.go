package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	backuparchive "github.com/amahane-love/amahane-resource-archive"
	"golang.org/x/term"
)

const agentVersion = "1.1.0"
const pairingCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

type agentConfig struct {
	BackendURL   string
	ResourceCode string
	AgentToken   string
	PrivateKey   string
	StoragePath  string
	DataDir      string
	Interval     time.Duration
}

type diskMetric struct {
	Path           string `json:"path"`
	FilesystemID   string `json:"filesystemId,omitempty"`
	UsedBytes      int64  `json:"usedBytes"`
	TotalBytes     int64  `json:"totalBytes"`
	AvailableBytes int64  `json:"availableBytes"`
}

type heartbeat struct {
	AgentVersion   string       `json:"agentVersion"`
	UptimeSec      int64        `json:"uptimeSec"`
	CPUPercent     float64      `json:"cpuPercent"`
	RAMUsedBytes   int64        `json:"ramUsedBytes"`
	RAMTotalBytes  int64        `json:"ramTotalBytes"`
	DiskUsedBytes  int64        `json:"diskUsedBytes"`
	DiskTotalBytes int64        `json:"diskTotalBytes"`
	Load1          float64      `json:"load1"`
	StorageMetrics []diskMetric `json:"storageMetrics,omitempty"`
}

type cpuTimes struct {
	total uint64
	idle  uint64
}

type cpuSampler struct {
	previous    cpuTimes
	hasPrevious bool
}

type persistedConfig struct {
	BackendURL   string `json:"backendUrl"`
	ResourceCode string `json:"resourceCode"`
	AgentToken   string `json:"agentToken"`
	PrivateKey   string `json:"privateKey"`
	StoragePath  string `json:"storagePath"`
}

type client struct {
	config agentConfig
	http   *http.Client
}

type resourceTask struct {
	ID             string `json:"id"`
	Type           string `json:"type"`
	BackupRecordID string `json:"backupRecordId,omitempty"`
	ObjectKey      string `json:"objectKey,omitempty"`
}

type backupTransfer struct {
	URL             string `json:"url"`
	BackupRecordID  string `json:"backupRecordId"`
	ObjectKey       string `json:"objectKey"`
	MaxInputBytes   int64  `json:"maxInputBytes"`
	MaxSourceBytes  int64  `json:"maxSourceBytes"`
	MaxArchiveBytes int64  `json:"maxArchiveBytes"`
}

var resourceBackupObjectKeyPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.tar\.zst$`)

var errBackupArchivePublishUncertain = errors.New("backup_archive_publish_uncertain")

const provisionerPasswordMinLength = 16

func validProvisionerUsername(value string) bool {
	if len(value) == 0 || len(value) > 48 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, char := range value[1:] {
		if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '_') {
			return false
		}
	}
	return true
}

func validProvisionerPassword(value string) bool {
	if len(value) < provisionerPasswordMinLength || len(value) > 256 || strings.ContainsAny(value, "\x00\r\n\t'\\") {
		return false
	}
	for _, char := range value {
		if unicode.IsSpace(char) || unicode.IsControl(char) {
			return false
		}
	}
	return true
}

func validPairingCode(value string) bool {
	if len(value) != 9 || value[4] != '-' {
		return false
	}
	for index := range value {
		if index != 4 && !strings.ContainsRune(pairingCodeAlphabet, rune(value[index])) {
			return false
		}
	}
	return true
}

func quoteSQLLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func quoteSQLIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

func quoteMariaIdentifier(value string) string {
	return "`" + strings.ReplaceAll(value, "`", "``") + "`"
}

func provisionerSQL(engine, username, password string) (string, error) {
	if !validProvisionerUsername(username) || !validProvisionerPassword(password) {
		return "", errors.New("provisioner credentials do not meet local policy")
	}
	switch engine {
	case "postgres":
		return "CREATE ROLE " + quoteSQLIdentifier(username) +
			" LOGIN NOSUPERUSER CREATEDB CREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD " + quoteSQLLiteral(password) + ";\n", nil
	case "mariadb":
		return mariadbProvisionerSetupSQL(username, password), nil
	default:
		return "", errors.New("unsupported provisioner database engine")
	}
}

func readProvisionerPassword() (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return "", errors.New("open /dev/tty for password input")
	}
	defer tty.Close()
	if _, err := fmt.Fprint(tty, "Provisioner password (hidden): "); err != nil {
		return "", err
	}
	first, err := term.ReadPassword(int(tty.Fd()))
	_, _ = fmt.Fprintln(tty)
	if err != nil {
		return "", errors.New("read provisioner password")
	}
	if _, err := fmt.Fprint(tty, "Repeat provisioner password (hidden): "); err != nil {
		return "", err
	}
	second, err := term.ReadPassword(int(tty.Fd()))
	_, _ = fmt.Fprintln(tty)
	if err != nil {
		return "", errors.New("read repeated provisioner password")
	}
	if !bytes.Equal(first, second) {
		return "", errors.New("provisioner passwords do not match")
	}
	password := string(first)
	if !validProvisionerPassword(password) {
		return "", fmt.Errorf("password must be %d-256 characters without whitespace, quotes or backslashes", provisionerPasswordMinLength)
	}
	return password, nil
}

func mariadbProvisionerSetupSQL(username, password string) string {
	user := quoteSQLLiteral(username) + "@'%'"
	setup := `CREATE DATABASE IF NOT EXISTS amahane_control;
DROP PROCEDURE IF EXISTS amahane_control.amh_provision_database;
DROP PROCEDURE IF EXISTS amahane_control.amh_drop_database;
DELIMITER //
CREATE DEFINER=CURRENT_USER PROCEDURE amahane_control.amh_provision_database(
 IN p_database VARCHAR(48), IN p_username VARCHAR(48), IN p_password VARCHAR(256)
) SQL SECURITY DEFINER
BEGIN
 DECLARE v_created_database BOOLEAN DEFAULT FALSE;
 DECLARE v_created_user BOOLEAN DEFAULT FALSE;
 DECLARE v_exists INT DEFAULT 0;
 DECLARE EXIT HANDLER FOR SQLEXCEPTION
 BEGIN
  IF v_created_user THEN
   SET @amh_sql = CONCAT('DROP USER IF EXISTS ''', p_username, '''@''%''');
   PREPARE amh_stmt FROM @amh_sql; EXECUTE amh_stmt; DEALLOCATE PREPARE amh_stmt;
  END IF;
  IF v_created_database THEN
	   SET @amh_sql = CONCAT('DROP DATABASE IF EXISTS ', p_database);
   PREPARE amh_stmt FROM @amh_sql; EXECUTE amh_stmt; DEALLOCATE PREPARE amh_stmt;
  END IF;
  RESIGNAL;
 END;
 IF p_database NOT REGEXP '^amh_[a-f0-9]{8}$'
    OR p_username NOT REGEXP '^amh_[a-f0-9]{8}$'
    OR p_password NOT REGEXP '^[A-Za-z0-9_-]{32}$' THEN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'invalid managed database input';
 END IF;
 SELECT COUNT(*) INTO v_exists FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = p_database;
 IF v_exists <> 0 THEN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'managed database already exists';
 END IF;
 SET v_created_database = TRUE;
 SET @amh_sql = CONCAT('CREATE DATABASE ', p_database, ' CHARACTER SET utf8mb4');
 PREPARE amh_stmt FROM @amh_sql; EXECUTE amh_stmt; DEALLOCATE PREPARE amh_stmt;
 SELECT COUNT(*) INTO v_exists FROM mysql.user WHERE User = p_username AND Host = '%';
 IF v_exists <> 0 THEN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'managed database user already exists';
 END IF;
 SET v_created_user = TRUE;
 SET @amh_sql = CONCAT('CREATE USER ''', p_username, '''@''%'' IDENTIFIED BY ', QUOTE(p_password));
 PREPARE amh_stmt FROM @amh_sql; EXECUTE amh_stmt; DEALLOCATE PREPARE amh_stmt;
 SET @amh_sql = CONCAT('GRANT ALL PRIVILEGES ON ', p_database, '.* TO ''', p_username, '''@''%''');
 PREPARE amh_stmt FROM @amh_sql; EXECUTE amh_stmt; DEALLOCATE PREPARE amh_stmt;
END//
CREATE DEFINER=CURRENT_USER PROCEDURE amahane_control.amh_drop_database(
 IN p_database VARCHAR(48), IN p_username VARCHAR(48)
) SQL SECURITY DEFINER
BEGIN
 IF p_database NOT REGEXP '^amh_[a-f0-9]{8}$'
    OR p_username NOT REGEXP '^amh_[a-f0-9]{8}$' THEN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'invalid managed database input';
 END IF;
	 SET @amh_sql = CONCAT('DROP DATABASE IF EXISTS ', p_database);
 PREPARE amh_stmt FROM @amh_sql; EXECUTE amh_stmt; DEALLOCATE PREPARE amh_stmt;
 SET @amh_sql = CONCAT('DROP USER IF EXISTS ''', p_username, '''@''%''');
 PREPARE amh_stmt FROM @amh_sql; EXECUTE amh_stmt; DEALLOCATE PREPARE amh_stmt;
END//
DELIMITER ;
`
	setup += "CREATE USER IF NOT EXISTS " + user + " IDENTIFIED BY " + quoteSQLLiteral(password) + ";\n"
	setup += "ALTER USER " + user + " IDENTIFIED BY " + quoteSQLLiteral(password) + ";\n"
	setup += "GRANT EXECUTE ON PROCEDURE amahane_control.amh_provision_database TO " + user + ";\n"
	setup += "GRANT EXECUTE ON PROCEDURE amahane_control.amh_drop_database TO " + user + ";\n"
	return setup
}

func runSQLScript(ctx context.Context, engine, script string) error {
	var command string
	var args []string
	if engine == "postgres" {
		command = "sudo"
		args = []string{"-u", "postgres", "--", "psql", "--dbname=postgres", "--no-psqlrc", "--quiet", "--set=ON_ERROR_STOP=1"}
		if os.Geteuid() == 0 {
			command = "runuser"
			args = []string{"--user", "postgres", "--", "psql", "--dbname=postgres", "--no-psqlrc", "--quiet", "--set=ON_ERROR_STOP=1"}
		}
		if _, err := exec.LookPath(command); err != nil {
			return fmt.Errorf("required command unavailable: %s", command)
		}
	} else if engine == "mariadb" {
		command = "mariadb"
		if _, err := exec.LookPath(command); err != nil {
			command = "mysql"
		}
		if _, err := exec.LookPath(command); err != nil {
			return errors.New("required MariaDB client unavailable")
		}
		args = []string{"--protocol=socket", "--batch", "--skip-column-names", "--binary-mode", "--silent"}
	} else {
		return errors.New("unsupported provisioner database engine")
	}
	process := exec.CommandContext(ctx, command, args...)
	process.Stdin = strings.NewReader(script)
	process.Stdout = io.Discard
	process.Stderr = io.Discard
	if err := process.Run(); err != nil {
		return fmt.Errorf("local %s provisioner setup failed", engine)
	}
	return nil
}

func runProvisionerSetup(args []string) error {
	engine := ""
	username := ""
	for index := 0; index < len(args); index++ {
		if index+1 >= len(args) {
			return errors.New("provisioner-setup requires --engine and --username")
		}
		switch args[index] {
		case "--engine":
			engine = strings.ToLower(strings.TrimSpace(args[index+1]))
		case "--username":
			username = strings.TrimSpace(args[index+1])
		default:
			return errors.New("unknown provisioner-setup option")
		}
		index++
	}
	if engine != "postgres" && engine != "mariadb" {
		return errors.New("--engine must be postgres or mariadb")
	}
	if !validProvisionerUsername(username) {
		return errors.New("--username is invalid")
	}
	password, err := readProvisionerPassword()
	if err != nil {
		return err
	}
	script, err := provisionerSQL(engine, username, password)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return runSQLScript(ctx, engine, script)
}

func loadConfig() (agentConfig, error) {
	envAgentToken := strings.TrimSpace(os.Getenv("AMAHANE_AGENT_TOKEN"))
	envPrivateKey := strings.TrimSpace(os.Getenv("AMAHANE_AGENT_PRIVATE_KEY"))
	config := agentConfig{
		BackendURL:   strings.TrimRight(strings.TrimSpace(os.Getenv("AMAHANE_AGENT_BACKEND_URL")), "/"),
		ResourceCode: strings.TrimSpace(os.Getenv("AMAHANE_AGENT_RESOURCE_CODE")),
		DataDir:      strings.TrimSpace(os.Getenv("AMAHANE_AGENT_DATA_DIR")),
		Interval:     1 * time.Minute,
	}
	if config.DataDir == "" {
		config.DataDir = "/var/lib/amahane-resource-agent"
	}
	if raw := strings.TrimSpace(os.Getenv("AMAHANE_AGENT_INTERVAL")); raw != "" {
		interval, err := time.ParseDuration(raw)
		if err != nil || interval < 30*time.Second || interval > time.Hour {
			return config, errors.New("AMAHANE_AGENT_INTERVAL must be between 30s and 1h")
		}
		config.Interval = interval
	}
	var err error
	config, err = loadPersisted(config)
	if err != nil {
		return config, err
	}
	if config.BackendURL == "" || !strings.HasPrefix(config.BackendURL, "https://") {
		return config, errors.New("AMAHANE_AGENT_BACKEND_URL must be an https:// address")
	}
	if config.ResourceCode == "" {
		return config, errors.New("AMAHANE_AGENT_RESOURCE_CODE is required")
	}
	if envAgentToken != "" {
		config.AgentToken = envAgentToken
	}
	if envPrivateKey != "" {
		config.PrivateKey = envPrivateKey
	}
	return config, nil
}

func loadPersisted(config agentConfig) (agentConfig, error) {
	path := filepath.Join(config.DataDir, "agent.json")
	body, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return config, nil
		}
		return config, err
	}
	var stored persistedConfig
	if err := json.Unmarshal(body, &stored); err != nil {
		return config, fmt.Errorf("decode agent state: %w", err)
	}
	if stored.BackendURL != "" {
		config.BackendURL = stored.BackendURL
	}
	if stored.ResourceCode != "" {
		config.ResourceCode = stored.ResourceCode
	}
	config.AgentToken = stored.AgentToken
	config.PrivateKey = stored.PrivateKey
	config.StoragePath = stored.StoragePath
	return config, nil
}

func savePersisted(config agentConfig) error {
	if err := os.MkdirAll(config.DataDir, 0o750); err != nil {
		return err
	}
	body, err := json.Marshal(persistedConfig{
		BackendURL: config.BackendURL, ResourceCode: config.ResourceCode,
		AgentToken: config.AgentToken, PrivateKey: config.PrivateKey,
		StoragePath: config.StoragePath,
	})
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(config.DataDir, ".agent-*.tmp")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(body); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, filepath.Join(config.DataDir, "agent.json"))
}

func keyPair(config agentConfig) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if config.PrivateKey != "" {
		raw, err := base64.RawURLEncoding.DecodeString(config.PrivateKey)
		if err != nil || len(raw) != ed25519.PrivateKeySize {
			return nil, nil, errors.New("stored agent key is invalid")
		}
		privateKey := ed25519.PrivateKey(raw)
		return privateKey.Public().(ed25519.PublicKey), privateKey, nil
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return publicKey, privateKey, nil
}

func (c client) post(path string, body []byte, token string) (int, []byte, error) {
	return c.postContext(context.Background(), path, body, token)
}

func (c client) postContext(ctx context.Context, path string, body []byte, token string) (int, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.config.BackendURL+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		stamp := strconv.FormatInt(time.Now().Unix(), 10)
		mac := hmac.New(sha256.New, []byte(token))
		mac.Write([]byte(stamp + "."))
		mac.Write(body)
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("X-Amahane-Timestamp", stamp)
		request.Header.Set("X-Amahane-Signature", hex.EncodeToString(mac.Sum(nil)))
	}
	response, err := c.http.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 32<<10))
	return response.StatusCode, responseBody, err
}

func (c client) hello(config *agentConfig, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey, bootstrap bool) (string, error) {
	agentVersionValue := agentVersion
	request := map[string]string{
		"nodeId": config.ResourceCode, "token": config.AgentToken,
		"agentVersion": agentVersionValue,
		"publicKey":    base64.RawURLEncoding.EncodeToString(publicKey),
	}
	if !bootstrap {
		stamp := time.Now().UTC().Format("20060102150405")
		request["timestamp"] = stamp
		message := stamp + "." + config.ResourceCode + "." + agentVersionValue
		request["signature"] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(message)))
	}
	body, err := json.Marshal(request)
	if err != nil {
		return "", err
	}
	status, responseBody, err := c.post("/api/node-agent/hello", body, "")
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("agent hello rejected: HTTP %d", status)
	}
	var response struct {
		SessionToken     string    `json:"sessionToken"`
		AgentToken       string    `json:"agentToken"`
		PairingCode      string    `json:"pairingCode"`
		PairingExpiresAt time.Time `json:"pairingExpiresAt"`
		StoragePath      string    `json:"storagePath"`
	}
	if err := json.Unmarshal(responseBody, &response); err != nil || response.SessionToken == "" {
		return "", errors.New("agent hello response invalid")
	}
	if bootstrap {
		if response.AgentToken == "" || !validPairingCode(response.PairingCode) {
			return "", errors.New("bootstrap response has invalid agent credential or pairing code")
		}
		config.AgentToken = response.AgentToken
		config.StoragePath = response.StoragePath
		config.PrivateKey = base64.RawURLEncoding.EncodeToString(privateKey)
		if err := savePersisted(*config); err != nil {
			return "", fmt.Errorf("save enrolled agent state: %w", err)
		}
		fmt.Printf("Amahane resource agent pairing code: %s (expires %s)\n", response.PairingCode, response.PairingExpiresAt.UTC().Format(time.RFC3339))
		fmt.Println("Enter this code in the admin console. It is not a database password.")
	}
	return response.SessionToken, nil
}

func (c client) nextTask(session string) (*resourceTask, error) {
	body, err := json.Marshal(struct{}{})
	if err != nil {
		return nil, err
	}
	status, responseBody, err := c.post("/api/node-agent/resource-tasks/next", body, session)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("resource task poll rejected: HTTP %d", status)
	}
	var response struct {
		Task *resourceTask `json:"task"`
	}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return nil, fmt.Errorf("decode resource task poll: %w", err)
	}
	return response.Task, nil
}

func (c client) completeTask(session, taskID string, success bool, resultCode string) error {
	return c.completeTaskResult(session, taskID, success, resultCode, nil)
}

func (c client) completeTaskResult(session, taskID string, success bool, resultCode string, archiveResult *backuparchive.Result) error {
	body, err := json.Marshal(struct {
		Success        bool   `json:"success"`
		ResultCode     string `json:"resultCode,omitempty"`
		SizeBytes      int64  `json:"sizeBytes,omitempty"`
		SourceBytes    int64  `json:"sourceBytes,omitempty"`
		ChecksumSHA256 string `json:"checksumSha256,omitempty"`
	}{Success: success, ResultCode: resultCode, SizeBytes: archiveResultSize(archiveResult),
		SourceBytes: archiveResultSource(archiveResult), ChecksumSHA256: archiveResultChecksum(archiveResult)})
	if err != nil {
		return err
	}
	status, _, err := c.post("/api/node-agent/resource-tasks/"+taskID+"/result", body, session)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("resource task result rejected: HTTP %d", status)
	}
	return nil
}

func (c client) renewTask(ctx context.Context, session, taskID string) error {
	body := []byte("{}")
	status, _, err := c.postContext(ctx, "/api/node-agent/resource-tasks/"+taskID+"/lease", body, session)
	if err != nil || status != http.StatusOK {
		return errors.New("resource task lease renewal failed")
	}
	return nil
}

func (c client) backupTransfer(ctx context.Context, session string, task resourceTask) (backupTransfer, error) {
	var response backupTransfer
	body := []byte("{}")
	endpoint := "/api/node-agent/resource-tasks/" + task.ID + "/backup-transfer"
	for {
		status, responseBody, err := c.postContext(ctx, endpoint, body, session)
		if err != nil {
			return backupTransfer{}, errors.New("backup transfer request failed")
		}
		if status == http.StatusTooEarly {
			select {
			case <-ctx.Done():
				return backupTransfer{}, ctx.Err()
			case <-time.After(10 * time.Second):
				continue
			}
		}
		if status != http.StatusOK || json.Unmarshal(responseBody, &response) != nil {
			return backupTransfer{}, errors.New("backup transfer was rejected")
		}
		if err := validateBackupTransfer(task, response); err != nil {
			return backupTransfer{}, err
		}
		return response, nil
	}
}

func validAgentUUID(value string) bool {
	return len(value) == 36 && resourceBackupObjectKeyPattern.MatchString(value+"/00000000-0000-0000-0000-000000000000.tar.zst")
}

func validateBackupTransfer(task resourceTask, transfer backupTransfer) error {
	parsed, err := url.Parse(strings.TrimSpace(transfer.URL))
	if err != nil || parsed == nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("backup transfer URL is invalid")
	}
	if !validAgentUUID(task.BackupRecordID) || transfer.BackupRecordID != task.BackupRecordID ||
		!resourceBackupObjectKeyPattern.MatchString(transfer.ObjectKey) ||
		!strings.HasSuffix(transfer.ObjectKey, "/"+task.BackupRecordID+".tar.zst") ||
		transfer.MaxInputBytes <= 0 || transfer.MaxSourceBytes <= 0 || transfer.MaxArchiveBytes <= 0 ||
		transfer.MaxInputBytes > 1<<44 || transfer.MaxSourceBytes > 1<<44 || transfer.MaxArchiveBytes > 1<<44 {
		return errors.New("backup transfer limits are invalid")
	}
	return nil
}

const backupPartialStaleAfter = 90 * time.Minute

func openBackupTarget(storagePath, objectKey, taskID string) (*os.Root, string, string, error) {
	if !filepath.IsAbs(storagePath) || filepath.Clean(storagePath) != storagePath ||
		!resourceBackupObjectKeyPattern.MatchString(objectKey) || !validAgentUUID(taskID) {
		return nil, "", "", errors.New("backup target path is invalid")
	}
	rootInfo, err := os.Lstat(storagePath)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || rootInfo.Mode().Perm()&0o022 != 0 {
		return nil, "", "", errors.New("backup storage root is unavailable")
	}
	root, err := os.OpenRoot(storagePath)
	if err != nil {
		return nil, "", "", errors.New("open backup storage root")
	}
	parts := strings.Split(objectKey, "/")
	if err := root.Mkdir(parts[0], 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		_ = root.Close()
		return nil, "", "", errors.New("create backup service directory")
	}
	dirInfo, err := root.Lstat(parts[0])
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 || dirInfo.Mode().Perm()&0o077 != 0 {
		_ = root.Close()
		return nil, "", "", errors.New("backup service directory is unsafe")
	}
	serviceRoot, err := root.OpenRoot(parts[0])
	_ = root.Close()
	if err != nil {
		return nil, "", "", errors.New("open backup service directory")
	}
	recordID := strings.TrimSuffix(parts[1], ".tar.zst")
	if err := cleanupStaleBackupPartials(serviceRoot, recordID, time.Now()); err != nil {
		_ = serviceRoot.Close()
		return nil, "", "", errors.New("clean stale backup temporary files")
	}
	target := parts[1]
	if info, err := serviceRoot.Lstat(target); err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		_ = serviceRoot.Close()
		return nil, "", "", errors.New("backup target is not a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = serviceRoot.Close()
		return nil, "", "", errors.New("inspect backup target")
	}
	temporary := "." + recordID + "." + taskID + ".partial"
	return serviceRoot, temporary, target, nil
}

func cleanupStaleBackupPartials(root *os.Root, recordID string, now time.Time) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, err := directory.ReadDir(-1)
	_ = directory.Close()
	if err != nil {
		return err
	}
	prefix := "." + recordID + "."
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".partial") {
			continue
		}
		taskID := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".partial")
		if !validAgentUUID(taskID) {
			continue
		}
		info, err := root.Lstat(name)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		if age := now.Sub(info.ModTime()); age >= backupPartialStaleAfter {
			if err := root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

func syncBackupDirectory(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func publishBackupFile(root *os.Root, temporaryName, targetName string, syncDirectory func(*os.Root) error) error {
	if info, err := root.Lstat(targetName); err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return errors.New("backup target changed during write")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("inspect backup target before publish")
	}
	if err := root.Rename(temporaryName, targetName); err != nil {
		return errors.New("publish backup archive")
	}
	if err := syncDirectory(root); err != nil {
		removeErr := root.Remove(targetName)
		if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return errBackupArchivePublishUncertain
		}
		if cleanupErr := syncDirectory(root); cleanupErr != nil {
			return errBackupArchivePublishUncertain
		}
		return errors.New("sync backup service directory")
	}
	return nil
}

func downloadAndArchiveBackup(ctx context.Context, config agentConfig, httpClient *http.Client,
	task resourceTask, transfer backupTransfer, beforePublish func() error) (*backuparchive.Result, error) {
	serviceRoot, temporaryName, targetName, err := openBackupTarget(config.StoragePath, transfer.ObjectKey, task.ID)
	if err != nil {
		return nil, err
	}
	defer serviceRoot.Close()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, transfer.URL, nil)
	if err != nil {
		return nil, errors.New("build backup download request")
	}
	request.Header.Set("Accept", "application/octet-stream")
	downloadClient := *httpClient
	downloadClient.Timeout = 0
	downloadClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := downloadClient.Do(request)
	if err != nil {
		return nil, errors.New("download backup snapshot")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength > transfer.MaxInputBytes {
		return nil, errors.New("backup snapshot download rejected")
	}
	output, err := serviceRoot.OpenFile(temporaryName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, errors.New("create temporary backup archive")
	}
	defer func() {
		_ = output.Close()
		_ = serviceRoot.Remove(temporaryName)
	}()
	result, err := backuparchive.Repackage(ctx, response.Body, output, backuparchive.Limits{
		MaxInputBytes: transfer.MaxInputBytes, MaxSourceBytes: transfer.MaxSourceBytes,
		MaxOutputBytes: transfer.MaxArchiveBytes,
	})
	if err != nil {
		return nil, err
	}
	if err := output.Sync(); err != nil {
		return nil, errors.New("sync temporary backup archive")
	}
	if err := output.Close(); err != nil {
		return nil, errors.New("close temporary backup archive")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if beforePublish != nil {
		if err := beforePublish(); err != nil {
			return nil, err
		}
	}
	if err := publishBackupFile(serviceRoot, temporaryName, targetName, syncBackupDirectory); err != nil {
		return nil, err
	}
	return &result, nil
}

func executeBackupArchiveTask(config agentConfig, c client, session string, task resourceTask) (string, *backuparchive.Result, error) {
	if task.ID == "" || !validAgentUUID(task.BackupRecordID) {
		return "backup_task_invalid", nil, errors.New("backup task reference is invalid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Minute)
	defer cancel()
	leaseLost := make(chan struct{}, 1)
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := c.renewTask(ctx, session, task.ID); err != nil {
					select {
					case leaseLost <- struct{}{}:
					default:
					}
					cancel()
					return
				}
			}
		}
	}()
	transfer, err := c.backupTransfer(ctx, session, task)
	if err != nil {
		select {
		case <-leaseLost:
			return "task_lease_lost", nil, err
		default:
		}
		return "backup_transfer_failed", nil, err
	}
	result, err := downloadAndArchiveBackup(ctx, config, c.http, task, transfer, func() error {
		if err := c.renewTask(ctx, session, task.ID); err != nil {
			return errors.New("resource task lease lost before publish")
		}
		return nil
	})
	if err != nil {
		select {
		case <-leaseLost:
			return "task_lease_lost", nil, err
		default:
		}
		if errors.Is(err, backuparchive.ErrTooLarge) {
			return "backup_archive_too_large", nil, err
		}
		if errors.Is(err, backuparchive.ErrInvalid) {
			return "backup_archive_invalid", nil, err
		}
		if errors.Is(err, errBackupArchivePublishUncertain) {
			return "backup_archive_cleanup_required", nil, err
		}
		return "backup_archive_failed", nil, err
	}
	return "backup_archive_ok", result, nil
}

func deleteBackupArchive(config agentConfig, objectKey, taskID string) (string, error) {
	if !resourceBackupObjectKeyPattern.MatchString(objectKey) || !validAgentUUID(taskID) {
		return "backup_delete_invalid", errors.New("backup delete reference is invalid")
	}
	serviceRoot, _, targetName, err := openBackupTarget(config.StoragePath, objectKey, taskID)
	if err != nil {
		return "backup_delete_failed", err
	}
	defer serviceRoot.Close()
	info, err := serviceRoot.Lstat(targetName)
	if errors.Is(err, os.ErrNotExist) {
		return "backup_delete_ok", nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "backup_delete_failed", errors.New("backup archive is not a regular file")
	}
	if err := serviceRoot.Remove(targetName); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "backup_delete_failed", err
	}
	if err := syncBackupDirectory(serviceRoot); err != nil {
		return "backup_delete_uncertain", err
	}
	return "backup_delete_ok", nil
}

func archiveResultSize(result *backuparchive.Result) int64 {
	if result == nil {
		return 0
	}
	return result.SizeBytes
}

func archiveResultSource(result *backuparchive.Result) int64 {
	if result == nil {
		return 0
	}
	return result.SourceBytes
}

func archiveResultChecksum(result *backuparchive.Result) string {
	if result == nil {
		return ""
	}
	return result.ChecksumSHA256
}

func runAllowlistedCommand(ctx context.Context, name string, args ...string) error {
	command, err := exec.LookPath(name)
	if err != nil {
		return fmt.Errorf("required command unavailable: %s", name)
	}
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("allowlisted command failed: %s", name)
	}
	return nil
}

func probeBackupStorage(config agentConfig) error {
	root := strings.TrimSpace(config.StoragePath)
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
		return errors.New("backup storage path is invalid")
	}
	info, err := os.Stat(root)
	if err != nil {
		return fmt.Errorf("backup storage path is unavailable: %w", err)
	}
	if !info.IsDir() {
		return errors.New("backup storage path is not a directory")
	}
	marker := make([]byte, 24)
	if _, err := rand.Read(marker); err != nil {
		return err
	}
	temporary := filepath.Join(root, ".amahane-probe-"+hex.EncodeToString(marker))
	data := make([]byte, 32<<10)
	if _, err := rand.Read(data); err != nil {
		return err
	}
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create backup probe file: %w", err)
	}
	cleanup := func() { _ = os.Remove(temporary) }
	defer cleanup()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write backup probe file: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync backup probe file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close backup probe file: %w", err)
	}
	readBack, err := os.ReadFile(temporary)
	if err != nil {
		return fmt.Errorf("read backup probe file: %w", err)
	}
	if !bytes.Equal(readBack, data) {
		return errors.New("backup probe file content mismatch")
	}
	if err := os.Remove(temporary); err != nil {
		return fmt.Errorf("delete backup probe file: %w", err)
	}
	return nil
}

func executeTask(config agentConfig, task resourceTask) (string, error) {
	if task.ID == "" {
		return "task_invalid", errors.New("resource task id is missing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	switch task.Type {
	case "system_update":
		if err := runAllowlistedCommand(ctx, "apt-get", "update"); err != nil {
			return "system_update_failed", err
		}
		if err := runAllowlistedCommand(ctx, "apt-get", "-y", "upgrade"); err != nil {
			return "system_update_failed", err
		}
		return "system_update_ok", nil
	case "install_postgres":
		if err := runAllowlistedCommand(ctx, "apt-get", "-y", "install", "postgresql"); err != nil {
			return "install_postgres_failed", err
		}
		if err := runAllowlistedCommand(ctx, "systemctl", "enable", "--now", "postgresql"); err != nil {
			return "install_postgres_failed", err
		}
		return "install_postgres_ok", nil
	case "install_mariadb":
		if err := runAllowlistedCommand(ctx, "apt-get", "-y", "install", "mariadb-server"); err != nil {
			return "install_mariadb_failed", err
		}
		if err := runAllowlistedCommand(ctx, "systemctl", "enable", "--now", "mariadb"); err != nil {
			return "install_mariadb_failed", err
		}
		return "install_mariadb_ok", nil
	case "probe_backup_storage":
		if err := probeBackupStorage(config); err != nil {
			return "backup_probe_failed", err
		}
		return "backup_probe_ok", nil
	case "delete_backup_archive":
		return deleteBackupArchive(config, task.ObjectKey, task.ID)
	default:
		return "task_type_invalid", errors.New("resource task type is not allowlisted")
	}
}

func readIntFile(path string) int64 {
	body, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	value, _ := strconv.ParseInt(strings.TrimSpace(string(body)), 10, 64)
	return value
}

func memoryMetric() (int64, int64) {
	body, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	var total, available int64
	for _, line := range strings.Split(string(body), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		value, _ := strconv.ParseInt(parts[1], 10, 64)
		switch parts[0] {
		case "MemTotal:":
			total = value * 1024
		case "MemAvailable:":
			available = value * 1024
		}
	}
	return total - available, total
}

func diskMetricFor(path string) (diskMetric, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return diskMetric{}, err
	}
	total := int64(stat.Blocks) * int64(stat.Bsize)
	available := int64(stat.Bavail) * int64(stat.Bsize)
	used := total - int64(stat.Bfree)*int64(stat.Bsize)
	return diskMetric{Path: path, FilesystemID: fmt.Sprintf("%v", stat.Fsid), UsedBytes: used, TotalBytes: total, AvailableBytes: available}, nil
}

func parseCPUTimes(body []byte) (cpuTimes, error) {
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[0] != "cpu" {
			continue
		}
		var times cpuTimes
		for _, field := range fields[1:] {
			value, err := strconv.ParseUint(field, 10, 64)
			if err != nil {
				return cpuTimes{}, fmt.Errorf("parse /proc/stat cpu time: %w", err)
			}
			times.total += value
		}
		idle, err := strconv.ParseUint(fields[4], 10, 64)
		if err != nil {
			return cpuTimes{}, fmt.Errorf("parse /proc/stat idle time: %w", err)
		}
		iowait, err := strconv.ParseUint(fields[5], 10, 64)
		if err != nil {
			return cpuTimes{}, fmt.Errorf("parse /proc/stat iowait: %w", err)
		}
		times.idle = idle + iowait
		return times, nil
	}
	return cpuTimes{}, errors.New("/proc/stat has no aggregate cpu line")
}

func readCPUTimes() (cpuTimes, error) {
	body, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuTimes{}, err
	}
	return parseCPUTimes(body)
}

func cpuPercentBetween(previous, current cpuTimes) float64 {
	if current.total <= previous.total || current.idle < previous.idle {
		return 0
	}
	totalDelta := current.total - previous.total
	idleDelta := current.idle - previous.idle
	if totalDelta == 0 || idleDelta > totalDelta {
		return 0
	}
	percent := float64(totalDelta-idleDelta) / float64(totalDelta) * 100
	if percent < 0 {
		return 0
	}
	if percent > 100 {
		return 100
	}
	return percent
}

func (s *cpuSampler) percent() float64 {
	current, err := readCPUTimes()
	if err != nil {
		return 0
	}
	if !s.hasPrevious {
		s.previous = current
		s.hasPrevious = true
		return 0
	}
	percent := cpuPercentBetween(s.previous, current)
	s.previous = current
	return percent
}

func collectHeartbeat(config agentConfig, cpu *cpuSampler) heartbeat {
	root, _ := diskMetricFor("/")
	metrics := []diskMetric{root}
	if config.StoragePath != "" && config.StoragePath != "/" {
		if target, err := diskMetricFor(config.StoragePath); err == nil {
			metrics = append(metrics, target)
		} else {
			log.Printf("storage path probe failed for %q: %v", config.StoragePath, err)
		}
	}
	usedMemory, totalMemory := memoryMetric()
	load1 := float64(0)
	if body, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(body))
		if len(fields) > 0 {
			load1, _ = strconv.ParseFloat(fields[0], 64)
		}
	}
	uptime, _ := os.ReadFile("/proc/uptime")
	uptimeParts := strings.Fields(string(uptime))
	uptimeSec := int64(0)
	if len(uptimeParts) > 0 {
		uptimeValue, _ := strconv.ParseFloat(uptimeParts[0], 64)
		uptimeSec = int64(uptimeValue)
	}
	return heartbeat{AgentVersion: agentVersion, UptimeSec: uptimeSec,
		CPUPercent:   cpu.percent(),
		RAMUsedBytes: usedMemory, RAMTotalBytes: totalMemory,
		DiskUsedBytes: root.UsedBytes, DiskTotalBytes: root.TotalBytes,
		Load1: load1, StorageMetrics: metrics}
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	if len(os.Args) > 1 && os.Args[1] == "provisioner-setup" {
		if err := runProvisionerSetup(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		fmt.Println("Provisioner account created. Enter the same username and password in the admin console.")
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "bootstrap" {
		if err := runBootstrap(); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) > 1 {
		log.Fatal("unknown command: use bootstrap or provisioner-setup")
	}
	config, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}
	publicKey, privateKey, err := keyPair(config)
	if err != nil {
		log.Fatal(err)
	}
	client := client{config: config, http: &http.Client{Timeout: 20 * time.Second}}
	cpu := &cpuSampler{}
	bootstrapToken := strings.TrimSpace(os.Getenv("AMAHANE_AGENT_BOOTSTRAP_TOKEN"))
	if bootstrapToken != "" {
		config.AgentToken = bootstrapToken
		session, helloErr := client.hello(&config, publicKey, privateKey, true)
		if helloErr != nil {
			log.Fatal(helloErr)
		}
		client.config = config
		log.Printf("resource agent enrolled; session ready")
		_ = session
	} else if config.AgentToken == "" || config.PrivateKey == "" {
		log.Fatal("agent is not enrolled: provide AMAHANE_AGENT_BOOTSTRAP_TOKEN once")
	} else {
		log.Printf("resource agent %s starting for %q", agentVersion, config.ResourceCode)
	}
	for {
		if config.AgentToken == "" {
			log.Fatal("agent token missing after enrollment")
		}
		session, helloErr := client.hello(&config, publicKey, privateKey, false)
		if helloErr != nil {
			log.Printf("handshake failed: %v; retry in %s", helloErr, config.Interval)
			time.Sleep(config.Interval)
			continue
		}
		heartbeatPayload, marshalErr := json.Marshal(collectHeartbeat(config, cpu))
		if marshalErr != nil {
			log.Printf("encode heartbeat: %v", marshalErr)
			time.Sleep(config.Interval)
			continue
		}
		status, _, postErr := client.post("/api/node-agent/heartbeat", heartbeatPayload, session)
		if postErr != nil {
			log.Printf("heartbeat failed: %v", postErr)
		} else if status != http.StatusOK {
			log.Printf("heartbeat rejected: HTTP %d", status)
		} else {
			log.Printf("heartbeat ok; target path %q", config.StoragePath)
			task, taskErr := client.nextTask(session)
			if taskErr != nil {
				log.Printf("resource task poll failed: %v", taskErr)
			} else if task != nil {
				var resultCode string
				var archiveResult *backuparchive.Result
				var executeErr error
				if task.Type == "write_backup_archive" {
					resultCode, archiveResult, executeErr = executeBackupArchiveTask(config, client, session, *task)
				} else {
					resultCode, executeErr = executeTask(config, *task)
				}
				if executeErr != nil {
					log.Printf("resource task %s failed: %s", task.ID, resultCode)
				} else {
					log.Printf("resource task %s completed: %s", task.ID, resultCode)
				}
				if resultErr := client.completeTaskResult(session, task.ID, executeErr == nil, resultCode, archiveResult); resultErr != nil {
					log.Printf("resource task %s result failed: %v", task.ID, resultErr)
				}
			}
		}
		time.Sleep(config.Interval)
	}
}

func runBootstrap() error {
	config, err := loadConfig()
	if err != nil {
		return err
	}
	bootstrapToken := strings.TrimSpace(os.Getenv("AMAHANE_AGENT_BOOTSTRAP_TOKEN"))
	if bootstrapToken == "" {
		return errors.New("bootstrap requires AMAHANE_AGENT_BOOTSTRAP_TOKEN")
	}
	publicKey, privateKey, err := keyPair(config)
	if err != nil {
		return err
	}
	config.AgentToken = bootstrapToken
	client := client{config: config, http: &http.Client{Timeout: 20 * time.Second}}
	if _, err := client.hello(&config, publicKey, privateKey, true); err != nil {
		return err
	}
	fmt.Println("Bootstrap complete. Enter the pairing code in the Amahane admin console, then start the systemd service.")
	return nil
}
