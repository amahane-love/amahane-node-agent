package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
)

const AgentVersion = "1.0.0"

type agentConfig struct {
	BackendURL string
	NodeCode   string
	Token      string
	Interval   time.Duration
}

type agentSnapshot struct {
	AgentVersion   string  `json:"agentVersion"`
	UptimeSec      int64   `json:"uptimeSec"`
	CPUPercent     float64 `json:"cpuPercent"`
	RAMUsedBytes   int64   `json:"ramUsedBytes"`
	RAMTotalBytes  int64   `json:"ramTotalBytes"`
	DiskUsedBytes  int64   `json:"diskUsedBytes"`
	DiskTotalBytes int64   `json:"diskTotalBytes"`
	Load1          float64 `json:"load1"`
}

func loadAgentConfig() (agentConfig, error) {
	config := agentConfig{
		BackendURL: strings.TrimRight(strings.TrimSpace(os.Getenv("AMAHANE_AGENT_BACKEND_URL")), "/"),
		NodeCode:   strings.TrimSpace(os.Getenv("AMAHANE_AGENT_NODE_CODE")),
		Token:      strings.TrimSpace(os.Getenv("AMAHANE_AGENT_TOKEN")),
		Interval:   5 * time.Minute,
	}
	if raw := strings.TrimSpace(os.Getenv("AMAHANE_AGENT_INTERVAL")); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed < 30*time.Second || parsed > time.Hour {
			return config, fmt.Errorf("AMAHANE_AGENT_INTERVAL must be between 30s and 1h")
		}
		config.Interval = parsed
	}
	if config.BackendURL == "" || !strings.HasPrefix(config.BackendURL, "https://") {
		return config, fmt.Errorf("AMAHANE_AGENT_BACKEND_URL must be an https:// backend address")
	}
	if config.NodeCode == "" || config.Token == "" {
		return config, fmt.Errorf("AMAHANE_AGENT_NODE_CODE and AMAHANE_AGENT_TOKEN are required")
	}
	return config, nil
}

func collectSnapshot() (agentSnapshot, error) {
	snapshot := agentSnapshot{AgentVersion: AgentVersion}
	if info, err := host.Info(); err == nil {
		snapshot.UptimeSec = int64(info.Uptime)
	}
	if averages, err := load.Avg(); err == nil {
		snapshot.Load1 = averages.Load1
	}
	if percents, err := cpu.Percent(time.Second, false); err == nil && len(percents) > 0 {
		snapshot.CPUPercent = roundPercent(percents[0])
	}
	if memory, err := mem.VirtualMemory(); err == nil {
		snapshot.RAMUsedBytes = int64(memory.Used)
		snapshot.RAMTotalBytes = int64(memory.Total)
	}
	if usage, err := disk.Usage("/"); err == nil {
		snapshot.DiskUsedBytes = int64(usage.Used)
		snapshot.DiskTotalBytes = int64(usage.Total)
	}
	return snapshot, nil
}

func roundPercent(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return float64(int(value*10+0.5)) / 10
}

type agentClient struct {
	config agentConfig
	http   *http.Client
}

func (c agentClient) post(path, sessionToken string, payload []byte) (int, []byte, error) {
	request, err := http.NewRequest(http.MethodPost, c.config.BackendURL+path, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	if sessionToken != "" {
		request.Header.Set("Authorization", "Bearer "+sessionToken)
		stamp := strconv.FormatInt(time.Now().Unix(), 10)
		mac := hmac.New(sha256.New, []byte(sessionToken))
		mac.Write([]byte(stamp + "."))
		mac.Write(payload)
		request.Header.Set("X-Amahane-Timestamp", stamp)
		request.Header.Set("X-Amahane-Signature", hex.EncodeToString(mac.Sum(nil)))
	}
	response, err := c.http.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 16<<10))
	return response.StatusCode, body, err
}

func (c agentClient) handshake() (string, error) {
	payload, err := json.Marshal(map[string]string{"nodeId": c.config.NodeCode, "token": c.config.Token})
	if err != nil {
		return "", err
	}
	status, body, err := c.post("/api/node-agent/hello", "", payload)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("handshake failed: HTTP %d", status)
	}
	var session struct {
		SessionToken string `json:"sessionToken"`
	}
	if err := json.Unmarshal(body, &session); err != nil || session.SessionToken == "" {
		return "", errors.New("handshake response invalid")
	}
	return session.SessionToken, nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	config, err := loadAgentConfig()
	if err != nil {
		log.Fatalf("agent config: %v", err)
	}
	client := agentClient{config: config, http: &http.Client{Timeout: 20 * time.Second}}
	log.Printf("agent %s starting for node %q, interval %s", AgentVersion, config.NodeCode, config.Interval)

	sessionToken := ""
	for {
		if sessionToken == "" {
			token, err := client.handshake()
			if err != nil {
				log.Printf("handshake: %v; retry in %s", err, config.Interval)
				time.Sleep(config.Interval)
				continue
			}
			sessionToken = token
			log.Printf("handshake ok, session valid for %s", config.Interval)
		}
		snapshot, err := collectSnapshot()
		if err != nil {
			log.Printf("collect metrics: %v", err)
			time.Sleep(config.Interval)
			continue
		}
		payload, err := json.Marshal(snapshot)
		if err != nil {
			log.Printf("encode metrics: %v", err)
			time.Sleep(config.Interval)
			continue
		}
		status, _, err := client.post("/api/node-agent/heartbeat", sessionToken, payload)
		if err != nil {
			log.Printf("heartbeat: %v", err)
		} else if status == http.StatusUnauthorized {
			log.Printf("session expired, re-handshaking")
			sessionToken = ""
		} else if status != http.StatusOK {
			log.Printf("heartbeat rejected: HTTP %d", status)
		} else {
			log.Printf("heartbeat ok: cpu %.1f%%, ram %.1f%%, disk %.1f%%",
				snapshot.CPUPercent,
				percentOf(snapshot.RAMUsedBytes, snapshot.RAMTotalBytes),
				percentOf(snapshot.DiskUsedBytes, snapshot.DiskTotalBytes))
		}
		time.Sleep(config.Interval)
	}
}

func percentOf(used, total int64) float64 {
	if total <= 0 {
		return 0
	}
	return roundPercent(float64(used) / float64(total) * 100)
}
