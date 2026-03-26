//go:build production

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestFullProductionFlow(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("production integration test requires Linux runtime")
	}

	repoRoot := findRepoRoot(t)
	httpClient := &http.Client{Timeout: 4 * time.Second}

	if err := runBash(repoRoot, "make build"); err != nil {
		t.Fatalf("check1 build failed: %v", err)
	}
	if err := runBash(repoRoot, "./scripts/start-rsbp.sh"); err != nil {
		t.Fatalf("check1 start daemon failed: %v", err)
	}
	defer func() { _ = runBash(repoRoot, "./scripts/stop-rsbp.sh") }()

	healthDeadline := time.Now().Add(30 * time.Second)
	for {
		loaded, err := ebpfLoaded(httpClient, "http://127.0.0.1:9001/health")
		if err == nil && loaded {
			break
		}
		if time.Now().After(healthDeadline) {
			t.Fatalf("check2 /health did not report ebpf.loaded=true in time: %v", err)
		}
		time.Sleep(1 * time.Second)
	}

	beforeCount, _ := esCount(httpClient, "http://localhost:9200/_count")
	beforeDetections, _ := detectionsTotal(httpClient, "http://127.0.0.1:9001/stats")

	if err := runBash(repoRoot, "sudo ./test/simulate/attack_sim.sh"); err != nil {
		t.Fatalf("check3 attack simulation failed: %v", err)
	}

	var gotAlert map[string]any
	alertDeadline := time.Now().Add(30 * time.Second)
	for {
		alerts, err := fetchAlerts(httpClient, "http://127.0.0.1:9001/alerts")
		if err == nil && len(alerts) > 0 {
			gotAlert = alerts[0]
			break
		}
		if time.Now().After(alertDeadline) {
			t.Fatalf("check4 no alert appeared in /alerts within 30s: %v", err)
		}
		time.Sleep(1 * time.Second)
	}

	score, _ := toFloat(gotAlert["score"])
	severity := strings.TrimSpace(fmt.Sprintf("%v", gotAlert["severity"]))
	mitre := gotAlert["mitre_techniques"]
	if score <= 0 || severity == "" || mitre == nil {
		t.Fatalf("check5 alert fields invalid: score=%v severity=%q mitre=%v", score, severity, mitre)
	}

	alertsFile := "/var/log/rsbp/alerts.jsonl"
	content, readErr := os.ReadFile(alertsFile)
	if readErr != nil {
		t.Fatalf("check6 failed reading alerts file: %v", readErr)
	}
	alertID := strings.TrimSpace(fmt.Sprintf("%v", gotAlert["id"]))
	if alertID != "" && !strings.Contains(string(content), alertID) {
		t.Fatalf("check6 alert id %s not found in alerts.jsonl", alertID)
	}

	afterCount, _ := esCount(httpClient, "http://localhost:9200/_count")
	if afterCount <= beforeCount {
		t.Fatalf("check7 ES document count did not increase: before=%d after=%d", beforeCount, afterCount)
	}

	afterDetections, _ := detectionsTotal(httpClient, "http://127.0.0.1:9001/stats")
	if afterDetections <= beforeDetections {
		t.Fatalf("check8 detections_total did not increase: before=%d after=%d", beforeDetections, afterDetections)
	}

	if err := runBash(repoRoot, "./scripts/stop-rsbp.sh"); err != nil {
		t.Fatalf("check9 failed to stop daemon cleanly: %v", err)
	}

	baseline := "/var/lib/rsbp/baseline.json"
	st, err := os.Stat(baseline)
	if err != nil {
		t.Fatalf("check9 baseline file missing after shutdown: %v", err)
	}
	if st.Size() == 0 {
		t.Fatalf("check9 baseline file is empty")
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("failed to detect current file path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("go.mod not found from inferred repo root: %s", root)
	}
	return root
}

func runBash(cwd, cmd string) error {
	c := exec.Command("bash", "-lc", cmd)
	c.Dir = cwd
	out, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func ebpfLoaded(client *http.Client, url string) (bool, error) {
	resp, err := client.Get(url)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return false, err
	}
	ebpfRaw, ok := payload["ebpf"].(map[string]any)
	if !ok {
		return false, fmt.Errorf("health payload missing ebpf object")
	}
	loaded, _ := ebpfRaw["loaded"].(bool)
	return loaded, nil
}

func fetchAlerts(client *http.Client, url string) ([]map[string]any, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

func esCount(client *http.Client, url string) (int64, error) {
	resp, err := client.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return 0, err
	}
	return int64(toNumber(payload["count"])), nil
}

func detectionsTotal(client *http.Client, url string) (int64, error) {
	resp, err := client.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return 0, err
	}
	detectionRaw, ok := payload["detection"].(map[string]any)
	if !ok {
		return 0, nil
	}
	return int64(toNumber(detectionRaw["DetectionsTotal"])), nil
}

func toFloat(v any) (float64, bool) {
	switch vv := v.(type) {
	case float64:
		return vv, true
	case int:
		return float64(vv), true
	case int64:
		return float64(vv), true
	default:
		return 0, false
	}
}

func toNumber(v any) float64 {
	if f, ok := toFloat(v); ok {
		return f
	}
	return 0
}
