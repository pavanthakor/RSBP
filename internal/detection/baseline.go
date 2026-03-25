package detection

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/yoursec/rsbp/internal/correlation"
)

type BaselineModel struct {
	mu          sync.Mutex
	UpdatedAt   time.Time         `json:"updated_at"`
	TotalEvents uint64            `json:"total_events"`
	TotalAlerts uint64            `json:"total_alerts"`
	PatternHits map[string]uint64 `json:"pattern_hits"`
	AvgScore    float64           `json:"avg_score"`
}

func NewBaselineModel() *BaselineModel {
	return &BaselineModel{PatternHits: map[string]uint64{}}
}

func LoadBaseline(path string) (*BaselineModel, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m BaselineModel
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	if m.PatternHits == nil {
		m.PatternHits = map[string]uint64{}
	}
	return &m, nil
}

func (b *BaselineModel) Observe(state *correlation.SessionState, score float64, alerted bool) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	b.TotalEvents++
	if alerted {
		b.TotalAlerts++
	}
	if b.TotalEvents == 1 {
		b.AvgScore = score
	} else {
		b.AvgScore = ((b.AvgScore * float64(b.TotalEvents-1)) + score) / float64(b.TotalEvents)
	}
	if p := correlation.BestMatchPattern(state); p != nil {
		b.PatternHits[p.Name]++
	}
	b.UpdatedAt = time.Now().UTC()
}

func (b *BaselineModel) Save(path string) error {
	if b == nil || path == "" {
		return nil
	}
	b.mu.Lock()
	payload, err := json.MarshalIndent(b, "", "  ")
	b.mu.Unlock()
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
