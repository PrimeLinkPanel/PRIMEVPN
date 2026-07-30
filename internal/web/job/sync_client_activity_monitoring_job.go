package job

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/config"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/logger"
)

const (
	clientActivityMonitoringFileName = "client-activity-monitoring.json"
	clientActivityMonitoringPathEnv  = "XRAY_CLIENT_ACTIVITY_FILE"
)

type clientActivityMonitoringClient struct {
	ClientID   int   `json:"clientId"`
	Generation int64 `json:"generation"`
	DataEpoch  int64 `json:"dataEpoch"`
}

type clientActivityMonitoringFile struct {
	Version int                                       `json:"version"`
	Clients map[string]clientActivityMonitoringClient `json:"clients"`
}

type clientActivityMonitoringRow struct {
	ClientID   int    `gorm:"column:client_id"`
	Email      string `gorm:"column:email"`
	Generation int64  `gorm:"column:generation"`
	DataEpoch  int64  `gorm:"column:data_epoch"`
}

// SyncClientActivityMonitoringJob publishes the current per-client Activity
// allowlist for the custom Core.
//
// The file contains only enabled Activity settings belonging to enabled
// clients. Xray reloads it independently, so Start and Stop do not require an
// Xray restart.
type SyncClientActivityMonitoringJob struct {
	mu   sync.Mutex
	path string
}

func NewSyncClientActivityMonitoringJob() *SyncClientActivityMonitoringJob {
	return &SyncClientActivityMonitoringJob{
		path: resolveClientActivityMonitoringPath(),
	}
}

func (j *SyncClientActivityMonitoringJob) Run() {
	if err := j.Sync(); err != nil {
		logger.Warning(
			"sync Core client Activity monitoring failed:",
			err,
		)
	}
}

func (j *SyncClientActivityMonitoringJob) Sync() error {
	j.mu.Lock()
	defer j.mu.Unlock()

	rows, err := loadClientActivityMonitoringRows()
	if err != nil {
		return err
	}

	normalized := normalizeClientActivityMonitoringRows(rows)

	data, err := buildClientActivityMonitoringJSON(normalized)
	if err != nil {
		return err
	}

	changed, err := writeFileAtomicallyIfChanged(
		j.path,
		data,
		0o600,
	)
	if err != nil {
		return err
	}

	if changed {
		logger.Infof(
			"Core client Activity monitoring synchronized: %d monitored clients -> %s",
			len(normalized),
			j.path,
		)
	}

	return nil
}

func loadClientActivityMonitoringRows() (
	[]clientActivityMonitoringRow,
	error,
) {
	db := database.GetDB()
	if db == nil {
		return nil, errors.New("database is not initialized")
	}

	var rows []clientActivityMonitoringRow

	err := db.
		Table(model.ClientActivitySetting{}.TableName()+" AS activity").
		Select(
			"clients.id AS client_id, "+
				"COALESCE(client_inbound_traffics.stat_email, clients.email) AS email, "+
				"activity.generation AS generation, "+
				"activity.data_epoch AS data_epoch",
		).
		Joins(
			"JOIN clients ON clients.id = activity.client_id",
		).
		Joins(
			"JOIN client_inbounds ON client_inbounds.client_id = clients.id",
		).
		Joins(
			"JOIN inbounds ON inbounds.id = client_inbounds.inbound_id",
		).
		Joins(
			"LEFT JOIN client_inbound_traffics ON client_inbound_traffics.client_id = clients.id AND client_inbound_traffics.inbound_id = client_inbounds.inbound_id",
		).
		Where(
			"activity.enabled = ? AND clients.enable = ? AND inbounds.enable = ?",
			true,
			true,
			true,
		).
		Order("email ASC").
		Scan(&rows).
		Error
	if err != nil {
		return nil, err
	}

	return normalizeClientActivityMonitoringRows(rows), nil
}

func normalizeClientActivityMonitoringRows(
	rows []clientActivityMonitoringRow,
) []clientActivityMonitoringRow {
	byEmail := make(
		map[string]clientActivityMonitoringRow,
		len(rows),
	)

	for _, row := range rows {
		row.Email = strings.TrimSpace(row.Email)

		if row.Email == "" || row.ClientID <= 0 {
			continue
		}

		if row.Generation < 0 {
			row.Generation = 0
		}
		if row.DataEpoch < 1 {
			row.DataEpoch = 1
		}

		existing, found := byEmail[row.Email]
		if !found || preferActivityMonitoringRow(row, existing) {
			byEmail[row.Email] = row
		}
	}

	normalized := make(
		[]clientActivityMonitoringRow,
		0,
		len(byEmail),
	)

	for _, row := range byEmail {
		normalized = append(normalized, row)
	}

	sort.Slice(normalized, func(i, k int) bool {
		return normalized[i].Email < normalized[k].Email
	})

	return normalized
}

func preferActivityMonitoringRow(
	incoming clientActivityMonitoringRow,
	existing clientActivityMonitoringRow,
) bool {
	if incoming.Generation != existing.Generation {
		return incoming.Generation > existing.Generation
	}

	if incoming.DataEpoch != existing.DataEpoch {
		return incoming.DataEpoch > existing.DataEpoch
	}

	return incoming.ClientID < existing.ClientID
}

func buildClientActivityMonitoringJSON(
	rows []clientActivityMonitoringRow,
) ([]byte, error) {
	normalized := normalizeClientActivityMonitoringRows(rows)

	clients := make(
		map[string]clientActivityMonitoringClient,
		len(normalized),
	)

	for _, row := range normalized {
		clients[row.Email] = clientActivityMonitoringClient{
			ClientID:   row.ClientID,
			Generation: row.Generation,
			DataEpoch:  row.DataEpoch,
		}
	}

	payload := clientActivityMonitoringFile{
		Version: 1,
		Clients: clients,
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return nil, err
	}

	return append(data, '\n'), nil
}

func resolveClientActivityMonitoringPath() string {
	if configured := strings.TrimSpace(
		os.Getenv(clientActivityMonitoringPathEnv),
	); configured != "" {
		return filepath.Clean(configured)
	}

	binFolder := config.GetBinFolderPath()

	if !filepath.IsAbs(binFolder) {
		if executable, err := os.Executable(); err == nil {
			binFolder = filepath.Join(
				filepath.Dir(executable),
				binFolder,
			)
		} else if absolute, absErr := filepath.Abs(binFolder); absErr == nil {
			binFolder = absolute
		}
	}

	return filepath.Join(
		filepath.Clean(binFolder),
		clientActivityMonitoringFileName,
	)
}
