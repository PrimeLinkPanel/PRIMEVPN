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
	"github.com/mhsanaei/PRIMEVPN/v3/internal/logger"
)

const (
	clientSpeedLimitsFileName = "client-speed-limits.json"
	clientSpeedLimitsPathEnv  = "XRAY_CLIENT_SPEED_LIMITS_FILE"
)

type clientSpeedLimit struct {
	UploadMbps   int `json:"uploadMbps"`
	DownloadMbps int `json:"downloadMbps"`
}

type clientSpeedLimitsFile struct {
	Version int                         `json:"version"`
	Clients map[string]clientSpeedLimit `json:"clients"`
}

type clientSpeedLimitRow struct {
	Email        string `gorm:"column:email"`
	UploadMbps   int    `gorm:"column:upload_mbps"`
	DownloadMbps int    `gorm:"column:download_mbps"`
}

// SyncClientSpeedLimitsJob keeps the Core speed-limit configuration synchronized
// with the normalized clients table. The Core reloads this file independently,
// so changing a client's speed does not require an Xray restart.
type SyncClientSpeedLimitsJob struct {
	mu   sync.Mutex
	path string
}

func NewSyncClientSpeedLimitsJob() *SyncClientSpeedLimitsJob {
	return &SyncClientSpeedLimitsJob{
		path: resolveClientSpeedLimitsPath(),
	}
}

func (j *SyncClientSpeedLimitsJob) Run() {
	if err := j.Sync(); err != nil {
		logger.Warning("sync Core client speed limits failed:", err)
	}
}

func (j *SyncClientSpeedLimitsJob) Sync() error {
	j.mu.Lock()
	defer j.mu.Unlock()

	rows, err := loadClientSpeedLimitRows()
	if err != nil {
		return err
	}

	data, err := buildClientSpeedLimitsJSON(rows)
	if err != nil {
		return err
	}

	changed, err := writeFileAtomicallyIfChanged(j.path, data, 0o600)
	if err != nil {
		return err
	}

	if changed {
		logger.Infof(
			"Core client speed limits synchronized: %d limited clients -> %s",
			len(normalizeClientSpeedLimitRows(rows)),
			j.path,
		)
	}

	return nil
}

func loadClientSpeedLimitRows() ([]clientSpeedLimitRow, error) {
	db := database.GetDB()
	if db == nil {
		return nil, errors.New("database is not initialized")
	}

	var rows []clientSpeedLimitRow
	err := db.Table("clients AS clients").
		Select("COALESCE(client_inbound_traffics.stat_email, clients.email) AS email, clients.upload_mbps, clients.download_mbps").
		Joins("JOIN client_inbounds ON client_inbounds.client_id = clients.id").
		Joins("JOIN inbounds ON inbounds.id = client_inbounds.inbound_id").
		Joins("LEFT JOIN client_inbound_traffics ON client_inbound_traffics.client_id = clients.id AND client_inbound_traffics.inbound_id = client_inbounds.inbound_id").
		Where(
			"clients.enable = ? AND inbounds.enable = ? AND (clients.upload_mbps > ? OR clients.download_mbps > ?)",
			true,
			true,
			0,
			0,
		).
		Order("email ASC").
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}

	return normalizeClientSpeedLimitRows(rows), nil
}

func normalizeClientSpeedLimitRows(rows []clientSpeedLimitRow) []clientSpeedLimitRow {
	byEmail := make(map[string]clientSpeedLimitRow, len(rows))

	for _, row := range rows {
		email := strings.TrimSpace(row.Email)
		if email == "" {
			continue
		}

		uploadMbps := row.UploadMbps
		if uploadMbps < 0 {
			uploadMbps = 0
		}

		downloadMbps := row.DownloadMbps
		if downloadMbps < 0 {
			downloadMbps = 0
		}

		if uploadMbps == 0 && downloadMbps == 0 {
			continue
		}

		existing, found := byEmail[email]
		if !found {
			byEmail[email] = clientSpeedLimitRow{
				Email:        email,
				UploadMbps:   uploadMbps,
				DownloadMbps: downloadMbps,
			}
			continue
		}

		existing.UploadMbps = strictestNonZeroLimit(
			existing.UploadMbps,
			uploadMbps,
		)
		existing.DownloadMbps = strictestNonZeroLimit(
			existing.DownloadMbps,
			downloadMbps,
		)
		byEmail[email] = existing
	}

	normalized := make([]clientSpeedLimitRow, 0, len(byEmail))
	for _, row := range byEmail {
		normalized = append(normalized, row)
	}

	sort.Slice(normalized, func(i, k int) bool {
		return normalized[i].Email < normalized[k].Email
	})

	return normalized
}

func strictestNonZeroLimit(current, incoming int) int {
	if current <= 0 {
		if incoming > 0 {
			return incoming
		}
		return 0
	}

	if incoming <= 0 {
		return current
	}

	if incoming < current {
		return incoming
	}

	return current
}

func buildClientSpeedLimitsJSON(rows []clientSpeedLimitRow) ([]byte, error) {
	normalized := normalizeClientSpeedLimitRows(rows)

	clients := make(map[string]clientSpeedLimit, len(normalized))
	for _, row := range normalized {
		clients[row.Email] = clientSpeedLimit{
			UploadMbps:   row.UploadMbps,
			DownloadMbps: row.DownloadMbps,
		}
	}

	payload := clientSpeedLimitsFile{
		Version: 1,
		Clients: clients,
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return nil, err
	}

	return append(data, '\n'), nil
}

func resolveClientSpeedLimitsPath() string {
	if configured := strings.TrimSpace(
		os.Getenv(clientSpeedLimitsPathEnv),
	); configured != "" {
		return filepath.Clean(configured)
	}

	binFolder := config.GetBinFolderPath()
	if !filepath.IsAbs(binFolder) {
		if executable, err := os.Executable(); err == nil {
			binFolder = filepath.Join(filepath.Dir(executable), binFolder)
		} else if absolute, absErr := filepath.Abs(binFolder); absErr == nil {
			binFolder = absolute
		}
	}

	return filepath.Join(
		filepath.Clean(binFolder),
		clientSpeedLimitsFileName,
	)
}
