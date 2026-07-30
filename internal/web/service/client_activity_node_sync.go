package service

import (
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	defaultClientActivitySyncLimit = 1000
	maxClientActivitySyncLimit     = 2000
	clientActivityRemoteRetention  = 7 * 24 * time.Hour
)

// ListNodeSyncStates returns the authoritative Activity state for clients
// attached to one remote node. Clients that have never opted into Activity do
// not have a settings row and are omitted; stopped clients remain included so
// the child receives the disable transition.
func (s *ClientActivityService) ListNodeSyncStates(
	nodeID int,
) ([]model.ClientActivitySyncState, error) {
	if nodeID <= 0 {
		return []model.ClientActivitySyncState{}, nil
	}

	rows := []model.ClientActivitySyncState{}
	err := database.GetDB().
		Table(model.ClientActivitySetting{}.TableName()+" AS activity").
		Select(
			"DISTINCT clients.email AS email, "+
				"activity.enabled AS enabled, "+
				"activity.generation AS generation, "+
				"activity.data_epoch AS data_epoch",
		).
		Joins("JOIN clients ON clients.id = activity.client_id").
		Joins("JOIN client_inbounds ON client_inbounds.client_id = clients.id").
		Joins("JOIN inbounds ON inbounds.id = client_inbounds.inbound_id").
		Where("inbounds.node_id = ?", nodeID).
		Order("clients.email ASC").
		Scan(&rows).
		Error
	if err != nil {
		return nil, err
	}
	if rows == nil {
		rows = []model.ClientActivitySyncState{}
	}
	return rows, nil
}

// ApplyNodeSyncAndExport applies a parent's canonical state, then returns
// incremental absolute rows for this panel and already-merged descendants.
func (s *ClientActivityService) ApplyNodeSyncAndExport(
	panelGUID string,
	req *model.ClientActivitySyncRequest,
) (*model.ClientActivitySyncResponse, error) {
	panelGUID = strings.TrimSpace(panelGUID)
	if panelGUID == "" {
		return nil, errors.New("panel GUID is empty")
	}
	if req == nil {
		req = &model.ClientActivitySyncRequest{}
	}

	if err := s.applyAuthoritativeNodeStates(req.States); err != nil {
		return nil, err
	}

	return s.exportNodeActivity(panelGUID, req.Cursors, req.Limit)
}

func normalizeActivitySyncStates(
	states []model.ClientActivitySyncState,
) []model.ClientActivitySyncState {
	byEmail := make(map[string]model.ClientActivitySyncState, len(states))
	for _, state := range states {
		state.Email = strings.TrimSpace(state.Email)
		if state.Email == "" {
			continue
		}
		if state.Generation < 0 {
			state.Generation = 0
		}
		if state.DataEpoch < 1 {
			state.DataEpoch = 1
		}
		byEmail[state.Email] = state
	}

	emails := make([]string, 0, len(byEmail))
	for email := range byEmail {
		emails = append(emails, email)
	}
	sort.Strings(emails)

	out := make([]model.ClientActivitySyncState, 0, len(emails))
	for _, email := range emails {
		out = append(out, byEmail[email])
	}
	return out
}

func (s *ClientActivityService) applyAuthoritativeNodeStates(
	states []model.ClientActivitySyncState,
) error {
	states = normalizeActivitySyncStates(states)
	if len(states) == 0 {
		return nil
	}

	emails := make([]string, 0, len(states))
	for _, state := range states {
		emails = append(emails, state.Email)
	}

	var clients []model.ClientRecord
	if err := database.GetDB().
		Select("id", "email").
		Where("email IN ?", emails).
		Find(&clients).
		Error; err != nil {
		return err
	}

	clientByEmail := make(map[string]int, len(clients))
	for _, client := range clients {
		clientByEmail[client.Email] = client.Id
	}

	return database.GetDB().Transaction(func(tx *gorm.DB) error {
		for _, state := range states {
			clientID, found := clientByEmail[state.Email]
			if !found || clientID <= 0 {
				// Reconcile may create the client later in the same parent tick. The
				// next sync retries the authoritative state.
				continue
			}

			if err := ensureClientActivitySetting(tx, clientID); err != nil {
				return err
			}

			var current model.ClientActivitySetting
			if err := tx.
				Where("client_id = ?", clientID).
				First(&current).
				Error; err != nil {
				return err
			}

			if current.Enabled == state.Enabled &&
				current.Generation == state.Generation &&
				current.DataEpoch == state.DataEpoch {
				continue
			}

			if current.DataEpoch != state.DataEpoch {
				if err := tx.
					Where("client_id = ?", clientID).
					Delete(&model.ClientActivityDestination{}).
					Error; err != nil {
					return err
				}
				if err := tx.
					Where("client_id = ?", clientID).
					Delete(&model.ClientActivityRemoteDestination{}).
					Error; err != nil {
					return err
				}
			}

			if err := tx.
				Model(&model.ClientActivitySetting{}).
				Where("client_id = ?", clientID).
				Updates(map[string]any{
					"enabled":    state.Enabled,
					"generation": state.Generation,
					"data_epoch": state.DataEpoch,
					"updated_at": time.Now().UnixMilli(),
				}).
				Error; err != nil {
				return err
			}
		}
		return nil
	})
}

type localActivitySyncRow struct {
	ID            int64  `gorm:"column:id"`
	UpdatedAt     int64  `gorm:"column:updated_at"`
	Email         string `gorm:"column:email"`
	DataEpoch     int64  `gorm:"column:data_epoch"`
	SourceIP      string `gorm:"column:source_ip"`
	Destination   string `gorm:"column:destination"`
	UploadBytes   int64  `gorm:"column:upload_bytes"`
	DownloadBytes int64  `gorm:"column:download_bytes"`
	LastSeen      int64  `gorm:"column:last_seen"`
}

type remoteActivitySyncRow struct {
	localActivitySyncRow
	OriginGUID string `gorm:"column:origin_guid"`
}

func normalizeActivitySyncLimit(limit int) int {
	if limit <= 0 {
		return defaultClientActivitySyncLimit
	}
	if limit > maxClientActivitySyncLimit {
		return maxClientActivitySyncLimit
	}
	return limit
}

func (s *ClientActivityService) exportNodeActivity(
	panelGUID string,
	cursors model.ClientActivitySyncCursors,
	limit int,
) (*model.ClientActivitySyncResponse, error) {
	limit = normalizeActivitySyncLimit(limit)
	db := database.GetDB()

	localRows := []localActivitySyncRow{}
	if err := db.
		Table(model.ClientActivityDestination{}.TableName()+" AS activity").
		Select(
			"activity.id, activity.updated_at, clients.email AS email, "+
				"activity.data_epoch, activity.source_ip, activity.destination, "+
				"activity.upload_bytes, activity.download_bytes, activity.last_seen",
		).
		Joins("JOIN clients ON clients.id = activity.client_id").
		Where(
			"activity.updated_at > ? OR (activity.updated_at = ? AND activity.id > ?)",
			cursors.Local.UpdatedAt,
			cursors.Local.UpdatedAt,
			cursors.Local.ID,
		).
		Order("activity.updated_at ASC").
		Order("activity.id ASC").
		Limit(limit).
		Scan(&localRows).
		Error; err != nil {
		return nil, err
	}

	remoteRows := []remoteActivitySyncRow{}
	if err := db.
		Table(model.ClientActivityRemoteDestination{}.TableName()+" AS activity").
		Select(
			"activity.id, activity.updated_at, clients.email AS email, "+
				"activity.data_epoch, activity.origin_guid, activity.source_ip, "+
				"activity.destination, activity.upload_bytes, "+
				"activity.download_bytes, activity.last_seen",
		).
		Joins("JOIN clients ON clients.id = activity.client_id").
		Where(
			"activity.updated_at > ? OR (activity.updated_at = ? AND activity.id > ?)",
			cursors.Remote.UpdatedAt,
			cursors.Remote.UpdatedAt,
			cursors.Remote.ID,
		).
		Order("activity.updated_at ASC").
		Order("activity.id ASC").
		Limit(limit).
		Scan(&remoteRows).
		Error; err != nil {
		return nil, err
	}

	items := make(
		[]model.ClientActivitySyncItem,
		0,
		len(localRows)+len(remoteRows),
	)

	for _, row := range localRows {
		items = append(items, model.ClientActivitySyncItem{
			OriginGUID:    panelGUID,
			Email:         row.Email,
			DataEpoch:     row.DataEpoch,
			SourceIP:      row.SourceIP,
			Destination:   row.Destination,
			UploadBytes:   row.UploadBytes,
			DownloadBytes: row.DownloadBytes,
			LastSeen:      row.LastSeen,
		})
		cursors.Local = model.ClientActivitySyncCursor{
			UpdatedAt: row.UpdatedAt,
			ID:        row.ID,
		}
	}

	for _, row := range remoteRows {
		items = append(items, model.ClientActivitySyncItem{
			OriginGUID:    row.OriginGUID,
			Email:         row.Email,
			DataEpoch:     row.DataEpoch,
			SourceIP:      row.SourceIP,
			Destination:   row.Destination,
			UploadBytes:   row.UploadBytes,
			DownloadBytes: row.DownloadBytes,
			LastSeen:      row.LastSeen,
		})
		cursors.Remote = model.ClientActivitySyncCursor{
			UpdatedAt: row.UpdatedAt,
			ID:        row.ID,
		}
	}

	if items == nil {
		items = []model.ClientActivitySyncItem{}
	}

	return &model.ClientActivitySyncResponse{
		Items:   items,
		Cursors: cursors,
		HasMore: len(localRows) == limit || len(remoteRows) == limit,
	}, nil
}

// MergeNodeActivity stores child counters as absolute snapshots. Retrying the
// same page or seeing the same descendant through another path overwrites the
// same origin-keyed row instead of adding it twice.
func (s *ClientActivityService) MergeNodeActivity(
	localPanelGUID string,
	response *model.ClientActivitySyncResponse,
) error {
	if response == nil || len(response.Items) == 0 {
		return nil
	}
	localPanelGUID = strings.TrimSpace(localPanelGUID)

	emailSet := make(map[string]struct{})
	for _, item := range response.Items {
		email := strings.TrimSpace(item.Email)
		if email != "" {
			emailSet[email] = struct{}{}
		}
	}
	emails := make([]string, 0, len(emailSet))
	for email := range emailSet {
		emails = append(emails, email)
	}

	var clients []model.ClientRecord
	if err := database.GetDB().
		Select("id", "email", "enable").
		Where("email IN ?", emails).
		Find(&clients).
		Error; err != nil {
		return err
	}
	clientByEmail := make(map[string]model.ClientRecord, len(clients))
	clientIDs := make([]int, 0, len(clients))
	for _, client := range clients {
		clientByEmail[client.Email] = client
		clientIDs = append(clientIDs, client.Id)
	}

	var settings []model.ClientActivitySetting
	if len(clientIDs) > 0 {
		if err := database.GetDB().
			Where("client_id IN ? AND enabled = ?", clientIDs, true).
			Find(&settings).
			Error; err != nil {
			return err
		}
	}
	settingByClient := make(map[int]model.ClientActivitySetting, len(settings))
	for _, setting := range settings {
		settingByClient[setting.ClientID] = setting
	}

	now := time.Now().UnixMilli()
	rows := make([]model.ClientActivityRemoteDestination, 0, len(response.Items))
	for _, item := range response.Items {
		item.Email = strings.TrimSpace(item.Email)
		item.OriginGUID = strings.TrimSpace(item.OriginGUID)
		item.SourceIP = strings.TrimSpace(item.SourceIP)
		item.Destination = strings.TrimSpace(item.Destination)

		client, found := clientByEmail[item.Email]
		setting, settingFound := settingByClient[client.Id]
		if !found || !settingFound || !client.Enable ||
			item.OriginGUID == "" || len(item.OriginGUID) > 64 ||
			item.OriginGUID == localPanelGUID ||
			item.DataEpoch != setting.DataEpoch ||
			item.SourceIP == "" || len(item.SourceIP) > 45 ||
			item.Destination == "" || len(item.Destination) > 253 ||
			item.UploadBytes < 0 || item.DownloadBytes < 0 ||
			item.LastSeen <= 0 || item.LastSeen > now+int64((24*time.Hour)/time.Millisecond) {
			continue
		}

		rows = append(rows, model.ClientActivityRemoteDestination{
			ClientID:      client.Id,
			DataEpoch:     item.DataEpoch,
			OriginGUID:    item.OriginGUID,
			SourceIP:      item.SourceIP,
			Destination:   item.Destination,
			UploadBytes:   item.UploadBytes,
			DownloadBytes: item.DownloadBytes,
			LastSeen:      item.LastSeen,
			CreatedAt:     now,
			UpdatedAt:     now,
		})
	}
	if len(rows) == 0 {
		return nil
	}

	return database.GetDB().Transaction(func(tx *gorm.DB) error {
		const batchSize = 200
		for start := 0; start < len(rows); start += batchSize {
			end := start + batchSize
			if end > len(rows) {
				end = len(rows)
			}
			batch := rows[start:end]
			if err := tx.Clauses(
				clientActivityRemoteUpsertClause(tx),
			).Create(&batch).Error; err != nil {
				return err
			}
		}

		cutoff := now - int64(clientActivityRemoteRetention/time.Millisecond)
		return tx.
			Where("last_seen < ?", cutoff).
			Delete(&model.ClientActivityRemoteDestination{}).
			Error
	})
}

func clientActivityRemoteUpsertClause(tx *gorm.DB) clause.OnConflict {
	prefix := ""
	if tx != nil && tx.Dialector != nil && tx.Dialector.Name() == "postgres" {
		prefix = "client_activity_remote_destinations."
	}

	return clause.OnConflict{
		Columns: []clause.Column{
			{Name: "client_id"},
			{Name: "data_epoch"},
			{Name: "origin_guid"},
			{Name: "source_ip"},
			{Name: "destination"},
		},
		DoUpdates: clause.Assignments(map[string]any{
			"upload_bytes": gorm.Expr(
				"CASE WHEN " + prefix +
					"upload_bytes > excluded.upload_bytes THEN " + prefix +
					"upload_bytes ELSE excluded.upload_bytes END",
			),
			"download_bytes": gorm.Expr(
				"CASE WHEN " + prefix +
					"download_bytes > excluded.download_bytes THEN " + prefix +
					"download_bytes ELSE excluded.download_bytes END",
			),
			"last_seen": gorm.Expr(
				"CASE WHEN " + prefix +
					"last_seen > excluded.last_seen THEN " + prefix +
					"last_seen ELSE excluded.last_seen END",
			),
			"updated_at": gorm.Expr("excluded.updated_at"),
		}),
	}
}
