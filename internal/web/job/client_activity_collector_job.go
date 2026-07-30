package job

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/logger"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	defaultClientActivitySocketPath = "/run/secx/client-activity.sock"
	clientActivitySocketEnv         = "XRAY_CLIENT_ACTIVITY_SOCKET"

	clientActivityDatagramSize = 4096
	clientActivityQueueSize    = 4096
	clientActivityBatchSize    = 512
	clientActivityUpsertBatch  = 200

	clientActivityFlushInterval = time.Second
	clientActivityRetention     = 7 * 24 * time.Hour
	clientActivityMaintenance   = 10 * time.Minute

	clientActivityRowsPerClient = 100000
	clientActivityMaxEmail      = 320
	clientActivityMaxDest       = 253
)

type clientActivityEvent struct {
	Version       int    `json:"version"`
	ClientID      int    `json:"clientId"`
	Email         string `json:"email"`
	Generation    int64  `json:"generation"`
	DataEpoch     int64  `json:"dataEpoch"`
	SourceIP      string `json:"sourceIp"`
	Destination   string `json:"destination"`
	UploadBytes   int64  `json:"uploadBytes"`
	DownloadBytes int64  `json:"downloadBytes"`
	ObservedAt    int64  `json:"observedAt"`
}

type clientActivityAggregateKey struct {
	ClientID    int
	Email       string
	Generation  int64
	DataEpoch   int64
	SourceIP    string
	Destination string
}

type ClientActivityCollector struct {
	socketPath    string
	flushInterval time.Duration
	queue         chan clientActivityEvent

	mu      sync.Mutex
	started bool
	ctx     context.Context
	cancel  context.CancelFunc
	conn    *net.UnixConn
	wg      sync.WaitGroup

	lastMaintenance atomic.Int64
}

func NewClientActivityCollector() *ClientActivityCollector {
	socketPath := strings.TrimSpace(
		os.Getenv(clientActivitySocketEnv),
	)
	if socketPath == "" {
		socketPath = defaultClientActivitySocketPath
	}

	return newClientActivityCollector(
		socketPath,
		clientActivityFlushInterval,
		clientActivityQueueSize,
	)
}

func newClientActivityCollector(
	socketPath string,
	flushInterval time.Duration,
	queueSize int,
) *ClientActivityCollector {
	if flushInterval <= 0 {
		flushInterval = clientActivityFlushInterval
	}
	if queueSize <= 0 {
		queueSize = 1
	}

	return &ClientActivityCollector{
		socketPath:    filepath.Clean(socketPath),
		flushInterval: flushInterval,
		queue:         make(chan clientActivityEvent, queueSize),
	}
}

func (c *ClientActivityCollector) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.started {
		return nil
	}

	if strings.TrimSpace(c.socketPath) == "" {
		return errors.New("client activity socket path is empty")
	}

	if err := os.MkdirAll(
		filepath.Dir(c.socketPath),
		0o755,
	); err != nil {
		return fmt.Errorf(
			"create client activity socket directory: %w",
			err,
		)
	}

	if info, err := os.Lstat(c.socketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf(
				"refusing to replace non-socket path %s",
				c.socketPath,
			)
		}

		if err := os.Remove(c.socketPath); err != nil {
			return fmt.Errorf(
				"remove stale client activity socket: %w",
				err,
			)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf(
			"inspect client activity socket: %w",
			err,
		)
	}

	address := &net.UnixAddr{
		Name: c.socketPath,
		Net:  "unixgram",
	}

	conn, err := net.ListenUnixgram(
		"unixgram",
		address,
	)
	if err != nil {
		return fmt.Errorf(
			"listen on client activity socket: %w",
			err,
		)
	}

	if err := os.Chmod(c.socketPath, 0o600); err != nil {
		_ = conn.Close()
		_ = os.Remove(c.socketPath)

		return fmt.Errorf(
			"secure client activity socket: %w",
			err,
		)
	}

	_ = conn.SetReadBuffer(1024 * 1024)

	ctx, cancel := context.WithCancel(
		context.Background(),
	)

	c.ctx = ctx
	c.cancel = cancel
	c.conn = conn
	c.started = true

	c.wg.Add(2)

	go c.readLoop(ctx, conn)
	go c.aggregateLoop(ctx)

	return nil
}

func (c *ClientActivityCollector) Stop() {
	c.mu.Lock()

	if !c.started {
		c.mu.Unlock()
		return
	}

	cancel := c.cancel
	conn := c.conn
	socketPath := c.socketPath

	c.started = false
	c.cancel = nil
	c.conn = nil
	c.ctx = nil

	c.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if conn != nil {
		_ = conn.Close()
	}

	c.wg.Wait()
	_ = os.Remove(socketPath)
}

func (c *ClientActivityCollector) readLoop(
	ctx context.Context,
	conn *net.UnixConn,
) {
	defer c.wg.Done()

	buffer := make(
		[]byte,
		clientActivityDatagramSize,
	)

	for {
		length, _, err := conn.ReadFromUnix(buffer)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}

			continue
		}

		if length <= 0 ||
			length > clientActivityDatagramSize {
			continue
		}

		var event clientActivityEvent

		if err := json.Unmarshal(
			buffer[:length],
			&event,
		); err != nil {
			continue
		}

		event, valid := normalizeClientActivityEvent(event)
		if !valid {
			continue
		}

		select {
		case c.queue <- event:
		default:
			// Collector pressure must never affect proxy traffic.
		}
	}
}

func (c *ClientActivityCollector) aggregateLoop(
	ctx context.Context,
) {
	defer c.wg.Done()

	ticker := time.NewTicker(c.flushInterval)
	defer ticker.Stop()

	pending := make(
		map[clientActivityAggregateKey]clientActivityEvent,
	)

	eventCount := 0

	flush := func() {
		if len(pending) == 0 {
			eventCount = 0
			return
		}

		events := make(
			[]clientActivityEvent,
			0,
			len(pending),
		)

		for _, event := range pending {
			events = append(events, event)
		}

		pending = make(
			map[clientActivityAggregateKey]clientActivityEvent,
		)
		eventCount = 0

		if err := c.persist(events); err != nil {
			log.Printf(
				"client activity collector flush failed: %v",
				err,
			)
		}
	}

	add := func(event clientActivityEvent) {
		key := clientActivityAggregateKey{
			ClientID:    event.ClientID,
			Email:       event.Email,
			Generation:  event.Generation,
			DataEpoch:   event.DataEpoch,
			SourceIP:    event.SourceIP,
			Destination: event.Destination,
		}

		current, found := pending[key]
		if !found {
			pending[key] = event
			eventCount++
			return
		}

		current.UploadBytes = saturatingAddInt64(
			current.UploadBytes,
			event.UploadBytes,
		)
		current.DownloadBytes = saturatingAddInt64(
			current.DownloadBytes,
			event.DownloadBytes,
		)

		if event.ObservedAt > current.ObservedAt {
			current.ObservedAt = event.ObservedAt
		}

		pending[key] = current
		eventCount++
	}

	for {
		select {
		case event := <-c.queue:
			add(event)

			if eventCount >= clientActivityBatchSize {
				flush()
			}

		case <-ticker.C:
			flush()

		case <-ctx.Done():
			for {
				select {
				case event := <-c.queue:
					add(event)
				default:
					flush()
					return
				}
			}
		}
	}
}

func normalizeClientActivityEvent(
	event clientActivityEvent,
) (clientActivityEvent, bool) {
	event.Email = strings.TrimSpace(event.Email)

	if event.Version != 1 ||
		event.ClientID <= 0 ||
		event.Email == "" ||
		len(event.Email) > clientActivityMaxEmail ||
		event.Generation < 0 ||
		event.DataEpoch < 1 ||
		event.UploadBytes < 0 ||
		event.DownloadBytes < 0 ||
		(event.UploadBytes == 0 &&
			event.DownloadBytes == 0) {
		return clientActivityEvent{}, false
	}

	sourceIP := net.ParseIP(
		strings.Trim(
			strings.TrimSpace(event.SourceIP),
			"[]",
		),
	)
	if sourceIP == nil {
		return clientActivityEvent{}, false
	}
	event.SourceIP = sourceIP.String()

	event.Destination = strings.ToLower(
		strings.TrimSuffix(
			strings.Trim(
				strings.TrimSpace(event.Destination),
				"[]",
			),
			".",
		),
	)

	if event.Destination == "" ||
		len(event.Destination) > clientActivityMaxDest {
		return clientActivityEvent{}, false
	}

	now := time.Now().UnixMilli()

	if event.ObservedAt <= 0 ||
		event.ObservedAt > now+int64(5*time.Minute/time.Millisecond) {
		event.ObservedAt = now
	}

	if event.ObservedAt <
		now-int64(clientActivityRetention/time.Millisecond) {
		return clientActivityEvent{}, false
	}

	return event, true
}

func (c *ClientActivityCollector) persist(
	events []clientActivityEvent,
) error {
	if len(events) == 0 {
		return nil
	}

	aggregated := make(
		map[clientActivityAggregateKey]clientActivityEvent,
		len(events),
	)

	clientIDsSet := make(map[int]struct{})

	for _, raw := range events {
		event, valid := normalizeClientActivityEvent(raw)
		if !valid {
			continue
		}

		key := clientActivityAggregateKey{
			ClientID:    event.ClientID,
			Email:       event.Email,
			Generation:  event.Generation,
			DataEpoch:   event.DataEpoch,
			SourceIP:    event.SourceIP,
			Destination: event.Destination,
		}

		current, found := aggregated[key]
		if !found {
			aggregated[key] = event
		} else {
			current.UploadBytes = saturatingAddInt64(
				current.UploadBytes,
				event.UploadBytes,
			)
			current.DownloadBytes = saturatingAddInt64(
				current.DownloadBytes,
				event.DownloadBytes,
			)

			if event.ObservedAt > current.ObservedAt {
				current.ObservedAt = event.ObservedAt
			}

			aggregated[key] = current
		}

		clientIDsSet[event.ClientID] = struct{}{}
	}

	if len(aggregated) == 0 {
		return nil
	}

	clientIDs := make(
		[]int,
		0,
		len(clientIDsSet),
	)
	for clientID := range clientIDsSet {
		clientIDs = append(clientIDs, clientID)
	}

	db := database.GetDB()

	var settings []model.ClientActivitySetting
	if err := db.
		Where(
			"client_id IN ? AND enabled = ?",
			clientIDs,
			true,
		).
		Find(&settings).
		Error; err != nil {
		return err
	}

	var clients []model.ClientRecord
	if err := db.
		Select("id", "email", "enable").
		Where(
			"id IN ? AND enable = ?",
			clientIDs,
			true,
		).
		Find(&clients).
		Error; err != nil {
		return err
	}

	settingsByClient := make(
		map[int]model.ClientActivitySetting,
		len(settings),
	)
	for _, setting := range settings {
		settingsByClient[setting.ClientID] = setting
	}

	clientsByID := make(
		map[int]model.ClientRecord,
		len(clients),
	)
	for _, client := range clients {
		clientsByID[client.Id] = client
	}

	var statEmailRows []struct {
		ClientID  int    `gorm:"column:client_id"`
		StatEmail string `gorm:"column:stat_email"`
	}
	if err := db.
		Table("client_inbound_traffics").
		Select("client_id, stat_email").
		Where("client_id IN ? AND stat_email <> ''", clientIDs).
		Find(&statEmailRows).
		Error; err != nil {
		return err
	}

	statEmailsByClient := make(
		map[int]map[string]struct{},
		len(statEmailRows),
	)
	for _, row := range statEmailRows {
		statEmail := strings.TrimSpace(row.StatEmail)
		if statEmail == "" {
			continue
		}
		if statEmailsByClient[row.ClientID] == nil {
			statEmailsByClient[row.ClientID] = make(map[string]struct{})
		}
		statEmailsByClient[row.ClientID][statEmail] = struct{}{}
	}

	now := time.Now().UnixMilli()

	rows := make(
		[]model.ClientActivityDestination,
		0,
		len(aggregated),
	)
	affectedClientIDs := make(map[int]struct{})

	for _, event := range aggregated {
		setting, settingFound :=
			settingsByClient[event.ClientID]

		client, clientFound :=
			clientsByID[event.ClientID]

		emailMatches := client.Email == event.Email
		if !emailMatches {
			if statEmails, ok := statEmailsByClient[event.ClientID]; ok {
				_, emailMatches = statEmails[event.Email]
			}
		}

		if !settingFound ||
			!clientFound ||
			!setting.Enabled ||
			!client.Enable ||
			!emailMatches ||
			setting.Generation != event.Generation ||
			setting.DataEpoch != event.DataEpoch {
			continue
		}

		rows = append(
			rows,
			model.ClientActivityDestination{
				ClientID:      event.ClientID,
				DataEpoch:     event.DataEpoch,
				SourceIP:      event.SourceIP,
				Destination:   event.Destination,
				UploadBytes:   event.UploadBytes,
				DownloadBytes: event.DownloadBytes,
				LastSeen:      event.ObservedAt,
				CreatedAt:     now,
				UpdatedAt:     now,
			},
		)

		affectedClientIDs[event.ClientID] = struct{}{}
	}

	if len(rows) == 0 {
		return nil
	}

	affectedIDs := make(
		[]int,
		0,
		len(affectedClientIDs),
	)
	for clientID := range affectedClientIDs {
		affectedIDs = append(affectedIDs, clientID)
	}

	return db.Transaction(func(tx *gorm.DB) error {
		for start := 0; start < len(rows); start += clientActivityUpsertBatch {
			end := start + clientActivityUpsertBatch
			if end > len(rows) {
				end = len(rows)
			}

			batch := rows[start:end]

			err := tx.Clauses(
				clientActivityUpsertClause(tx),
			).Create(&batch).Error

			if err != nil {
				return err
			}
		}

		if err := capClientActivityRows(
			tx,
			affectedIDs,
		); err != nil {
			return err
		}

		return c.runRetentionIfDue(tx, now)
	})
}

func clientActivityUpsertClause(
	tx *gorm.DB,
) clause.OnConflict {
	targetPrefix := ""

	// PostgreSQL exposes both the target row and excluded row inside
	// ON CONFLICT. Qualifying the target columns avoids dialect ambiguity.
	// SQLite keeps the original unqualified target-column syntax.
	if tx != nil &&
		tx.Dialector != nil &&
		tx.Dialector.Name() == "postgres" {
		targetPrefix = "client_activity_destinations."
	}

	return clause.OnConflict{
		Columns: []clause.Column{
			{Name: "client_id"},
			{Name: "data_epoch"},
			{Name: "source_ip"},
			{Name: "destination"},
		},
		DoUpdates: clause.Assignments(
			map[string]any{
				"upload_bytes": gorm.Expr(
					targetPrefix +
						"upload_bytes + excluded.upload_bytes",
				),
				"download_bytes": gorm.Expr(
					targetPrefix +
						"download_bytes + excluded.download_bytes",
				),
				"last_seen": gorm.Expr(
					"CASE WHEN " +
						targetPrefix +
						"last_seen > excluded.last_seen THEN " +
						targetPrefix +
						"last_seen ELSE excluded.last_seen END",
				),
				"updated_at": gorm.Expr(
					"excluded.updated_at",
				),
			},
		),
	}
}

func capClientActivityRows(
	tx *gorm.DB,
	clientIDs []int,
) error {
	return capClientActivityRowsToLimit(
		tx,
		clientIDs,
		clientActivityRowsPerClient,
	)
}

func capClientActivityRowsToLimit(
	tx *gorm.DB,
	clientIDs []int,
	rowLimit int,
) error {
	if len(clientIDs) == 0 {
		return nil
	}

	return tx.Exec(
		`
DELETE FROM client_activity_destinations
WHERE id IN (
	SELECT id
	FROM (
		SELECT
			id,
			ROW_NUMBER() OVER (
				PARTITION BY client_id
				ORDER BY last_seen DESC, id DESC
			) AS activity_row_number
		FROM client_activity_destinations
		WHERE client_id IN ?
	) ranked_activity
	WHERE activity_row_number > ?
)
`,
		clientIDs,
		rowLimit,
	).Error
}

func (c *ClientActivityCollector) runRetentionIfDue(
	tx *gorm.DB,
	now int64,
) error {
	last := c.lastMaintenance.Load()
	interval := int64(
		clientActivityMaintenance / time.Millisecond,
	)

	if last > 0 && now-last < interval {
		return nil
	}

	if !c.lastMaintenance.CompareAndSwap(last, now) {
		return nil
	}

	cutoff := now - int64(
		clientActivityRetention/time.Millisecond,
	)

	return tx.
		Where("last_seen < ?", cutoff).
		Delete(&model.ClientActivityDestination{}).
		Error
}

func saturatingAddInt64(
	current int64,
	addition int64,
) int64 {
	if addition <= 0 {
		return current
	}

	if current > math.MaxInt64-addition {
		return math.MaxInt64
	}

	return current + addition
}

type ClientActivityCollectorJob struct{}

var (
	clientActivityCollectorMu sync.Mutex
	activeActivityCollector   *ClientActivityCollector
)

func NewClientActivityCollectorJob() *ClientActivityCollectorJob {
	return &ClientActivityCollectorJob{}
}

// StopClientActivityCollector stops the process-wide collector and
// releases its Unix datagram socket. Calling it repeatedly is safe.
func StopClientActivityCollector() {
	clientActivityCollectorMu.Lock()
	collector := activeActivityCollector
	activeActivityCollector = nil
	clientActivityCollectorMu.Unlock()

	if collector != nil {
		collector.Stop()
	}
}

func (j *ClientActivityCollectorJob) Run() {
	clientActivityCollectorMu.Lock()
	defer clientActivityCollectorMu.Unlock()

	if activeActivityCollector != nil {
		return
	}

	collector := NewClientActivityCollector()

	if err := collector.Start(); err != nil {
		logger.Errorf(
			"start client Activity collector failed: %v",
			err,
		)
		return
	}

	activeActivityCollector = collector

	logger.Infof(
		"Client Activity collector listening on %s",
		collector.socketPath,
	)
}
