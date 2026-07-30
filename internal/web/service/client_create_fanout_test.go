package service

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
)

func setupClientCreateFanoutDB(t *testing.T) {
	t.Helper()

	if err := database.InitDB(filepath.Join(t.TempDir(), "x-ui.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() {
		_ = database.CloseDB()
	})
}

func createClientFanoutInbound(t *testing.T, tag string, port int) *model.Inbound {
	t.Helper()

	inbound := &model.Inbound{
		UserId:   1,
		Enable:   true,
		Remark:   tag,
		Tag:      tag,
		Port:     port,
		Protocol: model.MTProto,
		Settings: `{"clients":[]}`,
	}
	if err := database.GetDB().Create(inbound).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	return inbound
}

func TestCreateFanoutDeduplicatesInboundIDs(t *testing.T) {
	setupClientCreateFanoutDB(t)

	inbound := createClientFanoutInbound(t, "fanout-deduplicate", 31001)
	inboundService := &InboundService{}
	clientService := &ClientService{}

	_, err := clientService.Create(inboundService, &ClientCreatePayload{
		Client: model.Client{
			Email:  "deduplicate@example.test",
			SubID:  "deduplicate-sub-id",
			ID:     "deduplicate-client-id",
			Enable: true,
		},
		InboundIds: []int{inbound.Id, inbound.Id, inbound.Id},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	var linkCount int64
	if err := database.GetDB().
		Model(&model.ClientInbound{}).
		Where("inbound_id = ?", inbound.Id).
		Count(&linkCount).Error; err != nil {
		t.Fatalf("count client links: %v", err)
	}
	if linkCount != 1 {
		t.Fatalf("client links = %d, want 1", linkCount)
	}

	// Accurate per-inbound billing depends on this mapping being committed
	// atomically with the canonical client link.
	var mappingCount int64
	if err := database.GetDB().
		Model(&model.ClientInboundTraffic{}).
		Where("inbound_id = ?", inbound.Id).
		Count(&mappingCount).Error; err != nil {
		t.Fatalf("count traffic mappings: %v", err)
	}
	if mappingCount != 1 {
		t.Fatalf("traffic mappings = %d, want 1", mappingCount)
	}

	stored, err := inboundService.GetInbound(inbound.Id)
	if err != nil {
		t.Fatalf("GetInbound: %v", err)
	}
	clients, err := inboundService.GetClients(stored)
	if err != nil {
		t.Fatalf("GetClients: %v", err)
	}
	if len(clients) != 1 {
		t.Fatalf("embedded clients = %d, want 1", len(clients))
	}
}

func TestCreateFanoutValidatesAllTargetsBeforeWriting(t *testing.T) {
	setupClientCreateFanoutDB(t)

	const initialSettings = `{"clients":[]}`
	inbound := createClientFanoutInbound(t, "fanout-prevalidate", 31002)
	inboundService := &InboundService{}
	clientService := &ClientService{}

	_, err := clientService.Create(inboundService, &ClientCreatePayload{
		Client: model.Client{
			Email:  "prevalidate@example.test",
			SubID:  "prevalidate-sub-id",
			ID:     "prevalidate-client-id",
			Enable: true,
		},
		InboundIds: []int{inbound.Id, inbound.Id + 1000000},
	})
	if err == nil {
		t.Fatal("Create succeeded with a missing target inbound")
	}

	stored, getErr := inboundService.GetInbound(inbound.Id)
	if getErr != nil {
		t.Fatalf("GetInbound: %v", getErr)
	}
	if stored.Settings != initialSettings {
		t.Fatalf(
			"valid target was modified before validation completed: %s",
			stored.Settings,
		)
	}

	var clientCount int64
	if countErr := database.GetDB().
		Model(&model.ClientRecord{}).
		Where("email = ?", "prevalidate@example.test").
		Count(&clientCount).Error; countErr != nil {
		t.Fatalf("count client records: %v", countErr)
	}
	if clientCount != 0 {
		t.Fatalf("client records = %d, want 0", clientCount)
	}

	var linkCount int64
	if countErr := database.GetDB().
		Model(&model.ClientInbound{}).
		Where("inbound_id = ?", inbound.Id).
		Count(&linkCount).Error; countErr != nil {
		t.Fatalf("count client links: %v", countErr)
	}
	if linkCount != 0 {
		t.Fatalf("client links = %d, want 0", linkCount)
	}
}

func clientFanoutMedian(values []time.Duration) time.Duration {
	copied := append([]time.Duration(nil), values...)
	sort.Slice(copied, func(i, j int) bool {
		return copied[i] < copied[j]
	})
	return copied[len(copied)/2]
}

func TestCreateFanoutScaleDiagnostic(t *testing.T) {
	if os.Getenv("HEIMDALL_RUN_PERF_DIAGNOSTIC") != "1" {
		t.Skip("set HEIMDALL_RUN_PERF_DIAGNOSTIC=1 to run")
	}

	const repetitions = 3

	for _, inboundCount := range []int{1, 10, 50, 100} {
		inboundCount := inboundCount

		t.Run(fmt.Sprintf("inbounds_%d", inboundCount), func(t *testing.T) {
			setupClientCreateFanoutDB(t)

			createIDs := make([]int, 0, inboundCount)
			dummyIDs := make([]int, 0, inboundCount)

			for i := 0; i < inboundCount; i++ {
				createInbound := createClientFanoutInbound(
					t,
					fmt.Sprintf("create-%d-%d", inboundCount, i),
					32000+i,
				)
				createIDs = append(createIDs, createInbound.Id)

				dummyInbound := createClientFanoutInbound(
					t,
					fmt.Sprintf("dummy-%d-%d", inboundCount, i),
					42000+i,
				)
				dummyIDs = append(dummyIDs, dummyInbound.Id)
			}

			clientService := &ClientService{}
			inboundService := &InboundService{}
			durations := make([]time.Duration, 0, repetitions)
			referenceDurations := make(
				[]time.Duration,
				0,
				repetitions,
			)

			for repetition := 0; repetition < repetitions; repetition++ {
				client := model.Client{
					Email: fmt.Sprintf(
						"create-%d-%d@example.test",
						inboundCount,
						repetition,
					),
					SubID: fmt.Sprintf(
						"create-sub-%d-%d",
						inboundCount,
						repetition,
					),
					ID: fmt.Sprintf(
						"create-id-%d-%d",
						inboundCount,
						repetition,
					),
					Enable: true,
				}

				start := time.Now()
				_, err := clientService.Create(
					inboundService,
					&ClientCreatePayload{
						Client:     client,
						InboundIds: createIDs,
					},
				)
				durations = append(durations, time.Since(start))
				if err != nil {
					t.Fatalf(
						"Create fanout=%d repetition=%d: %v",
						inboundCount,
						repetition,
						err,
					)
				}

				// Populate the second inbound set after timing so each repetition
				// sees the same database growth as the original A/B benchmark.
				dummy := model.Client{
					Email: fmt.Sprintf(
						"dummy-%d-%d@example.test",
						inboundCount,
						repetition,
					),
					SubID: fmt.Sprintf(
						"dummy-sub-%d-%d",
						inboundCount,
						repetition,
					),
					ID: fmt.Sprintf(
						"dummy-id-%d-%d",
						inboundCount,
						repetition,
					),
					Enable: true,
				}
				referenceStart := time.Now()
				result, _, err := clientService.BulkCreate(
					inboundService,
					[]ClientCreatePayload{{
						Client:     dummy,
						InboundIds: dummyIDs,
					}},
				)
				referenceDurations = append(
					referenceDurations,
					time.Since(referenceStart),
				)
				if err != nil {
					t.Fatalf("dummy BulkCreate: %v", err)
				}
				if result.Created != 1 || len(result.Skipped) != 0 {
					t.Fatalf(
						"unexpected dummy result: %+v",
						result,
					)
				}
			}

			var links int64
			if err := database.GetDB().
				Model(&model.ClientInbound{}).
				Count(&links).Error; err != nil {
				t.Fatalf("count links: %v", err)
			}

			expectedLinks := int64(inboundCount * repetitions * 2)
			if links != expectedLinks {
				t.Fatalf(
					"links=%d, expected=%d",
					links,
					expectedLinks,
				)
			}

			createMedian := clientFanoutMedian(durations)
			referenceMedian := clientFanoutMedian(referenceDurations)

			ratio := 0.0
			if referenceMedian > 0 {
				ratio = float64(createMedian) /
					float64(referenceMedian)
			}

			t.Logf(
				"FANOUT_AB inbounds=%d repetitions=%d create_median=%s reference_median=%s ratio=%.2fx links=%d",
				inboundCount,
				repetitions,
				createMedian,
				referenceMedian,
				ratio,
				links,
			)
		})
	}
}
