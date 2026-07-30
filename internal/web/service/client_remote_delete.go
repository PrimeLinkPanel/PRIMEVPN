package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/logger"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/web/runtime"

	"gorm.io/gorm"
)

// remoteClientDeleter is intentionally narrower than runtime.Runtime. Detaching
// a client from one inbound and deleting the client record from a node are
// different operations; only Remote implements the latter.
type remoteClientDeleter interface {
	DeleteClientRecord(ctx context.Context, email string, keepTraffic bool) error
	DeleteClientRecords(ctx context.Context, emails []string, keepTraffic bool) error
}

var _ remoteClientDeleter = (*runtime.Remote)(nil)

type remoteClientDeleteTarget struct {
	nodeID  int
	deleter remoteClientDeleter
}

func normalizeClientEmails(emails []string) []string {
	seen := make(map[string]struct{}, len(emails))
	out := make([]string, 0, len(emails))
	for _, email := range emails {
		email = strings.TrimSpace(email)
		if email == "" {
			continue
		}
		key := strings.ToLower(email)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, email)
	}
	return out
}

// remoteDeleteNodeIDs returns every node known to have seen one of the clients.
// The inbound mappings cover the normal delete path; node_client_traffics keeps
// enough history to clean a node-side orphan after the central ClientRecord or
// mapping has already disappeared.
func remoteDeleteNodeIDs(emails []string, inboundIDs []int) ([]int, error) {
	emails = normalizeClientEmails(emails)
	nodeSet := make(map[int]struct{})
	db := database.GetDB()

	if len(inboundIDs) > 0 {
		var nodeIDs []int
		if err := db.Model(&model.Inbound{}).
			Where("id IN ? AND node_id IS NOT NULL", inboundIDs).
			Pluck("node_id", &nodeIDs).Error; err != nil {
			return nil, err
		}
		for _, nodeID := range nodeIDs {
			if nodeID > 0 {
				nodeSet[nodeID] = struct{}{}
			}
		}
	}

	if len(emails) > 0 {
		var nodeIDs []int
		if err := db.Model(&model.NodeClientTraffic{}).
			Where("email IN ?", emails).
			Distinct("node_id").
			Pluck("node_id", &nodeIDs).Error; err != nil {
			return nil, err
		}
		for _, nodeID := range nodeIDs {
			if nodeID > 0 {
				nodeSet[nodeID] = struct{}{}
			}
		}
	}

	out := make([]int, 0, len(nodeSet))
	for nodeID := range nodeSet {
		out = append(out, nodeID)
	}
	sort.Ints(out)
	return out, nil
}

func resolveRemoteDeleteTargets(nodeIDs []int) ([]remoteClientDeleteTarget, error) {
	if len(nodeIDs) == 0 {
		return nil, nil
	}
	var mgr *runtime.Manager
	targets := make([]remoteClientDeleteTarget, 0, len(nodeIDs))
	nodeSvc := NodeService{}
	for _, nodeID := range nodeIDs {
		enabled, status, _, _, err := nodeSvc.NodeSyncState(nodeID)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Stale node_client_traffics history must not block deleting the
			// central client. A live inbound still referencing this missing node
			// is reported later by its per-inbound mutation path.
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("resolve node %d for client delete: %w", nodeID, err)
		}
		if !enabled {
			return nil, fmt.Errorf("node %d is disabled; client delete was not committed", nodeID)
		}
		if status != "online" {
			return nil, fmt.Errorf("node %d is not online (status %q); client delete was not committed", nodeID, status)
		}
		if mgr == nil {
			mgr = runtime.GetManager()
			if mgr == nil {
				return nil, fmt.Errorf("runtime manager not initialised")
			}
		}
		rt, err := mgr.RuntimeFor(&nodeID)
		if err != nil {
			return nil, fmt.Errorf("resolve runtime for node %d: %w", nodeID, err)
		}
		deleter, ok := rt.(remoteClientDeleter)
		if !ok {
			return nil, fmt.Errorf("runtime for node %d does not support full client delete", nodeID)
		}
		targets = append(targets, remoteClientDeleteTarget{nodeID: nodeID, deleter: deleter})
	}
	return targets, nil
}

func markNodesDirtyBestEffort(nodeIDs []int) {
	nodeSvc := NodeService{}
	seen := make(map[int]struct{}, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		if nodeID <= 0 {
			continue
		}
		if _, ok := seen[nodeID]; ok {
			continue
		}
		seen[nodeID] = struct{}{}
		if err := nodeSvc.MarkNodeDirty(nodeID); err != nil {
			logger.Warning("mark node dirty after incomplete client delete:", nodeID, err)
		}
	}
}

// deleteClientsFromRemoteNodes performs the destructive node operation before
// the central DB is changed. This makes global delete fail closed: if a node is
// unavailable, the central ClientRecord remains. If a later node fails after an
// earlier node succeeded, successful nodes are marked dirty so normal reconcile
// recreates the still-authoritative central state.
func deleteClientsFromRemoteNodes(
	ctx context.Context,
	nodeIDs []int,
	emails []string,
	keepTraffic bool,
) ([]int, error) {
	emails = normalizeClientEmails(emails)
	if len(nodeIDs) == 0 || len(emails) == 0 {
		return nil, nil
	}
	targets, err := resolveRemoteDeleteTargets(nodeIDs)
	if err != nil {
		return nil, err
	}

	succeeded := make([]int, 0, len(targets))
	for _, target := range targets {
		if err := target.deleter.DeleteClientRecords(ctx, emails, keepTraffic); err != nil {
			markNodesDirtyBestEffort(succeeded)
			return succeeded, fmt.Errorf("delete clients from node %d: %w", target.nodeID, err)
		}
		succeeded = append(succeeded, target.nodeID)
	}
	return succeeded, nil
}
