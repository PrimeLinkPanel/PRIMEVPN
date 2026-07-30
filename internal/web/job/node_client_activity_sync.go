package job

import (
	"context"
	"strings"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/logger"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/web/runtime"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/web/service"
)

func (j *NodeTrafficSyncJob) clientActivityCursors(
	nodeID int,
) model.ClientActivitySyncCursors {
	j.activitySyncMu.Lock()
	defer j.activitySyncMu.Unlock()
	return j.activityCursors[nodeID]
}

func (j *NodeTrafficSyncJob) setClientActivityCursors(
	nodeID int,
	cursors model.ClientActivitySyncCursors,
) {
	j.activitySyncMu.Lock()
	defer j.activitySyncMu.Unlock()
	j.activityCursors[nodeID] = cursors
}

func (j *NodeTrafficSyncJob) syncClientActivity(
	node *model.Node,
	remote *runtime.Remote,
) {
	if node == nil || remote == nil {
		return
	}

	activityService := &service.ClientActivityService{}
	states, err := activityService.ListNodeSyncStates(node.Id)
	if err != nil {
		logger.Warningf(
			"node Activity sync: load states for %s failed: %v",
			node.Name,
			err,
		)
		return
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		nodeTrafficSyncRequestTimeout,
	)
	defer cancel()

	response, err := remote.SyncClientActivity(
		ctx,
		&model.ClientActivitySyncRequest{
			States:  states,
			Cursors: j.clientActivityCursors(node.Id),
		},
	)
	if err != nil {
		if strings.Contains(err.Error(), "HTTP 404") {
			if _, seen := j.noActivitySyncEndpoint.LoadOrStore(
				node.Id,
				true,
			); !seen {
				logger.Debugf(
					"node Activity sync: node %s has no Activity replication endpoint (old build)",
					node.Name,
				)
			}
			return
		}
		logger.Warningf(
			"node Activity sync: exchange with %s failed: %v",
			node.Name,
			err,
		)
		return
	}
	j.noActivitySyncEndpoint.Delete(node.Id)

	panelGUID, err := j.settingService.GetPanelGuid()
	if err != nil || strings.TrimSpace(panelGUID) == "" {
		logger.Warningf(
			"node Activity sync: get local panel GUID failed: %v",
			err,
		)
		return
	}

	if err := activityService.MergeNodeActivity(panelGUID, response); err != nil {
		logger.Warningf(
			"node Activity sync: merge from %s failed: %v",
			node.Name,
			err,
		)
		return
	}

	// Cursors advance only after the absolute rows are durably merged. A failed
	// merge therefore retries the same idempotent page on the next tick.
	j.setClientActivityCursors(node.Id, response.Cursors)

	if response.HasMore {
		// Do not spin inside one traffic tick; the next 5-second run continues
		// from the committed cursor and keeps node RPC latency bounded.
		logger.Debugf(
			"node Activity sync: %s has another Activity page pending",
			node.Name,
		)
	}
}
