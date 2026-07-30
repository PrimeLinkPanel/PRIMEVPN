package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
)

// SyncClientActivity applies authoritative parent state on a child and pulls
// an incremental absolute Activity snapshot in the same authenticated request.
func (r *Remote) SyncClientActivity(
	ctx context.Context,
	request *model.ClientActivitySyncRequest,
) (*model.ClientActivitySyncResponse, error) {
	env, err := r.do(
		ctx,
		http.MethodPost,
		"panel/api/clients/activity/node-sync",
		request,
	)
	if err != nil {
		return nil, err
	}

	response := &model.ClientActivitySyncResponse{}
	if len(env.Obj) > 0 {
		if err := json.Unmarshal(env.Obj, response); err != nil {
			return nil, fmt.Errorf("decode client Activity sync: %w", err)
		}
	}
	if response.Items == nil {
		response.Items = []model.ClientActivitySyncItem{}
	}
	return response, nil
}
