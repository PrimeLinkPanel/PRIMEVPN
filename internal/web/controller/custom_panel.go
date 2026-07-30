package controller

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/logger"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/sub"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/web/service"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/web/session"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const customPanelMaxBodyBytes = 64 << 10
const customPanelMillisPerDay = int64(24 * 60 * 60 * 1000)

type CustomPanelController struct {
	clientService  service.ClientService
	inboundService service.InboundService
	xrayService    service.XrayService
}

type customPanelRequest struct {
	Action    string          `json:"action"`
	Username  string          `json:"username"`
	DataLimit *int64          `json:"data_limit"`
	Expire    *int64          `json:"expire"`
	Note      *string         `json:"note"`
	Config    json.RawMessage `json:"config"`
	Status    *string         `json:"status"`
	Volume    *int64          `json:"volume"`
	Time      *int64          `json:"time"`
}

type customPanelModifyConfig struct {
	Status    *string `json:"status"`
	DataLimit *int64  `json:"data_limit"`
	Expire    *int64  `json:"expire"`
	Note      *string `json:"note"`
}

type customPanelPublicError struct {
	message string
}

func (e *customPanelPublicError) Error() string {
	return e.message
}

func newCustomPanelPublicError(message string) error {
	return &customPanelPublicError{message: message}
}

func customPanelPublicMessage(err error) string {
	if err == nil {
		return ""
	}
	var publicErr *customPanelPublicError
	if errors.As(err, &publicErr) {
		return publicErr.message
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "User not found"
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "email already in use") ||
		strings.Contains(message, "duplicate email") ||
		strings.Contains(message, "unique constraint failed: clients.email") {
		return "Username already exists"
	}
	return "Operation failed"
}

func customPanelWriteError(c *gin.Context, action string, err error) {
	message := customPanelPublicMessage(err)
	if message == "" {
		message = "Operation failed"
	}
	logger.Warningf("custom panel action %q failed: %v", action, err)
	c.JSON(http.StatusOK, gin.H{
		"status":  "error",
		"message": message,
	})
}

func customPanelWriteSuccess(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func decodeCustomPanelRequest(c *gin.Context) (*customPanelRequest, error) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, customPanelMaxBodyBytes)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()

	var request customPanelRequest
	if err := decoder.Decode(&request); err != nil {
		return nil, newCustomPanelPublicError("Invalid request")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, newCustomPanelPublicError("Invalid request")
	}
	request.Action = strings.ToLower(strings.TrimSpace(request.Action))
	if request.Action == "" {
		return nil, newCustomPanelPublicError("Invalid request")
	}
	return &request, nil
}

func decodeCustomPanelModifyConfig(raw json.RawMessage) (*customPanelModifyConfig, error) {
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, newCustomPanelPublicError("Invalid request")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()

	var config customPanelModifyConfig
	if err := decoder.Decode(&config); err != nil {
		return nil, newCustomPanelPublicError("Invalid request")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, newCustomPanelPublicError("Invalid request")
	}
	if config.Status == nil && config.DataLimit == nil && config.Expire == nil && config.Note == nil {
		return nil, newCustomPanelPublicError("Invalid request")
	}
	return &config, nil
}

func customPanelUsername(raw string, requireMinimum bool) (string, error) {
	username := strings.TrimSpace(raw)
	if username == "" {
		return "", newCustomPanelPublicError("Invalid request")
	}
	if requireMinimum && utf8.RuneCountInString(username) < 3 {
		return "", newCustomPanelPublicError("Invalid request")
	}
	return username, nil
}

func customPanelStatus(raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "active":
		return true, nil
	case "disabled":
		return false, nil
	default:
		return false, newCustomPanelPublicError("Invalid request")
	}
}

func customPanelExpiryMilliseconds(seconds int64) (int64, error) {
	if seconds < 0 || seconds > math.MaxInt64/1000 {
		return 0, newCustomPanelPublicError("Invalid request")
	}
	return seconds * 1000, nil
}

func customPanelExpirySeconds(milliseconds int64) (int64, error) {
	if milliseconds < 0 {
		return 0, newCustomPanelPublicError("Unsupported expiry mode")
	}
	return milliseconds / 1000, nil
}

func (a *CustomPanelController) user(c *gin.Context) (*model.User, error) {
	user := session.GetLoginUser(c)
	if user == nil || user.Id <= 0 {
		return nil, newCustomPanelPublicError("Invalid API Key")
	}
	return user, nil
}

func (a *CustomPanelController) requireClient(c *gin.Context, permission string, username string) (*model.ClientRecord, []int, error) {
	user, err := a.user(c)
	if err != nil {
		return nil, nil, err
	}
	scope := a.clientService.ClientAccessScopeForAdmin(user, permission)
	record, err := a.clientService.RequireClientForScopeByEmail(scope, username)
	if err != nil {
		return nil, nil, err
	}
	inboundIDs, err := a.clientService.GetInboundIdsForRecord(record.Id)
	if err != nil {
		return nil, nil, err
	}
	if !service.ClientInboundsAllowedForScope(scope, inboundIDs) {
		return nil, nil, gorm.ErrRecordNotFound
	}
	return record, inboundIDs, nil
}

func (a *CustomPanelController) subscriptionDetails(c *gin.Context, record *model.ClientRecord) (string, []string, error) {
	if record == nil {
		return "", nil, gorm.ErrRecordNotFound
	}
	subscriptionURL, err := sub.BuildSubscriptionURL(resolveHost(c), record.SubID)
	if err != nil {
		return "", nil, err
	}
	links, err := a.inboundService.GetAllClientLinks(resolveHost(c), record.Email)
	if err != nil {
		logger.Warningf("custom panel links for %q failed: %v", record.Email, err)
		links = []string{}
	}
	if links == nil {
		links = []string{}
	}
	return subscriptionURL, links, nil
}

func (a *CustomPanelController) markMutation(needRestart bool) {
	if needRestart {
		a.xrayService.SetToNeedRestart()
	}
	notifyClientsChanged()
}

func (a *CustomPanelController) handle(c *gin.Context) {
	request, err := decodeCustomPanelRequest(c)
	if err != nil {
		customPanelWriteError(c, "", err)
		return
	}

	switch request.Action {
	case "create_user":
		err = a.createUser(c, request)
	case "get_user":
		err = a.getUser(c, request)
	case "remove_user":
		err = a.removeUser(c, request)
	case "reset_user":
		err = a.resetUser(c, request)
	case "extend_user":
		err = a.extendUser(c, request)
	case "modify_user":
		err = a.modifyUser(c, request)
	case "change_status":
		err = a.changeStatus(c, request)
	case "count_users":
		err = a.countUsers(c)
	case "revoke_sub":
		err = a.revokeSubscription(c, request)
	case "extra_volume":
		err = a.extraVolume(c, request)
	case "extra_time":
		err = a.extraTime(c, request)
	default:
		err = newCustomPanelPublicError("Unknown action")
	}
	if err != nil {
		customPanelWriteError(c, request.Action, err)
	}
}

func (a *CustomPanelController) createUser(c *gin.Context, request *customPanelRequest) error {
	username, err := customPanelUsername(request.Username, true)
	if err != nil {
		return err
	}
	if request.DataLimit == nil || *request.DataLimit < 0 || request.Expire == nil {
		return newCustomPanelPublicError("Invalid request")
	}
	expiry, err := customPanelExpiryMilliseconds(*request.Expire)
	if err != nil {
		return err
	}
	user, err := a.user(c)
	if err != nil {
		return err
	}
	restricted, inboundIDs := a.clientService.RestrictedInboundIDsForAdmin(user)
	if !restricted || len(inboundIDs) == 0 {
		return newCustomPanelPublicError("Custom panel administrator requires explicit inbound access")
	}
	subID := uuid.NewString()
	subscriptionURL, err := sub.BuildSubscriptionURL(resolveHost(c), subID)
	if err != nil {
		return err
	}

	note := ""
	if request.Note != nil {
		note = *request.Note
	}
	payload := service.ClientCreatePayload{
		Client: model.Client{
			Email:      username,
			TotalGB:    *request.DataLimit,
			ExpiryTime: expiry,
			Enable:     true,
			Comment:    note,
			SubID:      subID,
		},
		InboundIds: append([]int(nil), inboundIDs...),
	}
	needRestart, err := a.clientService.CreateForAdmin(&a.inboundService, &payload, user)
	if err != nil {
		return err
	}
	a.markMutation(needRestart)
	links, linkErr := a.inboundService.GetAllClientLinks(resolveHost(c), username)
	if linkErr != nil {
		logger.Warningf("custom panel links for %q failed after create: %v", username, linkErr)
		links = []string{}
	}
	if links == nil {
		links = []string{}
	}
	c.JSON(http.StatusOK, gin.H{
		"status":           "success",
		"username":         username,
		"subscription_url": subscriptionURL,
		"configs":          links,
	})
	return nil
}

func (a *CustomPanelController) getUser(c *gin.Context, request *customPanelRequest) error {
	username, err := customPanelUsername(request.Username, false)
	if err != nil {
		return err
	}
	record, _, err := a.requireClient(c, "view", username)
	if err != nil {
		return err
	}
	expiry, err := customPanelExpirySeconds(record.ExpiryTime)
	if err != nil {
		return err
	}
	usedTraffic := int64(0)
	traffic, trafficErr := a.inboundService.GetClientTrafficByEmail(username)
	if trafficErr != nil {
		return trafficErr
	}
	if traffic != nil {
		usedTraffic = traffic.Up + traffic.Down
	}
	subscriptionURL, links, err := a.subscriptionDetails(c, record)
	if err != nil {
		return err
	}
	c.JSON(http.StatusOK, gin.H{
		"status":           "success",
		"username":         username,
		"data_limit":       record.TotalGB,
		"expire":           expiry,
		"used_traffic":     usedTraffic,
		"links":            links,
		"subscription_url": subscriptionURL,
	})
	return nil
}

func (a *CustomPanelController) removeUser(c *gin.Context, request *customPanelRequest) error {
	username, err := customPanelUsername(request.Username, false)
	if err != nil {
		return err
	}
	if _, _, err := a.requireClient(c, "delete", username); err != nil {
		return err
	}
	needRestart, err := a.clientService.DeleteByEmail(&a.inboundService, username, false)
	if err != nil {
		return err
	}
	a.markMutation(needRestart)
	customPanelWriteSuccess(c)
	return nil
}

func (a *CustomPanelController) resetUser(c *gin.Context, request *customPanelRequest) error {
	username, err := customPanelUsername(request.Username, false)
	if err != nil {
		return err
	}
	if _, _, err := a.requireClient(c, "resetUsage", username); err != nil {
		return err
	}
	user, err := a.user(c)
	if err != nil {
		return err
	}
	if err := a.clientService.ValidateAdminRoleFeatureForAdmin(user, "can_use_reset_strategy"); err != nil {
		return err
	}
	needRestart, err := a.clientService.ResetTrafficByEmail(&a.inboundService, username)
	if err != nil {
		return err
	}
	a.markMutation(needRestart)
	customPanelWriteSuccess(c)
	return nil
}

func (a *CustomPanelController) extendUser(c *gin.Context, request *customPanelRequest) error {
	username, err := customPanelUsername(request.Username, false)
	if err != nil {
		return err
	}
	if request.DataLimit == nil || *request.DataLimit < 0 || request.Expire == nil {
		return newCustomPanelPublicError("Invalid request")
	}
	expiry, err := customPanelExpiryMilliseconds(*request.Expire)
	if err != nil {
		return err
	}
	record, _, err := a.requireClient(c, "update", username)
	if err != nil {
		return err
	}
	updated := record.ToClient()
	updated.TotalGB = *request.DataLimit
	updated.ExpiryTime = expiry
	user, err := a.user(c)
	if err != nil {
		return err
	}
	if err := a.clientService.ValidateClientLimitsForAdmin(user, *updated, false); err != nil {
		return err
	}
	needRestart, err := a.clientService.UpdateByEmail(&a.inboundService, username, *updated)
	if err != nil {
		return err
	}
	a.markMutation(needRestart)
	customPanelWriteSuccess(c)
	return nil
}

func (a *CustomPanelController) modifyUser(c *gin.Context, request *customPanelRequest) error {
	username, err := customPanelUsername(request.Username, false)
	if err != nil {
		return err
	}
	config, err := decodeCustomPanelModifyConfig(request.Config)
	if err != nil {
		return err
	}
	record, _, err := a.requireClient(c, "update", username)
	if err != nil {
		return err
	}
	updated := record.ToClient()
	limitsChanged := false
	if config.Status != nil {
		enable, err := customPanelStatus(*config.Status)
		if err != nil {
			return err
		}
		updated.Enable = enable
	}
	if config.DataLimit != nil {
		if *config.DataLimit < 0 {
			return newCustomPanelPublicError("Invalid request")
		}
		updated.TotalGB = *config.DataLimit
		limitsChanged = true
	}
	if config.Expire != nil {
		expiry, err := customPanelExpiryMilliseconds(*config.Expire)
		if err != nil {
			return err
		}
		updated.ExpiryTime = expiry
		limitsChanged = true
	}
	if config.Note != nil {
		updated.Comment = *config.Note
	}
	user, err := a.user(c)
	if err != nil {
		return err
	}
	if limitsChanged {
		if err := a.clientService.ValidateClientLimitsForAdmin(user, *updated, false); err != nil {
			return err
		}
	}
	needRestart, err := a.clientService.UpdateByEmail(&a.inboundService, username, *updated)
	if err != nil {
		return err
	}
	a.markMutation(needRestart)
	c.JSON(http.StatusOK, gin.H{
		"status": "success",
		"data":   gin.H{},
	})
	return nil
}

func (a *CustomPanelController) changeStatus(c *gin.Context, request *customPanelRequest) error {
	username, err := customPanelUsername(request.Username, false)
	if err != nil {
		return err
	}
	if request.Status == nil {
		return newCustomPanelPublicError("Invalid request")
	}
	enable, err := customPanelStatus(*request.Status)
	if err != nil {
		return err
	}
	if _, _, err := a.requireClient(c, "update", username); err != nil {
		return err
	}
	result, needRestart, err := a.clientService.BulkSetEnable(&a.inboundService, []string{username}, enable)
	if err != nil {
		return err
	}
	if result.Changed != 1 {
		if len(result.Skipped) > 0 {
			return newCustomPanelPublicError(result.Skipped[0].Reason)
		}
		return newCustomPanelPublicError("Operation failed")
	}
	a.markMutation(needRestart)
	customPanelWriteSuccess(c)
	return nil
}

func (a *CustomPanelController) countUsers(c *gin.Context) error {
	user, err := a.user(c)
	if err != nil {
		return err
	}
	scope := a.clientService.ClientAccessScopeForAdmin(user, "view")
	clients, err := a.clientService.ListForScope(scope)
	if err != nil {
		return err
	}
	count := 0
	for _, client := range clients {
		if client.Enable && service.ClientInboundsAllowedForScope(scope, client.InboundIds) {
			count++
		}
	}
	c.JSON(http.StatusOK, gin.H{"count": count})
	return nil
}

func (a *CustomPanelController) revokeSubscription(c *gin.Context, request *customPanelRequest) error {
	username, err := customPanelUsername(request.Username, false)
	if err != nil {
		return err
	}
	record, _, err := a.requireClient(c, "revokeSubscription", username)
	if err != nil {
		return err
	}
	updated := record.ToClient()
	updated.SubID = uuid.NewString()
	subscriptionURL, err := sub.BuildSubscriptionURL(resolveHost(c), updated.SubID)
	if err != nil {
		return err
	}
	needRestart, err := a.clientService.UpdateByEmail(&a.inboundService, username, *updated)
	if err != nil {
		return err
	}
	a.markMutation(needRestart)
	links, linkErr := a.inboundService.GetAllClientLinks(resolveHost(c), username)
	if linkErr != nil {
		logger.Warningf("custom panel links for %q failed after revoke: %v", username, linkErr)
		links = []string{}
	}
	if links == nil {
		links = []string{}
	}
	c.JSON(http.StatusOK, gin.H{
		"status":           "success",
		"subscription_url": subscriptionURL,
		"configs":          links,
	})
	return nil
}

func (a *CustomPanelController) extraVolume(c *gin.Context, request *customPanelRequest) error {
	username, err := customPanelUsername(request.Username, false)
	if err != nil {
		return err
	}
	if request.Volume == nil || *request.Volume <= 0 {
		return newCustomPanelPublicError("Invalid request")
	}
	record, _, err := a.requireClient(c, "update", username)
	if err != nil {
		return err
	}
	if record.TotalGB > math.MaxInt64-*request.Volume {
		return newCustomPanelPublicError("Invalid request")
	}
	user, err := a.user(c)
	if err != nil {
		return err
	}
	result, needRestart, err := a.clientService.BulkAdjustForAdmin(
		&a.inboundService,
		[]string{username},
		0,
		*request.Volume,
		"",
		user,
	)
	if err != nil {
		return err
	}
	if result.Adjusted != 1 {
		if len(result.Skipped) > 0 {
			return newCustomPanelPublicError(result.Skipped[0].Reason)
		}
		return newCustomPanelPublicError("Operation failed")
	}
	a.markMutation(needRestart)
	customPanelWriteSuccess(c)
	return nil
}

func (a *CustomPanelController) extraTime(c *gin.Context, request *customPanelRequest) error {
	username, err := customPanelUsername(request.Username, false)
	if err != nil {
		return err
	}
	if request.Time == nil || *request.Time <= 0 || *request.Time > int64(math.MaxInt) {
		return newCustomPanelPublicError("Invalid request")
	}
	record, _, err := a.requireClient(c, "update", username)
	if err != nil {
		return err
	}
	if record.ExpiryTime < 0 || *request.Time > math.MaxInt64/customPanelMillisPerDay {
		return newCustomPanelPublicError("Unsupported expiry mode")
	}
	if record.ExpiryTime > 0 && record.ExpiryTime > math.MaxInt64-(*request.Time*customPanelMillisPerDay) {
		return newCustomPanelPublicError("Invalid request")
	}
	user, err := a.user(c)
	if err != nil {
		return err
	}
	result, needRestart, err := a.clientService.BulkAdjustForAdmin(
		&a.inboundService,
		[]string{username},
		int(*request.Time),
		0,
		"",
		user,
	)
	if err != nil {
		return err
	}
	if result.Adjusted != 1 {
		if len(result.Skipped) > 0 {
			return newCustomPanelPublicError(result.Skipped[0].Reason)
		}
		return newCustomPanelPublicError("Operation failed")
	}
	a.markMutation(needRestart)
	customPanelWriteSuccess(c)
	return nil
}
