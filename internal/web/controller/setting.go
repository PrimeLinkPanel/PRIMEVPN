package controller

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/logger"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/util/crypto"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/web/entity"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/web/middleware"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/web/service"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/web/service/email"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/web/service/panel"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/web/session"

	"github.com/gin-gonic/gin"
)

// updateUserForm represents the form for updating user credentials.
type updateUserForm struct {
	OldUsername   string `json:"oldUsername" form:"oldUsername"`
	OldPassword   string `json:"oldPassword" form:"oldPassword"`
	NewUsername   string `json:"newUsername" form:"newUsername"`
	NewPassword   string `json:"newPassword" form:"newPassword"`
	TwoFactorCode string `json:"twoFactorCode" form:"twoFactorCode"`
}

// updateSettingForm carries the persisted settings plus request-scoped fields
// that must never land in the settings table: the 2FA confirmation code and
// the explicit clear flags for redacted secrets (a blank secret alone means
// "unchanged", so clearing needs its own signal — see #5724).
type updateSettingForm struct {
	entity.AllSetting
	TwoFactorCode     string `json:"twoFactorCode" form:"twoFactorCode"`
	ClearTgBotToken   bool   `json:"clearTgBotToken" form:"clearTgBotToken"`
	ClearLdapPassword bool   `json:"clearLdapPassword" form:"clearLdapPassword"`
	ClearSmtpPassword bool   `json:"clearSmtpPassword" form:"clearSmtpPassword"`
}

// SettingController handles settings and user management operations.
type SettingController struct {
	settingService  service.SettingService
	userService     panel.UserService
	panelService    panel.PanelService
	apiTokenService panel.ApiTokenService
	xrayService     service.XrayService
}

// NewSettingController creates a new SettingController and initializes its routes.
func NewSettingController(g *gin.RouterGroup) *SettingController {
	a := &SettingController{}
	a.initRouter(g)
	return a
}

// initRouter sets up the routes for settings management.
func (a *SettingController) initRouter(g *gin.RouterGroup) {
	g = g.Group("/setting")

	g.POST("/all", requirePanelPermission("settings", "view"), a.getAllSetting)
	g.POST("/defaultSettings", requireAnyPanelPermission(
		panelPermissionRequirement{Section: "settings", Permission: "viewGeneral"},
		// Clients and Inbounds pages need these computed defaults for list/form UX
		// even when the operator has no access to Panel Settings itself.
		panelPermissionRequirement{Section: "users", Permission: "view"},
		panelPermissionRequirement{Section: "users", Permission: "create"},
		panelPermissionRequirement{Section: "users", Permission: "update"},
		panelPermissionRequirement{Section: "inbounds", Permission: "view"},
		panelPermissionRequirement{Section: "inbounds", Permission: "viewSimple"},
		panelPermissionRequirement{Section: "inbounds", Permission: "create"},
		panelPermissionRequirement{Section: "inbounds", Permission: "update"},
	), a.getDefaultSettings)
	g.POST("/update", requirePanelPermission("settings", "update"), a.updateSetting)
	// Updating the current admin's own username/password is protected by the old password check in updateUser.
	g.POST("/updateUser", a.updateUser)
	g.POST("/restartPanel", requirePanelPermission("settings", "update"), a.restartPanel)
	g.GET("/getDefaultJsonConfig", requirePanelPermission("settings", "viewGeneral"), a.getDefaultXrayConfig)
	// API token lifecycle is an owner-only browser operation. Bearer and mTLS
	// callers are rejected by requireOwnerAdminMiddleware even when they are
	// trusted service principals.
	g.GET("/apiTokens", requireOwnerAdminMiddleware(), a.listApiTokens)
	g.GET("/apiTokens/subjects", requireOwnerAdminMiddleware(), a.listApiTokenSubjects)
	g.POST("/apiTokens/create", requireOwnerAdminMiddleware(), a.createApiToken)
	g.POST("/apiTokens/delete/:id", requireOwnerAdminMiddleware(), a.deleteApiToken)
	g.POST("/apiTokens/setEnabled/:id", requireOwnerAdminMiddleware(), a.setApiTokenEnabled)
	g.POST("/testSmtp", requirePanelPermission("settings", "update"), a.testSmtp)
	g.POST("/testTgBot", requirePanelPermission("settings", "update"), a.testTgBot)
}

// getAllSetting retrieves all current settings as the browser-safe view:
// secret values are redacted and surfaced as has* presence flags instead.
func (a *SettingController) getAllSetting(c *gin.Context) {
	allSetting, err := a.settingService.GetAllSettingView()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.getSettings"), err)
		return
	}
	jsonObj(c, allSetting, nil)
}

// getDefaultSettings retrieves the default settings based on the host.
func (a *SettingController) getDefaultSettings(c *gin.Context) {
	result, err := a.settingService.GetDefaultSettings(c.Request.Host)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.getSettings"), err)
		return
	}
	jsonObj(c, result, nil)
}

// updateSetting updates all settings with the provided data.
func (a *SettingController) updateSetting(c *gin.Context) {
	form, ok := middleware.BindAndValidate[updateSettingForm](c)
	if !ok {
		return
	}
	allSetting := &form.AllSetting
	oldTwoFactor, twoFactorErr := a.settingService.GetTwoFactorEnable()
	oldPanelOutbound, _ := a.settingService.GetPanelOutbound()
	oldTgEnable, _ := a.settingService.GetTgbotEnabled()
	oldTgToken, _ := a.settingService.GetTgBotToken()
	oldTgChatId, _ := a.settingService.GetTgBotChatId()
	oldTgAPIServer, _ := a.settingService.GetTgBotAPIServer()
	if twoFactorErr == nil && oldTwoFactor && !allSetting.TwoFactorEnable {
		if err := a.settingService.VerifyTwoFactorCode(form.TwoFactorCode); err != nil {
			jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), err)
			return
		}
	}
	err := a.settingService.UpdateAllSetting(allSetting, service.SecretClears{
		TgBotToken:   form.ClearTgBotToken,
		LdapPassword: form.ClearLdapPassword,
		SmtpPassword: form.ClearSmtpPassword,
	})
	if err == nil && twoFactorErr == nil && !oldTwoFactor && allSetting.TwoFactorEnable {
		if bumpErr := a.userService.BumpLoginEpoch(); bumpErr != nil {
			err = bumpErr
		}
	}
	if err == nil && form.PanelOutbound != oldPanelOutbound {
		// The egress bridge lives in the generated config; reconcile the
		// running core. One SOCKS inbound plus one routing rule — both
		// hot-appliable, so this normally does not restart Xray.
		if applyErr := a.xrayService.RestartXray(false); applyErr != nil {
			logger.Warning("apply panel outbound change failed:", applyErr)
		}
	}
	// UpdateAllSetting already restored a redacted-blank token, so allSetting.TgBotToken is the effective value to compare.
	if err == nil && reloadTgbotFunc != nil {
		tgChanged := oldTgEnable != allSetting.TgBotEnable ||
			(allSetting.TgBotEnable && (oldTgToken != allSetting.TgBotToken ||
				oldTgChatId != allSetting.TgBotChatId ||
				oldTgAPIServer != allSetting.TgBotAPIServer))
		if tgChanged {
			reloadTgbotFunc()
		}
	}
	jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), err)
}

// updateUser updates the current user's username and password.
func (a *SettingController) updateUser(c *gin.Context) {
	form := &updateUserForm{}
	err := c.ShouldBind(form)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), err)
		return
	}
	user := session.GetLoginUser(c)
	if user.Username != form.OldUsername || !crypto.CheckPasswordHash(user.Password, form.OldPassword) {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifyUserError"), errors.New(I18nWeb(c, "pages.settings.toasts.originalUserPassIncorrect")))
		return
	}
	if form.NewUsername == "" || form.NewPassword == "" {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifyUserError"), errors.New(I18nWeb(c, "pages.settings.toasts.userPassMustBeNotEmpty")))
		return
	}
	if err := a.settingService.VerifyTwoFactorCode(form.TwoFactorCode); err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifyUserError"), err)
		return
	}
	err = a.userService.UpdateUser(user.Id, form.NewUsername, form.NewPassword)
	if err == nil {
		user.Username = form.NewUsername
		user.Password, _ = crypto.HashPasswordAsBcrypt(form.NewPassword)
		if saveErr := session.SetLoginUser(c, user); saveErr != nil {
			err = saveErr
		}
	}
	jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifyUser"), err)
}

// restartPanel restarts the panel service after a delay.
func (a *SettingController) restartPanel(c *gin.Context) {
	err := a.panelService.RestartPanel(time.Second * 3)
	jsonMsg(c, I18nWeb(c, "pages.settings.restartPanelSuccess"), err)
}

// getDefaultXrayConfig retrieves the default Xray configuration.
func (a *SettingController) getDefaultXrayConfig(c *gin.Context) {
	defaultJsonConfig, err := a.settingService.GetDefaultXrayConfig()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.getSettings"), err)
		return
	}
	jsonObj(c, defaultJsonConfig, nil)
}

type apiTokenCreateForm struct {
	Name           string   `json:"name" form:"name"`
	Kind           string   `json:"kind" form:"kind"`
	SubjectAdminId int      `json:"subjectAdminId" form:"subjectAdminId"`
	Scopes         []string `json:"scopes" form:"scopes"`
	ExpiresAt      int64    `json:"expiresAt" form:"expiresAt"`
}

type apiTokenEnabledForm struct {
	Enabled bool `json:"enabled" form:"enabled"`
}

func (a *SettingController) listApiTokens(c *gin.Context) {
	rows, err := a.apiTokenService.List()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.getSettings"), err)
		return
	}
	jsonObj(c, rows, nil)
}

func (a *SettingController) listApiTokenSubjects(c *gin.Context) {
	rows, err := a.apiTokenService.ListDelegatedSubjects()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.getSettings"), err)
		return
	}
	jsonObj(c, rows, nil)
}

func (a *SettingController) createApiToken(c *gin.Context) {
	form := &apiTokenCreateForm{}
	if err := c.ShouldBind(form); err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), err)
		return
	}
	owner := session.GetLoginUser(c)
	if owner == nil {
		pureJsonMsg(c, http.StatusUnauthorized, false, "login required")
		return
	}
	// An omitted kind preserves the historical owner-created service-token
	// request shape ({"name":"..."}) used for remote-panel integrations.
	// The delegated-token UI always sends kind=delegated explicitly.
	kind := strings.ToLower(strings.TrimSpace(form.Kind))
	if kind == "" {
		kind = model.ApiTokenKindService
	}
	row, err := a.apiTokenService.CreateWithOptions(panel.ApiTokenCreateOptions{
		Name:             form.Name,
		Kind:             kind,
		SubjectAdminId:   form.SubjectAdminId,
		CreatedByAdminId: owner.Id,
		Scopes:           form.Scopes,
		ExpiresAt:        form.ExpiresAt,
	})
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), err)
		return
	}
	jsonObj(c, row, nil)
}

func (a *SettingController) deleteApiToken(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), err)
		return
	}
	jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), a.apiTokenService.Delete(id))
}

func (a *SettingController) setApiTokenEnabled(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), err)
		return
	}
	form := &apiTokenEnabledForm{}
	if bindErr := c.ShouldBind(form); bindErr != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), bindErr)
		return
	}
	jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), a.apiTokenService.SetEnabled(id, form.Enabled))
}

func (a *SettingController) testSmtp(c *gin.Context) {
	if emailService == nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.smtpNotInitialized"), errors.New("email service not available"))
		return
	}
	logger.Info("SMTP test: starting...")
	result := emailService.TestConnection()
	if !result.Success {
		logger.Warning("SMTP test failed at", result.Stage+":", result.Message)
		c.JSON(200, gin.H{
			"success": false,
			"stage":   result.Stage,
			"msg":     result.Message,
		})
		return
	}
	logger.Info("SMTP test: success")
	c.JSON(200, gin.H{
		"success": true,
		"stage":   result.Stage,
		"msg":     result.Message,
	})
}

func (a *SettingController) testTgBot(c *gin.Context) {
	enabled, err := a.settingService.GetTgbotEnabled()
	if err != nil || !enabled {
		jsonMsg(c, I18nWeb(c, "pages.settings.tgBotNotEnabled"), errors.New("telegram bot disabled"))
		return
	}
	// Import tgbot package would create a circular dependency, so we call
	// the test through the global function registered at startup.
	if testTgFunc != nil {
		if err := testTgFunc(); err != nil {
			jsonMsg(c, I18nWeb(c, "pages.settings.tgTestFailed")+": "+err.Error(), err)
			return
		}
		jsonMsg(c, I18nWeb(c, "pages.settings.tgTestSuccess"), nil)
		return
	}
	jsonMsg(c, I18nWeb(c, "pages.settings.tgBotNotRunning"), errors.New("bot not started"))
}

// testTgFunc is set from web layer to test Telegram sending without circular imports.
var testTgFunc func() error

// SetTestTgFunc registers the function used to test Telegram sending.
func SetTestTgFunc(fn func() error) { testTgFunc = fn }

// reloadTgbotFunc is wired from the web layer; importing tgbot here would be a circular dependency.
var reloadTgbotFunc func()

func SetReloadTgbotFunc(fn func()) { reloadTgbotFunc = fn }

// emailService is set from web layer.
var emailService *email.EmailService

// SetEmailService registers the email service for test endpoints.
func SetEmailService(s *email.EmailService) { emailService = s }
