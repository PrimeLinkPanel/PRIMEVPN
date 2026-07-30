package sub

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"html/template"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/logger"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/web/service"
)

// writeSubError translates a service-layer result into an HTTP response.
// A nil error with no rows means the subId doesn't match anything (deleted
// client, never-existed id) and becomes 404. A real error becomes 500. No
// body — VPN clients only look at the status.
func writeSubError(c *gin.Context, err error) {
	if err == nil {
		c.Status(http.StatusNotFound)
		return
	}
	c.Status(http.StatusInternalServerError)
}

// splitSubscriptionInfoItems expands multi-line subscription entries for rich
// HTML templates. Raw subscription responses intentionally keep their existing
// behavior; this is only used by /sub/:subid/info so each profile appears as a
// separate row in templates such as Ourenus.
func splitSubscriptionInfoItems(items []string, emails []string) ([]string, []string) {
	if len(items) == 0 {
		return items, emails
	}

	flattenedItems := make([]string, 0, len(items))
	flattenedEmails := make([]string, 0, len(items))

	for index, item := range items {
		normalized := strings.ReplaceAll(item, "\r\n", "\n")
		normalized = strings.ReplaceAll(normalized, "\r", "\n")

		parts := strings.Split(normalized, "\n")
		email := ""
		if index < len(emails) {
			email = emails[index]
		}

		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			flattenedItems = append(flattenedItems, part)
			if len(emails) > 0 {
				flattenedEmails = append(flattenedEmails, email)
			}
		}
	}

	if len(flattenedItems) == 0 {
		return items, emails
	}

	return flattenedItems, flattenedEmails
}

// cachedSubTemplate holds a parsed custom subscription template together with
// the modification time of the file it was parsed from, so the cache can be
// invalidated when an admin edits the template on disk.
type cachedSubTemplate struct {
	tmpl    *template.Template
	modTime time.Time
}

// SUBController handles HTTP requests for subscription links and JSON configurations.
type SUBController struct {
	subTitle         string
	subSupportUrl    string
	subProfileUrl    string
	subAnnounce      string
	subEnableRouting bool
	subRoutingRules  string
	subHideSettings  bool

	subIncyEnableRouting bool
	subIncyRoutingRules  string

	subPath        string
	subJsonPath    string
	subClashPath   string
	jsonEnabled    bool
	clashEnabled   bool
	subEncrypt     bool
	updateInterval string

	subService      *SubService
	subJsonService  *SubJsonService
	subClashService *SubClashService
	settingService  service.SettingService

	subTemplateMu    sync.RWMutex
	subTemplateCache map[string]*cachedSubTemplate
}

// NewSUBController creates a new subscription controller with the given configuration.
func NewSUBController(
	g *gin.RouterGroup,
	subPath string,
	jsonPath string,
	clashPath string,
	jsonEnabled bool,
	clashEnabled bool,
	encrypt bool,
	remarkTemplate string,
	update string,
	jsonMux string,
	jsonRules string,
	jsonFinalMask string,
	clashEnableRouting bool,
	clashRules string,
	subTitle string,
	subSupportUrl string,
	subProfileUrl string,
	subAnnounce string,
	subEnableRouting bool,
	subRoutingRules string,
	subHideSettings bool,
	subIncyEnableRouting bool,
	subIncyRoutingRules string,
) *SUBController {
	sub := NewSubService(remarkTemplate)
	a := &SUBController{
		subTitle:         subTitle,
		subSupportUrl:    subSupportUrl,
		subProfileUrl:    subProfileUrl,
		subAnnounce:      subAnnounce,
		subEnableRouting: subEnableRouting,
		subRoutingRules:  subRoutingRules,
		subHideSettings:  subHideSettings,

		subIncyEnableRouting: subIncyEnableRouting,
		subIncyRoutingRules:  subIncyRoutingRules,

		subPath:        subPath,
		subJsonPath:    jsonPath,
		subClashPath:   clashPath,
		jsonEnabled:    jsonEnabled,
		clashEnabled:   clashEnabled,
		subEncrypt:     encrypt,
		updateInterval: update,

		subService:      sub,
		subJsonService:  NewSubJsonService(jsonMux, jsonRules, jsonFinalMask, sub),
		subClashService: NewSubClashService(clashEnableRouting, clashRules, sub),

		subTemplateCache: map[string]*cachedSubTemplate{},
	}
	a.initRouter(g)
	return a
}

// initRouter registers HTTP routes for subscription links and JSON endpoints
// on the provided router group.
func (a *SUBController) initRouter(g *gin.RouterGroup) {
	gLink := g.Group(a.subPath)
	gLink.GET(":subid", a.subs)
	gLink.HEAD(":subid", a.subs)
	gLink.GET(":subid/info", a.subInfo)
	gLink.HEAD(":subid/info", a.subInfo)
	if a.jsonEnabled {
		gJson := g.Group(a.subJsonPath)
		gJson.GET(":subid", a.subJsons)
		gJson.HEAD(":subid", a.subJsons)
	}
	if a.clashEnabled {
		gClash := g.Group(a.subClashPath)
		gClash.GET(":subid", a.subClashs)
		gClash.HEAD(":subid", a.subClashs)
	}
}

// maybeServeSubPage renders the HTML info page when the request comes from a
// browser (Accept: text/html) or explicitly asks for it (?html=1 or ?view=html).
// It reports whether the request was handled. The remark template's per-client
// info is for the content a client app imports — the raw subscription body. A
// browser viewing the HTML info page gets clean, name-only remarks (usage is
// shown in the page summary).
func (a *SUBController) maybeServeSubPage(c *gin.Context) bool {
	accept := c.GetHeader("Accept")
	wantsHTML := strings.Contains(strings.ToLower(accept), "text/html") || c.Query("html") == "1" || strings.EqualFold(c.Query("view"), "html")
	if !wantsHTML {
		return false
	}
	subId := c.Param("subid")
	_, host, _, hostHeader := a.subService.ResolveRequest(c)
	subReq := a.subService.ForRequest(host)
	subReq.subscriptionBody = false
	subs, emails, lastOnline, traffic, err := subReq.getSubs(subId)
	if err != nil || len(subs) == 0 {
		writeSubError(c, err)
		return true
	}
	subURL, subJsonURL, subClashURL := subReq.BuildURLs(a.subPath, a.subJsonPath, a.subClashPath, subId)
	if !a.jsonEnabled {
		subJsonURL = ""
	}
	if !a.clashEnabled {
		subClashURL = ""
	}
	basePath, exists := c.Get("base_path")
	if !exists {
		basePath = "/"
	}
	basePathStr := basePath.(string)
	page := subReq.BuildPageData(subId, hostHeader, traffic, lastOnline, subs, emails, subURL, subJsonURL, subClashURL, basePathStr, a.subTitle, a.subSupportUrl)
	a.serveSubPage(c, basePathStr, page)
	return true
}

// subs handles HTTP requests for subscription links, returning either HTML page or base64-encoded subscription data.
func (a *SUBController) subs(c *gin.Context) {
	if a.maybeServeSubPage(c) {
		return
	}
	subId := c.Param("subid")
	scheme, host, hostWithPort, _ := a.subService.ResolveRequest(c)
	subReq := a.subService.ForRequest(host)
	subReq.subscriptionBody = true
	subs, _, _, traffic, err := subReq.getSubs(subId)
	if err != nil || len(subs) == 0 {
		writeSubError(c, err)
	} else {
		var result strings.Builder
		for _, sub := range subs {
			result.WriteString(sub)
			result.WriteString("\n")
		}

		if a.jsonEnabled {
			clientImportFormat, _ := a.settingService.GetSubClientImportFormat()
			if strings.EqualFold(strings.TrimSpace(clientImportFormat), "json") {
				jsonSub, jsonHeader, jsonErr := a.subJsonService.GetJson(subId, host)
				if jsonErr == nil && len(jsonSub) > 0 {
					profileUrl := a.subProfileUrl
					if profileUrl == "" {
						profileUrl = fmt.Sprintf("%s://%s%s", scheme, hostWithPort, c.Request.RequestURI)
					}
					a.ApplyCommonHeaders(c, jsonHeader, a.updateInterval, a.subTitle, a.subSupportUrl, profileUrl, a.subAnnounce, a.subEnableRouting, a.subRoutingRules, false)
					c.String(http.StatusOK, jsonSub)
					return
				}
			}
		}

		// Add headers
		header := fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d", traffic.Up, traffic.Down, traffic.Total, traffic.ExpiryTime/1000)
		profileUrl := a.subProfileUrl
		if profileUrl == "" {
			profileUrl = fmt.Sprintf("%s://%s%s", scheme, hostWithPort, c.Request.RequestURI)
		}
		a.ApplyCommonHeaders(c, header, a.updateInterval, a.subTitle, a.subSupportUrl, profileUrl, a.subAnnounce, a.subEnableRouting, a.subRoutingRules, a.subHideSettings)

		if a.subIncyEnableRouting && a.subIncyRoutingRules != "" {
			result.WriteString(a.subIncyRoutingRules)
			result.WriteString("\n")
		}

		if a.subEncrypt {
			c.String(200, base64.StdEncoding.EncodeToString([]byte(result.String())))
		} else {
			c.String(200, result.String())
		}
	}
}

// subInfo returns a JSON view-model for rich subscription page templates such as Ourenus.
func (a *SUBController) subInfo(c *gin.Context) {
	subId := c.Param("subid")
	_, host, _, hostHeader := a.subService.ResolveRequest(c)
	subs, emails, lastOnline, traffic, err := a.subService.GetSubs(subId, host)
	if err != nil || len(subs) == 0 {
		writeSubError(c, err)
		return
	}

	subURL, subJsonURL, subClashURL := a.subService.BuildURLs(a.subPath, a.subJsonPath, a.subClashPath, subId)
	if !a.jsonEnabled {
		subJsonURL = ""
	}
	if !a.clashEnabled {
		subClashURL = ""
	}

	basePath, exists := c.Get("base_path")
	if !exists {
		basePath = "/"
	}
	basePathStr := basePath.(string)
	page := a.subService.BuildPageData(subId, hostHeader, traffic, lastOnline, subs, emails, subURL, subJsonURL, subClashURL, basePathStr, a.subTitle, a.subSupportUrl)

	usedTraffic := page.DownloadByte + page.UploadByte
	status := "disabled"
	if page.Enabled {
		status = "active"
	}

	infoItems, infoEmails := splitSubscriptionInfoItems(page.Result, page.Emails)

	subJsonLabel := "JSON Config"
	for _, itemEmail := range infoEmails {
		itemEmail = strings.TrimSpace(itemEmail)
		if itemEmail == "" {
			continue
		}
		if subJsonLabel == "JSON Config" || len([]rune(itemEmail)) < len([]rune(subJsonLabel)) {
			subJsonLabel = itemEmail
		}
	}

	clientSpeedLimits := a.getClientSpeedLimitsForSubID(subId)
	clientConnectionLimit := a.getClientConnectionLimitForSubID(subId)

	payload := gin.H{
		"sId":                       page.SId,
		"id":                        page.SId,
		"sub_id":                    page.SId,
		"username":                  page.SId,
		"name":                      page.SId,
		"status":                    status,
		"enabled":                   page.Enabled,
		"download":                  page.Download,
		"upload":                    page.Upload,
		"total":                     page.Total,
		"used":                      page.Used,
		"remained":                  page.Remained,
		"expire":                    page.Expire,
		"last_online":               page.LastOnline,
		"lastOnline":                page.LastOnline,
		"downloadByte":              page.DownloadByte,
		"uploadByte":                page.UploadByte,
		"totalByte":                 page.TotalByte,
		"data_limit":                page.TotalByte,
		"used_traffic":              usedTraffic,
		"subscription_url":          page.SubUrl,
		"subUrl":                    page.SubUrl,
		"subJsonUrl":                page.SubJsonUrl,
		"subJsonLabel":              subJsonLabel,
		"speedLimits":               clientSpeedLimits,
		"connectionLimit":           clientConnectionLimit,
		"subClashUrl":               page.SubClashUrl,
		"title":                     page.SubTitle,
		"subTitle":                  page.SubTitle,
		"support_url":               page.SubSupportUrl,
		"subSupportUrl":             page.SubSupportUrl,
		"links":                     infoItems,
		"configs":                   infoItems,
		"emails":                    infoEmails,
		"data_limit_reset_strategy": "no_reset",
	}

	setNoCacheHeaders(c)
	c.JSON(http.StatusOK, payload)
}

// serveSubPage renders internal/web/dist/subpage.html for the current subscription
// request. The Vite-built SPA reads window.__SUB_PAGE_DATA__ on mount —
// we inject that here, along with window.X_UI_BASE_PATH so the
// page's static asset references resolve correctly when the panel runs
// behind a URL prefix.
func (a *SUBController) serveSubPage(c *gin.Context, basePath string, page PageData) {
	var body []byte
	if diskBody, diskErr := os.ReadFile("internal/web/dist/subpage.html"); diskErr == nil {
		body = diskBody
	} else {
		readBody, err := distFS.ReadFile("dist/subpage.html")
		if err != nil {
			c.String(http.StatusInternalServerError, "missing embedded subpage")
			return
		}
		body = readBody
	}

	// Vite emits absolute asset URLs (`/assets/...`); when the panel is
	// installed under a custom URL prefix, rewrite them so the bundle
	// loads from `<basePath>assets/...` where the static handler is
	// actually mounted.
	if basePath != "/" && basePath != "" {
		body = bytes.ReplaceAll(body, []byte(`src="/assets/`), []byte(`src="`+basePath+`assets/`))
		body = bytes.ReplaceAll(body, []byte(`href="/assets/`), []byte(`href="`+basePath+`assets/`))
	}

	// JSON-marshal the view-model so the SPA can read it as a plain
	// The panel's "Calendar Type" setting decides whether the SubPage
	// renders dates in Gregorian or Jalali — surface it here so the SPA
	// can match the rest of the panel without a round-trip.
	datepicker, _ := a.settingService.GetDatepicker()
	if datepicker == "" {
		datepicker = "gregorian"
	}

	subData := map[string]any{
		"sId":           page.SId,
		"enabled":       page.Enabled,
		"download":      page.Download,
		"upload":        page.Upload,
		"total":         page.Total,
		"used":          page.Used,
		"remained":      page.Remained,
		"expire":        page.Expire,
		"lastOnline":    page.LastOnline,
		"downloadByte":  page.DownloadByte,
		"uploadByte":    page.UploadByte,
		"totalByte":     page.TotalByte,
		"subUrl":        page.SubUrl,
		"subJsonUrl":    page.SubJsonUrl,
		"subClashUrl":   page.SubClashUrl,
		"subTitle":      page.SubTitle,
		"subSupportUrl": page.SubSupportUrl,
		"links":         page.Result,
		"emails":        page.Emails,
		"datepicker":    datepicker,
		"announce":      a.subAnnounce,
	}

	const defaultPRIMEVPNSubThemeDir = "/usr/local/primevpn/sub_templates/ourenus"
	const sanaeiDefaultSubThemeDir = "__primevpn_sanaei_default__"

	themeDir, _ := a.settingService.GetSubThemeDir()
	themeDir = strings.TrimSpace(themeDir)
	if themeDir == "" {
		themeDir = defaultPRIMEVPNSubThemeDir
	} else if themeDir == sanaeiDefaultSubThemeDir {
		themeDir = ""
	}

	if themeDir != "" {
		if tmpl, err := a.loadSubTemplate(themeDir); err != nil {
			logger.Error("sub: custom template parse failed, using default page:", err)
		} else if tmpl == nil {
			logger.Warning("sub: subThemeDir set but no usable template found, using default page:", themeDir)
		} else {
			var buf bytes.Buffer
			if execErr := tmpl.Execute(&buf, subData); execErr != nil {
				logger.Error("sub: custom template execution failed, using default page:", execErr)
			} else {
				setNoCacheHeaders(c)
				c.Data(http.StatusOK, "text/html; charset=utf-8", buf.Bytes())
				return
			}
		}
	}

	subDataJSON, err := json.Marshal(subData)
	if err != nil {
		subDataJSON = []byte("{}")
	}

	// Defense-in-depth string-escape for the basePath embed — admin-
	// controlled but cheap to harden.
	jsEscape := strings.NewReplacer(
		`\`, `\\`,
		`"`, `\"`,
		"\n", `\n`,
		"\r", `\r`,
		"<", `<`,
		">", `>`,
		"&", `&`,
	)
	escapedBase := jsEscape.Replace(basePath)

	inject := []byte(`<script>window.X_UI_BASE_PATH="` + escapedBase + `";` +
		`window.__SUB_PAGE_DATA__=` + string(subDataJSON) + `;</script></head>`)
	out := bytes.Replace(body, []byte("</head>"), inject, 1)

	setNoCacheHeaders(c)
	c.Data(http.StatusOK, "text/html; charset=utf-8", out)
}

// setNoCacheHeaders marks a subscription page response as non-cacheable so VPN
// clients and browsers always fetch fresh traffic/expiry data.
func setNoCacheHeaders(c *gin.Context) {
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Pragma", "no-cache")
	c.Header("Expires", "0")
}

// loadSubTemplate returns the parsed custom subscription template located in
// themeDir, preferring sub.html over index.html. Parsed templates are cached and
// only re-parsed when the underlying file's modification time changes, so admin
// edits are picked up without paying a disk read + HTML parse on every request.
//
// It returns (nil, nil) when themeDir is not a usable directory or contains no
// template file — the caller should fall back to the default page. A non-nil
// error means a template file exists but failed to parse.
func (a *SUBController) loadSubTemplate(themeDir string) (*template.Template, error) {
	info, err := os.Stat(themeDir)
	if err != nil || !info.IsDir() {
		return nil, nil
	}

	templatePath := filepath.Join(themeDir, "index.html")
	if _, err := os.Stat(filepath.Join(themeDir, "sub.html")); err == nil {
		templatePath = filepath.Join(themeDir, "sub.html")
	}

	fi, err := os.Stat(templatePath)
	if err != nil {
		return nil, nil
	}
	modTime := fi.ModTime()

	a.subTemplateMu.RLock()
	cached := a.subTemplateCache[templatePath]
	a.subTemplateMu.RUnlock()
	if cached != nil && cached.modTime.Equal(modTime) {
		return cached.tmpl, nil
	}

	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		return nil, err
	}

	a.subTemplateMu.Lock()
	a.subTemplateCache[templatePath] = &cachedSubTemplate{tmpl: tmpl, modTime: modTime}
	a.subTemplateMu.Unlock()
	return tmpl, nil
}

// subJsons handles HTTP requests for JSON subscription configurations.
func (a *SUBController) subJsons(c *gin.Context) {
	if a.maybeServeSubPage(c) {
		return
	}
	subId := c.Param("subid")
	scheme, host, hostWithPort, _ := a.subService.ResolveRequest(c)
	jsonSub, header, err := a.subJsonService.GetJson(subId, host)
	if err != nil || len(jsonSub) == 0 {
		writeSubError(c, err)
	} else {
		profileUrl := a.subProfileUrl
		if profileUrl == "" {
			profileUrl = fmt.Sprintf("%s://%s%s", scheme, hostWithPort, c.Request.RequestURI)
		}
		a.ApplyCommonHeaders(c, header, a.updateInterval, a.subTitle, a.subSupportUrl, profileUrl, a.subAnnounce, a.subEnableRouting, a.subRoutingRules, a.subHideSettings)

		c.String(200, jsonSub)
	}
}

func (a *SUBController) subClashs(c *gin.Context) {
	if a.maybeServeSubPage(c) {
		return
	}
	subId := c.Param("subid")
	scheme, host, hostWithPort, _ := a.subService.ResolveRequest(c)
	clashSub, header, err := a.subClashService.GetClash(subId, host)
	if err != nil || len(clashSub) == 0 {
		writeSubError(c, err)
	} else {
		profileUrl := a.subProfileUrl
		if profileUrl == "" {
			profileUrl = fmt.Sprintf("%s://%s%s", scheme, hostWithPort, c.Request.RequestURI)
		}
		a.ApplyCommonHeaders(c, header, a.updateInterval, a.subTitle, a.subSupportUrl, profileUrl, a.subAnnounce, a.subEnableRouting, a.subRoutingRules, a.subHideSettings)
		if a.subTitle != "" {
			// Clash clients commonly use Content-Disposition to choose the imported profile name.
			c.Writer.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename*=UTF-8''%s`, url.PathEscape(a.subTitle)))
		}
		c.Data(200, "application/yaml; charset=utf-8", []byte(clashSub))
	}
}

// ApplyCommonHeaders sets common HTTP headers for subscription responses including user info, update interval, and profile title.
func (a *SUBController) ApplyCommonHeaders(
	c *gin.Context,
	header,
	updateInterval,
	profileTitle string,
	profileSupportUrl string,
	profileUrl string,
	profileAnnounce string,
	profileEnableRouting bool,
	profileRoutingRules string,
	profileHideSettings bool,
) {
	c.Writer.Header().Set("Subscription-Userinfo", header)
	c.Writer.Header().Set("Profile-Update-Interval", updateInterval)

	// Basics
	if profileTitle != "" {
		c.Writer.Header().Set("Profile-Title", "base64:"+base64.StdEncoding.EncodeToString([]byte(profileTitle)))
	}
	if profileSupportUrl != "" {
		c.Writer.Header().Set("Support-Url", profileSupportUrl)
	}
	if profileUrl != "" {
		c.Writer.Header().Set("Profile-Web-Page-Url", profileUrl)
	}
	if profileAnnounce != "" {
		c.Writer.Header().Set("Announce", "base64:"+base64.StdEncoding.EncodeToString([]byte(profileAnnounce)))
	}

	// Advanced (Happ)
	c.Writer.Header().Set("Routing-Enable", strconv.FormatBool(profileEnableRouting))
	if profileRoutingRules != "" {
		c.Writer.Header().Set("Routing", profileRoutingRules)
	}
	if profileHideSettings {
		c.Writer.Header().Set("Hide-Settings", "1")
	}
}

func (a *SUBController) getClientSpeedLimitsForSubID(subID string) gin.H {
	result := gin.H{
		"matched":      false,
		"uploadMbps":   int64(0),
		"downloadMbps": int64(0),
		"hasLimit":     false,
	}

	subID = strings.TrimSpace(subID)
	if subID == "" {
		return result
	}

	db := database.GetDB()
	if db == nil {
		return result
	}

	type inboundSettingsRow struct {
		Settings string `gorm:"column:settings"`
	}

	var rows []inboundSettingsRow
	if err := db.Table("inbounds").Select("settings").Find(&rows).Error; err != nil {
		return result
	}

	uploadKeys := []string{
		"upMbps", "uploadMbps", "uploadLimitMbps", "uploadLimit",
		"upLimitMbps", "upLimit", "uplinkLimitMbps", "uplinkLimit",
		"limitUploadMbps", "limitUpload", "upload", "up",
	}

	downloadKeys := []string{
		"downMbps", "downloadMbps", "downloadLimitMbps", "downloadLimit",
		"downLimitMbps", "downLimit", "downlinkLimitMbps", "downlinkLimit",
		"limitDownloadMbps", "limitDownload", "download", "down",
	}

	for _, row := range rows {
		if strings.TrimSpace(row.Settings) == "" {
			continue
		}

		var settings struct {
			Clients []map[string]any `json:"clients"`
		}
		if err := json.Unmarshal([]byte(row.Settings), &settings); err != nil {
			continue
		}

		for _, client := range settings.Clients {
			if speedLimitString(client["subId"]) != subID && speedLimitString(client["subid"]) != subID {
				continue
			}

			uploadMbps, uploadKey := speedLimitFirstNumber(client, uploadKeys...)
			downloadMbps, downloadKey := speedLimitFirstNumber(client, downloadKeys...)

			result["matched"] = true
			result["uploadMbps"] = uploadMbps
			result["downloadMbps"] = downloadMbps
			result["uploadKey"] = uploadKey
			result["downloadKey"] = downloadKey
			result["hasLimit"] = uploadMbps > 0 || downloadMbps > 0
			return result
		}
	}

	return result
}

func speedLimitString(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case json.Number:
		return strings.TrimSpace(typed.String())
	case float64:
		if math.Trunc(typed) == typed {
			return strconv.FormatInt(int64(typed), 10)
		}
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case float32:
		f := float64(typed)
		if math.Trunc(f) == f {
			return strconv.FormatInt(int64(f), 10)
		}
		return strconv.FormatFloat(f, 'f', -1, 64)
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case int32:
		return strconv.FormatInt(int64(typed), 10)
	default:
		return ""
	}
}

func speedLimitFirstNumber(client map[string]any, keys ...string) (int64, string) {
	for _, key := range keys {
		value, ok := client[key]
		if !ok {
			continue
		}

		number, valid := speedLimitNumber(value)
		if !valid {
			continue
		}

		return number, key
	}

	return 0, ""
}

func speedLimitNumber(value any) (int64, bool) {
	switch typed := value.(type) {
	case json.Number:
		floatValue, err := typed.Float64()
		if err != nil {
			return 0, false
		}
		return speedLimitSanitize(floatValue)
	case float64:
		return speedLimitSanitize(typed)
	case float32:
		return speedLimitSanitize(float64(typed))
	case int:
		return speedLimitSanitize(float64(typed))
	case int64:
		return speedLimitSanitize(float64(typed))
	case int32:
		return speedLimitSanitize(float64(typed))
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return 0, false
		}
		floatValue, err := strconv.ParseFloat(trimmed, 64)
		if err != nil {
			return 0, false
		}
		return speedLimitSanitize(floatValue)
	default:
		return 0, false
	}
}

func speedLimitSanitize(value float64) (int64, bool) {
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
		return 0, false
	}

	if value > 100000 {
		return 0, false
	}

	return int64(math.Round(value)), true
}

func (a *SUBController) getClientConnectionLimitForSubID(subID string) gin.H {
	result := gin.H{
		"matched":  false,
		"limitIp":  int64(0),
		"hasLimit": false,
	}

	subID = strings.TrimSpace(subID)
	if subID == "" {
		return result
	}

	db := database.GetDB()
	if db == nil {
		return result
	}

	type inboundSettingsRow struct {
		Settings string `gorm:"column:settings"`
	}

	var rows []inboundSettingsRow
	if err := db.Table("inbounds").Select("settings").Find(&rows).Error; err != nil {
		return result
	}

	limitKeys := []string{
		"limitIp",
		"limitIP",
		"limit_ip",
		"ipLimit",
		"iplimit",
		"ip_limit",
		"concurrentIpLimit",
		"concurrentIPLimit",
		"concurrent_ip_limit",
		"concurrentLimit",
	}

	for _, row := range rows {
		if strings.TrimSpace(row.Settings) == "" {
			continue
		}

		var settings struct {
			Clients []map[string]any `json:"clients"`
		}
		if err := json.Unmarshal([]byte(row.Settings), &settings); err != nil {
			continue
		}

		for _, client := range settings.Clients {
			if speedLimitString(client["subId"]) != subID && speedLimitString(client["subid"]) != subID {
				continue
			}

			limitIp, limitKey := speedLimitFirstNumber(client, limitKeys...)
			result["matched"] = true
			result["limitIp"] = limitIp
			result["limitKey"] = limitKey
			result["hasLimit"] = limitIp > 0
			return result
		}
	}

	return result
}
