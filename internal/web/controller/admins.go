package controller

import (
	"strconv"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/web/service/panel"

	"github.com/gin-gonic/gin"
)

type AdminController struct {
	adminService panel.AdminService
}

func NewAdminController(g *gin.RouterGroup) *AdminController {
	a := &AdminController{}
	a.initRouter(g)
	return a
}

func (a *AdminController) initRouter(g *gin.RouterGroup) {
	g.GET("/current", a.current)
	g.GET("/list", requireAdminPermission("admins", "view"), a.list)
	g.GET("/stats", requireAdminPermission("admins", "view"), a.stats)
	g.GET("/get/:id", requireAdminPermission("admins", "view"), a.get)

	g.POST("/add", requireAdminPermission("admins", "create"), a.add)
	g.POST("/update/:id", requireAdminPermission("admins", "update"), a.update)
	g.POST("/del/:id", requireAdminPermission("admins", "delete"), a.del)
	g.POST("/enable/:id", requireAdminPermission("admins", "update"), a.enable)
	g.POST("/disable/:id", requireAdminPermission("admins", "update"), a.disable)
	g.POST("/resetUsage/:id", requireAdminPermission("admins", "resetUsage"), a.resetUsage)
	g.POST("/users/disableActive/:id", requireAdminPermission("users", "update"), a.disableActiveUsers)
	g.POST("/users/activateDisabled/:id", requireAdminPermission("users", "update"), a.activateDisabledUsers)
	g.POST("/users/removeAll/:id", requireAdminPermission("users", "delete"), a.removeAllUsers)
}

func (a *AdminController) current(c *gin.Context) {
	user, role, ok := loginActiveAdminRole(c)
	if !ok {
		return
	}

	jsonObj(c, gin.H{
		"id":            user.Id,
		"username":      user.Username,
		"status":        user.Status,
		"roleId":        user.RoleId,
		"role_id":       user.RoleId,
		"profileTitle":  user.ProfileTitle,
		"profile_title": user.ProfileTitle,
		"permissions":   role.PermissionsJSON,
		"limits":        role.LimitsJSON,
		"features":      role.FeaturesJSON,
		"access":        role.AccessJSON,
		"role": gin.H{
			"id":          role.Id,
			"name":        role.Name,
			"slug":        role.Slug,
			"is_owner":    role.OwnerRole,
			"ownerRole":   role.OwnerRole,
			"owner_role":  role.OwnerRole,
			"permissions": role.PermissionsJSON,
			"limits":      role.LimitsJSON,
			"features":    role.FeaturesJSON,
			"access":      role.AccessJSON,
		},
	}, nil)
}

func (a *AdminController) list(c *gin.Context) {
	rows, err := a.adminService.List()
	jsonObj(c, rows, err)
}

func (a *AdminController) stats(c *gin.Context) {
	stats, err := a.adminService.Stats()
	jsonObj(c, stats, err)
}

func (a *AdminController) get(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "get"), err)
		return
	}
	row, err := a.adminService.Get(id)
	jsonObj(c, row, err)
}

func (a *AdminController) add(c *gin.Context) {
	var payload panel.AdminPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		jsonMsg(c, "create admin", err)
		return
	}
	row, err := a.adminService.Create(payload)
	if err != nil {
		jsonMsg(c, "create admin", err)
		return
	}
	jsonMsgObj(c, "create admin", row, nil)
}

func (a *AdminController) update(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "get"), err)
		return
	}
	var payload panel.AdminPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		jsonMsg(c, "update admin", err)
		return
	}
	row, err := a.adminService.Update(id, payload)
	if err != nil {
		jsonMsg(c, "update admin", err)
		return
	}
	jsonMsgObj(c, "update admin", row, nil)
}

func (a *AdminController) del(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "get"), err)
		return
	}
	jsonMsg(c, "delete admin", a.adminService.Delete(id))
}

func (a *AdminController) enable(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "get"), err)
		return
	}
	jsonMsg(c, "enable admin", a.adminService.SetEnabled(id, true))
}

func (a *AdminController) disable(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "get"), err)
		return
	}
	jsonMsg(c, "disable admin", a.adminService.SetEnabled(id, false))
}

func (a *AdminController) resetUsage(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "get"), err)
		return
	}
	jsonMsg(c, "reset admin usage", a.adminService.ResetUsage(id))
}

func (a *AdminController) disableActiveUsers(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "get"), err)
		return
	}
	count, err := a.adminService.DisableAllActiveUsers(id)
	jsonObj(c, gin.H{"count": count}, err)
}

func (a *AdminController) activateDisabledUsers(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "get"), err)
		return
	}
	count, err := a.adminService.ActivateAllDisabledUsers(id)
	jsonObj(c, gin.H{"count": count}, err)
}

func (a *AdminController) removeAllUsers(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "get"), err)
		return
	}
	deleted, err := a.adminService.RemoveAllUsers(id)
	jsonObj(c, gin.H{"count": deleted, "deleted": deleted}, err)
}
