package controller

import (
	"strconv"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/web/service/panel"

	"github.com/gin-gonic/gin"
)

type AdminRoleController struct {
	roleService panel.AdminRoleService
}

func NewAdminRoleController(g *gin.RouterGroup) *AdminRoleController {
	a := &AdminRoleController{}
	a.initRouter(g)
	return a
}

func (a *AdminRoleController) initRouter(g *gin.RouterGroup) {
	g.GET("/list", requireAdminPermission("roles", "view"), a.list)
	g.GET("/get/:id", requireAdminPermission("roles", "view"), a.get)
	g.POST("/add", requireAdminPermission("roles", "create"), a.add)
	g.POST("/update/:id", requireAdminPermission("roles", "update"), a.update)
	g.POST("/duplicate/:id", requireAdminPermission("roles", "create"), a.duplicate)
	g.POST("/del/:id", requireAdminPermission("roles", "delete"), a.del)
}

func (a *AdminRoleController) list(c *gin.Context) {
	rows, err := a.roleService.List()
	jsonObj(c, rows, err)
}

func (a *AdminRoleController) get(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "get"), err)
		return
	}
	row, err := a.roleService.Get(id)
	jsonObj(c, row, err)
}

func (a *AdminRoleController) add(c *gin.Context) {
	var payload panel.AdminRolePayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		jsonMsg(c, "create role", err)
		return
	}
	row, err := a.roleService.Create(payload)
	if err != nil {
		jsonMsg(c, "create role", err)
		return
	}
	jsonMsgObj(c, "create role", row, nil)
}

func (a *AdminRoleController) update(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "get"), err)
		return
	}
	var payload panel.AdminRolePayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		jsonMsg(c, "update role", err)
		return
	}
	row, err := a.roleService.Update(id, payload)
	if err != nil {
		jsonMsg(c, "update role", err)
		return
	}
	jsonMsgObj(c, "update role", row, nil)
}

func (a *AdminRoleController) duplicate(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "get"), err)
		return
	}
	row, err := a.roleService.Duplicate(id)
	if err != nil {
		jsonMsg(c, "duplicate role", err)
		return
	}
	jsonMsgObj(c, "duplicate role", row, nil)
}

func (a *AdminRoleController) del(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "get"), err)
		return
	}
	jsonMsg(c, "delete role", a.roleService.Delete(id))
}
