package controllers

import (
	"github.com/beego/beego/v2/server/web"
	beego "github.com/beego/beego/v2/server/web"
)

type MainController struct {
	beego.Controller
}

func (c *MainController) Get() {
	c.Data["Website"] = "beego.vip"
	c.Data["Email"] = "astaxie@gmail.com"
	c.TplName = "index.tpl"
}

type HelloController struct {
	web.Controller
}

func (c *HelloController) GetHello() {
	c.Data["json"] = map[string]interface{}{
		"message": "Hello Abhay! Redirect successful 🎉",
	}
	c.ServeJSON()
}
