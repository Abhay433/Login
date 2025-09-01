package main

import (
	_ "login/routers"

	"github.com/beego/beego/v2/client/orm"
	beego "github.com/beego/beego/v2/server/web"
	_ "github.com/lib/pq"
)

func init() {
	orm.RegisterDataBase(
		"default",
		"postgres",
		"user=abhay password=Abhay@123 dbname=apigo host=127.0.0.1 port=5432 sslmode=disable",
	)
}

func main() {
	beego.Run()
}
