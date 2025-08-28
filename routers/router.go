package routers

import (
	"login/controllers"
	"login/middlewares"

	"github.com/beego/beego/v2/server/web"
)

func init() {
	// Public Routes
	web.Router("/", &controllers.MainController{})
	web.Router("/login", &controllers.UserController{}, "post:Login")
	web.Router("/users", &controllers.UserController{}, "post:CreateUser") // Registration

	// Protected Routes (Require JWT)
	web.InsertFilter("/users", web.BeforeRouter, middlewares.JWTAuthMiddleware)   // Protect GET /users
	web.InsertFilter("/users/*", web.BeforeRouter, middlewares.JWTAuthMiddleware) // Protect /users/:id, etc.

	// User Routes
	web.Router("/users", &controllers.UserController{}, "get:GetAllUsers")
	web.Router("/users/:id", &controllers.UserController{}, "get:GetUserById")
	web.Router("/users/:id", &controllers.UserController{}, "put:UpdateUser")
	web.Router("/users/:id", &controllers.UserController{}, "delete:DeleteUser")
	// Refresh Token endpoint
	web.Router("/refresh", &controllers.UserController{}, "post:RefreshToken")

	//FORGOT PASSSWORD
	web.Router("/forgot-password", &controllers.UserController{}, "post:ForgotPassword")
	//RESET PASSWORD
	web.Router("/reset-password", &controllers.UserController{}, "post:ResetPassword")

}
