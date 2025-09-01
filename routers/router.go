package routers

import (
	"login/controllers"
	"login/middlewares"

	"github.com/beego/beego/v2/server/web"
)

func init() {
	// Public Routes (No JWT Required)
	web.Router("/", &controllers.MainController{})
	web.Router("/login", &controllers.UserController{}, "post:Login")
	web.Router("/CreateUser", &controllers.UserController{}, "post:CreateUser") // Signup
	web.Router("/forgot-password", &controllers.UserController{}, "post:ForgotPassword")
	web.Router("/reset-password", &controllers.UserController{}, "post:ResetPassword")
	web.Router("/refresh", &controllers.UserController{}, "post:RefreshToken") // Refresh token

	// Protected Routes (JWT Required)
	web.InsertFilter("/users", web.BeforeRouter, middlewares.JWTAuthMiddleware)   // Protect GET /users
	web.InsertFilter("/users/*", web.BeforeRouter, middlewares.JWTAuthMiddleware) // Protect /users/:id, etc.

	// User Routes
	web.Router("/GetAllUsers", &controllers.UserController{}, "get:GetAllUsers")     // GET ALL USERS
	web.Router("/GetUserById/:id", &controllers.UserController{}, "get:GetUserById") // GET USER BY ID
	web.Router("/UpdateUser/:id", &controllers.UserController{}, "put:UpdateUser")   // UPDATE USER BY ID
	web.Router("/delete/:id", &controllers.UserController{}, "delete:DeleteUser")    // DELETE USER BY ID
	web.Router("/hello", &controllers.HelloController{}, "get:GetHello")
}
