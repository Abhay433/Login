package middlewares

import (
	"login/utils"
	"net/http"
	"strings"

	"github.com/beego/beego/v2/server/web/context"
)

// JWTAuthMiddleware verifies JWT token before accessing protected routes
func JWTAuthMiddleware(ctx *context.Context) {
	path := ctx.Input.URL()

	// ✅ Skip Public Routes
	if path == "/" ||
		path == "/login" ||
		path == "/users" && ctx.Input.IsPost() ||
		path == "/forgot-password" ||
		path == "/reset-password" ||
		path == "/refresh" {
		return
	}

	// Check Authorization Header
	authHeader := ctx.Input.Header("Authorization")
	if authHeader == "" {
		ctx.Output.SetStatus(http.StatusUnauthorized)
		ctx.Output.JSON(map[string]string{"error": "Authorization header missing"}, false, false)
		return
	}

	// Token format: "Bearer <token>"
	tokenParts := strings.Split(authHeader, " ")
	if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
		ctx.Output.SetStatus(http.StatusUnauthorized)
		ctx.Output.JSON(map[string]string{"error": "Invalid authorization format"}, false, false)
		return
	}

	// Verify JWT Token
	claims, err := utils.VerifyJWT(tokenParts[1])
	if err != nil {
		ctx.Output.SetStatus(http.StatusUnauthorized)
		ctx.Output.JSON(map[string]string{"error": "Invalid or expired token"}, false, false)
		return
	}

	// Save user ID in context for controllers
	ctx.Input.SetData("user_id", claims["user_id"])
}
