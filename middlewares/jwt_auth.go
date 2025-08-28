package middlewares

import (
	"login/utils"
	"net/http"
	"strings"

	"github.com/beego/beego/v2/server/web/context"
)

// JWTAuthMiddleware verifies JWT token before accessing protected routes
func JWTAuthMiddleware(ctx *context.Context) {
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

	// Verify the token
	claims, err := utils.VerifyJWT(tokenParts[1])
	if err != nil {
		ctx.Output.SetStatus(http.StatusUnauthorized)
		ctx.Output.JSON(map[string]string{"error": "Invalid or expired token"}, false, false)
		return
	}

	// Save user ID in context (optional, useful for controllers)
	ctx.Input.SetData("user_id", claims["user_id"])
}
