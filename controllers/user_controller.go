package controllers

import (
	"encoding/json"
	"fmt"
	"io"
	"login/models"
	"login/utils"
	"net/http"
	"strconv"
	"strings"
	"time"

	"login/dto"

	"github.com/beego/beego/v2/client/orm"
	"github.com/beego/beego/v2/core/logs"
	"github.com/beego/beego/v2/server/web"
	"golang.org/x/crypto/bcrypt"
)

type UserController struct {
	web.Controller
}

// POST /users → Create User
func (c *UserController) CreateUser() {
	var user models.Users

	// ✅ Read request body
	body, err := io.ReadAll(c.Ctx.Request.Body)
	if err != nil {
		c.CustomAbort(http.StatusBadRequest, "Cannot read request body")
		return
	}

	// ✅ Decode JSON
	if err := json.Unmarshal(body, &user); err != nil {
		c.CustomAbort(http.StatusBadRequest, "Invalid JSON format")
		return
	}

	// ✅ Validate required fields
	if strings.TrimSpace(user.Name) == "" || strings.TrimSpace(user.Email) == "" || strings.TrimSpace(user.Password) == "" {
		c.CustomAbort(http.StatusBadRequest, "Name, Email, and Password are required")
		return
	}

	// ✅ STEP 2: Check if user already exists in our DB
	o := orm.NewOrm()
	existingUser := models.Users{}
	err = o.QueryTable("users").Filter("email", user.Email).One(&existingUser)
	if err == nil {
		c.CustomAbort(http.StatusConflict, "Email already registered")
		return
	} else if err != orm.ErrNoRows {
		c.CustomAbort(http.StatusInternalServerError, "Database error")
		return
	}

	// ✅ STEP 3: Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.CustomAbort(http.StatusInternalServerError, "Failed to hash password")
		return
	}
	user.Password = string(hashedPassword)

	// ✅ STEP 4: Insert into DB
	_, err = o.Insert(&user)
	if err != nil {
		c.CustomAbort(http.StatusInternalServerError, "Failed to create user")
		return
	}

	// ✅ STEP 5: Success Response
	c.Ctx.Output.SetStatus(http.StatusCreated)
	c.Data["json"] = map[string]string{
		"message": "User created successfully!",
		"user_id": fmt.Sprintf("%d", user.Id),
	}
	c.ServeJSON()
}

// GET /users → Get All Users
func (c *UserController) GetAllUsers() {
	var users []models.Users
	o := orm.NewOrm()
	_, err := o.QueryTable("users").All(&users)
	if err != nil {
		c.Ctx.Output.SetStatus(http.StatusInternalServerError)
		c.Data["json"] = map[string]string{"error": "Failed to fetch users"}
		c.ServeJSON()
		return
	}

	// Convert to DTO
	var userResponses []dto.UserResponse
	for _, user := range users {
		userResponses = append(userResponses, dto.UserResponse{
			Id:        user.Id,
			Name:      user.Name,
			Email:     user.Email,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
		})
	}

	c.Data["json"] = userResponses
	c.ServeJSON()
}

// GET /users/:id → Get Single User
func (c *UserController) GetUserById() {
	// Get ID from params
	idStr := c.Ctx.Input.Param(":id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.Ctx.Output.SetStatus(400)
		c.Data["json"] = map[string]string{"error": "Invalid user ID"}
		c.ServeJSON()
		return
	}

	o := orm.NewOrm()
	user := models.Users{}
	user.Id = id

	// Read the user from DB
	err = o.Read(&user, "Id")
	if err != nil {
		c.Ctx.Output.SetStatus(404)
		c.Data["json"] = map[string]string{"error": "User not found"}
	} else {
		// Use the UserResponse DTO
		userResponse := dto.UserResponse{
			Id:        user.Id,
			Name:      user.Name,
			Email:     user.Email,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
		}
		c.Data["json"] = userResponse
	}

	c.ServeJSON()
}

// PUT /users/:id → Update User
func (c *UserController) UpdateUser() {
	// Get ID from URL
	idStr := c.Ctx.Input.Param(":id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.Ctx.Output.SetStatus(400)
		c.Data["json"] = map[string]string{"error": "Invalid user ID"}
		c.ServeJSON()
		return
	}

	// Parse the request body into DTO
	var updateReq dto.UserUpdateRequest
	if err := json.NewDecoder(c.Ctx.Request.Body).Decode(&updateReq); err != nil {
		c.Ctx.Output.SetStatus(400)
		c.Data["json"] = map[string]string{"error": "Invalid JSON format"}
		c.ServeJSON()
		return
	}

	o := orm.NewOrm()
	user := models.Users{}
	user.Id = id

	// Check if the user exists
	if err := o.Read(&user, "Id"); err != nil {
		c.Ctx.Output.SetStatus(404)
		c.Data["json"] = map[string]string{"error": "User not found"}
		c.ServeJSON()
		return
	}

	// Update only allowed fields
	user.Name = updateReq.Name
	user.Email = updateReq.Email

	// Save the updated user
	if _, err := o.Update(&user, "Name", "Email"); err != nil {
		c.Ctx.Output.SetStatus(500)
		c.Data["json"] = map[string]string{"error": "Failed to update user"}
		c.ServeJSON()
		return
	}

	// Prepare the response DTO
	updatedUser := dto.UserResponse{
		Id:        user.Id,
		Name:      user.Name,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}

	// Send the updated response
	c.Data["json"] = updatedUser
	c.ServeJSON()
}

// DELETE /users/:id → Delete User
func (c *UserController) DeleteUser() {
	idStr := c.Ctx.Input.Param(":id")
	id, _ := strconv.Atoi(idStr)

	o := orm.NewOrm()
	_, err := o.Delete(&models.Users{Id: id})
	if err != nil {
		c.Ctx.Output.SetStatus(http.StatusInternalServerError)
		c.Data["json"] = map[string]string{"error": "Failed to delete user"}
		c.ServeJSON()
		return
	}

	c.Data["json"] = map[string]string{"message": "User deleted successfully"}
	c.ServeJSON()
}

// login
func (c *UserController) Login() {
	var loginReq dto.UserLoginRequest
	if err := json.NewDecoder(c.Ctx.Request.Body).Decode(&loginReq); err != nil {
		c.CustomAbort(400, "Invalid request body")
		return
	}

	o := orm.NewOrm()
	user := models.Users{}
	err := o.QueryTable("users").Filter("email", loginReq.Email).One(&user)
	if err == orm.ErrNoRows {
		// User not found
		c.Data["json"] = map[string]interface{}{
			"success": false,
			"error":   "User not authorized",
		}
		c.ServeJSON()
		return
	}

	// Compare password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginReq.Password)); err != nil {
		c.Data["json"] = map[string]interface{}{
			"success": false,
			"error":   "User not authorized",
		}
		c.ServeJSON()
		return
	}

	// Generate tokens
	accessToken, err := utils.GenerateJWT(user.Id)
	if err != nil {
		c.CustomAbort(500, "Failed to generate access token")
		return
	}

	refreshToken, err := utils.GenerateRefreshJWT(user.Id)
	if err != nil {
		c.CustomAbort(500, "Failed to generate refresh token")
		return
	}

	// Save refresh token in DB
	tokenModel := models.RefreshToken{
		UserId:    user.Id,
		Token:     refreshToken,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}
	if _, err := o.Insert(&tokenModel); err != nil {
		c.CustomAbort(500, "Failed to save refresh token")
		return
	}

	// ✅ Set Cookie for Access Token
	c.Ctx.Output.Header("Set-Cookie", "access_token="+accessToken+"; HttpOnly; Path=/; Max-Age=900")

	// ✅ Set Redirect URL
	c.Ctx.Output.Header("redirect-url", "http://localhost:3000/hello") // Your app URL

	// ✅ Set 301 Redirect Status
	c.Ctx.Output.SetStatus(http.StatusMovedPermanently)

	// ✅ Send JSON response
	c.Data["json"] = map[string]interface{}{
		"success": true,
		"message": "Redirecting...",
	}
	c.ServeJSON()
}

// refresh token
func (c *UserController) RefreshToken() {
	// Parse request body
	var req dto.RefreshTokenRequest
	if err := json.NewDecoder(c.Ctx.Request.Body).Decode(&req); err != nil {
		c.Ctx.Output.SetStatus(400)
		c.Data["json"] = map[string]string{"error": "Invalid request body"}
		c.ServeJSON()
		return
	}

	// Verify refresh token (JWT)
	claims, err := utils.VerifyRefreshJWT(req.RefreshToken)
	if err != nil {
		c.Ctx.Output.SetStatus(401)
		c.Data["json"] = map[string]string{"error": "Invalid or expired refresh token"}
		c.ServeJSON()
		return
	}

	// Extract user_id from claims
	userIdFloat, ok := claims["user_id"].(float64)
	if !ok {
		c.Ctx.Output.SetStatus(400)
		c.Data["json"] = map[string]string{"error": "Invalid token claims"}
		c.ServeJSON()
		return
	}
	userId := int(userIdFloat)

	// Check if refresh token exists in DB
	o := orm.NewOrm()
	tokenModel := models.RefreshToken{}
	err = o.QueryTable("refresh_tokens").
		Filter("user_id", userId).
		Filter("token", req.RefreshToken).
		One(&tokenModel)

	if err == orm.ErrNoRows {
		c.Ctx.Output.SetStatus(401)
		c.Data["json"] = map[string]string{"error": "Refresh token not found"}
		c.ServeJSON()
		return
	}

	// Check if token expired
	if tokenModel.ExpiresAt.Before(time.Now()) {
		c.Ctx.Output.SetStatus(401)
		c.Data["json"] = map[string]string{"error": "Refresh token expired"}
		c.ServeJSON()
		return
	}

	// ✅ Generate new tokens
	newAccessToken, err := utils.GenerateJWT(userId)
	if err != nil {
		c.Ctx.Output.SetStatus(500)
		c.Data["json"] = map[string]string{"error": "Failed to generate new access token"}
		c.ServeJSON()
		return
	}

	newRefreshToken, err := utils.GenerateRefreshJWT(userId) // NEW FUNCTION for long expiry
	if err != nil {
		c.Ctx.Output.SetStatus(500)
		c.Data["json"] = map[string]string{"error": "Failed to generate new refresh token"}
		c.ServeJSON()
		return
	}

	// ✅ Update DB with new refresh token
	tokenModel.Token = newRefreshToken
	tokenModel.ExpiresAt = time.Now().Add(7 * 24 * time.Hour)
	o.Update(&tokenModel)

	// ✅ Return both tokens
	c.Data["json"] = map[string]string{
		"access_token":  newAccessToken,
		"refresh_token": newRefreshToken,
	}
	c.ServeJSON()
}

// FORGOT PASSWORD
func (c *UserController) ForgotPassword() {
	var req dto.ForgotPasswordRequest
	if err := json.NewDecoder(c.Ctx.Request.Body).Decode(&req); err != nil {
		c.Ctx.Output.SetStatus(400)
		c.Data["json"] = map[string]string{"error": "Invalid request body"}
		c.ServeJSON()
		return
	}

	o := orm.NewOrm()
	user := models.Users{}
	err := o.QueryTable("users").Filter("email", req.Email).One(&user)
	if err == orm.ErrNoRows {
		c.Ctx.Output.SetStatus(404)
		c.Data["json"] = map[string]string{"error": "Email not found"}
		c.ServeJSON()
		return
	}

	// Generate reset token
	token, _ := utils.GenerateResetToken()

	resetToken := models.PasswordResetToken{
		UserId:    user.Id,
		Token:     token,
		ExpiresAt: time.Now().Add(time.Hour), // 1 hour expiry
	}
	o.Insert(&resetToken)

	c.Data["json"] = map[string]string{"message": "Password reset link sent to your email"}
	c.ServeJSON()
}

// RESET PASSWORD
func (c *UserController) ResetPassword() {
	var req dto.ResetPasswordRequest
	if err := json.NewDecoder(c.Ctx.Request.Body).Decode(&req); err != nil {
		c.Ctx.Output.SetStatus(400)
		c.Data["json"] = map[string]string{"error": "Invalid request body"}
		c.ServeJSON()
		return
	}

	o := orm.NewOrm()
	resetToken := models.PasswordResetToken{}

	// Step 1: Token Fetch
	err := o.QueryTable("password_reset_tokens").
		Filter("token", req.Token).
		One(&resetToken)

	if err != nil {
		if err == orm.ErrNoRows {
			// Token exist nahi karta
			c.Ctx.Output.SetStatus(401)
			c.Data["json"] = map[string]string{"error": "Invalid token"}
		} else {
			// DB issue ya koi aur error
			c.Ctx.Output.SetStatus(500)
			c.Data["json"] = map[string]string{"error": "Something went wrong"}
		}
		c.ServeJSON()
		return
	}

	// Step 2: Token Expiry Check
	if resetToken.ExpiresAt.Before(time.Now()) {
		c.Ctx.Output.SetStatus(401)
		c.Data["json"] = map[string]string{"error": "Token has expired"}
		c.ServeJSON()
		return
	}

	// Step 3: User Fetch
	// Step 3: User Fetch (unchanged)
	user := models.Users{}
	user.Id = resetToken.UserId

	if err := o.Read(&user); err != nil {
		c.Ctx.Output.SetStatus(404)
		c.Data["json"] = map[string]string{"error": "User not found"}
		c.ServeJSON()
		return
	}

	// DEBUG: print current stored hash before update
	fmt.Println("DEBUG: before update - user id:", user.Id, "stored password:", user.Password)

	// Step 4: New Password Hashing
	hashed, hashErr := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if hashErr != nil {
		c.Ctx.Output.SetStatus(500)
		c.Data["json"] = map[string]string{"error": "Failed to hash password"}
		c.ServeJSON()
		return
	}
	user.Password = string(hashed)

	// Step 5: Password Update
	if _, updateErr := o.Update(&user, "Password"); updateErr != nil {
		c.Ctx.Output.SetStatus(500)
		c.Data["json"] = map[string]string{"error": "Failed to update password"}
		c.ServeJSON()
		return
	}

	// DEBUG: read back and verify
	updatedUser := models.Users{Id: user.Id}
	if err := o.Read(&updatedUser); err != nil {
		fmt.Println("DEBUG: failed to read back updated user:", err)
	} else {
		fmt.Println("DEBUG: after update - stored password:", updatedUser.Password)
		// quick verify - should return nil if match
		if bcrypt.CompareHashAndPassword([]byte(updatedUser.Password), []byte(req.NewPassword)) == nil {
			fmt.Println("DEBUG: bcrypt verification SUCCESS for new password")
		} else {
			fmt.Println("DEBUG: bcrypt verification FAILED for new password")
		}
	}

	// Step 6: Delete Reset Token
	if _, delErr := o.Delete(&resetToken); delErr != nil {
		logs.Warn("Failed to delete reset token: ", delErr)
	}

	// Step 7: Success Response
	c.Data["json"] = map[string]string{"message": "Password updated successfully"}
	c.ServeJSON()
}
