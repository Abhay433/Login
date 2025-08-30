package controllers

import (
	"encoding/json"
	"fmt"
	"io"
	"login/models"
	"login/utils"
	"net/http"
	"strconv"
	"time"

	"login/dto"

	"github.com/beego/beego/v2/client/orm"
	"github.com/beego/beego/v2/server/web"
	"golang.org/x/crypto/bcrypt"
)

type UserController struct {
	web.Controller
}

// POST /users → Create User
func (c *UserController) CreateUser() {
	var user models.Users

	// ✅ Read the raw body manually
	body, err := io.ReadAll(c.Ctx.Request.Body)
	if err != nil {
		fmt.Println("Error reading body:", err)
		c.Ctx.Output.SetStatus(http.StatusBadRequest)
		c.Data["json"] = map[string]string{"error": "Cannot read request body"}
		c.ServeJSON()
		return
	}

	fmt.Println("RAW BODY:", string(body))

	// ✅ Decode JSON into struct
	if err := json.Unmarshal(body, &user); err != nil {
		fmt.Println("JSON Unmarshal Error:", err)
		c.Ctx.Output.SetStatus(http.StatusBadRequest)
		c.Data["json"] = map[string]string{"error": "Invalid JSON format"}
		c.ServeJSON()
		return
	}

	fmt.Println("Parsed User Data:", user)

	// ✅ Validate required fields
	if user.Name == "" || user.Email == "" || user.Password == "" {
		c.Ctx.Output.SetStatus(http.StatusBadRequest)
		c.Data["json"] = map[string]string{"error": "Name, Email, and Password are required"}
		c.ServeJSON()
		return
	}

	// ✅ Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.Ctx.Output.SetStatus(http.StatusInternalServerError)
		c.Data["json"] = map[string]string{"error": "Failed to hash password"}
		c.ServeJSON()
		return
	}
	user.Password = string(hashedPassword)

	// ✅ Save user in database
	o := orm.NewOrm()
	_, err = o.Insert(&user)
	if err != nil {
		fmt.Println("DB Insert Error:", err)
		c.Ctx.Output.SetStatus(http.StatusInternalServerError)
		c.Data["json"] = map[string]string{"error": "Failed to create user"}
		c.ServeJSON()
		return
	}

	// ✅ Success response
	c.Ctx.Output.SetStatus(http.StatusCreated)
	c.Data["json"] = map[string]string{"message": "User created successfully!"}
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
		c.Ctx.Output.SetStatus(400)
		c.Data["json"] = map[string]string{"error": "Invalid request body"}
		c.ServeJSON()
		return
	}

	o := orm.NewOrm()
	user := models.Users{}
	err := o.QueryTable("users").Filter("Email", loginReq.Email).One(&user)
	if err == orm.ErrNoRows {
		c.Ctx.Output.SetStatus(401)
		c.Data["json"] = map[string]string{"error": "Invalid email or password"}
		c.ServeJSON()
		return
	}

	// Compare password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginReq.Password)); err != nil {
		c.Ctx.Output.SetStatus(401)
		c.Data["json"] = map[string]string{"error": "Invalid email or password"}
		c.ServeJSON()
		return
	}

	// Generate Access Token (short-lived)
	accessToken, err := utils.GenerateJWT(user.Id)
	if err != nil {
		c.Ctx.Output.SetStatus(500)
		c.Data["json"] = map[string]string{"error": "Failed to generate access token"}
		c.ServeJSON()
		return
	}

	// Generate Refresh Token (long-lived)
	refreshToken, err := utils.GenerateRefreshJWT(user.Id) // new function
	if err != nil {
		c.Ctx.Output.SetStatus(500)
		c.Data["json"] = map[string]string{"error": "Failed to generate refresh token"}
		c.ServeJSON()
		return
	}

	// Store refresh token in DB
	tokenModel := models.RefreshToken{
		UserId:    user.Id,
		Token:     refreshToken,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour), // 7 days
	}
	if _, err := o.Insert(&tokenModel); err != nil {
		c.Ctx.Output.SetStatus(500)
		c.Data["json"] = map[string]string{"error": "Failed to save refresh token"}
		c.ServeJSON()
		return
	}

	// Send response
	c.Data["json"] = dto.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
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

	// TODO: Send email with token link
	// e.g., http://localhost:8080/reset-password?token=<token>

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
	err := o.QueryTable("password_reset_tokens").
		Filter("token", req.Token).
		One(&resetToken)

	if err == orm.ErrNoRows || resetToken.ExpiresAt.Before(time.Now()) {
		c.Ctx.Output.SetStatus(401)
		c.Data["json"] = map[string]string{"error": "Invalid or expired token"}
		c.ServeJSON()
		return
	}

	user := models.Users{Id: resetToken.UserId}
	o.Read(&user)
	hashed, _ := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	user.Password = string(hashed)
	o.Update(&user)

	// Optionally delete token after use
	o.Delete(&resetToken)

	c.Data["json"] = map[string]string{"message": "Password updated successfully"}
	c.ServeJSON()
}
