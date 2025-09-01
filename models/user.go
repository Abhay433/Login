package models

import (
	"time"

	"github.com/beego/beego/v2/client/orm"
)

type User struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func init() {
	orm.RegisterModel(new(Users), new(RefreshToken))
	orm.RegisterModel(new(PasswordResetToken))

}

type Users struct {
	Id        int       `json:"id" orm:"column(id);auto"`
	Name      string    `json:"name" orm:"column(name);size(50)"`
	Email     string    `json:"email" orm:"column(email);size(50);unique"`
	Password  string    `json:"password" orm:"column(password);size(255)"`
	CreatedAt time.Time `json:"created_at" orm:"column(created_at);auto_now_add;type(datetime)"`
	UpdatedAt time.Time `json:"updated_at" orm:"column(updated_at);auto_now;type(datetime)"`
}

// RefreshToken maps to refresh_tokens table
type RefreshToken struct {
	Id        int       `orm:"column(id);auto" json:"id"`
	UserId    int       `orm:"column(user_id)" json:"user_id"`
	Token     string    `orm:"column(token);size(500)" json:"token"`
	ExpiresAt time.Time `orm:"column(expires_at);type(datetime)" json:"expires_at"`
	CreatedAt time.Time `orm:"column(created_at);auto_now_add;type(datetime)" json:"created_at"`
}

// TableName sets custom table name
func (r *RefreshToken) TableName() string {
	return "refresh_tokens"
}

type PasswordResetToken struct {
	Id        int       `orm:"column(id);auto" json:"id"`
	UserId    int       `orm:"column(user_id)" json:"user_id"`
	Token     string    `orm:"column(token);size(500)" json:"token"`
	ExpiresAt time.Time `orm:"column(expires_at);type(datetime)" json:"expires_at"`
	CreatedAt time.Time `orm:"column(created_at);auto_now_add;type(datetime)" json:"created_at"`
}

func (p *PasswordResetToken) TableName() string {
	return "password_reset_tokens"
}

type RegisterRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Response struct
type Response struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
}
