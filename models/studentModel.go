package models

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Student model
type Student struct {
	gorm.Model

	ID              uuid.UUID     `json:"ID" gorm:"type:uuid;default:gen_random_uuid();primary_key"`
	Name            string        `json:"name" gorm:"type:varchar(255);not null"`
	Email           string        `json:"email" gorm:"unique;not null"`
	Password        string        `json:"-" gorm:"not null"` // "-" exclude field from json response
	Role            string        `json:"role" gorm:"default:student"`
	Balance         float64       `json:"balance" gorm:"default:0"`
    ActiveSpend     float64       `json:"active_spend" gorm:"default:0"`
	TotalSpent      float64       `json:"total_spent" gorm:"default:0"`
	Suspended       bool          `json:"suspended" gorm:"default:false"`
	Status          string        `json:"status" gorm:"default:'active'"`
	PlacedOrders    int           `json:"placed_orders" gorm:"default:0"`
	CompletedOrders int           `json:"completed_orders" gorm:"default:0"`
}

// User data response
type StudentResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Name         string `json:"name"`
	Message      string `json:"message"`
}

type StudentSignUp struct {
	Name     string `json:"name" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

type SignInInput struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type UpdatePassword struct {
	CurrentPassword string `json:"current_password" binding:"required,min=8"`
	NewPassword     string `json:"new_password" binding:"required,min=8"`
}
