package models

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Writer model
type Admin struct {
	gorm.Model

	ID       uuid.UUID `json:"ID" gorm:"type:uuid;default:gen_random_uuid();primary_key"`
	Name     string    `json:"name" gorm:"type:varchar(255);not null"`
	Email    string    `json:"email" gorm:"unique;not null"`
	Password string    `json:"-" gorm:"not null"` // "-" exclude field from json response
	Role     string    `json:"role" gorm:"type:varchar(255);default:'admin';not null"`
}

// AdminSignUp struct
type AdminSignUp struct {
	Name     string `json:"name" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
    Role     string `json:"role" binding:"required"`
}
