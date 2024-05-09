package database

import (
	"fmt"

	"github.com/codedwells/GoServer/models"
	"gorm.io/gorm"
)

func MigrateDatabase(DB *gorm.DB) {
	fmt.Println("Running migration")

	DB.AutoMigrate(
		&models.Student{},
		&models.Admin{},
			)

	fmt.Println("Migration ran!")
}
