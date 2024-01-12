package database

import (
	"github.com/ak1729/go-jwt/models"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var DB *gorm.DB

func Connect()  {
	connection, err := gorm.Open(mysql.Open("root:anurag108&@/go-jwt"), &gorm.Config{})

	if err != nil {
		panic("could not connect to the database")
	}

	DB = connection

	connection.AutoMigrate(&models.User{})
}

