package main

import (
	"log"
	"os"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"teach_partner_dev/database"
	"teach_partner_dev/routes"
)

func main() {
	// Load file .env
	err := godotenv.Load()
	if err != nil {
		log.Println("Peringatan: File .env tidak ditemukan, menggunakan environment system")
	}

	database.ConnectDB()

	r := gin.Default()


	r.Use(cors.New(cors.Config{
		AllowOrigins: []string{
			"http://localhost:5173",                 
			"http://localhost:3000",                 
			"https://teachpartner.skoolago.com/", 
		},
		AllowMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders: []string{"Origin", "Content-Type", "Authorization"},
	}))

	routes.SetupRoutes(r)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server berjalan di port %s...", port)
	r.Run(":" + port)
}