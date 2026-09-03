package routes

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"teach_partner_dev/database"
	"teach_partner_dev/middleware"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/generative-ai-go/genai"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/api/option"
)

// --- Struct Superadmin ---
type AdminLoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
	Location *LocationData `json:"location"`
}

type UpdateUserStatusRequest struct {
	IsActive bool `json:"is_active"`
}

type CreateEbookRequest struct {
	Judul         string `json:"judul" binding:"required"`
	Jenjang       string `json:"jenjang" binding:"required"`
	MataPelajaran string `json:"mata_pelajaran" binding:"required"`
	Kategori      string `json:"kategori" binding:"required"`
	CoverUrl      string `json:"cover_url"`
	FileUrl       string `json:"file_url" binding:"required"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=6"`
	Location    *LocationData `json:"location"`
}

// --- Struct Pembelian Token & Midtrans ---
type CreateTransactionRequest struct {
	PackageName string `json:"package_name" binding:"required"`
	TokenAmount int    `json:"token_amount" binding:"required"`
	Amount      int    `json:"amount" binding:"required"`
}

type LocationData struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

type UpdateProfileRequest struct {
	NamaGuru               string `json:"nama_guru"`
	NipGuru                string `json:"nip_guru"`
	NamaSekolah            string `json:"nama_sekolah"`
	MataPelajaran          string `json:"mata_pelajaran"`
	Fase                   string `json:"fase"`
	Kelas                  string `json:"kelas"`
	Semester               string `json:"semester"`
	TahunPelajaran         string `json:"tahun_pelajaran"`
	NamaKepalaSekolah      string `json:"nama_kepala_sekolah"`
	NipKepalaSekolah       string `json:"nip_kepala_sekolah"`
	KotaKabupaten          string `json:"kota_kabupaten"`
	TanggalPenandatanganan string `json:"tanggal_penandatanganan"`
	AlamatSekolah          string `json:"alamat_sekolah"`
	KecamatanKabupaten     string `json:"kecamatan_kabupaten"`
	KodePos                string `json:"kode_pos"`
	TeleponSekolah         string `json:"telepon_sekolah"`
	EmailSekolah           string `json:"email_sekolah"`
	Npsn                   string `json:"npsn"`
	WebsiteSekolah         string `json:"website_sekolah"`
}

type QuestionInput struct {
	QuestionText   string `json:"question_text" binding:"required"`
	QuestionType   string `json:"question_type" binding:"required"`
	Options        any    `json:"options"`
	CorrectAnswer  any    `json:"correct_answer" binding:"required"`
	Explanation    string `json:"explanation"`
	CognitiveLevel string `json:"cognitive_level"`
}

type CreateQuestionBankRequest struct {
	Title         string          `json:"title" binding:"required"`
	Description   string          `json:"description"`
	Subject       string          `json:"subject" binding:"required"`
	Phase         string          `json:"phase" binding:"required"`
	PriceInTokens int             `json:"price_in_tokens"`
	IsPublic      bool            `json:"is_public"`
	Questions     []QuestionInput `json:"questions"`
}

type GenerateAIRequest struct {
	Topic          string `json:"topic" binding:"required"`
	QuestionType   string `json:"question_type" binding:"required"`
	NumberOfQ      int    `json:"number_of_q" binding:"required"`
	CognitiveLevel string `json:"cognitive_level"`
}

func logSuperAdminActivity(adminID int, action, ipAddress, userAgent, location, details string) {
	query := `INSERT INTO super_admin_logs (admin_id, action, ip_address, user_agent, location, details) VALUES ($1, $2, $3, $4, $5, $6)`
	_, err := database.DB.Exec(query, adminID, action, ipAddress, userAgent, location, details)
	if err != nil {
		fmt.Printf("Gagal mencatat log superadmin: %v\n", err)
	}
}

func AdminAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token tidak valid"})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		jwtSecret := os.Getenv("JWT_ADMIN_SECRET")
		if jwtSecret == "" {
			jwtSecret = "supersecretadminKey_default"
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
			return []byte(jwtSecret), nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token tidak valid atau kedaluwarsa"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || claims["role"] != "superadmin" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Akses ditolak: Bukan level administrator"})
			c.Abort()
			return
		}

		c.Set("admin_email", claims["email"])
		if adminID, ok := claims["admin_id"]; ok {
			c.Set("admin_id", adminID)
		}
		
		c.Next()
	}
}

func sendWhatsAppNotification(targetPhone string, message string) {
	apiToken := os.Getenv("WA_GATEWAY_TOKEN")
	apiURL := os.Getenv("WA_GATEWAY_URL") 

	if apiToken == "" || apiURL == "" || targetPhone == "" {
		return 
	}

	payload := map[string]string{
		"target":  targetPhone,
		"message": message,
	}
	jsonBody, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", apiToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	_, _ = client.Do(req)
}

func randString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[time.Now().UnixNano()%int64(len(letters))]
	}
	return string(b)
}

func SetupRoutes(r *gin.Engine) {
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "Server berjalan dengan baik"})
	})

	// --- Endpoint Debug Sentry ---
	r.GET("/debug-sentry", func(c *gin.Context) {
		panic("Test Sentry Error dari Backend Golang!")
	})

	// --- Endpoint Webhook Midtrans (Publik) ---
	r.POST("/api/payment/webhook", func(c *gin.Context) {
		var notification map[string]any
		if err := c.ShouldBindJSON(&notification); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Format notifikasi tidak valid"})
			return
		}

		transactionStatus, _ := notification["transaction_status"].(string)
		orderID, _ := notification["order_id"].(string)
		fraudStatus, _ := notification["fraud_status"].(string)

		switch transactionStatus {
			case "capture", "settlement":
			if fraudStatus == "" || fraudStatus == "accept" {
				var userID string
				var tokenAmount int
				var currentStatus string
				err := database.DB.QueryRow(
					`SELECT user_id, token_amount, status FROM token_orders WHERE order_id = $1`,
					orderID,
				).Scan(&userID, &tokenAmount, &currentStatus)

				if err == nil && currentStatus == "pending" {
					_, _ = database.DB.Exec(
						`UPDATE token_orders SET status = 'success', updated_at = NOW() WHERE order_id = $1`,
						orderID,
					)

					_, _ = database.DB.Exec(
						`UPDATE profiles SET token_balance = token_balance + $1, updated_at = NOW() WHERE id = $2`,
						tokenAmount, userID,
					)
				}
			}
		case "cancel", "deny", "expire":
			_, _ = database.DB.Exec(
				`UPDATE token_orders SET status = $1, updated_at = NOW() WHERE order_id = $2`,
				transactionStatus, orderID,
			)
		}

		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	r.POST("/api/superadmin/superadmin-login", func(c *gin.Context) {
		var req AdminLoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Format input tidak valid: " + err.Error()})
			return
		}

		var adminID int
		var hashedPassword string
		var adminName string
		var failedAttempts int
		var lockedUntil sql.NullTime
		var waNumber sql.NullString

		query := `SELECT id, password_hash, nama, failed_login_attempts, locked_until, no_whatsapp FROM super_admins WHERE email = $1`
		err := database.DB.QueryRow(query, req.Email).Scan(&adminID, &hashedPassword, &adminName, &failedAttempts, &lockedUntil, &waNumber)
		if err != nil {
			if err == sql.ErrNoRows {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Email salah, periksa kembali"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Kesalahan database: " + err.Error()})
			return
		}

		// Siapkan string lokasi untuk database & WhatsApp
		lokasiStr := "Tidak diizinkan / Tidak tersedia"
		mapsLink := "Tidak tersedia"
		if req.Location != nil {
			lokasiStr = fmt.Sprintf("%.6f, %.6f", req.Location.Latitude, req.Location.Longitude)
			mapsLink = fmt.Sprintf("%.6f, %.6f (https://maps.google.com/?q=%.6f,%.6f)", 
				req.Location.Latitude, req.Location.Longitude, 
				req.Location.Latitude, req.Location.Longitude)
		}

		// 1. Cek apakah akun sedang diblokir sementara
		if lockedUntil.Valid && lockedUntil.Time.After(time.Now()) {
			sisaWaktu := int(time.Until(lockedUntil.Time).Seconds())
			c.JSON(http.StatusLocked, gin.H{
				"error": fmt.Sprintf("Akun Anda dikunci sementara karena terlalu banyak percobaan gagal. Coba lagi dalam %d detik.", sisaWaktu),
			})
			return
		}

		// 2. Validasi Password
		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.Password))
		if err != nil {
			failedAttempts++
			
			if failedAttempts >= 3 {
				_, _ = database.DB.Exec(
					`UPDATE super_admins SET failed_login_attempts = $1, locked_until = NOW() + INTERVAL '1 minute' WHERE id = $2`,
					failedAttempts, adminID,
				)

				if waNumber.Valid && waNumber.String != "" {
					ipClient := c.ClientIP()
					userAgent := c.Request.UserAgent()

					pesanAlert := fmt.Sprintf(
						"PERINGATAN KEAMANAN\n\nTerdeteksi 3 kali percobaan login yang gagal pada akun Superadmin Anda.\nAkun telah dikunci sementara selama 1 menit.\n\nDetail Akses:\n- Lokasi: %s\n- Alamat IP: %s\n- Perangkat: %s",
						mapsLink, ipClient, userAgent,
					)
					go sendWhatsAppNotification(waNumber.String, pesanAlert)
				}

				// Menyimpan lokasi pada log LOGIN_LOCKED
				logSuperAdminActivity(adminID, "LOGIN_LOCKED", c.ClientIP(), c.Request.UserAgent(), lokasiStr, "Akun dikunci 1 menit karena 3x salah password")
				c.JSON(http.StatusLocked, gin.H{"error": "Terlalu banyak percobaan gagal. Akun dikunci sementara selama 1 menit."})
				return
			} else {
				_, _ = database.DB.Exec(
					`UPDATE super_admins SET failed_login_attempts = $1 WHERE id = $2`,
					failedAttempts, adminID,
				)
				// Menyimpan lokasi pada log LOGIN_FAILED
				logSuperAdminActivity(adminID, "LOGIN_FAILED", c.ClientIP(), c.Request.UserAgent(), lokasiStr, "Password salah")
				c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Sprintf("Kata sandi salah! Sisa percobaan: %d", 3-failedAttempts)})
				return
			}
		}

		// 3. Jika Login Berhasil, Reset Counter Gagal & Locked
		_, _ = database.DB.Exec(
			`UPDATE super_admins SET failed_login_attempts = 0, locked_until = NULL WHERE id = $1`,
			adminID,
		)

		logSuperAdminActivity(adminID, "LOGIN_SUCCESS", c.ClientIP(), c.Request.UserAgent(), lokasiStr, "Login berhasil")

		if waNumber.Valid && waNumber.String != "" {
			ipClient := c.ClientIP()
			userAgent := c.Request.UserAgent()

			pesanWA := fmt.Sprintf(
				"INFORMASI LOGIN SUPERADMIN\n\nAkun Superadmin Anda baru saja masuk pada %s.\n\nDetail Akses:\n- Lokasi (Koordinat): %s\n- Alamat IP: %s\n- Perangkat: %s\n\nJika ini bukan Anda, segera amankan akun Anda!", 
				time.Now().Format("02-01-2006 15:04:05"), 
				mapsLink, 
				ipClient, 
				userAgent,
			)
			go sendWhatsAppNotification(waNumber.String, pesanWA)
		}

		jwtSecret := os.Getenv("JWT_ADMIN_SECRET")
		if jwtSecret == "" {
			jwtSecret = "supersecretadminKey_default"
		}

		claims := jwt.MapClaims{
			"admin_id": adminID,
			"email":    req.Email,
			"role":     "superadmin",
			"exp":      time.Now().Add(time.Hour * 24).Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(jwtSecret))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menghasilkan token admin"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Login superadmin berhasil",
			"token":   tokenString,
			"nama":    adminName,
		})
	})

	// --- Route superadmin dibungkus proteksi middleware ---
	adminApi := r.Group("/api/superadmin")
	adminApi.Use(AdminAuthMiddleware())
	{
		adminApi.GET("/stats", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"message": "Selamat datang di Panel Superadmin!",
				"admin":   c.MustGet("admin_email"),
			})
		})

		adminApi.GET("/logs", func(c *gin.Context) {
			rows, err := database.DB.Query(`
				SELECT l.id, a.email, l.action, l.ip_address, l.user_agent, l.location, l.details, l.created_at 
				FROM super_admin_logs l
				LEFT JOIN super_admins a ON l.admin_id = a.id
				ORDER BY l.created_at DESC
				LIMIT 50
			`)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memuat log aktivitas: " + err.Error()})
				return
			}
			defer rows.Close()

			type LogItem struct {
				ID        int       `json:"id"`
				Email     string    `json:"email"`
				Action    string    `json:"action"`
				IpAddress string    `json:"ip_address"`
				UserAgent string    `json:"user_agent"`
				Location  string    `json:"location"`
				Details   string    `json:"details"`
				CreatedAt time.Time `json:"created_at"`
			}

			var logs []LogItem
			for rows.Next() {
				var item LogItem
				var email, ip, ua, loc, details sql.NullString
				if err := rows.Scan(&item.ID, &email, &item.Action, &ip, &ua, &loc, &details, &item.CreatedAt); err == nil {
					item.Email = email.String
					item.IpAddress = ip.String
					item.UserAgent = ua.String
					item.Location = loc.String
					item.Details = details.String
					logs = append(logs, item)
				}
			}

			c.JSON(http.StatusOK, gin.H{"logs": logs})
		})

		adminApi.POST("/change-password", func(c *gin.Context) {
			adminIDVal, exists := c.Get("admin_id")
			if !exists {
				email := c.MustGet("admin_email").(string)
				err := database.DB.QueryRow(`SELECT id FROM super_admins WHERE email = $1`, email).Scan(&adminIDVal)
				if err != nil {
					c.JSON(http.StatusUnauthorized, gin.H{"error": "Sesi admin tidak dikenali"})
					return
				}
			}
			adminID := int(adminIDVal.(float64))

			var req ChangePasswordRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Format input tidak valid (minimal 6 karakter): " + err.Error()})
				return
			}

			var currentHash string
			var waNumber sql.NullString
			err := database.DB.QueryRow(`SELECT password_hash, no_whatsapp FROM super_admins WHERE id = $1`, adminID).Scan(&currentHash, &waNumber)
			if err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "Data admin tidak ditemukan"})
				return
			}

			err = bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(req.OldPassword))
			if err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Kata sandi lama salah!"})
				return
			}

			newHashBytes, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memproses kata sandi baru"})
				return
			}

			_, err = database.DB.Exec(`UPDATE super_admins SET password_hash = $1, updated_at = NOW() WHERE id = $2`, string(newHashBytes), adminID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyimpan kata sandi ke database"})
				return
			}

			// Format lokasi untuk ganti password
			lokasiStr := "Tidak diizinkan / Tidak tersedia"
			if req.Location != nil {
				lokasiStr = fmt.Sprintf("%.6f, %.6f", req.Location.Latitude, req.Location.Longitude)
			}

			logSuperAdminActivity(adminID, "CHANGE_PASSWORD", c.ClientIP(), c.Request.UserAgent(), lokasiStr, "Berhasil mengubah kata sandi")
			if waNumber.Valid && waNumber.String != "" {
					mapsLink := "Tidak tersedia"
						if req.Location != nil {
							mapsLink = fmt.Sprintf("%.6f, %.6f (https://maps.google.com/?q=%.6f,%.6f)", 
								req.Location.Latitude, req.Location.Longitude, 
								req.Location.Latitude, req.Location.Longitude)
						}

					pesanWA := fmt.Sprintf(
							"PERINGATAN KEAMANAN\n\nKata sandi akun Superadmin Anda baru saja diubah pada %s.\n\nDetail Akses:\n- Lokasi: %s\n\nJika Anda tidak merasa melakukan ini, segera amankan akun Anda!", 
							time.Now().Format("02-01-2006 15:04:05"), 
							mapsLink,
						)
					go sendWhatsAppNotification(waNumber.String, pesanWA)
			}

			c.JSON(http.StatusOK, gin.H{"message": "Kata sandi berhasil diperbarui"})
		})

		adminApi.GET("/registered-users", func(c *gin.Context) {
			rows, err := database.DB.Query(`
				SELECT id, nama_guru, nip_guru, nama_sekolah, mata_pelajaran, token_balance, is_active, last_login, updated_at 
				FROM profiles 
				ORDER BY updated_at DESC
			`)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil data pengguna: " + err.Error()})
				return
			}
			defer rows.Close()

			type UserListItem struct {
				ID            string     `json:"id"`
				NamaGuru      string     `json:"nama_guru"`
				NipGuru       string     `json:"nip_guru"`
				NamaSekolah   string     `json:"nama_sekolah"`
				MataPelajaran string     `json:"mata_pelajaran"`
				TokenBalance  int        `json:"token_balance"`
				IsActive      bool       `json:"is_active"`
				LastLogin     *time.Time `json:"last_login"`
				UpdatedAt     time.Time  `json:"updated_at"`
			}

			var users []UserListItem
			for rows.Next() {
				var u UserListItem
				var namaGuru, nipGuru, namaSekolah, mataPelajaran sql.NullString
				var lastLogin sql.NullTime
				var updatedAt time.Time

				err := rows.Scan(&u.ID, &namaGuru, &nipGuru, &namaSekolah, &mataPelajaran, &u.TokenBalance, &u.IsActive, &lastLogin, &updatedAt)
				if err != nil {
					continue
				}

				u.NamaGuru = namaGuru.String
				u.NipGuru = nipGuru.String
				u.NamaSekolah = namaSekolah.String
				u.MataPelajaran = mataPelajaran.String
				if lastLogin.Valid {
					u.LastLogin = &lastLogin.Time
				}
				u.UpdatedAt = updatedAt

				users = append(users, u)
			}

			c.JSON(http.StatusOK, gin.H{
				"total_users": len(users),
				"users":       users,
			})
		})

		adminApi.PATCH("/users/:id/status", func(c *gin.Context) {
			userID := c.Param("id")
			var req UpdateUserStatusRequest

			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Format data tidak valid: " + err.Error()})
				return
			}

			query := `UPDATE profiles SET is_active = $1, updated_at = NOW() WHERE id = $2`
			result, err := database.DB.Exec(query, req.IsActive, userID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memperbarui status pengguna: " + err.Error()})
				return
			}

			rowsAffected, _ := result.RowsAffected()
			if rowsAffected == 0 {
				c.JSON(http.StatusNotFound, gin.H{"error": "Pengguna tidak ditemukan"})
				return
			}

			statusText := "diaktifkan"
			if !req.IsActive {
				statusText = "diblokir"
			}

			c.JSON(http.StatusOK, gin.H{
				"message":   fmt.Sprintf("Pengguna berhasil %s", statusText),
				"user_id":   userID,
				"is_active": req.IsActive,
			})
		})

		adminApi.GET("/ebooks", func(c *gin.Context) {
			rows, err := database.DB.Query(`
				SELECT id, judul, jenjang, mata_pelajaran, kategori, cover_url, file_url, created_at 
				FROM ebooks 
				ORDER BY created_at DESC
			`)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil data e-book: " + err.Error()})
				return
			}
			defer rows.Close()

			type EbookItem struct {
				ID            string    `json:"id"`
				Judul         string    `json:"judul"`
				Jenjang       string    `json:"jenjang"`
				MataPelajaran string    `json:"mata_pelajaran"`
				Kategori      string    `json:"kategori"`
				CoverUrl      string    `json:"cover_url"`
				FileUrl       string    `json:"file_url"`
				CreatedAt     time.Time `json:"created_at"`
			}

			var ebooks []EbookItem
			for rows.Next() {
				var e EbookItem
				var coverUrl sql.NullString
				
				err := rows.Scan(&e.ID, &e.Judul, &e.Jenjang, &e.MataPelajaran, &e.Kategori, &coverUrl, &e.FileUrl, &e.CreatedAt)
				if err != nil {
					continue
				}
				e.CoverUrl = coverUrl.String
				ebooks = append(ebooks, e)
			}

			c.JSON(http.StatusOK, gin.H{
				"total_ebooks": len(ebooks),
				"ebooks":       ebooks,
			})
		})

		adminApi.POST("/ebooks", func(c *gin.Context) {
			var req CreateEbookRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Format data e-book tidak valid: " + err.Error()})
				return
			}

			var ebookID string
			query := `INSERT INTO ebooks (judul, jenjang, mata_pelajaran, kategori, cover_url, file_url) 
			          VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`
			
			err := database.DB.QueryRow(query, req.Judul, req.Jenjang, req.MataPelajaran, req.Kategori, req.CoverUrl, req.FileUrl).Scan(&ebookID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyimpan e-book ke database: " + err.Error()})
				return
			}

			c.JSON(http.StatusCreated, gin.H{
				"message":  "E-book berhasil ditambahkan",
				"ebook_id": ebookID,
			})
		})

		adminApi.DELETE("/ebooks/:id", func(c *gin.Context) {
			ebookID := c.Param("id")

			var judulBuku string
			_ = database.DB.QueryRow(`SELECT judul FROM ebooks WHERE id = $1`, ebookID).Scan(&judulBuku)

			query := `DELETE FROM ebooks WHERE id = $1`
			result, err := database.DB.Exec(query, ebookID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menghapus e-book: " + err.Error()})
				return
			}

			rowsAffected, _ := result.RowsAffected()
			if rowsAffected == 0 {
				c.JSON(http.StatusNotFound, gin.H{"error": "E-book tidak ditemukan"})
				return
			}

			adminIDVal, _ := c.Get("admin_id")
			if adminIDVal != nil {
				adminID := int(adminIDVal.(float64))
				logSuperAdminActivity(adminID, "DELETE_EBOOK", c.ClientIP(), c.Request.UserAgent(), "", fmt.Sprintf("Menghapus e-book: %s", judulBuku))
			}

			c.JSON(http.StatusOK, gin.H{
				"message":  "E-book berhasil dihapus",
				"ebook_id": ebookID,
			})
		})
	}

	api := r.Group("/api")
	api.Use(middleware.AuthMiddleware())
	{
		// Endpoint untuk membuat Snap Token Midtrans Pembelian Token
		api.POST("/payment/create-snap", func(c *gin.Context) {
			userID, _ := c.Get("user_id")

			var req CreateTransactionRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Data paket tidak valid: " + err.Error()})
				return
			}

			orderID := fmt.Sprintf("TP-%d-%s", time.Now().Unix(), strings.ToUpper(randString(4)))

			_, err := database.DB.Exec(
				`INSERT INTO token_orders (user_id, order_id, package_name, token_amount, amount, status) VALUES ($1, $2, $3, $4, $5, 'pending')`,
				userID, orderID, req.PackageName, req.TokenAmount, req.Amount,
			)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mencatat pesanan ke database"})
				return
			}

			serverKey := os.Getenv("MIDTRANS_SERVER_KEY")
			isProduction := os.Getenv("MIDTRANS_IS_PRODUCTION") == "true" 
			
			midtransURL := "https://app.sandbox.midtrans.com/snap/v1/transactions"
			if isProduction {
				midtransURL = "https://app.midtrans.com/snap/v1/transactions"
			}

			payload := map[string]any{
				"transaction_details": map[string]any{
					"order_id":     orderID,
					"gross_amount": req.Amount,
				},
				"item_details": []map[string]any{
					{
						"id":       req.PackageName,
						"price":    req.Amount,
						"quantity": 1,
						"name":     fmt.Sprintf("Paket Token %s (%d Token)", req.PackageName, req.TokenAmount),
					},
				},
			}

			jsonBody, _ := json.Marshal(payload)
			httpReq, _ := http.NewRequest("POST", midtransURL, bytes.NewBuffer(jsonBody))
			httpReq.Header.Set("Content-Type", "application/json")
			httpReq.Header.Set("Accept", "application/json")
			httpReq.SetBasicAuth(serverKey, "")

			client := &http.Client{Timeout: 15 * time.Second}
			resp, err := client.Do(httpReq)
			if err != nil {
				fmt.Printf("DEBUG ERROR KONEKSI MIDTRANS: %v\n", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal terhubung ke gateway pembayaran Midtrans"})
				return
			}
			defer resp.Body.Close()

			var midtransResp map[string]any
			json.NewDecoder(resp.Body).Decode(&midtransResp)

			// Cetak respons dari Midtrans 
			fmt.Printf("RESPON MIDTRANS STATUS: %d, BODY: %+v\n", resp.StatusCode, midtransResp)

			if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
				errMsg := "Gagal membuat transaksi dari Midtrans"
				if errs, ok := midtransResp["error_messages"].([]any); ok && len(errs) > 0 {
					errMsg = fmt.Sprintf("%v", errs[0])
				}
				c.JSON(http.StatusBadRequest, gin.H{"error": errMsg})
				return
			}

			snapToken, _ := midtransResp["token"].(string)
			redirectURL, _ := midtransResp["redirect_url"].(string)

			if snapToken == "" {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Token Snap tidak ditemukan dari Midtrans"})
				return
			}

			_, _ = database.DB.Exec(
				`UPDATE token_orders SET snap_token = $1, snap_redirect_url = $2 WHERE order_id = $3`,
				snapToken, redirectURL, orderID,
			)

			c.JSON(http.StatusOK, gin.H{
				"order_id":     orderID,
				"snap_token":   snapToken,
				"redirect_url": redirectURL,
			})
		})

		api.GET("/profile", func(c *gin.Context) {
			userID, _ := c.Get("user_id")

			_, _ = database.DB.Exec(`UPDATE profiles SET last_login = NOW() WHERE id = $1`, userID)

			var p UpdateProfileRequest
			var tokenBalance int

			queryFixed := `SELECT 
				COALESCE(nama_guru, ''), COALESCE(nip_guru, ''), COALESCE(nama_sekolah, ''), 
				COALESCE(mata_pelajaran, ''), COALESCE(fase, ''), COALESCE(kelas, ''), 
				COALESCE(semester, ''), COALESCE(tahun_pelajaran, ''), COALESCE(nama_kepala_sekolah, ''), 
				COALESCE(nip_kepala_sekolah, ''), COALESCE(kota_kabupaten, ''), COALESCE(tanggal_penandatanganan, ''), 
				COALESCE(alamat_sekolah, ''), COALESCE(kecamatan_kabupaten, ''), COALESCE(kode_pos, ''), 
				COALESCE(telepon_sekolah, ''), COALESCE(email_sekolah, ''), COALESCE(npsn, ''), 
				COALESCE(website_sekolah, ''), token_balance 
				FROM profiles WHERE id = $1`

			err := database.DB.QueryRow(queryFixed, userID).Scan(
				&p.NamaGuru, &p.NipGuru, &p.NamaSekolah, &p.MataPelajaran, &p.Fase, &p.Kelas,
				&p.Semester, &p.TahunPelajaran, &p.NamaKepalaSekolah, &p.NipKepalaSekolah,
				&p.KotaKabupaten, &p.TanggalPenandatanganan, &p.AlamatSekolah, &p.KecamatanKabupaten,
				&p.KodePos, &p.TeleponSekolah, &p.EmailSekolah, &p.Npsn, &p.WebsiteSekolah, &tokenBalance,
			)

			if err != nil {
				if err == sql.ErrNoRows {
					c.JSON(http.StatusNotFound, gin.H{"error": "Profil tidak ditemukan"})
					return
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"user_id":       userID,
				"profile":       p,
				"token_balance": tokenBalance,
			})
		})

		api.PUT("/profile", func(c *gin.Context) {
			userID, _ := c.Get("user_id")

			var req UpdateProfileRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Format data tidak valid: " + err.Error()})
				return
			}

			query := `UPDATE profiles SET 
				nama_guru = $1, nip_guru = $2, nama_sekolah = $3, mata_pelajaran = $4, 
				fase = $5, kelas = $6, semester = $7, tahun_pelajaran = $8, 
				nama_kepala_sekolah = $9, nip_kepala_sekolah = $10, kota_kabupaten = $11, 
				tanggal_penandatanganan = $12, alamat_sekolah = $13, kecamatan_kabupaten = $14, 
				kode_pos = $15, telepon_sekolah = $16, email_sekolah = $17, npsn = $18, 
				website_sekolah = $19, updated_at = NOW() 
				WHERE id = $20`

			_, err := database.DB.Exec(query,
				req.NamaGuru, req.NipGuru, req.NamaSekolah, req.MataPelajaran,
				req.Fase, req.Kelas, req.Semester, req.TahunPelajaran,
				req.NamaKepalaSekolah, req.NipKepalaSekolah, req.KotaKabupaten,
				req.TanggalPenandatanganan, req.AlamatSekolah, req.KecamatanKabupaten,
				req.KodePos, req.TeleponSekolah, req.EmailSekolah, req.Npsn,
				req.WebsiteSekolah, userID,
			)

			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memperbarui profil: " + err.Error()})
				return
			}

            c.JSON(http.StatusOK, gin.H{"message": "Identitas perangkat berhasil diperbarui"})
		})

		api.POST("/question-banks", func(c *gin.Context) {
			userID, _ := c.Get("user_id")

			var req CreateQuestionBankRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Data input tidak valid: " + err.Error()})
				return
			}

			tx, err := database.DB.Begin()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memulai transaksi database"})
				return
			}
			defer tx.Rollback()

			var bankID string
			bankQuery := `INSERT INTO question_banks (user_id, title, description, subject, phase, price_in_tokens, is_public) 
			              VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`
			
			err = tx.QueryRow(bankQuery, userID, req.Title, req.Description, req.Subject, req.Phase, req.PriceInTokens, req.IsPublic).Scan(&bankID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyimpan bank soal: " + err.Error()})
				return
			}

			for _, q := range req.Questions {
				var optionsStr string
				if q.Options == nil || q.Options == "" {
					optionsStr = "null"
				} else {
					optionsBytes, err := json.Marshal(q.Options)
					if err != nil {
						c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memproses format options soal"})
						return
					}
					optionsStr = string(optionsBytes)
				}

				qQuery := `INSERT INTO questions (question_bank_id, question_text, question_type, options, correct_answer, explanation, cognitive_level)
				           VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7)`
				
				_, err = tx.Exec(qQuery, bankID, q.QuestionText, q.QuestionType, optionsStr, q.CorrectAnswer, q.Explanation, q.CognitiveLevel)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyimpan butir soal: " + err.Error()})
					return
				}
			}

			if err := tx.Commit(); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyimpan perubahan secara permanen"})
				return
			}

			c.JSON(http.StatusCreated, gin.H{
				"message": "Bank soal dan butir soal berhasil dibuat",
				"bank_id": bankID,
			})
		})

		api.POST("/ai/generate-questions", func(c *gin.Context) {
			var req GenerateAIRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Parameter AI tidak valid: " + err.Error()})
				return
			}

			ctx := context.Background()
			apiKey := os.Getenv("GEMINI_API_KEY")
			if apiKey == "" {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "API Key Gemini belum dikonfigurasi di server"})
				return
			}

			client, err := genai.NewClient(ctx, option.WithAPIKey(apiKey))
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal inisialisasi client AI"})
				return
			}
			defer client.Close()

			model := client.GenerativeModel("gemini-3.7-flash")
			model.GenerationConfig = genai.GenerationConfig{
				ResponseMIMEType: "application/json",
			}

			prompt := fmt.Sprintf(
				"Buatkan %d butir soal tipe %s untuk topik '%s' dengan level kognitif %s. "+
					"Format output harus berupa JSON Array murni berisi objek dengan properti: "+
					"question_text (string), question_type (string), options (object atau null jika essay/isian singkat), "+
					"correct_answer (string atau array), explanation (string), cognitive_level (string).",
				req.NumberOfQ, req.QuestionType, req.Topic, req.CognitiveLevel,
			)

			resp, err := model.GenerateContent(ctx, genai.Text(prompt))
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal men-generate soal dari AI: " + err.Error()})
				return
			}

			var jsonResult string
			for _, part := range resp.Candidates[0].Content.Parts {
				jsonResult += fmt.Sprintf("%v", part)
			}

			c.Data(http.StatusOK, "application/json", []byte(jsonResult))
		})

		api.GET("/ebooks-list", func(c *gin.Context) {
			rows, err := database.DB.Query(`
				SELECT id, judul, jenjang, mata_pelajaran, kategori, cover_url, file_url, created_at 
				FROM ebooks 
				ORDER BY created_at DESC
			`)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memuat daftar e-book"})
				return
			}
			defer rows.Close()

			type EbookPublicItem struct {
				ID            string    `json:"id"`
				Judul         string    `json:"judul"`
				Jenjang       string    `json:"jenjang"`
				MataPelajaran string    `json:"mata_pelajaran"`
				Kategori      string    `json:"kategori"`
				CoverUrl      string    `json:"cover_url"`
				FileUrl       string    `json:"file_url"`
			}

			var list []EbookPublicItem
			for rows.Next() {
				var item EbookPublicItem
				var cover sql.NullString
				var createdAt time.Time
				
				if err := rows.Scan(&item.ID, &item.Judul, &item.Jenjang, &item.MataPelajaran, &item.Kategori, &cover, &item.FileUrl, &createdAt); err == nil {
					item.CoverUrl = cover.String
					list = append(list, item)
				}
			}

			c.JSON(http.StatusOK, gin.H{"ebooks": list})
		})

		api.POST("/ebooks-list/history", func(c *gin.Context) {
			userID, _ := c.Get("user_id")

			var req struct {
				EbookID    string `json:"ebook_id" binding:"required"`
				ActionType string `json:"action_type" binding:"required"`
			}

			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Data riwayat tidak valid"})
				return
			}

			_, err := database.DB.Exec(
				`INSERT INTO ebook_history (user_id, ebook_id, action_type) VALUES ($1, $2, $3)`,
				userID, req.EbookID, req.ActionType,
			)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mencatat riwayat e-book"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "Riwayat berhasil dicatat/disimpan"})
		})
	}
}