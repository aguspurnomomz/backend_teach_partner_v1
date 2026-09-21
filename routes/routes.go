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

// --- Struct untuk Superadmin ---
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

// B2B struct admin school
type CreateSchoolRequest struct {
	SchoolName string `json:"school_name" binding:"required"`
	Npsn       string `json:"npsn" binding:"required"`
	Address    string `json:"address"`
	Jenjang    string `json:"jenjang" binding:"required"` 
}

type AcademicYearRequest struct {
	Name      string `json:"name" binding:"required"`
	Semester  string `json:"semester" binding:"required"`
	StartDate string `json:"start_date"`
	EndDate   string `json:"end_date"`
}

type UpdateSchoolProfileRequest struct {
	SchoolName string `json:"school_name" binding:"required"`
	Npsn       string `json:"npsn" binding:"required"`
	Address    string `json:"address"`
	City       string `json:"city"`
	Email      string `json:"email"`
}

type CreateClassGroupRequest struct {
	Name           string `json:"name" binding:"required"`
	Level          string `json:"level" binding:"required"`
	Major          string `json:"major"`
	ClassType      string `json:"class_type"`
	AcademicYearID string `json:"academic_year_id" binding:"required"`
}

// --- Struct Pembelian Token & Midtrans ---
type CreateTransactionRequest struct {
	PackageName string `json:"package_name" binding:"required"`
	TokenAmount int    `json:"token_amount" binding:"required"`
	Amount      int    `json:"amount" binding:"required"`
}

type CreateSchoolAdminRequest struct {
	SchoolID string `json:"school_id" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
	FullName string `json:"full_name" binding:"required"`
	Nip      string `json:"nip"` 
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

type CreateExamSessionRequest struct {
	Title            string `json:"title" binding:"required"`
	QuestionBankID   string `json:"question_bank_id" binding:"required"`
	DurationMinutes  int    `json:"duration_minutes"`
}

type SubmitExamRequest struct {
	SessionID     string            `json:"session_id" binding:"required"`
	StudentName   string            `json:"student_name" binding:"required"`
	StudentNumber string            `json:"student_number" binding:"required"`
	NISN          string            `json:"nisn" binding:"required"`
	Answers       map[string]string `json:"answers" binding:"required"`
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

func sendResendEmail(toEmail string, subject string, htmlContent string) {
	apiKey := os.Getenv("RESEND_API_KEY")
	fromEmail := os.Getenv("RESEND_FROM_EMAIL") 

	if apiKey == "" || fromEmail == "" || toEmail == "" {
		fmt.Printf("Resend API Key atau From Email belum dikonfigurasi\n")
		return
	}

	payload := map[string]any{
		"from":    fromEmail,
		"to":      []string{toEmail},
		"subject": subject,
		"html":    htmlContent,
	}

	jsonBody, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Gagal marshal payload Resend: %v\n", err)
		return
	}

	req, err := http.NewRequest("POST", "https://api.resend.com/emails", bytes.NewBuffer(jsonBody))
	if err != nil {
		fmt.Printf("Gagal membuat request Resend: %v\n", err)
		return
	}

	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Gagal mengirim email via Resend: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		fmt.Printf("Resend mengembalikan status error: %d\n", resp.StatusCode)
	}
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

	r.GET("/debug-sentry", func(c *gin.Context) {
		panic("Test Sentry Error dari Backend Golang!")
	})

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

		lokasiStr := "Tidak diizinkan / Tidak tersedia"
		mapsLink := "Tidak tersedia"
		if req.Location != nil {
			lokasiStr = fmt.Sprintf("%.6f, %.6f", req.Location.Latitude, req.Location.Longitude)
			mapsLink = fmt.Sprintf("%.6f, %.6f (https://maps.google.com/?q=%.6f,%.6f)", 
				req.Location.Latitude, req.Location.Longitude, 
				req.Location.Latitude, req.Location.Longitude)
		}

		// Cek apakah akun sedang diblokir sementara
		if lockedUntil.Valid && lockedUntil.Time.After(time.Now()) {
			sisaWaktu := int(time.Until(lockedUntil.Time).Seconds())
			c.JSON(http.StatusLocked, gin.H{
				"error": fmt.Sprintf("Akun Anda dikunci sementara karena terlalu banyak percobaan gagal. Coba lagi dalam %d detik.", sisaWaktu),
			})
			return
		}

		// Validasi Password
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

				// simpen lokasi di log LOGIN_LOCKED
				logSuperAdminActivity(adminID, "LOGIN_LOCKED", c.ClientIP(), c.Request.UserAgent(), lokasiStr, "Akun dikunci 1 menit karena 3x salah password")
				c.JSON(http.StatusLocked, gin.H{"error": "Terlalu banyak percobaan gagal. Akun dikunci sementara selama 1 menit."})
				return
			} else {
				_, _ = database.DB.Exec(
					`UPDATE super_admins SET failed_login_attempts = $1 WHERE id = $2`,
					failedAttempts, adminID,
				)
				// simpen lokasi log LOGIN_FAILED
				logSuperAdminActivity(adminID, "LOGIN_FAILED", c.ClientIP(), c.Request.UserAgent(), lokasiStr, "Password salah")
				c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Sprintf("Kata sandi salah! Sisa percobaan: %d", 3-failedAttempts)})
				return
			}
		}

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
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyimpan kata sandi baru"})
				return
			}

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

		//B2B
		// Endpoint Superadmin: Mendaftarkan Sekolah Baru (B2B)
		adminApi.POST("/schools", func(c *gin.Context) {
			var req CreateSchoolRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Format data sekolah tidak valid: " + err.Error()})
				return
			}

			// Cek apakah NPSN sudah terdaftar sebelumnya
			var existingID string
			err := database.DB.QueryRow(`SELECT id FROM schools WHERE npsn = $1`, req.Npsn).Scan(&existingID)
			if err == nil && existingID != "" {
				c.JSON(http.StatusConflict, gin.H{"error": "Sekolah dengan NPSN tersebut sudah terdaftar di sistem"})
				return
			}

			// Simpan sekolah baru beserta jenjangnya ke database
			var schoolID string
			query := `INSERT INTO schools (school_name, npsn, address, jenjang, is_active) VALUES ($1, $2, $3, $4, TRUE) RETURNING id`
			err = database.DB.QueryRow(query, req.SchoolName, req.Npsn, req.Address, req.Jenjang).Scan(&schoolID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyimpan data sekolah ke database: " + err.Error()})
				return
			}

			// Catat log aktivitas superadmin
			adminIDVal, _ := c.Get("admin_id")
			if adminIDVal != nil {
				adminID := int(adminIDVal.(float64))
				logSuperAdminActivity(adminID, "CREATE_SCHOOL", c.ClientIP(), c.Request.UserAgent(), "", fmt.Sprintf("Mendaftarkan sekolah baru: %s (NPSN: %s)", req.SchoolName, req.Npsn))
			}

			c.JSON(http.StatusCreated, gin.H{
				"message":     "Sekolah berhasil didaftarkan",
				"school_id":   schoolID,
				"school_name": req.SchoolName,
				"npsn":        req.Npsn,
			})
		})

		// Endpoint Superadmin: Melihat Daftar Sekolah B2B
		adminApi.GET("/schools", func(c *gin.Context) {
			rows, err := database.DB.Query(`
				SELECT id, school_name, npsn, address, is_active, created_at 
				FROM schools 
				ORDER BY created_at DESC
			`)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil daftar sekolah: " + err.Error()})
				return
			}
			defer rows.Close()

			type SchoolItem struct {
				ID         string    `json:"id"`
				SchoolName string    `json:"school_name"`
				Npsn       string    `json:"npsn"`
				Address    string    `json:"address"`
				IsActive   bool      `json:"is_active"`
				CreatedAt  time.Time `json:"created_at"`
			}

			var schools []SchoolItem
			for rows.Next() {
				var s SchoolItem
				var address sql.NullString
				if err := rows.Scan(&s.ID, &s.SchoolName, &s.Npsn, &address, &s.IsActive, &s.CreatedAt); err == nil {
					s.Address = address.String
					schools = append(schools, s)
				}
			}

			c.JSON(http.StatusOK, gin.H{
				"total_schools": len(schools),
				"schools":       schools,
			})
		})

		// Endpoint Superadmin: Mendaftarkan Akun Admin Sekolah (B2B)
		adminApi.POST("/school-admins", func(c *gin.Context) {
			var req CreateSchoolAdminRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Format input tidak valid: " + err.Error()})
				return
			}

			// 1. Pastikan school_id yang dipilih valid dan ada di database
			var schoolExists string
			err := database.DB.QueryRow(`SELECT id FROM schools WHERE id = $1`, req.SchoolID).Scan(&schoolExists)
			if err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "Institusi sekolah tidak ditemukan"})
				return
			}

			// 2. Daftarkan user ke Supabase Auth menggunakan Admin API
			supabaseURL := os.Getenv("SUPABASE_URL")
			serviceRoleKey := os.Getenv("SUPABASE_SERVICE_ROLE_KEY")

			if supabaseURL == "" || serviceRoleKey == "" {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Konfigurasi Supabase URL atau Service Role Key belum lengkap di server"})
				return
			}

			supabaseAdminURL := fmt.Sprintf("%s/auth/v1/admin/users", supabaseURL)
			
			payloadAuth := map[string]any{
				"email":          req.Email,
				"password":       req.Password,
				"email_confirm":  true, // Otomatis aktifkan email
				"user_metadata": map[string]any{
					"full_name": req.FullName,
					"role":      "school_admin",
				},
			}
			jsonAuthBody, _ := json.Marshal(payloadAuth)

			httpReq, err := http.NewRequest("POST", supabaseAdminURL, bytes.NewBuffer(jsonAuthBody))
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyiapkan request ke Supabase Auth"})
				return
			}
			httpReq.Header.Set("Content-Type", "application/json")
			httpReq.Header.Set("apikey", serviceRoleKey)
			httpReq.Header.Set("Authorization", "Bearer "+serviceRoleKey)

			client := &http.Client{Timeout: 15 * time.Second}
			resp, err := client.Do(httpReq)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal terhubung ke layanan Supabase Auth"})
				return
			}
			defer resp.Body.Close()

			var authResp map[string]any
			json.NewDecoder(resp.Body).Decode(&authResp)

			if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
				errMsg := "Gagal membuat akun di Supabase Auth"
				if msg, ok := authResp["msg"].(string); ok {
					errMsg = msg
				} else if message, ok := authResp["message"].(string); ok {
					errMsg = message
				}
				c.JSON(http.StatusBadRequest, gin.H{"error": errMsg})
				return
			}

			// Ambil UUID user yang baru dibuat dari respon Supabase Auth
			userID, ok := authResp["id"].(string)
			if !ok || userID == "" {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mendapatkan UUID dari Supabase Auth"})
				return
			}

			// 3. Masukkan data ke tabel khusus school_admins

			query := `
				INSERT INTO school_admins (id, school_id, full_name, email, nip, user_type, is_active, updated_at) 
				VALUES ($1, $2, $3, $4, $5, 'school_admin', TRUE, NOW())
			`
			
			_, err = database.DB.Exec(query, userID, req.SchoolID, req.FullName, req.Email, req.Nip)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyimpan data admin sekolah ke database: " + err.Error()})
				return
			}

			// 4. Catat log aktivitas superadmin
			adminIDVal, _ := c.Get("admin_id")
			if adminIDVal != nil {
				adminID := int(adminIDVal.(float64))
				logSuperAdminActivity(adminID, "CREATE_SCHOOL_ADMIN", c.ClientIP(), c.Request.UserAgent(), "", fmt.Sprintf("Membuat akun admin sekolah untuk: %s (%s)", req.FullName, req.Email))
			}

			c.JSON(http.StatusCreated, gin.H{
				"message":   "Akun Admin Sekolah berhasil dibuat dan tersimpan.",
				"admin_id":  userID,
				"email":     req.Email,
				"school_id": req.SchoolID,
			})
		})

		// Endpoint Superadmin: Melihat Daftar Admin Sekolah B2B
		adminApi.GET("/school-admins", func(c *gin.Context) {
			rows, err := database.DB.Query(`
				SELECT sa.id, sa.full_name, sa.email, sa.nip, sa.is_active, sa.created_at, s.school_name, s.npsn
				FROM school_admins sa
				JOIN schools s ON sa.school_id = s.id
				ORDER BY sa.created_at DESC
			`)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil daftar admin sekolah: " + err.Error()})
				return
			}
			defer rows.Close()

			type SchoolAdminItem struct {
				ID         string    `json:"id"`
				FullName   string    `json:"full_name"`
				Email      string    `json:"email"`
				Nip        string    `json:"nip"`
				IsActive   bool      `json:"is_active"`
				CreatedAt  time.Time `json:"created_at"`
				SchoolName string    `json:"school_name"`
				Npsn       string    `json:"npsn"`
			}

			var admins []SchoolAdminItem
			for rows.Next() {
				var a SchoolAdminItem
				var nip sql.NullString
				if err := rows.Scan(&a.ID, &a.FullName, &a.Email, &nip, &a.IsActive, &a.CreatedAt, &a.SchoolName, &a.Npsn); err == nil {
					a.Nip = nip.String
					admins = append(admins, a)
				}
			}

			c.JSON(http.StatusOK, gin.H{
				"total_admins": len(admins),
				"admins":       admins,
			})
		})

		// adminApi.GET("/academic-years", func(c *gin.Context) {
		// 	adminID := c.MustGet("admin_id") // Atau ambil berdasarkan sesi school_admin yang login

		// 	// Ambil school_id berdasarkan admin yang sedang login
		// 	var schoolID string
		// 	err := database.DB.QueryRow(`SELECT school_id FROM school_admins WHERE id = $1`, adminID).Scan(&schoolID)
		// 	if err != nil {
		// 		c.JSON(http.StatusNotFound, gin.H{"error": "Data institusi admin tidak ditemukan"})
		// 		return
		// 	}

		// 	rows, err := database.DB.Query(`
		// 		SELECT id, name, semester, start_date, end_date, is_active, created_at 
		// 		FROM school_academic_years 
		// 		WHERE school_id = $1 
		// 		ORDER BY created_at DESC
		// 	`, schoolID)
		// 	if err != nil {
		// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil data tahun akademik"})
		// 		return
		// 	}
		// 	defer rows.Close()

		// 	type AcademicYear struct {
		// 		ID        string     `json:"id"`
		// 		Name      string     `json:"name"`
		// 		Semester  string     `json:"semester"`
		// 		StartDate *string    `json:"start_date"`
		// 		EndDate   *string    `json:"end_date"`
		// 		IsActive  bool       `json:"is_active"`
		// 		CreatedAt time.Time  `json:"created_at"`
		// 	}

		// 	var years []AcademicYear
		// 	for rows.Next() {
		// 		var y AcademicYear
		// 		var start, end sql.NullString
		// 		if err := rows.Scan(&y.ID, &y.Name, &y.Semester, &start, &end, &y.IsActive, &y.CreatedAt); err == nil {
		// 			if start.Valid { y.StartDate = &start.String }
		// 			if end.Valid { y.EndDate = &end.String }
		// 			years = append(years, y)
		// 		}
		// 	}

		// 	c.JSON(http.StatusOK, gin.H{"academic_years": years})
		// })

		// adminApi.POST("/academic-years", func(c *gin.Context) {
		// 	adminID := c.MustGet("admin_id")
		// 	var schoolID string
		// 	_ = database.DB.QueryRow(`SELECT school_id FROM school_admins WHERE id = $1`, adminID).Scan(&schoolID)

		// 	var req AcademicYearRequest
		// 	if err := c.ShouldBindJSON(&req); err != nil {
		// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Format data tidak valid: " + err.Error()})
		// 		return
		// 	}

		// 	var yearID string
		// 	err := database.DB.QueryRow(`
		// 		INSERT INTO school_academic_years (school_id, name, semester, start_date, end_date, is_active)
		// 		VALUES ($1, $2, $3, NULLIF($4, '')::date, NULLIF($5, '')::date, FALSE)
		// 		RETURNING id
		// 	`, schoolID, req.Name, req.Semester, req.StartDate, req.EndDate).Scan(&yearID)

		// 	if err != nil {
		// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyimpan tahun akademik: " + err.Error()})
		// 		return
		// 	}

		// 	c.JSON(http.StatusCreated, gin.H{"message": "Tahun akademik berhasil ditambahkan", "id": yearID})
		// })

		// adminApi.PATCH("/academic-years/:id/activate", func(c *gin.Context) {
		// 	adminID := c.MustGet("admin_id")
		// 	var schoolID string
		// 	_ = database.DB.QueryRow(`SELECT school_id FROM school_admins WHERE id = $1`, adminID).Scan(&schoolID)
		// 	yearID := c.Param("id")

		// 	// Nonaktifkan semua tahun akademik di sekolah ini terlebih dahulu
		// 	_, _ = database.DB.Exec(`UPDATE school_academic_years SET is_active = FALSE WHERE school_id = $1`, schoolID)

		// 	// Aktifkan tahun akademik yang dipilih
		// 	_, err := database.DB.Exec(`UPDATE school_academic_years SET is_active = TRUE WHERE id = $1 AND school_id = $2`, yearID, schoolID)
		// 	if err != nil {
		// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengaktifkan tahun akademik"})
		// 		return
		// 	}

		// 	c.JSON(http.StatusOK, gin.H{"message": "Tahun akademik aktif berhasil diperbarui"})
		// })
	}

	// ==========================================
	// Endpoint yang diakses siswa (uji coba ujian)
	// ==========================================
	apiPub := r.Group("/api")
	{
		// Endpoint Siswa Memuat Soal Berdasarkan Token QR
		apiPub.GET("/exam/session-questions", func(c *gin.Context) {
			token := c.Query("token")
			if token == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Token sesi tidak disertakan"})
				return
			}

			var sessionID, examTitle string
			var questionBankID sql.NullString
			
			err := database.DB.QueryRow(`
				SELECT id, title, question_bank_id 
				FROM exam_sessions 
				WHERE (qr_code_token = $1 OR id::text = $1) AND deleted_at IS NULL
			`, token).Scan(&sessionID, &examTitle, &questionBankID)

			if err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "Sesi ujian tidak ditemukan atau QR Code tidak valid"})
				return
			}

			if !questionBankID.Valid {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Sesi ujian ini tidak memiliki bank soal yang terhubung"})
				return
			}

			rows, err := database.DB.Query(`
				SELECT id, question_text, question_type, options, cognitive_level 
				FROM questions 
				WHERE question_bank_id = $1
			`, questionBankID.String)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memuat butir soal dari database: " + err.Error()})
				return
			}
			defer rows.Close()

			type QuestionItem struct {
				ID             string `json:"id"`
				QuestionText   string `json:"question_text"`
				QuestionType   string `json:"question_type"`
				Options        any    `json:"options"`
				CognitiveLevel string `json:"cognitive_level"`
			}

			var questions []QuestionItem
			for rows.Next() {
				var q QuestionItem
				var optionsJson []byte
				var cogLevel sql.NullString
				
				if err := rows.Scan(&q.ID, &q.QuestionText, &q.QuestionType, &optionsJson, &cogLevel); err != nil {
					continue
				}

				var parsedOptions any
				if len(optionsJson) > 0 {
					_ = json.Unmarshal(optionsJson, &parsedOptions)
				}
				q.Options = parsedOptions
				q.CognitiveLevel = cogLevel.String
				
				questions = append(questions, q)
			}

			c.JSON(http.StatusOK, gin.H{
				"session_id": sessionID,
				"title":      examTitle,
				"questions":  questions,
			})
		})

		// Endpoint Siswa Mengumpulkan Jawaban Ujian
		apiPub.POST("/exam/submit", func(c *gin.Context) {
			var req SubmitExamRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Data pengumpulan ujian tidak lengkap: " + err.Error()})
				return
			}

			var existingID string
			err := database.DB.QueryRow(`
				SELECT id FROM exam_submissions WHERE exam_session_id = $1 AND nisn = $2
			`, req.SessionID, req.NISN).Scan(&existingID)

			if err == nil && existingID != "" {
				c.JSON(http.StatusForbidden, gin.H{"error": "Akses ditolak! Anda (NISN " + req.NISN + ") sudah pernah mengumpulkan ujian ini."})
				return
			}

			var questionBankID string
			err = database.DB.QueryRow(`
				SELECT question_bank_id FROM exam_sessions WHERE id = $1
			`, req.SessionID).Scan(&questionBankID)

			if err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "Sesi ujian tidak valid"})
				return
			}

			rows, err := database.DB.Query(`
				SELECT id, correct_answer FROM questions WHERE question_bank_id = $1
			`, questionBankID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memvalidasi kunci jawaban"})
				return
			}
			defer rows.Close()

			correctAnswersMap := make(map[string]string)
			totalQuestions := 0
			for rows.Next() {
				var qID string
				var correctAnsJSON []byte
				if err := rows.Scan(&qID, &correctAnsJSON); err == nil {
					var rawAns string
					if json.Unmarshal(correctAnsJSON, &rawAns) == nil {
						correctAnswersMap[qID] = rawAns
					} else {
						correctAnswersMap[qID] = string(correctAnsJSON)
					}
					totalQuestions++
				}
			}

			correctCount := 0
			for qID, studentAns := range req.Answers {
				if correctAns, exists := correctAnswersMap[qID]; exists {
					cleanedCorrect := strings.Trim(correctAns, `"`)
					if strings.EqualFold(strings.TrimSpace(studentAns), strings.TrimSpace(cleanedCorrect)) {
						correctCount++
					}
				}
			}

			var score float64 = 0
			if totalQuestions > 0 {
				score = (float64(correctCount) / float64(totalQuestions)) * 100
			}

			answersBytes, _ := json.Marshal(req.Answers)
			queryInsert := `
				INSERT INTO exam_submissions (exam_session_id, student_name, student_number, nisn, answers, score)
				VALUES ($1, $2, $3, $4, $5::jsonb, $6)
			`

			_, err = database.DB.Exec(queryInsert, req.SessionID, req.StudentName, req.StudentNumber, req.NISN, string(answersBytes), score)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyimpan jawaban: Siswa dengan NISN ini sudah tercatat mengumpulkan ujian."})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"message": "Ujian berhasil dikumpulkan",
				"score":   score,
			})
		})

		// Endpoint Cek Status Siswa
		apiPub.GET("/exam/check-student", func(c *gin.Context) {
			sessionID := c.Query("session_id")
			nisn := c.Query("nisn")

			if sessionID == "" || nisn == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Parameter tidak lengkap"})
				return
			}

			var existingID string
			err := database.DB.QueryRow(`
				SELECT id FROM exam_submissions WHERE exam_session_id = $1 AND nisn = $2
			`, sessionID, nisn).Scan(&existingID)

			if err == nil && existingID != "" {
				c.JSON(http.StatusOK, gin.H{"has_submitted": true, "message": "NISN ini sudah pernah mengumpulkan ujian."})
				return
			}

			c.JSON(http.StatusOK, gin.H{"has_submitted": false})
		})
	}

	// ==========================================
	// --- ROUTE TERPROTEKSI (api) ---
	// Wajib Auth: Hanya guru yang login yang bisa mengakses data miliknya sendiri
	// ==========================================
	api := r.Group("/api")
	api.Use(middleware.AuthMiddleware())
	{

		
		api.GET("/auth/check-role", func(c *gin.Context) {
			userID, exists := c.Get("user_id")
			if !exists {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
				return
			}

			// Safe conversion userID ke string
			var userIDStr string
			switch v := userID.(type) {
			case string:
				userIDStr = v
			case fmt.Stringer:
				userIDStr = v.String()
			default:
				userIDStr = fmt.Sprintf("%v", v)
			}

			fmt.Printf("[check-role] userID=%s\n", userIDStr)

			// ==========================================
			// 1. Ambil email user dari auth.users
			// ==========================================
			var userEmail string
			err := database.DB.QueryRow(
				`SELECT COALESCE(email, '') FROM auth.users WHERE id = $1`,
				userIDStr,
			).Scan(&userEmail)

			if err != nil {
				fmt.Printf("[check-role] Gagal ambil email dari auth.users: %v\n", err)
				// fallback ke context
				if emailFromCtx, ok := c.Get("email"); ok {
					userEmail, _ = emailFromCtx.(string)
				}
			}
			fmt.Printf("[check-role] email=%s\n", userEmail)

			// ==========================================
			// 2. Cek apakah user adalah school_admin
			// ==========================================
			var userType string
			err = database.DB.QueryRow(`
				SELECT user_type FROM school_admins 
				WHERE (id = $1 OR (email <> '' AND email = $2)) 
				AND is_active = TRUE
			`, userIDStr, userEmail).Scan(&userType)  // ← PASTIKAN 2 ARGUMEN!

			if err == nil {
				fmt.Printf("[check-role] User adalah school_admin (%s)\n", userType)

				// Pastikan row profiles juga ada
				_, _ = database.DB.Exec(`
					INSERT INTO profiles (id, email_sekolah, token_balance, is_active, updated_at)
					VALUES ($1, $2, 0, TRUE, NOW())
					ON CONFLICT (id) DO NOTHING
				`, userIDStr, userEmail)  // ← PASTIKAN 2 ARGUMEN!

				c.JSON(http.StatusOK, gin.H{"role": userType})
				return
			}

			// ==========================================
			// 3. Upsert sebagai teacher
			// ==========================================
			fmt.Println("[check-role] Bukan school_admin, upsert sebagai teacher")

			_, err = database.DB.Exec(`
				INSERT INTO profiles (id, email_sekolah, token_balance, is_active, updated_at)
				VALUES ($1, $2, 0, TRUE, NOW())
				ON CONFLICT (id) DO NOTHING
			`, userIDStr, userEmail)  // ← PASTIKAN 2 ARGUMEN!

			if err != nil {
				fmt.Printf("[check-role] Gagal upsert profile: %v\n", err)
			} else {
				fmt.Println("[check-role] Upsert profile OK")
			}

			c.JSON(http.StatusOK, gin.H{"role": "teacher"})
		})

		api.POST("/auth/notify-password-changed", func(c *gin.Context) {
			userID, exists := c.Get("user_id")
			if !exists {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
				return
			}

			// Ambil email guru dari tabel profiles
			var userEmail string
			err := database.DB.QueryRow(`SELECT email_sekolah FROM profiles WHERE id = $1`, userID).Scan(&userEmail)
			if err != nil || userEmail == "" {
				c.JSON(http.StatusOK, gin.H{"message": "Kata sandi diperbarui, namun email profil tidak ditemukan"})
				return
			}

			// Format waktu kejadian (WIB)
			loc, _ := time.LoadLocation("Asia/Jakarta")
			waktuUbah := time.Now().In(loc).Format("02 January 2006 pukul 15:04 WIB")
			ipClient := c.ClientIP()

			subjek := "Keamanan Akun: Kata Sandi Anda Telah Diubah"
			
			// Buat template HTML email yang rapi
			htmlBody := fmt.Sprintf(`
				<div style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 10px;">
					<h2 style="color: #10b981;">TeachPartner Security Alert</h2>
					<p>Halo Guru,</p>
					<p>Kami ingin menginformasikan bahwa kata sandi untuk akun TeachPartner Anda baru saja berhasil diubah.</p>
					<div style="background-color: #f8fafc; padding: 15px; border-radius: 8px; margin: 20px 0;">
						<p style="margin: 5px 0;"><strong>Waktu:</strong> %s</p>
						<p style="margin: 5px 0;"><strong>Alamat IP:</strong> %s</p>
					</div>
					<p>Jika Anda yang melakukan perubahan ini, Anda dapat mengabaikan email ini dengan aman.</p>
					<p style="color: #ef4444; font-weight: bold;">Jika Anda TIDAK merasa melakukan perubahan ini, segera hubungi administrator atau amankan akun Anda!</p>
					<hr style="border: none; border-top: 1px solid #e0e0e0; margin: 20px 0;" />
					<p style="font-size: 12px; color: #64748b;">Email otomatis ini dikirimkan oleh sistem keamanan TeachPartner.</p>
				</div>
			`, waktuUbah, ipClient)

			// Kirim secara asynchronous agar tidak memblokir respon HTTP
			go sendResendEmail(userEmail, subjek, htmlBody)

			c.JSON(http.StatusOK, gin.H{"message": "Notifikasi perubahan kata sandi berhasil diproses"})
		})
		
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
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal terhubung ke gateway pembayaran Midtrans"})
				return
			}
			defer resp.Body.Close()

			var midtransResp map[string]any
			json.NewDecoder(resp.Body).Decode(&midtransResp)

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
			fmt.Println("========================================")
			fmt.Println(">>> [1] Handler /profile MULAI")

			userID, exists := c.Get("user_id")
			if !exists {
				fmt.Println(">>> [1b] ERROR: user_id tidak ada di context!")
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
				return
			}
			fmt.Printf(">>> [2] userID=%v (type=%T)\n", userID, userID)

			// --- UPDATE last_login ---
			fmt.Println(">>> [3] Akan UPDATE last_login...")
			res, err := database.DB.Exec(`UPDATE profiles SET last_login = NOW() WHERE id = $1`, userID)
			if err != nil {
				fmt.Printf(">>> [3b] UPDATE last_login ERROR: %v\n", err)
				// jangan return, lanjut saja — biar tahu error di step berikutnya
			} else {
				rowsAffected, _ := res.RowsAffected()
				fmt.Printf(">>> [3c] UPDATE last_login OK, rows affected=%d\n", rowsAffected)
			}

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

			// Hitung jumlah $N di query
			dollarCount := strings.Count(queryFixed, "$")
			fmt.Printf(">>> [4] Query SELECT siap. Jumlah placeholder $N = %d\n", dollarCount)
			fmt.Printf(">>> [4b] Query full:\n%s\n", queryFixed)

			// Hitung jumlah argumen yang dikirim
			args := []any{userID}
			fmt.Printf(">>> [5] Jumlah argumen yang dikirim = %d\n", len(args))
			for i, a := range args {
				fmt.Printf(">>> [5.%d] arg[%d] = %v (type=%T)\n", i, i, a, a)
			}

			if dollarCount != len(args) {
				fmt.Printf(">>> [5b] ⚠️ MISMATCH! Query butuh %d param, tapi dikirim %d param\n", dollarCount, len(args))
			}

			fmt.Println(">>> [6] Akan eksekusi QueryRow...")
			err = database.DB.QueryRow(queryFixed, args...).Scan(
				&p.NamaGuru, &p.NipGuru, &p.NamaSekolah, &p.MataPelajaran, &p.Fase, &p.Kelas,
				&p.Semester, &p.TahunPelajaran, &p.NamaKepalaSekolah, &p.NipKepalaSekolah,
				&p.KotaKabupaten, &p.TanggalPenandatanganan, &p.AlamatSekolah, &p.KecamatanKabupaten,
				&p.KodePos, &p.TeleponSekolah, &p.EmailSekolah, &p.Npsn, &p.WebsiteSekolah, &tokenBalance,
			)

			if err != nil {
				fmt.Printf(">>> [6b] QueryRow ERROR: %v\n", err)
				fmt.Printf(">>> [6c] Error type: %T\n", err)

				if err == sql.ErrNoRows {
					fmt.Println(">>> [6d] Tidak ada row di profiles untuk userID ini")
					c.JSON(http.StatusNotFound, gin.H{"error": "Profil tidak ditemukan"})
					return
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			fmt.Printf(">>> [7] QueryRow SUKSES! token_balance=%d, nama_guru=%s\n", tokenBalance, p.NamaGuru)
			fmt.Println(">>> [8] Handler /profile SELESAI")
			fmt.Println("========================================")

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

		
		api.GET("/my-question-banks", func(c *gin.Context) {
			userID, exists := c.Get("user_id")
			if !exists {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
				return
			}

			rows, err := database.DB.Query(`
				SELECT id, title, subject, phase, created_at 
				FROM question_banks 
				WHERE user_id = $1 
				ORDER BY created_at DESC
			`, userID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil daftar bank soal"})
				return
			}
			defer rows.Close()

			type BankItem struct {
				ID        string    `json:"id"`
				Title     string    `json:"title"`
				Subject   string    `json:"subject"`
				Phase     string    `json:"phase"`
				CreatedAt time.Time `json:"created_at"`
			}

			var banks []BankItem
			for rows.Next() {
				var b BankItem
				if err := rows.Scan(&b.ID, &b.Title, &b.Subject, &b.Phase, &b.CreatedAt); err == nil {
					banks = append(banks, b)
				}
			}

			c.JSON(http.StatusOK, gin.H{"question_banks": banks})
		})

		
		api.POST("/exam-sessions", func(c *gin.Context) {
			userID, exists := c.Get("user_id")
			if !exists {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
				return
			}

			var req CreateExamSessionRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Data sesi ujian tidak valid: " + err.Error()})
				return
			}

			qrToken := randString(12)
			expiresAt := time.Now().Add(time.Hour * 3)

			durasi := req.DurationMinutes
			if durasi <= 0 {
				durasi = 60
			}

			var sessionID string
			queryExec := `INSERT INTO exam_sessions (user_id, title, question_bank_id, qr_code_token, duration_minutes, expires_at) 
			              VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`

			err := database.DB.QueryRow(queryExec, userID, req.Title, req.QuestionBankID, qrToken, durasi, expiresAt).Scan(&sessionID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal membuat sesi ujian di database: " + err.Error()})
				return
			}

			c.JSON(http.StatusCreated, gin.H{
				"message":          "Sesi ujian berhasil dibuat",
				"session_id":       sessionID,
				"qr_code_token":    qrToken,
				"duration_minutes": durasi,
			})
		})

	
		api.GET("/exam-sessions", func(c *gin.Context) {
			userID, exists := c.Get("user_id")
			if !exists {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
				return
			}

			rows, err := database.DB.Query(`
				SELECT id, title, qr_code_token, duration_minutes, is_active, created_at 
				FROM exam_sessions 
				WHERE user_id = $1 AND deleted_at IS NULL
				ORDER BY created_at DESC
			`, userID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memuat daftar sesi ujian"})
				return
			}
			defer rows.Close()

			type SessionItem struct {
				ID              string    `json:"id"`
				Title           string    `json:"title"`
				QRCodeToken     string    `json:"qr_code_token"`
				DurationMinutes int       `json:"duration_minutes"`
				IsActive        bool      `json:"is_active"`
				CreatedAt       time.Time `json:"created_at"`
			}

			var sessions []SessionItem
			for rows.Next() {
				var s SessionItem
				if err := rows.Scan(&s.ID, &s.Title, &s.QRCodeToken, &s.DurationMinutes, &s.IsActive, &s.CreatedAt); err == nil {
					sessions = append(sessions, s)
				}
			}

			c.JSON(http.StatusOK, gin.H{"sessions": sessions})
		})

		
		api.GET("/exam-sessions/:id/submissions", func(c *gin.Context) {
			userID, _ := c.Get("user_id")
			sessionID := c.Param("id")

			// Pastikan sesi ini benar milik guru yang bersangkutan
			var ownerID string
			err := database.DB.QueryRow(`SELECT user_id FROM exam_sessions WHERE id = $1`, sessionID).Scan(&ownerID)
			if err != nil || ownerID != userID {
				c.JSON(http.StatusForbidden, gin.H{"error": "Akses ditolak! Sesi ujian bukan milik Anda."})
				return
			}

			rows, err := database.DB.Query(`
				SELECT id, student_name, student_number, nisn, score, submitted_at 
				FROM exam_submissions 
				WHERE exam_session_id = $1 
				ORDER BY submitted_at DESC
			`, sessionID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memuat data log monitoring"})
				return
			}
			defer rows.Close()

			type SubmissionItem struct {
				ID            string    `json:"id"`
				StudentName   string    `json:"student_name"`
				StudentNumber string    `json:"student_number"`
				NISN          string    `json:"nisn"`
				Score         float64   `json:"score"`
				SubmittedAt   time.Time `json:"submitted_at"`
			}

			submissions := make([]SubmissionItem, 0)
			for rows.Next() {
				var s SubmissionItem
				if err := rows.Scan(&s.ID, &s.StudentName, &s.StudentNumber, &s.NISN, &s.Score, &s.SubmittedAt); err == nil {
					submissions = append(submissions, s)
				}
			}

			c.JSON(http.StatusOK, gin.H{"submissions": submissions})
		})

	
		api.DELETE("/exam-sessions/:id", func(c *gin.Context) {
			userID, _ := c.Get("user_id")
			sessionID := c.Param("id")

			result, err := database.DB.Exec(`
				UPDATE exam_sessions SET deleted_at = NOW(), is_active = FALSE WHERE id = $1 AND user_id = $2
			`, sessionID, userID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menghapus sesi ujian"})
				return
			}

			rowsAffected, _ := result.RowsAffected()
			if rowsAffected == 0 {
				c.JSON(http.StatusNotFound, gin.H{"error": "Sesi ujian tidak ditemukan atau bukan milik Anda"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "Sesi ujian berhasil dipindahkan ke tempat sampah (Trash Bin)"})
		})

	
		api.GET("/exam-sessions/trash", func(c *gin.Context) {
			userID, _ := c.Get("user_id")

			rows, err := database.DB.Query(`
				SELECT id, title, qr_code_token, duration_minutes, is_active, created_at, deleted_at 
				FROM exam_sessions 
				WHERE user_id = $1 AND deleted_at IS NOT NULL
				ORDER BY deleted_at DESC
			`, userID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memuat data tempat sampah"})
				return
			}
			defer rows.Close()

			type TrashItem struct {
				ID              string     `json:"id"`
				Title           string     `json:"title"`
				QRCodeToken     string     `json:"qr_code_token"`
				DurationMinutes int        `json:"duration_minutes"`
				IsActive        bool       `json:"is_active"`
				CreatedAt       time.Time  `json:"created_at"`
				DeletedAt       *time.Time `json:"deleted_at"`
			}

			trashes := make([]TrashItem, 0)
			for rows.Next() {
				var t TrashItem
				var deletedAt sql.NullTime
				if err := rows.Scan(&t.ID, &t.Title, &t.QRCodeToken, &t.DurationMinutes, &t.IsActive, &t.CreatedAt, &deletedAt); err == nil {
					if deletedAt.Valid {
						t.DeletedAt = &deletedAt.Time
					}
					trashes = append(trashes, t)
				}
			}

			c.JSON(http.StatusOK, gin.H{"trash_sessions": trashes})
		})

		
		api.POST("/exam-sessions/:id/restore", func(c *gin.Context) {
			userID, _ := c.Get("user_id")
			sessionID := c.Param("id")

			result, err := database.DB.Exec(`
				UPDATE exam_sessions SET deleted_at = NULL, is_active = TRUE WHERE id = $1 AND user_id = $2
			`, sessionID, userID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memulihkan sesi ujian"})
				return
			}

			rowsAffected, _ := result.RowsAffected()
			if rowsAffected == 0 {
				c.JSON(http.StatusNotFound, gin.H{"error": "Sesi ujian tidak ditemukan di tempat sampah"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "Sesi ujian berhasil dipulihkan"})
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

		api.GET("/school-admin/academic-years", func(c *gin.Context) {
			userID, exists := c.Get("user_id")
			if !exists {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
				return
			}

			// Debugging: Cetak userID ke terminal Go
			fmt.Printf("DEBUG userID yang mencoba akses academic-years: %v\n", userID)

			var schoolID string
			err := database.DB.QueryRow(`SELECT school_id FROM school_admins WHERE id = $1 AND is_active = TRUE`, userID).Scan(&schoolID)
			if err != nil {
				fmt.Printf("DEBUG Error ambil school_id: %v\n", err) // <-- Lihat error ini di terminal Go Anda
				c.JSON(http.StatusForbidden, gin.H{"error": "Akses ditolak: Data admin sekolah tidak valid atau tidak aktif"})
				return
			}

			rows, err := database.DB.Query(`
				SELECT id, name, semester, start_date, end_date, is_active, created_at 
				FROM school_academic_years 
				WHERE school_id = $1 
				ORDER BY created_at DESC
			`, schoolID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil data tahun akademik"})
				return
			}
			defer rows.Close()

			type AcademicYear struct {
				ID        string     `json:"id"`
				Name      string     `json:"name"`
				Semester  string     `json:"semester"`
				StartDate *string    `json:"start_date"`
				EndDate   *string    `json:"end_date"`
				IsActive  bool       `json:"is_active"`
				CreatedAt time.Time  `json:"created_at"`
			}

			var years []AcademicYear
			for rows.Next() {
				var y AcademicYear
				var start, end sql.NullString
				if err := rows.Scan(&y.ID, &y.Name, &y.Semester, &start, &end, &y.IsActive, &y.CreatedAt); err == nil {
					if start.Valid { y.StartDate = &start.String }
					if end.Valid { y.EndDate = &end.String }
					years = append(years, y)
				}
			}

			c.JSON(http.StatusOK, gin.H{"academic_years": years})
		})

		api.POST("/school-admin/academic-years", func(c *gin.Context) {
			userID, exists := c.Get("user_id")
			if !exists {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
				return
			}

			var schoolID string
			err := database.DB.QueryRow(`SELECT school_id FROM school_admins WHERE id = $1 AND is_active = TRUE`, userID).Scan(&schoolID)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": "Akses ditolak: Anda bukan admin sekolah yang aktif"})
				return
			}

			var req AcademicYearRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Format data tidak valid: " + err.Error()})
				return
			}

			var yearID string
			err = database.DB.QueryRow(`
				INSERT INTO school_academic_years (school_id, name, semester, start_date, end_date, is_active)
				VALUES ($1, $2, $3, NULLIF($4, '')::date, NULLIF($5, '')::date, FALSE)
				RETURNING id
			`, schoolID, req.Name, req.Semester, req.StartDate, req.EndDate).Scan(&yearID)

			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyimpan tahun akademik: " + err.Error()})
				return
			}

			c.JSON(http.StatusCreated, gin.H{"message": "Tahun akademik berhasil ditambahkan", "id": yearID})
		})

		api.PATCH("/school-admin/academic-years/:id/activate", func(c *gin.Context) {
			userID, exists := c.Get("user_id")
			if !exists {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
				return
			}

			var schoolID string
			err := database.DB.QueryRow(`SELECT school_id FROM school_admins WHERE id = $1 AND is_active = TRUE`, userID).Scan(&schoolID)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": "Akses ditolak: Anda bukan admin sekolah yang aktif"})
				return
			}

			yearID := c.Param("id")

			// Nonaktifkan semua tahun akademik di sekolah ini terlebih dahulu
			_, _ = database.DB.Exec(`UPDATE school_academic_years SET is_active = FALSE WHERE school_id = $1`, schoolID)

			// Aktifkan tahun akademik yang dipilih
			_, err = database.DB.Exec(`UPDATE school_academic_years SET is_active = TRUE WHERE id = $1 AND school_id = $2`, yearID, schoolID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengaktifkan tahun akademik"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "Tahun akademik aktif berhasil diperbarui"})
		})

		
		api.GET("/school-admin/profile", func(c *gin.Context) {
			userID, exists := c.Get("user_id")
			if !exists {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
				return
			}

			// Normalisasi userID
			var userIDStr string
			switch v := userID.(type) {
			case string:
				userIDStr = v
			default:
				userIDStr = fmt.Sprintf("%v", v)
			}

			// Ambil email sebagai fallback
			var userEmail string
			_ = database.DB.QueryRow(
				`SELECT COALESCE(email, '') FROM auth.users WHERE id = $1`,
				userIDStr,
			).Scan(&userEmail)

			// Ambil school_id dengan dua cara
			var schoolID string
			err := database.DB.QueryRow(`
				SELECT school_id FROM school_admins 
				WHERE (id = $1 OR (email <> '' AND email = $2)) 
				AND is_active = TRUE
				LIMIT 1
			`, userIDStr, userEmail).Scan(&schoolID)

			if err != nil {
				fmt.Printf("[GET PROFILE] Gagal ambil school_id: %v (userID=%s, email=%s)\n", err, userIDStr, userEmail)
				c.JSON(http.StatusForbidden, gin.H{"error": "Akses ditolak: Anda bukan admin sekolah yang aktif"})
				return
			}

			var id, schoolName, npsn, address, city, email, jenjang sql.NullString
			var isActive bool
			var createdAt time.Time

			err = database.DB.QueryRow(`
				SELECT id, school_name, npsn, address, COALESCE(city, ''), 
					COALESCE(email, ''), COALESCE(jenjang, 'SMP'), is_active, created_at 
				FROM schools WHERE id = $1
			`, schoolID).Scan(&id, &schoolName, &npsn, &address, &city, &email, &jenjang, &isActive, &createdAt)

			if err != nil {
				fmt.Printf("[GET PROFILE] Gagal ambil data sekolah: %v (schoolID=%s)\n", err, schoolID)
				c.JSON(http.StatusNotFound, gin.H{"error": "Data sekolah tidak ditemukan"})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"school": gin.H{
					"id":          id.String,
					"school_name": schoolName.String,
					"npsn":        npsn.String,
					"address":     address.String,
					"city":        city.String,
					"email":       email.String,
					"jenjang":     jenjang.String,
					"is_active":   isActive,
					"created_at":  createdAt,
				},
			})
		})

		
		api.PUT("/school-admin/profile", func(c *gin.Context) {
			userID, exists := c.Get("user_id")
			if !exists {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
				return
			}

			var schoolID string
			err := database.DB.QueryRow(`SELECT school_id FROM school_admins WHERE id = $1 AND is_active = TRUE`, userID).Scan(&schoolID)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": "Akses ditolak: Anda bukan admin sekolah yang aktif"})
				return
			}

			var req UpdateSchoolProfileRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Format data tidak valid: " + err.Error()})
				return
			}

			_, err = database.DB.Exec(`
				UPDATE schools 
				SET school_name = $1, npsn = $2, address = $3, city = $4, email = $5, updated_at = NOW() 
				WHERE id = $6
			`, req.SchoolName, req.Npsn, req.Address, req.City, req.Email, schoolID)

			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memperbarui data sekolah: " + err.Error()})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "Profil sekolah berhasil diperbarui"})
		})

		// Endpoint Admin Sekolah: Mengambil Daftar Kelas
		api.GET("/school-admin/classes", func(c *gin.Context) {
			userID, exists := c.Get("user_id")
			if !exists {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
				return
			}

			var schoolID, schoolName string
			err := database.DB.QueryRow(`
				SELECT sa.school_id, s.school_name 
				FROM school_admins sa 
				JOIN schools s ON sa.school_id = s.id 
				WHERE sa.id = $1 AND sa.is_active = TRUE
			`, userID).Scan(&schoolID, &schoolName)
			
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": "Akses ditolak: Anda bukan admin sekolah yang aktif"})
				return
			}

			rows, err := database.DB.Query(`
				SELECT cg.id, cg.name, cg.level, COALESCE(cg.class_type, 'Umum'), 
					cg.academic_year_id, 
					COALESCE(say.name, '-'), COALESCE(say.semester, '-'), cg.created_at
				FROM class_groups cg
				LEFT JOIN school_academic_years say ON cg.academic_year_id = say.id
				WHERE cg.school_id = $1
				ORDER BY cg.created_at DESC
			`, schoolID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil data kelas"})
				return
			}
			defer rows.Close()

			type ClassItem struct {
				ID               string    `json:"id"`
				SchoolName       string    `json:"school_name"`
				Name             string    `json:"name"`
				Level            string    `json:"level"`
				ClassType        string    `json:"class_type"`
				AcademicYearID   string    `json:"academic_year_id"`
				AcademicYearName string    `json:"academic_year_name"`
				Semester         string    `json:"semester"`
				CreatedAt        time.Time `json:"created_at"`
			}

			var classes []ClassItem
			for rows.Next() {
				var cl ClassItem
				cl.SchoolName = schoolName
				if err := rows.Scan(&cl.ID, &cl.Name, &cl.Level, &cl.ClassType, &cl.AcademicYearID, &cl.AcademicYearName, &cl.Semester, &cl.CreatedAt); err == nil {
					classes = append(classes, cl)
				}
			}

			c.JSON(http.StatusOK, gin.H{"classes": classes})
		})

		// Endpoint Admin Sekolah: Menambah Kelas Baru
		api.POST("/school-admin/classes", func(c *gin.Context) {
			userID, exists := c.Get("user_id")
			if !exists {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
				return
			}

		
			var userIDStr string
			switch v := userID.(type) {
			case string:
				userIDStr = v
			case fmt.Stringer:
				userIDStr = v.String()
			default:
				userIDStr = fmt.Sprintf("%v", v)
			}

			// fmt.Println("════════════════════════════════════════")
			// fmt.Println("[CREATE CLASS] ▶ MULAI")
			// fmt.Printf("[CREATE CLASS] userIDStr = %q\n", userIDStr)

			// Ambil email dari auth.users
			var userEmail string
			err := database.DB.QueryRow(
				`SELECT COALESCE(email, '') FROM auth.users WHERE id = $1`,
				userIDStr,
			).Scan(&userEmail)
			if err != nil {
				fmt.Printf("[CREATE CLASS] ⚠️ Gagal ambil email: %v\n", err)
			}
			fmt.Printf("[CREATE CLASS] userEmail = %q\n", userEmail)

			// Ambil school_id dengan DUA cara
			var schoolID string
			err = database.DB.QueryRow(`
				SELECT school_id FROM school_admins 
				WHERE (id = $1 OR (email <> '' AND email = $2)) 
				AND is_active = TRUE
				LIMIT 1
			`, userIDStr, userEmail).Scan(&schoolID)

			if err != nil {
				fmt.Printf("[CREATE CLASS] ❌ Gagal ambil school_id: %v\n", err)
				c.JSON(http.StatusForbidden, gin.H{"error": "Akses ditolak: Anda bukan admin sekolah yang aktif"})
				return
			}
			// fmt.Printf("[CREATE CLASS] ✅ schoolID = %q\n", schoolID)

			var req CreateClassGroupRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Format data tidak valid: " + err.Error()})
				return
			}
			// fmt.Printf("[CREATE CLASS] req.AcademicYearID = %q\n", req.AcademicYearID)
			// fmt.Printf("[CREATE CLASS] req.Name = %q, req.Level = %q, req.ClassType = %q\n", 
			// 	req.Name, req.Level, req.ClassType)

			// ==========================================
			// VALIDASI: Cek academic_year_id milik sekolah ini
			// ==========================================
			var validYearSchoolID string
			err = database.DB.QueryRow(`
				SELECT school_id FROM school_academic_years 
				WHERE id = $1
			`, req.AcademicYearID).Scan(&validYearSchoolID)

			if err != nil {
				if err == sql.ErrNoRows {
					fmt.Printf("[CREATE CLASS] ❌ academic_year_id=%s TIDAK ADA di tabel\n", req.AcademicYearID)
					c.JSON(http.StatusBadRequest, gin.H{
						"error": "Tahun akademik tidak ditemukan di sistem.",
					})
					return
				}
				fmt.Printf("[CREATE CLASS] ❌ Query error: %v\n", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal validasi tahun akademik: " + err.Error()})
				return
			}

			// fmt.Printf("[CREATE CLASS] academic_year milik school_id = %q\n", validYearSchoolID)
			// fmt.Printf("[CREATE CLASS] admin school_id           = %q\n", schoolID)

			if validYearSchoolID != schoolID {
				fmt.Println("[CREATE CLASS] ❌❌❌ MISMATCH SCHOOL_ID! ❌❌❌")
				c.JSON(http.StatusBadRequest, gin.H{
					"error": fmt.Sprintf(
						"Tahun akademik ini milik sekolah lain. (school_id Anda: %s, school_id tahun: %s)",
						schoolID, validYearSchoolID,
					),
				})
				return
			}

			// fmt.Println("[CREATE CLASS] ✅ Validasi OK, akan INSERT...")

			// ==========================================
			// INSERT
			// ==========================================
			var classID string
			err = database.DB.QueryRow(`
				INSERT INTO class_groups (school_id, academic_year_id, name, level, class_type)
				VALUES ($1, $2, $3, $4, NULLIF($5, ''))
				RETURNING id
			`, schoolID, req.AcademicYearID, req.Name, req.Level, req.ClassType).Scan(&classID)

			if err != nil {
				fmt.Printf("[CREATE CLASS] ❌ INSERT ERROR: %v\n", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyimpan data kelas: " + err.Error()})
				return
			}

			// fmt.Printf("[CREATE CLASS] ✅ SUKSES! classID = %s\n", classID)
			// fmt.Println("════════════════════════════════════════")

			c.JSON(http.StatusCreated, gin.H{
				"message": "Kelas berhasil ditambahkan",
				"id":      classID,
			})
		})

		// Endpoint Admin Sekolah: Menghapus Kelas
		api.DELETE("/school-admin/classes/:id", func(c *gin.Context) {
			userID, exists := c.Get("user_id")
			if !exists {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
				return
			}

			var schoolID string
			err := database.DB.QueryRow(`SELECT school_id FROM school_admins WHERE id = $1 AND is_active = TRUE`, userID).Scan(&schoolID)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": "Akses ditolak: Anda bukan admin sekolah yang aktif"})
				return
			}

			classID := c.Param("id")
			result, err := database.DB.Exec(`DELETE FROM class_groups WHERE id = $1 AND school_id = $2`, classID, schoolID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menghapus kelas"})
				return
			}

			rowsAffected, _ := result.RowsAffected()
			if rowsAffected == 0 {
				c.JSON(http.StatusNotFound, gin.H{"error": "Kelas tidak ditemukan atau bukan milik institusi Anda"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "Kelas berhasil dihapus"})
		})
	}
}