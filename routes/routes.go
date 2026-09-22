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
	"github.com/lib/pq"
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

type CreateSubClassRequest struct {
	ClassGroupID      string `json:"class_group_id" binding:"required"`
	Name              string `json:"name" binding:"required"`
	Code              string `json:"code"`
	Capacity          int    `json:"capacity"`
	HomeroomTeacherID string `json:"homeroom_teacher_id"`
	Notes             string `json:"notes"`
}

type UpdateSubClassRequest struct {
	Name              string `json:"name"`
	Code              string `json:"code"`
	Capacity          int    `json:"capacity"`
	HomeroomTeacherID string `json:"homeroom_teacher_id"`
	Notes             string `json:"notes"`
	IsActive          *bool  `json:"is_active"`
}

type CreateStudentRequest struct {
	ClassSubGroupID string `json:"class_sub_group_id" binding:"required"`
	FullName        string `json:"full_name" binding:"required"`
	StudentNumber   string `json:"student_number"`
	NISN            string `json:"nisn"`
}

type UpdateStudentRequest struct {
	ClassSubGroupID string `json:"class_sub_group_id"`
	FullName        string `json:"full_name"`
	StudentNumber   string `json:"student_number"`
	NISN            string `json:"nisn"`
	IsActive        *bool  `json:"is_active"`
}

type MoveStudentRequest struct {
	TargetSubGroupID string `json:"target_sub_group_id" binding:"required"`
}

// ==========================================
// ATTENDANCE SYSTEM STRUCTS
// ==========================================

// --- Academic Calendar ---
type CreateCalendarEventRequest struct {
	CalendarDate       string   `json:"calendar_date" binding:"required"` // YYYY-MM-DD
	DayType            string   `json:"day_type" binding:"required"`      // school_day | holiday | weekend | exam | event | emergency
	Name               string   `json:"name" binding:"required"`
	Description        string   `json:"description"`
	IsAttendanceRequired *bool  `json:"is_attendance_required"`
	IncludeInReport    *bool    `json:"include_in_report"`
	TargetClassGroupIDs []string `json:"target_class_group_ids"`
}

type UpdateCalendarEventRequest struct {
	Name                 string   `json:"name"`
	Description          string   `json:"description"`
	IsAttendanceRequired *bool    `json:"is_attendance_required"`
	IncludeInReport      *bool    `json:"include_in_report"`
	TargetClassGroupIDs  []string `json:"target_class_group_ids"`
}

// --- Attendance Shifts ---
type CreateShiftRequest struct {
	Name        string `json:"name" binding:"required"`
	Code        string `json:"code" binding:"required"`
	Description string `json:"description"`

	ShiftCategory string `json:"shift_category"` // regular | exam | event | extracurricular

	CheckInStart       string `json:"check_in_start" binding:"required"`
	CheckInOnTimeStart string `json:"check_in_on_time_start" binding:"required"`
	CheckInOnTimeEnd   string `json:"check_in_on_time_end" binding:"required"`
	CheckInEnd         string `json:"check_in_end" binding:"required"`

	RequireCheckOut      bool   `json:"require_check_out"`
	CheckOutStart        string `json:"check_out_start"`
	CheckOutOnTimeStart  string `json:"check_out_on_time_start"`
	CheckOutOnTimeEnd    string `json:"check_out_on_time_end"`
	CheckOutEnd          string `json:"check_out_end"`

	AllowEarlyCheckIn  *bool `json:"allow_early_check_in"`
	AllowLateCheckOut  *bool `json:"allow_late_check_out"`

	AutoCloseMinutesAfterCheckIn  *int `json:"auto_close_minutes_after_check_in"`
	AutoCloseMinutesAfterCheckOut *int `json:"auto_close_minutes_after_check_out"`

	EarlyThresholdMinutes      *int `json:"early_threshold_minutes"`
	LateToleranceMinutes       *int `json:"late_tolerance_minutes"`
	EarlyLeaveToleranceMinutes *int `json:"early_leave_tolerance_minutes"`

	ApplicableDays []int `json:"applicable_days"`

	IsActive  *bool `json:"is_active"`
	IsDefault *bool `json:"is_default"`
}

type UpdateShiftRequest struct {
	Name        string `json:"name"`
	Code        string `json:"code"`
	Description string `json:"description"`
	// Semua field opsional untuk partial update
	CheckInStart       string `json:"check_in_start"`
	CheckInOnTimeStart string `json:"check_in_on_time_start"`
	CheckInOnTimeEnd   string `json:"check_in_on_time_end"`
	CheckInEnd         string `json:"check_in_end"`

	RequireCheckOut     *bool  `json:"require_check_out"`
	CheckOutStart       string `json:"check_out_start"`
	CheckOutOnTimeStart string `json:"check_out_on_time_start"`
	CheckOutOnTimeEnd   string `json:"check_out_on_time_end"`
	CheckOutEnd         string `json:"check_out_end"`

	IsActive *bool `json:"is_active"`
}

// --- Class Shift Assignments ---
type CreateClassShiftAssignmentRequest struct {
	ClassGroupID    string `json:"class_group_id"`
	ClassSubGroupID string `json:"class_sub_group_id"`
	ShiftID         string `json:"shift_id" binding:"required"`

	Priority  int   `json:"priority"`
	IsPrimary *bool `json:"is_primary"`

	OverrideCheckInStart  string `json:"override_check_in_start"`
	OverrideCheckInEnd    string `json:"override_check_in_end"`
	OverrideCheckOutStart string `json:"override_check_out_start"`
	OverrideCheckOutEnd   string `json:"override_check_out_end"`

	EffectiveFrom string `json:"effective_from"`
	EffectiveTo   string `json:"effective_to"`
}

// --- Attendance Sessions ---
type CreateAttendanceSessionRequest struct {
	ShiftID string `json:"shift_id" binding:"required"`

	ClassGroupID    string `json:"class_group_id"`
	ClassSubGroupID string `json:"class_sub_group_id"`

	Title       string `json:"title"`
	SessionDate string `json:"session_date"` // YYYY-MM-DD, default today
	Notes       string `json:"notes"`
}

type CloseAttendanceSessionRequest struct {
	Notes string `json:"notes"`
}

// --- Scan ---
type ScanQRRequest struct {
	SessionID     string `json:"session_id" binding:"required"`
	QRToken       string `json:"qr_token" binding:"required"`
	ForceMode     string `json:"force_mode"` // check_in | check_out (opsional, untuk override)
}

// --- Student QR ---
type GenerateQRRequest struct {
	StudentIDs []string `json:"student_ids"` // jika kosong, generate untuk semua siswa sekolah
	ClassSubGroupID string `json:"class_sub_group_id"` // filter by sub class (opsional)
}

type RegenerateQRRequest struct {
	Reason string `json:"reason"`
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

func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}

func strPtr(s string) *string {
	return &s
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

func getSchoolIDFromUser(c *gin.Context) (string, error) {
	userID, exists := c.Get("user_id")
	if !exists {
		return "", fmt.Errorf("unauthorized")
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

	var userEmail string
	_ = database.DB.QueryRow(
		`SELECT COALESCE(email, '') FROM auth.users WHERE id = $1`,
		userIDStr,
	).Scan(&userEmail)

	var schoolID string
	err := database.DB.QueryRow(`
		SELECT school_id FROM school_admins 
		WHERE (id = $1 OR (email <> '' AND email = $2)) 
		AND is_active = TRUE
		LIMIT 1
	`, userIDStr, userEmail).Scan(&schoolID)

	if err != nil {
		return "", fmt.Errorf("akses ditolak: admin sekolah tidak valid")
	}

	return schoolID, nil
}

// getAdminIDFromUser — helper untuk ambil admin UUID (untuk opened_by, closed_by, dll)
func getAdminIDFromUser(c *gin.Context) (string, error) {
	userID, exists := c.Get("user_id")
	if !exists {
		return "", fmt.Errorf("unauthorized")
	}

	var userIDStr string
	switch v := userID.(type) {
	case string:
		userIDStr = v
	default:
		userIDStr = fmt.Sprintf("%v", v)
	}

	return userIDStr, nil
}

// generateQRToken — generate token STU-xxxxxxxxxxxxxxxx
func generateQRToken() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 16)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
		time.Sleep(1 * time.Nanosecond) // ensure different seed
	}
	return "STU-" + string(b)
}

// parseTimeString — parse "HH:MM" atau "HH:MM:SS" → time.Time
func parseTimeString(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, fmt.Errorf("empty time string")
	}
	// Coba HH:MM:SS dulu
	t, err := time.Parse("15:04:05", s)
	if err == nil {
		return t, nil
	}
	// Fallback HH:MM
	return time.Parse("15:04", s)
}

// timeToMinutes — konversi time ke menit dari tengah malam
func timeToMinutes(t time.Time) int {
	return t.Hour()*60 + t.Minute()
}

// determineCheckInStatus — tentukan status check-in
func determineCheckInStatus(checkInStart, checkInEnd, scanTime time.Time) string {
	startMin := timeToMinutes(checkInStart)
	endMin := timeToMinutes(checkInEnd)
	scanMin := timeToMinutes(scanTime)

	if scanMin < startMin {
		return "early"
	}
	if scanMin > endMin {
		return "late"
	}
	// Di tengah: on_time atau early (tergantung konfigurasi)
	// Untuk simple: pakai 1/3 dan 2/3 sebagai threshold
	rangeMin := endMin - startMin
	if rangeMin > 0 {
		firstThird := startMin + rangeMin/3
		if scanMin < firstThird {
			return "early"
		}
	}
	return "on_time"
}

// determineCheckOutStatus — tentukan status check-out
func determineCheckOutStatus(checkOutStart, checkOutEnd, scanTime time.Time) string {
	startMin := timeToMinutes(checkOutStart)
	endMin := timeToMinutes(checkOutEnd)
	scanMin := timeToMinutes(scanTime)

	if scanMin < startMin {
		return "early_leave"
	}
	if scanMin > endMin {
		return "late_leave"
	}
	// Di tengah: on_time_leave atau early_leave
	rangeMin := endMin - startMin
	if rangeMin > 0 {
		firstThird := startMin + rangeMin/3
		if scanMin < firstThird {
			return "early_leave"
		}
	}
	return "on_time_leave"
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

			var id, schoolName, npsn, address, jenjang sql.NullString
			var isActive bool
			var createdAt time.Time

			err = database.DB.QueryRow(`
				SELECT 
					id, 
					school_name, 
					npsn, 
					COALESCE(address, ''), 
					COALESCE(jenjang, 'SMP'), 
					is_active, 
					created_at 
				FROM schools WHERE id = $1
			`, schoolID).Scan(&id, &schoolName, &npsn, &address, &jenjang, &isActive, &createdAt)

			if err != nil {
				fmt.Printf("[GET PROFILE] Gagal ambil data sekolah: %v (schoolID=%s)\n", err, schoolID)
				if err == sql.ErrNoRows {
					c.JSON(http.StatusNotFound, gin.H{"error": "Data sekolah tidak ditemukan"})
					return
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"school": gin.H{
					"id":          id.String,
					"school_name": schoolName.String,
					"npsn":        npsn.String,
					"address":     address.String,
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
				SET school_name = $1, npsn = $2, address = $3, updated_at = NOW() 
				WHERE id = $4
			`, req.SchoolName, req.Npsn, req.Address, schoolID)

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
				// fmt.Printf("[CREATE CLASS] ❌ INSERT ERROR: %v\n", err)
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

		// GET: List sub kelas berdasarkan class_group_id
		api.GET("/school-admin/classes/:classId/sub-classes", func(c *gin.Context) {
			userID, exists := c.Get("user_id")
			if !exists {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
				return
			}

			var schoolID string
			err := database.DB.QueryRow(`
				SELECT school_id FROM school_admins 
				WHERE id = $1 AND is_active = TRUE
			`, userID).Scan(&schoolID)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": "Akses ditolak"})
				return
			}

			classID := c.Param("classId")

			// Validasi class_group milik sekolah ini
			var classExists string
			err = database.DB.QueryRow(`
				SELECT id FROM class_groups WHERE id = $1 AND school_id = $2
			`, classID, schoolID).Scan(&classExists)
			if err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "Kelas tidak ditemukan"})
				return
			}

			rows, err := database.DB.Query(`
				SELECT 
					csg.id, csg.name, COALESCE(csg.code, ''), 
					COALESCE(csg.capacity, 0), COALESCE(csg.notes, ''),
					csg.homeroom_teacher_id, 
					COALESCE(p.nama_guru, '') AS homeroom_teacher_name,
					csg.is_active, csg.created_at
				FROM class_sub_groups csg
				LEFT JOIN profiles p ON csg.homeroom_teacher_id = p.id
				WHERE csg.class_group_id = $1 AND csg.school_id = $2
				ORDER BY csg.created_at ASC
			`, classID, schoolID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil sub kelas: " + err.Error()})
				return
			}
			defer rows.Close()

			type SubClassItem struct {
				ID                  string    `json:"id"`
				Name                string    `json:"name"`
				Code                string    `json:"code"`
				Capacity            int       `json:"capacity"`
				Notes               string    `json:"notes"`
				HomeroomTeacherID   *string   `json:"homeroom_teacher_id"`
				HomeroomTeacherName string    `json:"homeroom_teacher_name"`
				IsActive            bool      `json:"is_active"`
				CreatedAt           time.Time `json:"created_at"`
			}

			var subs []SubClassItem
			for rows.Next() {
				var s SubClassItem
				var teacherID sql.NullString
				if err := rows.Scan(
					&s.ID, &s.Name, &s.Code, &s.Capacity, &s.Notes,
					&teacherID, &s.HomeroomTeacherName, &s.IsActive, &s.CreatedAt,
				); err == nil {
					if teacherID.Valid {
						s.HomeroomTeacherID = &teacherID.String
					}
					subs = append(subs, s)
				}
			}

			c.JSON(http.StatusOK, gin.H{
				"class_group_id": classID,
				"sub_classes":    subs,
			})
		})

		// POST: Tambah sub kelas baru
		api.POST("/school-admin/sub-classes", func(c *gin.Context) {
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

			// Ambil school_id (fallback via email)
			var userEmail string
			_ = database.DB.QueryRow(
				`SELECT COALESCE(email, '') FROM auth.users WHERE id = $1`,
				userIDStr,
			).Scan(&userEmail)

			var schoolID string
			err := database.DB.QueryRow(`
				SELECT school_id FROM school_admins 
				WHERE (id = $1 OR (email <> '' AND email = $2)) 
				AND is_active = TRUE
				LIMIT 1
			`, userIDStr, userEmail).Scan(&schoolID)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": "Akses ditolak"})
				return
			}

			var req CreateSubClassRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Format data tidak valid: " + err.Error()})
				return
			}

			// Validasi class_group milik sekolah ini
			var classExists string
			err = database.DB.QueryRow(`
				SELECT id FROM class_groups WHERE id = $1 AND school_id = $2
			`, req.ClassGroupID, schoolID).Scan(&classExists)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Kelas induk tidak ditemukan atau bukan milik sekolah Anda"})
				return
			}

			// Cek duplikat nama
			var existingID string
			err = database.DB.QueryRow(`
				SELECT id FROM class_sub_groups 
				WHERE class_group_id = $1 AND name = $2
			`, req.ClassGroupID, req.Name).Scan(&existingID)
			if err == nil && existingID != "" {
				c.JSON(http.StatusConflict, gin.H{"error": "Sub kelas dengan nama tersebut sudah ada"})
				return
			}

			// Insert
			var subID string
			var homeroomTeacher interface{} = nil
			if req.HomeroomTeacherID != "" {
				homeroomTeacher = req.HomeroomTeacherID
			}

			err = database.DB.QueryRow(`
				INSERT INTO class_sub_groups 
					(class_group_id, school_id, name, code, capacity, homeroom_teacher_id, notes)
				VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6, NULLIF($7, ''))
				RETURNING id
			`, req.ClassGroupID, schoolID, req.Name, req.Code, req.Capacity, homeroomTeacher, req.Notes).Scan(&subID)

			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyimpan sub kelas: " + err.Error()})
				return
			}

			c.JSON(http.StatusCreated, gin.H{
				"message": "Sub kelas berhasil ditambahkan",
				"id":      subID,
			})
		})

		// PUT: Update sub kelas
		api.PUT("/school-admin/sub-classes/:id", func(c *gin.Context) {
			userID, exists := c.Get("user_id")
			if !exists {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
				return
			}

			var schoolID string
			err := database.DB.QueryRow(`
				SELECT school_id FROM school_admins 
				WHERE id = $1 AND is_active = TRUE
			`, userID).Scan(&schoolID)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": "Akses ditolak"})
				return
			}

			subID := c.Param("id")

			var req UpdateSubClassRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Format data tidak valid: " + err.Error()})
				return
			}

			var homeroomTeacher interface{} = nil
			if req.HomeroomTeacherID != "" {
				homeroomTeacher = req.HomeroomTeacherID
			}

			var isActive interface{} = nil
			if req.IsActive != nil {
				isActive = *req.IsActive
			}

			result, err := database.DB.Exec(`
				UPDATE class_sub_groups SET
					name = COALESCE(NULLIF($1, ''), name),
					code = NULLIF($2, ''),
					capacity = $3,
					homeroom_teacher_id = $4,
					notes = NULLIF($5, ''),
					is_active = COALESCE($6, is_active),
					updated_at = NOW()
				WHERE id = $7 AND school_id = $8
			`, req.Name, req.Code, req.Capacity, homeroomTeacher, req.Notes, isActive, subID, schoolID)

			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memperbarui sub kelas: " + err.Error()})
				return
			}

			rowsAffected, _ := result.RowsAffected()
			if rowsAffected == 0 {
				c.JSON(http.StatusNotFound, gin.H{"error": "Sub kelas tidak ditemukan"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "Sub kelas berhasil diperbarui"})
		})

		// DELETE: Hapus sub kelas
		api.DELETE("/school-admin/sub-classes/:id", func(c *gin.Context) {
			userID, exists := c.Get("user_id")
			if !exists {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
				return
			}

			var schoolID string
			err := database.DB.QueryRow(`
				SELECT school_id FROM school_admins 
				WHERE id = $1 AND is_active = TRUE
			`, userID).Scan(&schoolID)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": "Akses ditolak"})
				return
			}

			subID := c.Param("id")

			result, err := database.DB.Exec(`
				DELETE FROM class_sub_groups WHERE id = $1 AND school_id = $2
			`, subID, schoolID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menghapus sub kelas: " + err.Error()})
				return
			}

			rowsAffected, _ := result.RowsAffected()
			if rowsAffected == 0 {
				c.JSON(http.StatusNotFound, gin.H{"error": "Sub kelas tidak ditemukan"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "Sub kelas berhasil dihapus"})
		})

		// GET: List semua sub kelas milik sekolah
		api.GET("/school-admin/sub-classes", func(c *gin.Context) {
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

			// Ambil school_id
			var schoolID string
			err := database.DB.QueryRow(`
				SELECT school_id FROM school_admins 
				WHERE (id = $1 OR (email <> '' AND email = $2)) 
				AND is_active = TRUE
				LIMIT 1
			`, userIDStr, userEmail).Scan(&schoolID)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": "Akses ditolak"})
				return
			}

			// Query semua sub kelas dengan info master kelasnya
			rows, err := database.DB.Query(`
				SELECT 
					csg.id,
					csg.name,
					COALESCE(csg.code, ''),
					COALESCE(csg.capacity, 0),
					COALESCE(csg.notes, ''),
					csg.homeroom_teacher_id,
					COALESCE(p.nama_guru, '') AS homeroom_teacher_name,
					csg.is_active,
					csg.created_at,
					cg.id AS class_group_id,
					cg.name AS class_group_name,
					cg.level AS class_group_level,
					COALESCE(cg.class_type, 'Umum') AS class_group_type,
					cg.academic_year_id,
					COALESCE(say.name, '-') AS academic_year_name,
					COALESCE(say.semester, '-') AS semester
				FROM class_sub_groups csg
				JOIN class_groups cg ON csg.class_group_id = cg.id
				LEFT JOIN school_academic_years say ON cg.academic_year_id = say.id
				LEFT JOIN profiles p ON csg.homeroom_teacher_id = p.id
				WHERE csg.school_id = $1
				ORDER BY cg.level ASC, cg.name ASC, csg.name ASC
			`, schoolID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil daftar sub kelas: " + err.Error()})
				return
			}
			defer rows.Close()

			type SubClassWithClass struct {
				ID                  string    `json:"id"`
				Name                string    `json:"name"`
				Code                string    `json:"code"`
				Capacity            int       `json:"capacity"`
				Notes               string    `json:"notes"`
				HomeroomTeacherID   *string   `json:"homeroom_teacher_id"`
				HomeroomTeacherName string    `json:"homeroom_teacher_name"`
				IsActive            bool      `json:"is_active"`
				CreatedAt           time.Time `json:"created_at"`
				ClassGroupID        string    `json:"class_group_id"`
				ClassGroupName      string    `json:"class_group_name"`
				ClassGroupLevel     string    `json:"class_group_level"`
				ClassGroupType      string    `json:"class_group_type"`
				AcademicYearID      string    `json:"academic_year_id"`
				AcademicYearName    string    `json:"academic_year_name"`
				Semester            string    `json:"semester"`
			}

			var subClasses []SubClassWithClass
			for rows.Next() {
				var s SubClassWithClass
				var teacherID sql.NullString
				if err := rows.Scan(
					&s.ID, &s.Name, &s.Code, &s.Capacity, &s.Notes,
					&teacherID, &s.HomeroomTeacherName, &s.IsActive, &s.CreatedAt,
					&s.ClassGroupID, &s.ClassGroupName, &s.ClassGroupLevel, &s.ClassGroupType,
					&s.AcademicYearID, &s.AcademicYearName, &s.Semester,
				); err == nil {
					if teacherID.Valid {
						s.HomeroomTeacherID = &teacherID.String
					}
					subClasses = append(subClasses, s)
				}
			}

			c.JSON(http.StatusOK, gin.H{
				"total":       len(subClasses),
				"sub_classes": subClasses,
			})
		})

		// GET: List semua murid (dengan filter opsional by sub class)
		api.GET("/school-admin/students", func(c *gin.Context) {
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

			var userEmail string
			_ = database.DB.QueryRow(
				`SELECT COALESCE(email, '') FROM auth.users WHERE id = $1`,
				userIDStr,
			).Scan(&userEmail)

			var schoolID string
			err := database.DB.QueryRow(`
				SELECT school_id FROM school_admins 
				WHERE (id = $1 OR (email <> '' AND email = $2)) 
				AND is_active = TRUE
				LIMIT 1
			`, userIDStr, userEmail).Scan(&schoolID)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": "Akses ditolak"})
				return
			}

			// Filter opsional: ?sub_class_id=xxx
			subClassID := c.Query("sub_class_id")

			query := `
				SELECT 
					s.id, s.full_name, COALESCE(s.student_number, ''), 
					COALESCE(s.nisn, ''), s.is_active, s.created_at,
					s.class_sub_group_id,
					COALESCE(csg.name, '') AS sub_class_name,
					csg.class_group_id,
					COALESCE(cg.name, '') AS class_group_name,
					COALESCE(cg.class_type, 'Umum') AS class_group_type
				FROM students s
				LEFT JOIN class_sub_groups csg ON s.class_sub_group_id = csg.id
				LEFT JOIN class_groups cg ON csg.class_group_id = cg.id
				WHERE s.school_id = $1
			`
			args := []any{schoolID}

			if subClassID != "" {
				query += ` AND s.class_sub_group_id = $2`
				args = append(args, subClassID)
			}

			query += ` ORDER BY cg.level ASC, csg.name ASC, s.full_name ASC`

			rows, err := database.DB.Query(query, args...)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil data murid: " + err.Error()})
				return
			}
			defer rows.Close()

			type StudentItem struct {
				ID               string    `json:"id"`
				FullName         string    `json:"full_name"`
				StudentNumber    string    `json:"student_number"`
				NISN             string    `json:"nisn"`
				IsActive         bool      `json:"is_active"`
				CreatedAt        time.Time `json:"created_at"`
				ClassSubGroupID  *string   `json:"class_sub_group_id"`
				SubClassName     string    `json:"sub_class_name"`
				ClassGroupID     *string   `json:"class_group_id"`
				ClassGroupName   string    `json:"class_group_name"`
				ClassGroupType   string    `json:"class_group_type"`
			}

			var students []StudentItem
			for rows.Next() {
				var s StudentItem
				var subGroupID, classGroupID sql.NullString
				if err := rows.Scan(
					&s.ID, &s.FullName, &s.StudentNumber, &s.NISN, &s.IsActive, &s.CreatedAt,
					&subGroupID, &s.SubClassName, &classGroupID, &s.ClassGroupName, &s.ClassGroupType,
				); err == nil {
					if subGroupID.Valid {
						s.ClassSubGroupID = &subGroupID.String
					}
					if classGroupID.Valid {
						s.ClassGroupID = &classGroupID.String
					}
					students = append(students, s)
				}
			}

			c.JSON(http.StatusOK, gin.H{
				"total":    len(students),
				"students": students,
			})
		})

		// POST: Tambah murid baru & distribusikan ke sub kelas
		api.POST("/school-admin/students", func(c *gin.Context) {
			userID, exists := c.Get("user_id")
			if !exists {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
				return
			}

			var userIDStr string
			switch v := userID.(type) {
			case string:
				userIDStr = v
			default:
				userIDStr = fmt.Sprintf("%v", v)
			}

			var userEmail string
			_ = database.DB.QueryRow(
				`SELECT COALESCE(email, '') FROM auth.users WHERE id = $1`,
				userIDStr,
			).Scan(&userEmail)

			var schoolID string
			err := database.DB.QueryRow(`
				SELECT school_id FROM school_admins 
				WHERE (id = $1 OR (email <> '' AND email = $2)) 
				AND is_active = TRUE
				LIMIT 1
			`, userIDStr, userEmail).Scan(&schoolID)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": "Akses ditolak"})
				return
			}

			var req CreateStudentRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Format data tidak valid: " + err.Error()})
				return
			}

			// Validasi sub class milik sekolah ini
			var classGroupID string
			err = database.DB.QueryRow(`
				SELECT class_group_id FROM class_sub_groups 
				WHERE id = $1 AND school_id = $2
			`, req.ClassSubGroupID, schoolID).Scan(&classGroupID)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Sub kelas tidak ditemukan atau bukan milik sekolah Anda"})
				return
			}

			// Cek duplikat NISN (jika diisi)
			if req.NISN != "" {
				var existingID string
				err = database.DB.QueryRow(`
					SELECT id FROM students WHERE school_id = $1 AND nisn = $2
				`, schoolID, req.NISN).Scan(&existingID)
				if err == nil && existingID != "" {
					c.JSON(http.StatusConflict, gin.H{"error": "NISN sudah terdaftar di sekolah ini"})
					return
				}
			}

			// Insert
			var studentID string
			err = database.DB.QueryRow(`
				INSERT INTO students 
					(school_id, class_group_id, class_sub_group_id, full_name, student_number, nisn, is_active)
				VALUES ($1, $2, $3, $4, NULLIF($5, ''), NULLIF($6, ''), TRUE)
				RETURNING id
			`, schoolID, classGroupID, req.ClassSubGroupID, req.FullName, req.StudentNumber, req.NISN).Scan(&studentID)

			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyimpan data murid: " + err.Error()})
				return
			}

			c.JSON(http.StatusCreated, gin.H{
				"message": "Murid berhasil ditambahkan",
				"id":      studentID,
			})
		})

		// PUT: Update data murid (termasuk pindah sub kelas)
		api.PUT("/school-admin/students/:id", func(c *gin.Context) {
			userID, exists := c.Get("user_id")
			if !exists {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
				return
			}

			var userIDStr string
			switch v := userID.(type) {
			case string:
				userIDStr = v
			default:
				userIDStr = fmt.Sprintf("%v", v)
			}

			var userEmail string
			_ = database.DB.QueryRow(
				`SELECT COALESCE(email, '') FROM auth.users WHERE id = $1`,
				userIDStr,
			).Scan(&userEmail)

			var schoolID string
			err := database.DB.QueryRow(`
				SELECT school_id FROM school_admins 
				WHERE (id = $1 OR (email <> '' AND email = $2)) 
				AND is_active = TRUE
				LIMIT 1
			`, userIDStr, userEmail).Scan(&schoolID)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": "Akses ditolak"})
				return
			}

			studentID := c.Param("id")

			var req UpdateStudentRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Format data tidak valid: " + err.Error()})
				return
			}

			// Jika pindah sub kelas, validasi dulu
			var newClassGroupID interface{} = nil
			if req.ClassSubGroupID != "" {
				var cgID string
				err = database.DB.QueryRow(`
					SELECT class_group_id FROM class_sub_groups 
					WHERE id = $1 AND school_id = $2
				`, req.ClassSubGroupID, schoolID).Scan(&cgID)
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Sub kelas tujuan tidak valid"})
					return
				}
				newClassGroupID = cgID
			}

			var isActive interface{} = nil
			if req.IsActive != nil {
				isActive = *req.IsActive
			}

			var subGroupID interface{} = nil
			if req.ClassSubGroupID != "" {
				subGroupID = req.ClassSubGroupID
			}

			result, err := database.DB.Exec(`
				UPDATE students SET
					full_name = COALESCE(NULLIF($1, ''), full_name),
					student_number = NULLIF($2, ''),
					nisn = NULLIF($3, ''),
					class_sub_group_id = $4,
					class_group_id = COALESCE($5, class_group_id),
					is_active = COALESCE($6, is_active),
					updated_at = NOW()
				WHERE id = $7 AND school_id = $8
			`, req.FullName, req.StudentNumber, req.NISN, subGroupID, newClassGroupID, isActive, studentID, schoolID)

			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memperbarui data murid: " + err.Error()})
				return
			}

			rowsAffected, _ := result.RowsAffected()
			if rowsAffected == 0 {
				c.JSON(http.StatusNotFound, gin.H{"error": "Murid tidak ditemukan"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "Data murid berhasil diperbarui"})
		})

		// DELETE: Hapus murid
		api.DELETE("/school-admin/students/:id", func(c *gin.Context) {
			userID, exists := c.Get("user_id")
			if !exists {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
				return
			}

			var schoolID string
			err := database.DB.QueryRow(`
				SELECT school_id FROM school_admins 
				WHERE id = $1 AND is_active = TRUE
			`, userID).Scan(&schoolID)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": "Akses ditolak"})
				return
			}

			studentID := c.Param("id")

			result, err := database.DB.Exec(`
				DELETE FROM students WHERE id = $1 AND school_id = $2
			`, studentID, schoolID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menghapus murid: " + err.Error()})
				return
			}

			rowsAffected, _ := result.RowsAffected()
			if rowsAffected == 0 {
				c.JSON(http.StatusNotFound, gin.H{"error": "Murid tidak ditemukan"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "Murid berhasil dihapus"})
		})

		// GET: Statistik distribusi per sub kelas
		api.GET("/school-admin/students/stats", func(c *gin.Context) {
			userID, exists := c.Get("user_id")
			if !exists {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
				return
			}

			var userIDStr string
			switch v := userID.(type) {
			case string:
				userIDStr = v
			default:
				userIDStr = fmt.Sprintf("%v", v)
			}

			var userEmail string
			_ = database.DB.QueryRow(
				`SELECT COALESCE(email, '') FROM auth.users WHERE id = $1`,
				userIDStr,
			).Scan(&userEmail)

			var schoolID string
			err := database.DB.QueryRow(`
				SELECT school_id FROM school_admins 
				WHERE (id = $1 OR (email <> '' AND email = $2)) 
				AND is_active = TRUE
				LIMIT 1
			`, userIDStr, userEmail).Scan(&schoolID)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": "Akses ditolak"})
				return
			}

			rows, err := database.DB.Query(`
				SELECT 
					csg.id, csg.name, COALESCE(csg.capacity, 0),
					cg.name AS class_group_name,
					COUNT(s.id) AS student_count
				FROM class_sub_groups csg
				JOIN class_groups cg ON csg.class_group_id = cg.id
				LEFT JOIN students s ON s.class_sub_group_id = csg.id AND s.is_active = TRUE
				WHERE csg.school_id = $1
				GROUP BY csg.id, csg.name, csg.capacity, cg.name
				ORDER BY cg.name ASC, csg.name ASC
			`, schoolID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil statistik: " + err.Error()})
				return
			}
			defer rows.Close()

			type StatItem struct {
				ID             string `json:"id"`
				Name           string `json:"name"`
				Capacity       int    `json:"capacity"`
				ClassGroupName string `json:"class_group_name"`
				StudentCount   int    `json:"student_count"`
			}

			var stats []StatItem
			for rows.Next() {
				var s StatItem
				if err := rows.Scan(&s.ID, &s.Name, &s.Capacity, &s.ClassGroupName, &s.StudentCount); err == nil {
					stats = append(stats, s)
				}
			}

			c.JSON(http.StatusOK, gin.H{"stats": stats})
		})

		api.GET("/school-admin/calendar", func(c *gin.Context) {
			schoolID, err := getSchoolIDFromUser(c)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
				return
			}

			// Filter opsional
			fromDate := c.Query("from")     // YYYY-MM-DD
			toDate := c.Query("to")         // YYYY-MM-DD
			dayType := c.Query("type")      // school_day | holiday | dll

			query := `
				SELECT id, calendar_date, day_type, name, COALESCE(description, ''),
					is_attendance_required, include_in_report,
					COALESCE(target_class_group_ids, ARRAY[]::uuid[]),
					created_at
				FROM academic_calendar
				WHERE school_id = $1
			`
			args := []any{schoolID}
			argIdx := 2

			if fromDate != "" {
				query += fmt.Sprintf(" AND calendar_date >= $%d", argIdx)
				args = append(args, fromDate)
				argIdx++
			}
			if toDate != "" {
				query += fmt.Sprintf(" AND calendar_date <= $%d", argIdx)
				args = append(args, toDate)
				argIdx++
			}
			if dayType != "" {
				query += fmt.Sprintf(" AND day_type = $%d", argIdx)
				args = append(args, dayType)
				argIdx++
			}

			query += " ORDER BY calendar_date ASC"

			rows, err := database.DB.Query(query, args...)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil kalender: " + err.Error()})
				return
			}
			defer rows.Close()

			type CalendarItem struct {
				ID                   string    `json:"id"`
				CalendarDate         string    `json:"calendar_date"`
				DayType              string    `json:"day_type"`
				Name                 string    `json:"name"`
				Description          string    `json:"description"`
				IsAttendanceRequired bool      `json:"is_attendance_required"`
				IncludeInReport      bool      `json:"include_in_report"`
				TargetClassGroupIDs  []string  `json:"target_class_group_ids"`
				CreatedAt            time.Time `json:"created_at"`
			}

			var list []CalendarItem
			for rows.Next() {
				var item CalendarItem
				var dateVal time.Time
				var targetIDs []string

				if err := rows.Scan(
					&item.ID, &dateVal, &item.DayType, &item.Name, &item.Description,
					&item.IsAttendanceRequired, &item.IncludeInReport, &targetIDs, &item.CreatedAt,
				); err == nil {
					item.CalendarDate = dateVal.Format("2006-01-02")
					item.TargetClassGroupIDs = targetIDs
					list = append(list, item)
				}
			}

			c.JSON(http.StatusOK, gin.H{"calendar": list, "total": len(list)})
		})

		api.POST("/school-admin/calendar", func(c *gin.Context) {
			schoolID, err := getSchoolIDFromUser(c)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
				return
			}
			adminID, _ := getAdminIDFromUser(c)

			var req CreateCalendarEventRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Format tidak valid: " + err.Error()})
				return
			}

			isAttendanceRequired := true
			if req.IsAttendanceRequired != nil {
				isAttendanceRequired = *req.IsAttendanceRequired
			}
			includeInReport := true
			if req.IncludeInReport != nil {
				includeInReport = *req.IncludeInReport
			}

			var targetIDs interface{} = nil
			if len(req.TargetClassGroupIDs) > 0 {
				targetIDs = req.TargetClassGroupIDs
			}

			var newID string
			err = database.DB.QueryRow(`
				INSERT INTO academic_calendar (
					school_id, calendar_date, day_type, name, description,
					is_attendance_required, include_in_report,
					target_class_group_ids, created_by
				) VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6, $7, $8, $9)
				RETURNING id
			`, schoolID, req.CalendarDate, req.DayType, req.Name, req.Description,
				isAttendanceRequired, includeInReport, targetIDs, adminID).Scan(&newID)

			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyimpan: " + err.Error()})
				return
			}

			c.JSON(http.StatusCreated, gin.H{"message": "Event kalender berhasil dibuat", "id": newID})
		})

		// PUT: Update kalender event
		api.PUT("/school-admin/calendar/:id", func(c *gin.Context) {
			schoolID, err := getSchoolIDFromUser(c)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
				return
			}

			eventID := c.Param("id")
			var req UpdateCalendarEventRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Format tidak valid"})
				return
			}

			var targetIDs interface{} = nil
			if len(req.TargetClassGroupIDs) > 0 {
				targetIDs = req.TargetClassGroupIDs
			}

			result, err := database.DB.Exec(`
				UPDATE academic_calendar SET
					name = COALESCE(NULLIF($1, ''), name),
					description = COALESCE(NULLIF($2, ''), description),
					is_attendance_required = COALESCE($3, is_attendance_required),
					include_in_report = COALESCE($4, include_in_report),
					target_class_group_ids = COALESCE($5, target_class_group_ids),
					updated_at = NOW()
				WHERE id = $6 AND school_id = $7
			`, req.Name, req.Description, req.IsAttendanceRequired, req.IncludeInReport,
				targetIDs, eventID, schoolID)

			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			affected, _ := result.RowsAffected()
			if affected == 0 {
				c.JSON(http.StatusNotFound, gin.H{"error": "Event tidak ditemukan"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "Event berhasil diperbarui"})
		})

		// DELETE: Hapus kalender event
		api.DELETE("/school-admin/calendar/:id", func(c *gin.Context) {
			schoolID, err := getSchoolIDFromUser(c)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
				return
			}

			result, err := database.DB.Exec(
				`DELETE FROM academic_calendar WHERE id = $1 AND school_id = $2`,
				c.Param("id"), schoolID,
			)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			affected, _ := result.RowsAffected()
			if affected == 0 {
				c.JSON(http.StatusNotFound, gin.H{"error": "Event tidak ditemukan"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "Event berhasil dihapus"})
		})

		// ==========================================
		// ATTENDANCE SHIFTS
		// ==========================================

		// GET: List shifts
		api.GET("/school-admin/attendance/shifts", func(c *gin.Context) {
			fmt.Println("════════════════════════════════════════")
			fmt.Println("[GET SHIFTS] ▶ START")

			schoolID, err := getSchoolIDFromUser(c)
			if err != nil {
				fmt.Printf("[GET SHIFTS] ❌ getSchoolIDFromUser error: %v\n", err)
				c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
				return
			}
			fmt.Printf("[GET SHIFTS] ✅ schoolID = %q\n", schoolID)

			rows, err := database.DB.Query(`
				SELECT id, name, code, COALESCE(description, ''), shift_category,
					check_in_start, check_in_on_time_start, check_in_on_time_end, check_in_end,
					require_check_out, check_out_start, check_out_on_time_start, 
					check_out_on_time_end, check_out_end,
					allow_early_check_in, allow_late_check_out,
					auto_close_minutes_after_check_in, auto_close_minutes_after_check_out,
					early_threshold_minutes, late_tolerance_minutes, early_leave_tolerance_minutes,
					COALESCE(applicable_days, ARRAY[1,2,3,4,5,6]),
					is_active, is_default, created_at
				FROM attendance_shifts
				WHERE school_id = $1
				ORDER BY is_default DESC, code ASC
			`, schoolID)
			if err != nil {
				fmt.Printf("[GET SHIFTS] ❌ Query error: %v\n", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memuat shift: " + err.Error()})
				return
			}
			defer rows.Close()

			type ShiftItem struct {
				ID                            string   `json:"id"`
				Name                          string   `json:"name"`
				Code                          string   `json:"code"`
				Description                   string   `json:"description"`
				ShiftCategory                 string   `json:"shift_category"`
				CheckInStart                  string   `json:"check_in_start"`
				CheckInOnTimeStart            string   `json:"check_in_on_time_start"`
				CheckInOnTimeEnd              string   `json:"check_in_on_time_end"`
				CheckInEnd                    string   `json:"check_in_end"`
				RequireCheckOut               bool     `json:"require_check_out"`
				CheckOutStart                 *string  `json:"check_out_start"`
				CheckOutOnTimeStart           *string  `json:"check_out_on_time_start"`
				CheckOutOnTimeEnd             *string  `json:"check_out_on_time_end"`
				CheckOutEnd                   *string  `json:"check_out_end"`
				AllowEarlyCheckIn             bool     `json:"allow_early_check_in"`
				AllowLateCheckOut             bool     `json:"allow_late_check_out"`
				AutoCloseMinutesAfterCheckIn  int      `json:"auto_close_minutes_after_check_in"`
				AutoCloseMinutesAfterCheckOut int      `json:"auto_close_minutes_after_check_out"`
				EarlyThresholdMinutes         int      `json:"early_threshold_minutes"`
				LateToleranceMinutes          int      `json:"late_tolerance_minutes"`
				EarlyLeaveToleranceMinutes    int      `json:"early_leave_tolerance_minutes"`
				ApplicableDays                []int    `json:"applicable_days"`
				IsActive                      bool     `json:"is_active"`
				IsDefault                     bool     `json:"is_default"`
				CreatedAt                     time.Time `json:"created_at"`
			}

			list := []ShiftItem{}
			for rows.Next() {
				var s ShiftItem
				var ciStart, ciOnTimeStart, ciOnTimeEnd, ciEnd time.Time
				var coStart, coOnTimeStart, coOnTimeEnd, coEnd sql.NullString
				var applicableDays pq.Int64Array  // ← PAKAI INI

				if err := rows.Scan(
					&s.ID, &s.Name, &s.Code, &s.Description, &s.ShiftCategory,
					&ciStart, &ciOnTimeStart, &ciOnTimeEnd, &ciEnd,
					&s.RequireCheckOut, &coStart, &coOnTimeStart, &coOnTimeEnd, &coEnd,
					&s.AllowEarlyCheckIn, &s.AllowLateCheckOut,
					&s.AutoCloseMinutesAfterCheckIn, &s.AutoCloseMinutesAfterCheckOut,
					&s.EarlyThresholdMinutes, &s.LateToleranceMinutes, &s.EarlyLeaveToleranceMinutes,
					&applicableDays,  // ← SCAN ke pq.Int64Array
					&s.IsActive, &s.IsDefault, &s.CreatedAt,
				); err != nil {
					fmt.Printf("[GET SHIFTS] ⚠️ Scan error: %v\n", err)
					continue
				}

				// Convert pq.Int64Array → []int
				s.ApplicableDays = make([]int, len(applicableDays))
				for i, v := range applicableDays {
					s.ApplicableDays[i] = int(v)
				}

				s.CheckInStart = ciStart.Format("15:04")
				s.CheckInOnTimeStart = ciOnTimeStart.Format("15:04")
				s.CheckInOnTimeEnd = ciOnTimeEnd.Format("15:04")
				s.CheckInEnd = ciEnd.Format("15:04")

				if coStart.Valid { t, _ := time.Parse("15:04:05", coStart.String); s.CheckOutStart = strPtr(t.Format("15:04")) }
				if coOnTimeStart.Valid { t, _ := time.Parse("15:04:05", coOnTimeStart.String); s.CheckOutOnTimeStart = strPtr(t.Format("15:04")) }
				if coOnTimeEnd.Valid { t, _ := time.Parse("15:04:05", coOnTimeEnd.String); s.CheckOutOnTimeEnd = strPtr(t.Format("15:04")) }
				if coEnd.Valid { t, _ := time.Parse("15:04:05", coEnd.String); s.CheckOutEnd = strPtr(t.Format("15:04")) }

				list = append(list, s)
			}

			fmt.Printf("[GET SHIFTS] ✅ Total shifts returned: %d\n", len(list))
			c.JSON(http.StatusOK, gin.H{"shifts": list, "total": len(list)})
		})

		// POST: Create shift
		api.POST("/school-admin/attendance/shifts", func(c *gin.Context) {
			schoolID, err := getSchoolIDFromUser(c)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
				return
			}
			adminID, _ := getAdminIDFromUser(c)

			var req CreateShiftRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Format tidak valid: " + err.Error()})
				return
			}

			// Defaults
			allowEarly := true
			if req.AllowEarlyCheckIn != nil { allowEarly = *req.AllowEarlyCheckIn }
			allowLateOut := false
			if req.AllowLateCheckOut != nil { allowLateOut = *req.AllowLateCheckOut }
			autoCloseIn := 120
			if req.AutoCloseMinutesAfterCheckIn != nil { autoCloseIn = *req.AutoCloseMinutesAfterCheckIn }
			autoCloseOut := 60
			if req.AutoCloseMinutesAfterCheckOut != nil { autoCloseOut = *req.AutoCloseMinutesAfterCheckOut }
			earlyThreshold := 15
			if req.EarlyThresholdMinutes != nil { earlyThreshold = *req.EarlyThresholdMinutes }
			lateTolerance := 5
			if req.LateToleranceMinutes != nil { lateTolerance = *req.LateToleranceMinutes }
			earlyLeaveTolerance := 15
			if req.EarlyLeaveToleranceMinutes != nil { earlyLeaveTolerance = *req.EarlyLeaveToleranceMinutes }
			isActive := true
			if req.IsActive != nil { isActive = *req.IsActive }
			isDefault := false
			if req.IsDefault != nil { isDefault = *req.IsDefault }
			applicableDays := req.ApplicableDays
			if len(applicableDays) == 0 { applicableDays = []int{1, 2, 3, 4, 5, 6} }

			shiftCategory := req.ShiftCategory
			if shiftCategory == "" { shiftCategory = "regular" }

			// Prepare nullable check-out
			var coStart, coOnTimeStart, coOnTimeEnd, coEnd interface{} = nil, nil, nil, nil
			if req.RequireCheckOut {
				if req.CheckOutStart != "" { coStart = req.CheckOutStart }
				if req.CheckOutOnTimeStart != "" { coOnTimeStart = req.CheckOutOnTimeStart }
				if req.CheckOutOnTimeEnd != "" { coOnTimeEnd = req.CheckOutOnTimeEnd }
				if req.CheckOutEnd != "" { coEnd = req.CheckOutEnd }
			}

			// Kalau set is_default = true, nonaktifkan default lain
			if isDefault {
				_, _ = database.DB.Exec(
					`UPDATE attendance_shifts SET is_default = false WHERE school_id = $1`,
					schoolID,
				)
			}

			var shiftID string
			err = database.DB.QueryRow(`
				INSERT INTO attendance_shifts (
					school_id, name, code, description, shift_category,
					check_in_start, check_in_on_time_start, check_in_on_time_end, check_in_end,
					require_check_out, check_out_start, check_out_on_time_start,
					check_out_on_time_end, check_out_end,
					allow_early_check_in, allow_late_check_out,
					auto_close_minutes_after_check_in, auto_close_minutes_after_check_out,
					early_threshold_minutes, late_tolerance_minutes, early_leave_tolerance_minutes,
					applicable_days, is_active, is_default, created_by
				) VALUES (
					$1, $2, $3, NULLIF($4, ''), $5,
					$6, $7, $8, $9,
					$10, $11, $12, $13, $14,
					$15, $16,
					$17, $18,
					$19, $20, $21,
					$22, $23, $24, $25
				) RETURNING id
			`, schoolID, req.Name, req.Code, req.Description, shiftCategory,
				req.CheckInStart, req.CheckInOnTimeStart, req.CheckInOnTimeEnd, req.CheckInEnd,
				req.RequireCheckOut, coStart, coOnTimeStart, coOnTimeEnd, coEnd,
				allowEarly, allowLateOut,
				autoCloseIn, autoCloseOut,
				earlyThreshold, lateTolerance, earlyLeaveTolerance,
				applicableDays, isActive, isDefault, adminID).Scan(&shiftID)

			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyimpan shift: " + err.Error()})
				return
			}

			c.JSON(http.StatusCreated, gin.H{"message": "Shift berhasil dibuat", "id": shiftID})
		})

		// PUT: Update shift
		api.PUT("/school-admin/attendance/shifts/:id", func(c *gin.Context) {
			schoolID, err := getSchoolIDFromUser(c)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
				return
			}

			shiftID := c.Param("id")
			var req UpdateShiftRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Format tidak valid"})
				return
			}

			// Build dynamic query — hanya update field yang diisi
			updates := []string{}
			args := []interface{}{}
			argIdx := 1

			if req.Name != "" {
				updates = append(updates, fmt.Sprintf("name = $%d", argIdx))
				args = append(args, req.Name); argIdx++
			}
			if req.Code != "" {
				updates = append(updates, fmt.Sprintf("code = $%d", argIdx))
				args = append(args, req.Code); argIdx++
			}
			if req.Description != "" {
				updates = append(updates, fmt.Sprintf("description = $%d", argIdx))
				args = append(args, req.Description); argIdx++
			}
			if req.CheckInStart != "" {
				updates = append(updates, fmt.Sprintf("check_in_start = $%d", argIdx))
				args = append(args, req.CheckInStart); argIdx++
			}
			if req.CheckInOnTimeStart != "" {
				updates = append(updates, fmt.Sprintf("check_in_on_time_start = $%d", argIdx))
				args = append(args, req.CheckInOnTimeStart); argIdx++
			}
			if req.CheckInOnTimeEnd != "" {
				updates = append(updates, fmt.Sprintf("check_in_on_time_end = $%d", argIdx))
				args = append(args, req.CheckInOnTimeEnd); argIdx++
			}
			if req.CheckInEnd != "" {
				updates = append(updates, fmt.Sprintf("check_in_end = $%d", argIdx))
				args = append(args, req.CheckInEnd); argIdx++
			}
			if req.RequireCheckOut != nil {
				updates = append(updates, fmt.Sprintf("require_check_out = $%d", argIdx))
				args = append(args, *req.RequireCheckOut); argIdx++
			}
			if req.CheckOutStart != "" {
				updates = append(updates, fmt.Sprintf("check_out_start = $%d", argIdx))
				args = append(args, req.CheckOutStart); argIdx++
			}
			if req.CheckOutOnTimeStart != "" {
				updates = append(updates, fmt.Sprintf("check_out_on_time_start = $%d", argIdx))
				args = append(args, req.CheckOutOnTimeStart); argIdx++
			}
			if req.CheckOutOnTimeEnd != "" {
				updates = append(updates, fmt.Sprintf("check_out_on_time_end = $%d", argIdx))
				args = append(args, req.CheckOutOnTimeEnd); argIdx++
			}
			if req.CheckOutEnd != "" {
				updates = append(updates, fmt.Sprintf("check_out_end = $%d", argIdx))
				args = append(args, req.CheckOutEnd); argIdx++
			}
			if req.IsActive != nil {
				updates = append(updates, fmt.Sprintf("is_active = $%d", argIdx))
				args = append(args, *req.IsActive); argIdx++
			}

			if len(updates) == 0 {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Tidak ada field yang diupdate"})
				return
			}

			updates = append(updates, "updated_at = NOW()")
			query := fmt.Sprintf(
				"UPDATE attendance_shifts SET %s WHERE id = $%d AND school_id = $%d",
				joinStrings(updates, ", "), argIdx, argIdx+1,
			)
			args = append(args, shiftID, schoolID)

			result, err := database.DB.Exec(query, args...)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			affected, _ := result.RowsAffected()
			if affected == 0 {
				c.JSON(http.StatusNotFound, gin.H{"error": "Shift tidak ditemukan"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "Shift berhasil diperbarui"})
		})

		// DELETE: Hapus shift
		api.DELETE("/school-admin/attendance/shifts/:id", func(c *gin.Context) {
			schoolID, err := getSchoolIDFromUser(c)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
				return
			}

			shiftID := c.Param("id")

			// Cek apakah ada session aktif pakai shift ini
			var activeCount int
			_ = database.DB.QueryRow(`
				SELECT count(*) FROM attendance_sessions
				WHERE shift_id = $1 AND status IN ('open', 'scheduled')
			`, shiftID).Scan(&activeCount)

			if activeCount > 0 {
				c.JSON(http.StatusConflict, gin.H{
					"error": fmt.Sprintf("Tidak bisa hapus: ada %d sesi aktif pakai shift ini", activeCount),
				})
				return
			}

			result, err := database.DB.Exec(
				`DELETE FROM attendance_shifts WHERE id = $1 AND school_id = $2`,
				shiftID, schoolID,
			)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			affected, _ := result.RowsAffected()
			if affected == 0 {
				c.JSON(http.StatusNotFound, gin.H{"error": "Shift tidak ditemukan"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "Shift berhasil dihapus"})
		})

		// ==========================================
		// CLASS SHIFT ASSIGNMENTS
		// ==========================================

		// GET: List assignments
		api.GET("/school-admin/attendance/assignments", func(c *gin.Context) {
			schoolID, err := getSchoolIDFromUser(c)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
				return
			}

			classGroupID := c.Query("class_group_id")
			shiftID := c.Query("shift_id")

			query := `
				SELECT 
					csa.id, csa.class_group_id, csa.class_sub_group_id, csa.shift_id,
					csa.priority, csa.is_primary,
					csa.override_check_in_start, csa.override_check_in_end,
					csa.override_check_out_start, csa.override_check_out_end,
					csa.effective_from, csa.effective_to, csa.is_active,
					csa.created_at,
					COALESCE(cg.name, '') AS class_group_name,
					COALESCE(csg.name, '') AS class_sub_group_name,
					COALESCE(s.name, '') AS shift_name,
					COALESCE(s.code, '') AS shift_code
				FROM class_shift_assignments csa
				LEFT JOIN class_groups cg ON csa.class_group_id = cg.id
				LEFT JOIN class_sub_groups csg ON csa.class_sub_group_id = csg.id
				LEFT JOIN attendance_shifts s ON csa.shift_id = s.id
				WHERE csa.school_id = $1
			`
			args := []any{schoolID}
			argIdx := 2

			if classGroupID != "" {
				query += fmt.Sprintf(" AND csa.class_group_id = $%d", argIdx)
				args = append(args, classGroupID); argIdx++
			}
			if shiftID != "" {
				query += fmt.Sprintf(" AND csa.shift_id = $%d", argIdx)
				args = append(args, shiftID); argIdx++
			}

			query += " ORDER BY csa.is_primary DESC, csa.priority ASC"

			rows, err := database.DB.Query(query, args...)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			defer rows.Close()

			type AssignmentItem struct {
				ID                     string     `json:"id"`
				ClassGroupID           *string    `json:"class_group_id"`
				ClassSubGroupID        *string    `json:"class_sub_group_id"`
				ShiftID                string     `json:"shift_id"`
				Priority               int        `json:"priority"`
				IsPrimary              bool       `json:"is_primary"`
				OverrideCheckInStart   *string    `json:"override_check_in_start"`
				OverrideCheckInEnd     *string    `json:"override_check_in_end"`
				OverrideCheckOutStart  *string    `json:"override_check_out_start"`
				OverrideCheckOutEnd    *string    `json:"override_check_out_end"`
				EffectiveFrom          *string    `json:"effective_from"`
				EffectiveTo            *string    `json:"effective_to"`
				IsActive               bool       `json:"is_active"`
				CreatedAt              time.Time  `json:"created_at"`
				ClassGroupName         string     `json:"class_group_name"`
				ClassSubGroupName      string     `json:"class_sub_group_name"`
				ShiftName              string     `json:"shift_name"`
				ShiftCode              string     `json:"shift_code"`
			}

			var list []AssignmentItem
			for rows.Next() {
				var a AssignmentItem
				var cgID, csgID sql.NullString
				var ociStart, ociEnd, ocoStart, ocoEnd sql.NullString
				var effFrom, effTo sql.NullTime

				if err := rows.Scan(
					&a.ID, &cgID, &csgID, &a.ShiftID,
					&a.Priority, &a.IsPrimary,
					&ociStart, &ociEnd, &ocoStart, &ocoEnd,
					&effFrom, &effTo, &a.IsActive, &a.CreatedAt,
					&a.ClassGroupName, &a.ClassSubGroupName, &a.ShiftName, &a.ShiftCode,
				); err == nil {
					if cgID.Valid { a.ClassGroupID = &cgID.String }
					if csgID.Valid { a.ClassSubGroupID = &csgID.String }
					if ociStart.Valid { t, _ := time.Parse("15:04:05", ociStart.String); s := t.Format("15:04"); a.OverrideCheckInStart = &s }
					if ociEnd.Valid { t, _ := time.Parse("15:04:05", ociEnd.String); s := t.Format("15:04"); a.OverrideCheckInEnd = &s }
					if ocoStart.Valid { t, _ := time.Parse("15:04:05", ocoStart.String); s := t.Format("15:04"); a.OverrideCheckOutStart = &s }
					if ocoEnd.Valid { t, _ := time.Parse("15:04:05", ocoEnd.String); s := t.Format("15:04"); a.OverrideCheckOutEnd = &s }
					if effFrom.Valid { s := effFrom.Time.Format("2006-01-02"); a.EffectiveFrom = &s }
					if effTo.Valid { s := effTo.Time.Format("2006-01-02"); a.EffectiveTo = &s }

					list = append(list, a)
				}
			}

			c.JSON(http.StatusOK, gin.H{"assignments": list, "total": len(list)})
		})

		// POST: Create assignment
		api.POST("/school-admin/attendance/assignments", func(c *gin.Context) {
			schoolID, err := getSchoolIDFromUser(c)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
				return
			}
			adminID, _ := getAdminIDFromUser(c)

			var req CreateClassShiftAssignmentRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Format tidak valid"})
				return
			}

			if req.ClassGroupID == "" && req.ClassSubGroupID == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Minimal isi class_group_id atau class_sub_group_id"})
				return
			}

			priority := req.Priority
			if priority == 0 { priority = 1 }
			isPrimary := true
			if req.IsPrimary != nil { isPrimary = *req.IsPrimary }

			var classGroupID, classSubGroupID interface{} = nil, nil
			if req.ClassGroupID != "" { classGroupID = req.ClassGroupID }
			if req.ClassSubGroupID != "" { classSubGroupID = req.ClassSubGroupID }

			var ociStart, ociEnd, ocoStart, ocoEnd interface{} = nil, nil, nil, nil
			if req.OverrideCheckInStart != "" { ociStart = req.OverrideCheckInStart }
			if req.OverrideCheckInEnd != "" { ociEnd = req.OverrideCheckInEnd }
			if req.OverrideCheckOutStart != "" { ocoStart = req.OverrideCheckOutStart }
			if req.OverrideCheckOutEnd != "" { ocoEnd = req.OverrideCheckOutEnd }

			var effFrom, effTo interface{} = nil, nil
			if req.EffectiveFrom != "" { effFrom = req.EffectiveFrom }
			if req.EffectiveTo != "" { effTo = req.EffectiveTo }

			var assignmentID string
			err = database.DB.QueryRow(`
				INSERT INTO class_shift_assignments (
					school_id, class_group_id, class_sub_group_id, shift_id,
					priority, is_primary,
					override_check_in_start, override_check_in_end,
					override_check_out_start, override_check_out_end,
					effective_from, effective_to, created_by
				) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
				RETURNING id
			`, schoolID, classGroupID, classSubGroupID, req.ShiftID,
				priority, isPrimary,
				ociStart, ociEnd, ocoStart, ocoEnd,
				effFrom, effTo, adminID).Scan(&assignmentID)

			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyimpan: " + err.Error()})
				return
			}

			c.JSON(http.StatusCreated, gin.H{"message": "Assignment berhasil dibuat", "id": assignmentID})
		})

		// DELETE: Hapus assignment
		api.DELETE("/school-admin/attendance/assignments/:id", func(c *gin.Context) {
			schoolID, err := getSchoolIDFromUser(c)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
				return
			}

			result, err := database.DB.Exec(
				`DELETE FROM class_shift_assignments WHERE id = $1 AND school_id = $2`,
				c.Param("id"), schoolID,
			)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			affected, _ := result.RowsAffected()
			if affected == 0 {
				c.JSON(http.StatusNotFound, gin.H{"error": "Assignment tidak ditemukan"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "Assignment berhasil dihapus"})
		})

				// ==========================================
		// STUDENT QR CODES
		// ==========================================

		// GET: List QR codes siswa
		api.GET("/school-admin/students/qr-list", func(c *gin.Context) {
			schoolID, err := getSchoolIDFromUser(c)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
				return
			}

			rows, err := database.DB.Query(`
				SELECT 
					sqc.id, sqc.student_id, sqc.qr_token, sqc.is_active,
					sqc.generated_at, sqc.regenerated_count,
					s.full_name, COALESCE(s.nisn, ''), COALESCE(s.student_number, '')
				FROM student_qr_codes sqc
				JOIN students s ON sqc.student_id = s.id
				WHERE sqc.school_id = $1
				ORDER BY s.full_name ASC
			`, schoolID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memuat QR: " + err.Error()})
				return
			}
			defer rows.Close()

			type QRItem struct {
				ID                string    `json:"id"`
				StudentID         string    `json:"student_id"`
				QRToken           string    `json:"qr_token"`
				IsActive          bool      `json:"is_active"`
				GeneratedAt       time.Time `json:"generated_at"`
				RegeneratedCount  int       `json:"regenerated_count"`
				StudentName       string    `json:"student_name"`
				NISN              string    `json:"nisn"`
				StudentNumber     string    `json:"student_number"`
			}

			var list []QRItem
			for rows.Next() {
				var q QRItem
				if err := rows.Scan(
					&q.ID, &q.StudentID, &q.QRToken, &q.IsActive,
					&q.GeneratedAt, &q.RegeneratedCount,
					&q.StudentName, &q.NISN, &q.StudentNumber,
				); err == nil {
					list = append(list, q)
				}
			}

			c.JSON(http.StatusOK, gin.H{"qr_codes": list, "total": len(list)})
		})

		// POST: Generate QR untuk 1 siswa
		api.POST("/school-admin/students/:id/generate-qr", func(c *gin.Context) {
			schoolID, err := getSchoolIDFromUser(c)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
				return
			}
			adminID, _ := getAdminIDFromUser(c)
			studentID := c.Param("id")

			// Validasi siswa milik sekolah
			var exists string
			err = database.DB.QueryRow(`
				SELECT id FROM students WHERE id = $1 AND school_id = $2
			`, studentID, schoolID).Scan(&exists)
			if err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "Siswa tidak ditemukan"})
				return
			}

			// Cek apakah sudah punya QR
			var existingID string
			err = database.DB.QueryRow(`
				SELECT id FROM student_qr_codes WHERE student_id = $1
			`, studentID).Scan(&existingID)
			if err == nil && existingID != "" {
				c.JSON(http.StatusConflict, gin.H{"error": "Siswa ini sudah punya QR code"})
				return
			}

			// Generate token
			token := generateQRToken()

			var qrID string
			err = database.DB.QueryRow(`
				INSERT INTO student_qr_codes (student_id, school_id, qr_token, generated_by)
				VALUES ($1, $2, $3, $4)
				RETURNING id
			`, studentID, schoolID, token, adminID).Scan(&qrID)

			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyimpan QR: " + err.Error()})
				return
			}

			c.JSON(http.StatusCreated, gin.H{
				"message":  "QR berhasil dibuat",
				"id":       qrID,
				"qr_token": token,
			})
		})

		// POST: Generate QR bulk
		api.POST("/school-admin/students/generate-qr-bulk", func(c *gin.Context) {
			schoolID, err := getSchoolIDFromUser(c)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
				return
			}
			adminID, _ := getAdminIDFromUser(c)

			var req GenerateQRRequest
			_ = c.ShouldBindJSON(&req)

			// Cari siswa yang belum punya QR
			query := `
				SELECT s.id FROM students s
				LEFT JOIN student_qr_codes sqc ON sqc.student_id = s.id
				WHERE s.school_id = $1 AND s.is_active = TRUE AND sqc.id IS NULL
			`
			args := []any{schoolID}
			argIdx := 2

			if req.ClassSubGroupID != "" {
				query += fmt.Sprintf(" AND s.class_sub_group_id = $%d", argIdx)
				args = append(args, req.ClassSubGroupID)
				argIdx++
			}

			rows, err := database.DB.Query(query, args...)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal query siswa: " + err.Error()})
				return
			}
			defer rows.Close()

			var studentIDs []string
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err == nil {
					studentIDs = append(studentIDs, id)
				}
			}

			if len(studentIDs) == 0 {
				c.JSON(http.StatusOK, gin.H{"message": "Semua siswa sudah punya QR", "generated": 0})
				return
			}

			// Batch insert
			tx, err := database.DB.Begin()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mulai transaksi"})
				return
			}
			defer tx.Rollback()

			generated := 0
			for _, sid := range studentIDs {
				token := generateQRToken()
				_, err := tx.Exec(`
					INSERT INTO student_qr_codes (student_id, school_id, qr_token, generated_by)
					VALUES ($1, $2, $3, $4)
				`, sid, schoolID, token, adminID)
				if err == nil {
					generated++
				}
			}

			if err := tx.Commit(); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal commit"})
				return
			}

			c.JSON(http.StatusCreated, gin.H{
				"message":   fmt.Sprintf("%d QR berhasil dibuat", generated),
				"generated": generated,
			})
		})

		// POST: Regenerate QR siswa
		api.POST("/school-admin/students/:id/regenerate-qr", func(c *gin.Context) {
			schoolID, err := getSchoolIDFromUser(c)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
				return
			}
			studentID := c.Param("id")

			// Cek QR existing
			var qrID string
			err = database.DB.QueryRow(`
				SELECT id FROM student_qr_codes 
				WHERE student_id = $1 AND school_id = $2
			`, studentID, schoolID).Scan(&qrID)
			if err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "QR tidak ditemukan"})
				return
			}

			newToken := generateQRToken()
			_, err = database.DB.Exec(`
				UPDATE student_qr_codes SET
					qr_token = $1,
					regenerated_count = regenerated_count + 1,
					generated_at = NOW(),
					updated_at = NOW()
				WHERE id = $2
			`, newToken, qrID)

			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal regenerate: " + err.Error()})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"message":  "QR berhasil di-regenerate",
				"qr_token": newToken,
			})
		})

		// ==========================================
		// ATTENDANCE SESSIONS
		// ==========================================

		// GET: List semua sessions
		api.GET("/school-admin/attendance/sessions", func(c *gin.Context) {
			schoolID, err := getSchoolIDFromUser(c)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
				return
			}

			// Filter opsional
			dateFrom := c.Query("from")
			dateTo := c.Query("to")
			status := c.Query("status")
			limit := c.DefaultQuery("limit", "100")

			query := `
				SELECT 
					ases.id, ases.title, ases.session_date, ases.status,
					ases.shift_id, COALESCE(sh.name, '') AS shift_name, COALESCE(sh.code, '') AS shift_code,
					ases.class_group_id, COALESCE(cg.name, '') AS class_group_name,
					ases.class_sub_group_id, COALESCE(csg.name, '') AS class_sub_group_name,
					ases.total_students, ases.total_check_in, ases.total_check_out,
					ases.total_absent,
					ases.opened_at, ases.closed_at,
					ases.created_at
				FROM attendance_sessions ases
				LEFT JOIN attendance_shifts sh ON ases.shift_id = sh.id
				LEFT JOIN class_groups cg ON ases.class_group_id = cg.id
				LEFT JOIN class_sub_groups csg ON ases.class_sub_group_id = csg.id
				WHERE ases.school_id = $1
			`
			args := []any{schoolID}
			argIdx := 2

			if dateFrom != "" {
				query += fmt.Sprintf(" AND ases.session_date >= $%d", argIdx)
				args = append(args, dateFrom); argIdx++
			}
			if dateTo != "" {
				query += fmt.Sprintf(" AND ases.session_date <= $%d", argIdx)
				args = append(args, dateTo); argIdx++
			}
			if status != "" {
				query += fmt.Sprintf(" AND ases.status = $%d", argIdx)
				args = append(args, status); argIdx++
			}

			query += fmt.Sprintf(" ORDER BY ases.session_date DESC, ases.created_at DESC LIMIT $%d", argIdx)
			args = append(args, limit)

			rows, err := database.DB.Query(query, args...)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memuat sesi: " + err.Error()})
				return
			}
			defer rows.Close()

			type SessionItem struct {
				ID                 string     `json:"id"`
				Title              string     `json:"title"`
				SessionDate        string     `json:"session_date"`
				Status             string     `json:"status"`
				ShiftID            string     `json:"shift_id"`
				ShiftName          string     `json:"shift_name"`
				ShiftCode          string     `json:"shift_code"`
				ClassGroupID       *string    `json:"class_group_id"`
				ClassGroupName     string     `json:"class_group_name"`
				ClassSubGroupID    *string    `json:"class_sub_group_id"`
				ClassSubGroupName  string     `json:"class_sub_group_name"`
				TotalStudents      int        `json:"total_students"`
				TotalCheckIn       int        `json:"total_check_in"`
				TotalCheckOut      int        `json:"total_check_out"`
				TotalAbsent        int        `json:"total_absent"`
				OpenedAt           *time.Time `json:"opened_at"`
				ClosedAt           *time.Time `json:"closed_at"`
				CreatedAt          time.Time  `json:"created_at"`
			}

			var sessions []SessionItem
			for rows.Next() {
				var s SessionItem
				var dateVal time.Time
				var cgID, csgID sql.NullString
				var openedAt, closedAt sql.NullTime

				if err := rows.Scan(
					&s.ID, &s.Title, &dateVal, &s.Status,
					&s.ShiftID, &s.ShiftName, &s.ShiftCode,
					&cgID, &s.ClassGroupName,
					&csgID, &s.ClassSubGroupName,
					&s.TotalStudents, &s.TotalCheckIn, &s.TotalCheckOut,
					&s.TotalAbsent,
					&openedAt, &closedAt, &s.CreatedAt,
				); err == nil {
					s.SessionDate = dateVal.Format("2006-01-02")
					if cgID.Valid { s.ClassGroupID = &cgID.String }
					if csgID.Valid { s.ClassSubGroupID = &csgID.String }
					if openedAt.Valid { s.OpenedAt = &openedAt.Time }
					if closedAt.Valid { s.ClosedAt = &closedAt.Time }
					sessions = append(sessions, s)
				}
			}

			c.JSON(http.StatusOK, gin.H{"sessions": sessions, "total": len(sessions)})
		})

		// GET: Today's sessions (untuk dashboard)
		api.GET("/school-admin/attendance/sessions/today", func(c *gin.Context) {
			schoolID, err := getSchoolIDFromUser(c)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
				return
			}

			rows, err := database.DB.Query(`
				SELECT 
					ases.id, ases.title, ases.session_date, ases.status,
					ases.shift_id, COALESCE(sh.name, '') AS shift_name,
					ases.class_group_id, COALESCE(cg.name, '') AS class_group_name,
					ases.total_students, ases.total_check_in, ases.total_absent
				FROM attendance_sessions ases
				LEFT JOIN attendance_shifts sh ON ases.shift_id = sh.id
				LEFT JOIN class_groups cg ON ases.class_group_id = cg.id
				WHERE ases.school_id = $1 
					AND ases.session_date = CURRENT_DATE
					AND ases.status IN ('scheduled', 'open')
				ORDER BY ases.created_at ASC
			`, schoolID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			defer rows.Close()

			type TodayItem struct {
				ID              string  `json:"id"`
				Title           string  `json:"title"`
				SessionDate     string  `json:"session_date"`
				Status          string  `json:"status"`
				ShiftID         string  `json:"shift_id"`
				ShiftName       string  `json:"shift_name"`
				ClassGroupID    *string `json:"class_group_id"`
				ClassGroupName  string  `json:"class_group_name"`
				TotalStudents   int     `json:"total_students"`
				TotalCheckIn    int     `json:"total_check_in"`
				TotalAbsent     int     `json:"total_absent"`
			}

			var sessions []TodayItem
			for rows.Next() {
				var s TodayItem
				var dateVal time.Time
				var cgID sql.NullString
				if err := rows.Scan(
					&s.ID, &s.Title, &dateVal, &s.Status,
					&s.ShiftID, &s.ShiftName,
					&cgID, &s.ClassGroupName,
					&s.TotalStudents, &s.TotalCheckIn, &s.TotalAbsent,
				); err == nil {
					s.SessionDate = dateVal.Format("2006-01-02")
					if cgID.Valid { s.ClassGroupID = &cgID.String }
					sessions = append(sessions, s)
				}
			}

			c.JSON(http.StatusOK, gin.H{"sessions": sessions, "total": len(sessions)})
		})

		// GET: Detail session
		api.GET("/school-admin/attendance/sessions/:id", func(c *gin.Context) {
			schoolID, err := getSchoolIDFromUser(c)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
				return
			}

			sessionID := c.Param("id")

			var s struct {
				ID                 string
				Title              string
				SessionDate        time.Time
				Status             string
				ShiftID            string
				ShiftName          string
				ShiftCode          string
				ClassGroupID       sql.NullString
				ClassGroupName     string
				ClassSubGroupID    sql.NullString
				ClassSubGroupName  string
				TotalStudents      int
				TotalCheckIn       int
				TotalCheckOut      int
				TotalAbsent        int
				OpenedAt           sql.NullTime
				ClosedAt           sql.NullTime
			}

			err = database.DB.QueryRow(`
				SELECT 
					ases.id, ases.title, ases.session_date, ases.status,
					ases.shift_id, COALESCE(sh.name, ''), COALESCE(sh.code, ''),
					ases.class_group_id, COALESCE(cg.name, ''),
					ases.class_sub_group_id, COALESCE(csg.name, ''),
					ases.total_students, ases.total_check_in, ases.total_check_out,
					ases.total_absent, ases.opened_at, ases.closed_at
				FROM attendance_sessions ases
				LEFT JOIN attendance_shifts sh ON ases.shift_id = sh.id
				LEFT JOIN class_groups cg ON ases.class_group_id = cg.id
				LEFT JOIN class_sub_groups csg ON ases.class_sub_group_id = csg.id
				WHERE ases.id = $1 AND ases.school_id = $2
			`, sessionID, schoolID).Scan(
				&s.ID, &s.Title, &s.SessionDate, &s.Status,
				&s.ShiftID, &s.ShiftName, &s.ShiftCode,
				&s.ClassGroupID, &s.ClassGroupName,
				&s.ClassSubGroupID, &s.ClassSubGroupName,
				&s.TotalStudents, &s.TotalCheckIn, &s.TotalCheckOut,
				&s.TotalAbsent, &s.OpenedAt, &s.ClosedAt,
			)

			if err != nil {
				if err == sql.ErrNoRows {
					c.JSON(http.StatusNotFound, gin.H{"error": "Sesi tidak ditemukan"})
					return
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			result := gin.H{
				"id":                  s.ID,
				"title":               s.Title,
				"session_date":        s.SessionDate.Format("2006-01-02"),
				"status":              s.Status,
				"shift_id":            s.ShiftID,
				"shift_name":          s.ShiftName,
				"shift_code":          s.ShiftCode,
				"class_group_name":    s.ClassGroupName,
				"class_sub_group_name": s.ClassSubGroupName,
				"total_students":      s.TotalStudents,
				"total_check_in":      s.TotalCheckIn,
				"total_check_out":     s.TotalCheckOut,
				"total_absent":        s.TotalAbsent,
			}
			if s.ClassGroupID.Valid { result["class_group_id"] = s.ClassGroupID.String }
			if s.ClassSubGroupID.Valid { result["class_sub_group_id"] = s.ClassSubGroupID.String }
			if s.OpenedAt.Valid { result["opened_at"] = s.OpenedAt.Time }
			if s.ClosedAt.Valid { result["closed_at"] = s.ClosedAt.Time }

			c.JSON(http.StatusOK, gin.H{"session": result})
		})

		// POST: Buat session baru
		api.POST("/school-admin/attendance/sessions", func(c *gin.Context) {
			schoolID, err := getSchoolIDFromUser(c)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
				return
			}
			adminID, _ := getAdminIDFromUser(c)

			var req CreateAttendanceSessionRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Format tidak valid: " + err.Error()})
				return
			}

			// Ambil shift config
			var shiftName, shiftCode string
			var checkInStart, checkInEnd time.Time
			var requireCheckOut bool
			var shiftConfigJSON []byte

			err = database.DB.QueryRow(`
				SELECT name, code, check_in_start, check_in_end, require_check_out,
					row_to_json(attendance_shifts)
				FROM attendance_shifts
				WHERE id = $1 AND school_id = $2
			`, req.ShiftID, schoolID).Scan(
				&shiftName, &shiftCode, &checkInStart, &checkInEnd, &requireCheckOut, &shiftConfigJSON,
			)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Shift tidak ditemukan"})
				return
			}

			// Session date (default today)
			sessionDate := req.SessionDate
			if sessionDate == "" {
				sessionDate = time.Now().Format("2006-01-02")
			}

			// Title (auto-generate jika kosong)
			title := req.Title
			if title == "" {
				title = fmt.Sprintf("%s - %s", shiftName, sessionDate)
			}

			// Count total_students berdasarkan filter kelas
			countQuery := `SELECT COUNT(*) FROM students WHERE school_id = $1 AND is_active = TRUE`
			countArgs := []any{schoolID}
			countIdx := 2

			var classGroupID, classSubGroupID interface{} = nil, nil
			if req.ClassGroupID != "" {
				classGroupID = req.ClassGroupID
				countQuery += fmt.Sprintf(" AND class_group_id = $%d", countIdx)
				countArgs = append(countArgs, req.ClassGroupID)
				countIdx++
			}
			if req.ClassSubGroupID != "" {
				classSubGroupID = req.ClassSubGroupID
				countQuery += fmt.Sprintf(" AND class_sub_group_id = $%d", countIdx)
				countArgs = append(countArgs, req.ClassSubGroupID)
				countIdx++
			}

			var totalStudents int
			_ = database.DB.QueryRow(countQuery, countArgs...).Scan(&totalStudents)

			// Auto-close time = session_date + check_in_end + auto_close_minutes
			autoCloseMinutes := 120
			var acm sql.NullInt64
			_ = database.DB.QueryRow(`
				SELECT auto_close_minutes_after_check_in FROM attendance_shifts WHERE id = $1
			`, req.ShiftID).Scan(&acm)
			if acm.Valid {
				autoCloseMinutes = int(acm.Int64)
			}

			autoCloseTime := time.Date(
				time.Now().Year(), time.Now().Month(), time.Now().Day(),
				checkInEnd.Hour(), checkInEnd.Minute(), 0, 0, time.Local,
			).Add(time.Duration(autoCloseMinutes) * time.Minute)

			var sessionID string
			err = database.DB.QueryRow(`
				INSERT INTO attendance_sessions (
					school_id, shift_id, class_group_id, class_sub_group_id,
					title, session_date, shift_config_snapshot,
					status, opened_by, auto_close_at, total_students, notes
				) VALUES ($1, $2, $3, $4, $5, $6, $7, 'scheduled', $8, $9, $10, NULLIF($11, ''))
				RETURNING id
			`, schoolID, req.ShiftID, classGroupID, classSubGroupID,
				title, sessionDate, shiftConfigJSON,
				adminID, autoCloseTime, totalStudents, req.Notes).Scan(&sessionID)

			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal membuat sesi: " + err.Error()})
				return
			}

			c.JSON(http.StatusCreated, gin.H{
				"message":    "Sesi berhasil dibuat",
				"id":         sessionID,
				"session_id": sessionID,
			})
		})

		// POST: Open session
		api.POST("/school-admin/attendance/sessions/:id/open", func(c *gin.Context) {
			schoolID, err := getSchoolIDFromUser(c)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
				return
			}

			sessionID := c.Param("id")
			adminID, _ := getAdminIDFromUser(c)

			result, err := database.DB.Exec(`
				UPDATE attendance_sessions SET
					status = 'open',
					opened_at = COALESCE(opened_at, NOW()),
					opened_by = COALESCE(opened_by, $1),
					updated_at = NOW()
				WHERE id = $2 AND school_id = $3 AND status IN ('scheduled', 'open')
			`, adminID, sessionID, schoolID)

			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			affected, _ := result.RowsAffected()
			if affected == 0 {
				c.JSON(http.StatusNotFound, gin.H{"error": "Sesi tidak ditemukan atau sudah ditutup"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "Sesi berhasil dibuka"})
		})

		// POST: Close session (dengan auto-absent)
		api.POST("/school-admin/attendance/sessions/:id/close", func(c *gin.Context) {
			schoolID, err := getSchoolIDFromUser(c)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
				return
			}

			sessionID := c.Param("id")
			adminID, _ := getAdminIDFromUser(c)

			// Validasi session milik sekolah
			var sStatus string
			err = database.DB.QueryRow(`
				SELECT status FROM attendance_sessions 
				WHERE id = $1 AND school_id = $2
			`, sessionID, schoolID).Scan(&sStatus)
			if err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "Sesi tidak ditemukan"})
				return
			}

			if sStatus == "closed" || sStatus == "auto_closed" {
				c.JSON(http.StatusConflict, gin.H{"error": "Sesi sudah ditutup"})
				return
			}

			// Panggil function auto-mark absent
			var absentCount int
			err = database.DB.QueryRow(
				`SELECT auto_mark_absent_for_session($1)`,
				sessionID,
			).Scan(&absentCount)
			if err != nil {
				fmt.Printf("[CLOSE SESSION] Auto absent error: %v\n", err)
				absentCount = 0
			}

			// Update status
			_, _ = database.DB.Exec(`
				UPDATE attendance_sessions SET
					status = 'closed',
					closed_by = $1,
					closed_at = NOW(),
					updated_at = NOW()
				WHERE id = $2
			`, adminID, sessionID)

			// Recalculate stats
			_, _ = database.DB.Exec(`SELECT recalculate_session_stats($1)`, sessionID)

			c.JSON(http.StatusOK, gin.H{
				"message":      "Sesi berhasil ditutup",
				"absent_count": absentCount,
			})
		})

		// DELETE: Hapus session
		api.DELETE("/school-admin/attendance/sessions/:id", func(c *gin.Context) {
			schoolID, err := getSchoolIDFromUser(c)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
				return
			}

			result, err := database.DB.Exec(`
				DELETE FROM attendance_sessions WHERE id = $1 AND school_id = $2
			`, c.Param("id"), schoolID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			affected, _ := result.RowsAffected()
			if affected == 0 {
				c.JSON(http.StatusNotFound, gin.H{"error": "Sesi tidak ditemukan"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "Sesi berhasil dihapus"})
		})

		// GET: Records untuk session (untuk report)
		api.GET("/school-admin/attendance/sessions/:id/records", func(c *gin.Context) {
			schoolID, err := getSchoolIDFromUser(c)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
				return
			}

			sessionID := c.Param("id")

			// Ambil session info dulu
			var classGroupID, classSubGroupID sql.NullString
			err = database.DB.QueryRow(`
				SELECT class_group_id, class_sub_group_id 
				FROM attendance_sessions 
				WHERE id = $1 AND school_id = $2
			`, sessionID, schoolID).Scan(&classGroupID, &classSubGroupID)
			if err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "Sesi tidak ditemukan"})
				return
			}

			// Query semua siswa target + LEFT JOIN ke records
			query := `
				SELECT 
					s.id AS student_id,
					s.full_name AS student_name,
					COALESCE(s.nisn, '') AS nisn,
					COALESCE(csg.name, '') AS sub_class_name,
					ci.status AS check_in_status,
					ci.scanned_at AS check_in_at,
					co.status AS check_out_status,
					co.scanned_at AS check_out_at,
					COALESCE(ci.status = 'absent', false) AS is_absent
				FROM students s
				LEFT JOIN class_sub_groups csg ON s.class_sub_group_id = csg.id
				LEFT JOIN attendance_records ci ON ci.student_id = s.id 
					AND ci.session_id = $1 AND ci.record_type = 'check_in'
				LEFT JOIN attendance_records co ON co.student_id = s.id 
					AND co.session_id = $1 AND co.record_type = 'check_out'
				WHERE s.school_id = $2 AND s.is_active = TRUE
			`
			args := []any{sessionID, schoolID}
			argIdx := 3

			if classGroupID.Valid {
				query += fmt.Sprintf(" AND s.class_group_id = $%d", argIdx)
				args = append(args, classGroupID.String)
				argIdx++
			}
			if classSubGroupID.Valid {
				query += fmt.Sprintf(" AND s.class_sub_group_id = $%d", argIdx)
				args = append(args, classSubGroupID.String)
				argIdx++
			}

			query += " ORDER BY s.full_name ASC"

			rows, err := database.DB.Query(query, args...)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal query records: " + err.Error()})
				return
			}
			defer rows.Close()

			type RecordItem struct {
				StudentID        string  `json:"student_id"`
				StudentName      string  `json:"student_name"`
				NISN             string  `json:"nisn"`
				SubClassName     string  `json:"sub_class_name"`
				CheckInStatus    *string `json:"check_in_status"`
				CheckInTime      *string `json:"check_in_time"`
				CheckOutStatus   *string `json:"check_out_status"`
				CheckOutTime     *string `json:"check_out_time"`
				IsAbsent         bool    `json:"is_absent"`
			}

			var records []RecordItem
			for rows.Next() {
				var r RecordItem
				var ciStatus, coStatus sql.NullString
				var ciAt, coAt sql.NullTime

				if err := rows.Scan(
					&r.StudentID, &r.StudentName, &r.NISN, &r.SubClassName,
					&ciStatus, &ciAt, &coStatus, &coAt, &r.IsAbsent,
				); err == nil {
					if ciStatus.Valid { r.CheckInStatus = &ciStatus.String }
					if coStatus.Valid { r.CheckOutStatus = &coStatus.String }
					if ciAt.Valid {
						t := ciAt.Time.Format("15:04")
						r.CheckInTime = &t
					}
					if coAt.Valid {
						t := coAt.Time.Format("15:04")
						r.CheckOutTime = &t
					}
					records = append(records, r)
				}
			}

			c.JSON(http.StatusOK, gin.H{"records": records, "total": len(records)})
		})

				// ==========================================
		// SCAN HANDLER (CORE)
		// ==========================================

		api.POST("/school-admin/attendance/scan", func(c *gin.Context) {
			schoolID, err := getSchoolIDFromUser(c)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
				return
			}
			adminID, _ := getAdminIDFromUser(c)

			var req ScanQRRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Format tidak valid: " + err.Error()})
				return
			}

			// 1. Validasi session
			var sessionStatus string
			var shiftID string
			var sessionClassGroupID, sessionClassSubGroupID sql.NullString
			var checkInStart, checkInEnd time.Time
			var requireCheckOut bool
			var checkOutStart, checkOutEnd sql.NullTime

			err = database.DB.QueryRow(`
				SELECT 
					ases.status, ases.shift_id,
					ases.class_group_id, ases.class_sub_group_id,
					sh.check_in_start, sh.check_in_end,
					sh.require_check_out, sh.check_out_start, sh.check_out_end
				FROM attendance_sessions ases
				JOIN attendance_shifts sh ON ases.shift_id = sh.id
				WHERE ases.id = $1 AND ases.school_id = $2
			`, req.SessionID, schoolID).Scan(
				&sessionStatus, &shiftID,
				&sessionClassGroupID, &sessionClassSubGroupID,
				&checkInStart, &checkInEnd,
				&requireCheckOut, &checkOutStart, &checkOutEnd,
			)

			if err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "Sesi tidak ditemukan"})
				return
			}

			if sessionStatus != "open" && sessionStatus != "scheduled" {
				c.JSON(http.StatusConflict, gin.H{"error": "Sesi sudah ditutup"})
				return
			}

			// Auto-open session jika masih scheduled
			if sessionStatus == "scheduled" {
				_, _ = database.DB.Exec(`
					UPDATE attendance_sessions SET status = 'open', opened_at = NOW(), opened_by = $1
					WHERE id = $2
				`, adminID, req.SessionID)
			}

			// 2. Cari student by QR token
			var studentID, studentName, studentNISN string
			var studentClassGroupID, studentClassSubGroupID sql.NullString

			err = database.DB.QueryRow(`
				SELECT 
					s.id, s.full_name, COALESCE(s.nisn, ''),
					s.class_group_id, s.class_sub_group_id
				FROM student_qr_codes sqc
				JOIN students s ON sqc.student_id = s.id
				WHERE sqc.qr_token = $1 AND sqc.school_id = $2 AND sqc.is_active = TRUE
			`, req.QRToken, schoolID).Scan(
				&studentID, &studentName, &studentNISN,
				&studentClassGroupID, &studentClassSubGroupID,
			)

			if err != nil {
				c.JSON(http.StatusNotFound, gin.H{
					"error":   "QR tidak dikenal",
					"qr_token": req.QRToken,
				})
				return
			}

			// 3. Validasi kelas
			if sessionClassGroupID.Valid && studentClassGroupID.Valid {
				if sessionClassGroupID.String != studentClassGroupID.String {
					c.JSON(http.StatusBadRequest, gin.H{
						"error":   "Siswa bukan bagian dari kelas yang di-absensi",
						"student": gin.H{"full_name": studentName, "nisn": studentNISN},
					})
					return
				}
			}
			if sessionClassSubGroupID.Valid && studentClassSubGroupID.Valid {
				if sessionClassSubGroupID.String != studentClassSubGroupID.String {
					c.JSON(http.StatusBadRequest, gin.H{
						"error":   "Siswa bukan bagian dari sub kelas yang di-absensi",
						"student": gin.H{"full_name": studentName, "nisn": studentNISN},
					})
					return
				}
			}

			// 4. Tentukan mode: check_in atau check_out
			var hasCheckIn, hasCheckOut bool
			_ = database.DB.QueryRow(`
				SELECT 
					EXISTS(SELECT 1 FROM attendance_records WHERE session_id = $1 AND student_id = $2 AND record_type = 'check_in'),
					EXISTS(SELECT 1 FROM attendance_records WHERE session_id = $1 AND student_id = $2 AND record_type = 'check_out')
			`, req.SessionID, studentID).Scan(&hasCheckIn, &hasCheckOut)

			// Force mode dari request (override)
			mode := ""
			if req.ForceMode == "check_in" || req.ForceMode == "check_out" {
				mode = req.ForceMode
			} else {
				if !hasCheckIn {
					mode = "check_in"
				} else if requireCheckOut && !hasCheckOut {
					mode = "check_out"
				} else {
					// Sudah check-in & tidak butuh check-out ATAU sudah check-out
					c.JSON(http.StatusConflict, gin.H{
						"duplicate": true,
						"error":     "Siswa sudah tercatat sebelumnya",
						"student":   gin.H{"full_name": studentName, "nisn": studentNISN},
					})
					return
				}
			}

			// 5. Hitung status berdasarkan waktu
			now := time.Now()
			currentTime := time.Date(2000, 1, 1, now.Hour(), now.Minute(), now.Second(), 0, time.UTC)

			var status string
			var deviation int

			if mode == "check_in" {
				status = determineCheckInStatus(
					checkInStart, checkInEnd, currentTime,
				)
				// Hitung deviation
				if currentTime.Before(checkInStart) {
					deviation = -int(checkInStart.Sub(currentTime).Minutes())
				} else if currentTime.After(checkInEnd) {
					deviation = int(currentTime.Sub(checkInEnd).Minutes())
				}
			} else {
				if !checkOutStart.Valid || !checkOutEnd.Valid {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Shift ini tidak support check-out"})
					return
				}
				status = determineCheckOutStatus(
					checkOutStart.Time, checkOutEnd.Time, currentTime,
				)
			}

			// 6. Insert record
			var recordID string
			err = database.DB.QueryRow(`
				INSERT INTO attendance_records (
					session_id, student_id, school_id,
					record_type, status, scanned_at, scanned_by,
					scan_method, deviation_minutes
				) VALUES ($1, $2, $3, $4, $5, NOW(), $6, 'qr', $7)
				RETURNING id
			`, req.SessionID, studentID, schoolID,
				mode, status, adminID, deviation).Scan(&recordID)

			if err != nil {
				// Kemungkinan duplikat
				fmt.Printf("[SCAN] Insert error: %v\n", err)
				c.JSON(http.StatusConflict, gin.H{
					"duplicate": true,
					"error":     "Siswa sudah tercatat di sesi ini",
					"student":   gin.H{"full_name": studentName, "nisn": studentNISN},
				})
				return
			}

			// 7. Update counter di session
			if mode == "check_in" {
				_, _ = database.DB.Exec(`
					UPDATE attendance_sessions 
					SET total_check_in = total_check_in + 1,
						total_on_time = CASE WHEN $2 IN ('on_time', 'early') THEN total_on_time + 1 ELSE total_on_time END,
						total_late = CASE WHEN $2 IN ('late', 'very_late') THEN total_late + 1 ELSE total_late END,
						updated_at = NOW()
					WHERE id = $1
				`, req.SessionID, status)
			} else {
				_, _ = database.DB.Exec(`
					UPDATE attendance_sessions 
					SET total_check_out = total_check_out + 1,
						updated_at = NOW()
					WHERE id = $1
				`, req.SessionID)
			}

			// 8. Upsert summary
			_, _ = database.DB.Exec(`
				INSERT INTO student_attendance_summary 
					(student_id, school_id, session_id, summary_date, 
					 check_in_status, check_in_time,
					 check_out_status, check_out_time,
					 is_complete, is_absent)
				VALUES ($1, $2, $3, CURRENT_DATE,
					CASE WHEN $4 = 'check_in' THEN $5::text ELSE NULL END,
					CASE WHEN $4 = 'check_in' THEN $6::time ELSE NULL END,
					CASE WHEN $4 = 'check_out' THEN $5::text ELSE NULL END,
					CASE WHEN $4 = 'check_out' THEN $6::time ELSE NULL END,
					false, false)
				ON CONFLICT (student_id, session_id) DO UPDATE SET
					check_in_status = CASE WHEN $4 = 'check_in' THEN $5 ELSE student_attendance_summary.check_in_status END,
					check_in_time = CASE WHEN $4 = 'check_in' THEN $6::time ELSE student_attendance_summary.check_in_time END,
					check_out_status = CASE WHEN $4 = 'check_out' THEN $5 ELSE student_attendance_summary.check_out_status END,
					check_out_time = CASE WHEN $4 = 'check_out' THEN $6::time ELSE student_attendance_summary.check_out_time END,
					is_complete = CASE WHEN $4 = 'check_out' THEN true ELSE student_attendance_summary.is_complete END,
					updated_at = NOW()
			`, studentID, schoolID, req.SessionID,
				mode, status, now.Format("15:04:05"))

			c.JSON(http.StatusOK, gin.H{
				"success": true,
				"mode":    mode,
				"status":  status,
				"student": gin.H{
					"id":              studentID,
					"full_name":       studentName,
					"nisn":            studentNISN,
					"sub_class_name":  studentClassSubGroupID.String,
				},
				"scanned_at": now,
				"record_id":  recordID,
			})
		})

	}
}