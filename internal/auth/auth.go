package auth

import (
	"database/sql"
	"errors"
	"log/slog"
	"mobydevLogin/internal/helpers"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

type DBHandler interface {
	Login(w http.ResponseWriter, r *http.Request, db *sql.DB, log *slog.Logger)
	Register(w http.ResponseWriter, r *http.Request, db *sql.DB, log *slog.Logger)
}

type dbHandler struct{}

var jwtSecret = []byte("your-secret-key") // TODO: keep in env

func (h *dbHandler) Login(w http.ResponseWriter, r *http.Request, db *sql.DB, log *slog.Logger) {

	email := r.FormValue("email")
	password := r.FormValue("password")

	var storedPassword string
	var isAdmin bool

	if !helpers.IsValidEmail(email) {
		helpers.ServeError(errors.New("wrong email format"), w, "wrong email format", log, http.StatusBadRequest)
		return
	}

	err := db.QueryRow("SELECT password, isAdmin FROM users WHERE email=?", email).Scan(&storedPassword, &isAdmin)
	if err == sql.ErrNoRows {
		helpers.ServeError(err, w, "user doesn't exist", log, http.StatusBadRequest)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password))
	if err != nil {
		helpers.ServeError(err, w, "wrong credentials", log, http.StatusBadRequest)
		return
	}

	token, err := generateJWT(email, isAdmin)
	if err != nil {
		helpers.ServeError(err, w, "Internal server error", log, http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:  "token",
		Value: token,
		Path:  "/",
	})
	log.Info("User logged:", slog.String("email", email))

	w.Write([]byte("Login successful!"))

}

func (h *dbHandler) Register(w http.ResponseWriter, r *http.Request, db *sql.DB, log *slog.Logger) {

	email := r.FormValue("email")
	password := r.FormValue("password")
	verPassword := r.FormValue("verPassword")

	// TODO: use context for multple errors return

	if !helpers.IsValidEmail(email) {
		helpers.ServeError(errors.New("wrong email format"), w, "wrong email format", log, http.StatusBadRequest)
		return
	}

	if password != verPassword {
		helpers.ServeError(errors.New("passowrd dont match"), w, "passowrd dont match", log, http.StatusBadRequest)
		return
	}

	if email == "" || password == "" {
		helpers.ServeError(errors.New("input is empty"), w, "Input is empty", log, http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	if err != nil {
		helpers.ServeError(err, w, "Internal server error", log, http.StatusInternalServerError)
		return
	}

	err = createUser(email, string(hashedPassword), db)

	if err != nil {

		if sqliteErr, ok := err.(sqlite3.Error); ok && sqliteErr.Code == sqlite3.ErrConstraint {
			helpers.ServeError(err, w, "email alreadt exists", log, http.StatusConflict)
			return
		}

		helpers.ServeError(err, w, "Internal server error", log, http.StatusInternalServerError)
		return
	}

	log.Info("User registered:", slog.String("email", email))

	w.Write([]byte("User registered successfully!"))

}

func createUser(email, password string, db *sql.DB) error {
	_, err := db.Exec(`
		INSERT INTO users (email, password)
		VALUES (?, ?)
	`, email, password)
	return err
}

func generateJWT(email string, isAdmin bool) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email":   email,
		"isAdmin": isAdmin,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
	})

	return token.SignedString(jwtSecret)
}

func NewDBHandler() DBHandler {
	return &dbHandler{}
}
