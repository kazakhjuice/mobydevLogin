package router

import (
	"database/sql"
	"log/slog"
	"net/http"

	"mobydevLogin/internal/auth"

	"github.com/gorilla/mux"
)

func NewRouter(db *sql.DB, log *slog.Logger) *mux.Router {
	router := mux.NewRouter()

	dbHandler := auth.NewDBHandler()

	router.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		dbHandler.Login(w, r, db, log)
	}).Methods("POST")

	router.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		dbHandler.Register(w, r, db, log)
	}).Methods("POST")

	return router
}
