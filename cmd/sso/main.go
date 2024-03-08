package main

import (
	"context"
	"database/sql"
	"log/slog"
	"mobydevLogin/internal/helpers"
	"mobydevLogin/internal/router"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func main() {

	log := slog.New( //TODO: make pretty
		slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
	)

	var err error
	var db *sql.DB
	db, err = sql.Open("sqlite3", "./storage/sso.db")

	if err != nil {
		log.Error("failed to open db", helpers.Err(err))
		os.Exit(1)
	}
	defer db.Close()

	handler := router.NewRouter(db, log)

	server := &http.Server{
		Addr:         ":8080",
		Handler:      handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Error("failed to start server", helpers.Err(err))
		}
	}()

	log.Info("Server is running on :8080")

	<-done
	log.Info("stopping server")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Error("failed to stop server", helpers.Err(err))

		return
	}

	log.Info("server stopped")
}
