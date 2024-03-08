package helpers

import (
	"log/slog"
	"net/http"
	"regexp"
)

func ServeError(err error, w http.ResponseWriter, errText string, log *slog.Logger, code int) {
	http.Error(w, errText, code)

	log.Error(errText, Err(err))

}

func Err(err error) slog.Attr {
	return slog.Attr{
		Key:   "error",
		Value: slog.StringValue(err.Error()),
	}
}

func IsValidEmail(email string) bool {
	pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`

	re := regexp.MustCompile(pattern)

	return re.MatchString(email)
}
