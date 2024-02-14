package web

import (
	"embed"
	"io/fs"
	"net/http"

	"github.com/rs/zerolog/log"
)

//go:embed html/**
var webRoot embed.FS

func GetHandleFunc() http.Handler {
	sub, err := fs.Sub(webRoot, "html")
	if err != nil {
		log.Panic().Err(err).Msg("error getting subdirectory for webRoot")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.FileServer(http.FS(sub)).ServeHTTP(w, r)
	})
}

func CacheControlMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=86400")
		next.ServeHTTP(w, r)
	})
}
