package web

import (
	"embed"
	"io/fs"
	"net/http"

	"github.com/rs/zerolog/log"
)

//go:embed html/**
var webRoot embed.FS

func GetHandleFunc() func(w http.ResponseWriter, r *http.Request) {
	sub, err := fs.Sub(webRoot, "html")
	if err != nil {
		log.Panic().Err(err).Msg("error getting subdirectory for webRoot")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		http.FileServer(http.FS(sub)).ServeHTTP(w, r)
	}
}
