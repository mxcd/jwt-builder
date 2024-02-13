package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/rs/zerolog/log"

	"github.com/mxcd/go-config/config"
	"github.com/mxcd/jwt-builder/internal/util"
	"github.com/mxcd/jwt-builder/internal/web"
)

func main() {
	if err := util.InitConfig(); err != nil {
		log.Panic().Err(err).Msg("error initializing config")
	}

	if err := util.InitLogger(); err != nil {
		log.Panic().Err(err).Msg("error initializing logger")
	}

	block, _ := pem.Decode([]byte(config.Get().String("JWT_PRIVATE_KEY")))
	if block == nil {
		log.Panic().Msg("failed to decode private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Panic().Err(err).Msg("failed to parse private key")
	}

	jwkPublicKey, err := jwk.FromRaw(privateKey.Public())
	if err != nil {
		log.Panic().Err(err).Msg("failed to create JWK from RSA private key")
	}

	err = jwkPublicKey.Set(jwk.KeyIDKey, "1") // Set a key ID; adjust as necessary
	if err != nil {
		log.Panic().Err(err).Msg("failed to set key ID")
	}

	err = jwkPublicKey.Set(jwk.AlgorithmKey, "RS512")
	if err != nil {
		log.Panic().Err(err).Msg("failed to set algorithm")
	}

	err = jwkPublicKey.Set(jwk.KeyUsageKey, jwk.ForSignature)
	if err != nil {
		log.Panic().Err(err).Msg("failed to set algorithm")
	}

	err = jwkPublicKey.Set("iss", config.Get().String("JWT_ISSUER"))
	if err != nil {
		log.Panic().Err(err).Msg("failed to set algorithm")
	}

	set := jwk.NewSet()

	set.AddKey(jwkPublicKey)

	jwks, err := json.Marshal(set)
	if err != nil {
		log.Panic().Err(err).Msg("failed to generate jwks json")
	}

	jwkPrivateKey, err := jwk.FromRaw(privateKey)
	if err != nil {
		log.Panic().Err(err).Msg("failed to create JWK from RSA private key")
	}
	jwkPrivateKey.Set(jwk.KeyIDKey, "1")
	jwkPrivateKey.Set(jwk.AlgorithmKey, "RS512")
	jwkPrivateKey.Set(jwk.KeyTypeKey, "JWT")
	jwkPrivateKey.Set(jwk.KeyUsageKey, jwk.ForSignature)
	jwkPrivateKey.Set("iss", config.Get().String("JWT_ISSUER"))
	jwkPrivateKey.Set("jku", fmt.Sprintf("%s/JWKS", config.Get().String("JWT_ISSUER")))

	http.HandleFunc("/JWKS", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(jwks)
	})

	http.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var claims map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&claims); err != nil {
			log.Error().Err(err).Msg("failed to decode request body")
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		token := jwt.New()
		token.Set(jwt.IssuerKey, config.Get().String("JWT_ISSUER"))
		token.Set(jwt.JwtIDKey, uuid.New().String())
		token.Set(jwt.IssuedAtKey, time.Now().Unix())
		token.Set(jwt.ExpirationKey, time.Now().Add(time.Hour).Unix())
		token.Set(jwt.NotBeforeKey, time.Now().Add(-time.Minute).Unix())

		for k, v := range claims {
			if err := token.Set(k, v); err != nil {
				log.Error().Err(err).Msg("failed to set JWT claim")
				http.Error(w, "Failed to set JWT claim", http.StatusInternalServerError)
				return
			}
		}

		signedToken, err := jwt.Sign(token, jwt.WithKey(jwa.RS512, jwkPrivateKey))
		if err != nil {
			log.Error().Err(err).Msg("failed to sign JWT")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write(signedToken)
	})

	http.HandleFunc("/", web.GetHandleFunc())

	log.Info().Msg("starting server")
	portString := fmt.Sprintf(":%d", config.Get().Int("PORT"))
	http.ListenAndServe(portString, nil)
}
