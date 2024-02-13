package util

import "github.com/mxcd/go-config/config"

func InitConfig() error {
	err := config.LoadConfig([]config.Value{
		config.String("LOG_LEVEL").NotEmpty().Default("info"),
		config.Int("PORT").Default(8080),

		config.Bool("DEV").Default(false),

		config.String("JWT_ALGORITHM").NotEmpty(),
		config.String("JWT_PRIVATE_KEY").NotEmpty().Sensitive(),
		config.String("JWT_ISSUER").NotEmpty(),
	})
	return err
}
