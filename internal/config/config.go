package config

import (
	"github.com/Brain-Wave-Ecosystem/go-common/pkg/config"
	"time"
)

type Config struct {
	config.DefaultServiceConfig
	JWT          JWTConfig    `envPrefix:"JWT_"`
	Redis        RedisConfig  `envPrefix:"REDIS_"`
	UsersService UsersService `envPrefix:"USERS_SERVICE_"`
	Rabbit       RabbitConfig `envPrefix:"REBBIT_"`
}

type JWTConfig struct {
	Secret                string        `env:"SECRET"`
	AccessExpirationTime  time.Duration `env:"ACCESS_EXPIRATION_TIME"`
	RefreshExpirationTime time.Duration `env:"REFRESH_EXPIRATION_TIME"`
}

type RedisConfig struct {
	URL string `env:"URL"`
}

type UsersService struct {
	Address string `env:"ADDRESS"`
}

type RabbitConfig struct {
	URL string `env:"URL"`
}
