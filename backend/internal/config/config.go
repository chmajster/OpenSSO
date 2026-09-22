package config

import (
	"encoding/base64"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddr        string
	PublicURL         string
	DatabaseURL       string
	RedisURL          string
	CookieSecure      bool
	TrustProxyHeaders bool
	SessionTTL        time.Duration
	BootstrapToken    string
	MasterKey         []byte
}

func Load() (Config, error) {
	cfg := Config{
		ListenAddr:        env("OPENSSO_LISTEN_ADDR", ":8080"),
		PublicURL:         strings.TrimRight(env("OPENSSO_PUBLIC_URL", "http://localhost:8080"), "/"),
		DatabaseURL:       os.Getenv("OPENSSO_DATABASE_URL"),
		RedisURL:          env("OPENSSO_REDIS_URL", "redis://redis:6379/0"),
		CookieSecure:      envBool("OPENSSO_COOKIE_SECURE", false),
		TrustProxyHeaders: envBool("OPENSSO_TRUST_PROXY_HEADERS", false),
		SessionTTL:        envDuration("OPENSSO_SESSION_TTL", 12*time.Hour),
		BootstrapToken:    os.Getenv("OPENSSO_BOOTSTRAP_TOKEN"),
	}
	if cfg.DatabaseURL == "" {
		return Config{}, errors.New("OPENSSO_DATABASE_URL is required")
	}
	if cfg.BootstrapToken != "" && len(cfg.BootstrapToken) < 24 {
		return Config{}, errors.New("OPENSSO_BOOTSTRAP_TOKEN must contain at least 24 characters")
	}
	rawMaster := os.Getenv("OPENSSO_MASTER_KEY")
	if rawMaster == "" {
		return Config{}, errors.New("OPENSSO_MASTER_KEY is required")
	}
	master, err := base64.StdEncoding.DecodeString(rawMaster)
	if err != nil || len(master) != 32 {
		return Config{}, errors.New("OPENSSO_MASTER_KEY must be base64-encoded 32-byte key")
	}
	cfg.MasterKey = master
	return cfg, nil
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func envBool(k string, d bool) bool {
	v := os.Getenv(k)
	if v == "" {
		return d
	}
	b, e := strconv.ParseBool(v)
	if e != nil {
		return d
	}
	return b
}

func envDuration(k string, d time.Duration) time.Duration {
	v := os.Getenv(k)
	if v == "" {
		return d
	}
	x, e := time.ParseDuration(v)
	if e != nil {
		return d
	}
	return x
}
