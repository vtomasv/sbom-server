package server

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
)

const defaultMaxReportBytes = 64 << 20

// Config contains the settings required to start an HTTPS listener.
type Config struct {
	Listen         string            `json:"listen"`
	DataDir        string            `json:"data_dir"`
	TLSCert        string            `json:"tls_cert"`
	TLSKey         string            `json:"tls_key"`
	ClientCA       string            `json:"client_ca"`
	AdminToken     string            `json:"admin_token"`
	Clients        map[string]string `json:"clients"`
	MaxReportBytes int64             `json:"max_report_bytes"`
}

func LoadConfig(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer file.Close()

	config := Config{
		Listen:         ":8443",
		DataDir:        "/var/lib/sbom-server",
		MaxReportBytes: defaultMaxReportBytes,
	}
	if err := decodeJSON(io.LimitReader(file, (1<<20)+1), &config); err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	if config.Listen == "" || config.DataDir == "" || config.TLSCert == "" || config.TLSKey == "" {
		return Config{}, fmt.Errorf("listen, data_dir, tls_cert and tls_key are required")
	}
	return config, nil
}

func (config Config) TLSConfig() (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(config.TLSCert, config.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}
	settings := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
	}
	if config.ClientCA == "" {
		return settings, nil
	}
	pem, err := os.ReadFile(config.ClientCA)
	if err != nil {
		return nil, fmt.Errorf("read client CA: %w", err)
	}
	settings.ClientCAs = x509.NewCertPool()
	if !settings.ClientCAs.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("client_ca has no readable PEM certificate")
	}
	settings.ClientAuth = tls.RequireAndVerifyClientCert
	return settings, nil
}

type principal struct {
	client string
	admin  bool
}

func credentials(config Config) (map[[sha256.Size]byte]principal, error) {
	if !validToken(config.AdminToken) {
		return nil, fmt.Errorf("admin_token must contain 24 to 512 characters without whitespace or control characters")
	}
	if len(config.Clients) == 0 {
		return nil, fmt.Errorf("configure at least one client")
	}
	identities := map[[sha256.Size]byte]principal{
		sha256.Sum256([]byte(config.AdminToken)): {admin: true},
	}
	for client, token := range config.Clients {
		if !slugPattern.MatchString(client) || client == "admin" {
			return nil, fmt.Errorf("invalid or reserved client identifier %q", client)
		}
		if !validToken(token) {
			return nil, fmt.Errorf("invalid token for client %q", client)
		}
		digest := sha256.Sum256([]byte(token))
		if _, exists := identities[digest]; exists {
			return nil, fmt.Errorf("token for client %q is already in use", client)
		}
		identities[digest] = principal{client: client}
	}
	return identities, nil
}

func validToken(token string) bool {
	return len(token) >= 24 && len(token) <= 512 && strings.IndexFunc(token, unicode.IsSpace) == -1 &&
		strings.IndexFunc(token, unicode.IsControl) == -1
}
