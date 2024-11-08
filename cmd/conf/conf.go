package conf

import (
	"github.com/BurntSushi/toml"
)

type Config struct {
	App    AppConfig    `toml:"app"`
	Client ClientConfig `toml:"client"`
	Server ServerConfig `toml:"server"`
}

type AppConfig struct {
	SecretsDir string `toml:"secrets_dir"`
	PublicKey  string `toml:"public_key"`
	PrivateKey string `toml:"private_key"`
}

type ClientConfig struct {
	ID     string `toml:"id"`
	Secret string `toml:"secret"`
}

type ServerConfig struct {
	Host string `toml:"host"`
}

type AgentConfig struct {
	OnboardPath string `toml:"onboard_path"`
}

func NewConfig(path string) (*Config, error) {
	var conf Config

	_, err := toml.DecodeFile(path, &conf)

	if err != nil {
		return nil, err
	}

	return &conf, nil
}
