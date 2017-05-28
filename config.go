package pkiadm

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

var configLookupPath = []string{
	"config.json",
	"pkiadm.json",
	"/etc/pkiadm.json",
}

type (
	Config struct {
		Path    string // path to the unix socket
		Storage string // path to the storage location
	}
)

func LoadConfig() (*Config, error) {
	for _, path := range configLookupPath {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}
		return tryToLoadConfig(path)
	}
	return nil, fmt.Errorf("no config file found")
}

// tryToLoadConfig loads the config and tries to parse the file. When this
// doesn't work out, the error is returned.
func tryToLoadConfig(path string) (*Config, error) {
	var cfg *Config
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
