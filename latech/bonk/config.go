package main

import (
	"encoding/json"
	"io/ioutil"
	"strings"
)

type Config struct {
	BadIPs   []string `json:"banned-ips"`
	GoodIPs  []string `json:"allowed-ips"`
	Users    []string `json:"allowed-user"`
	Rules    []string `json:"rules"`
	Bonkable []string `json:"bonkable"`
}

func (config *Config) Load(path string) error {
	file, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	err = json.Unmarshal([]byte(file), &config)
	if err != nil {
		return err
	}
	return nil
}

func (config Config) BannedIP(allowMe string) bool {

	for _, ip := range config.BadIPs {
		if strings.Contains(allowMe, ip) {
			return true
		}
	}

	return false

}

func (config Config) AllowedIP(allowMe string) bool {
	for _, ip := range config.GoodIPs {
		if strings.Contains(allowMe, ip) {
			return true
		}
	}

	return allowMe == ""

}

func (config Config) AllowedUser(allowMe string) bool {

	for _, user := range config.Users {
		if strings.Contains(allowMe, user) {
			return true
		}
	}

	return allowMe == ""

}

func (config Config) IsBonkable(allowMe string) bool {
	for _, key := range config.Bonkable {
		if allowMe == key {
			return true
		}
	}
	return false
}
