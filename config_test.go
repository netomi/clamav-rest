package main

import (
	"os"
	"testing"
	"time"
)

func TestGetEnvStr(t *testing.T) {
	tests := []struct {
		name         string
		key          string
		defaultValue string
		envValue     string
		setEnv       bool
		want         string
	}{
		{
			name:         "returns default when env not set",
			key:          "TEST_VAR_STR",
			defaultValue: "default",
			setEnv:       false,
			want:         "default",
		},
		{
			name:         "returns env value when set",
			key:          "TEST_VAR_STR",
			defaultValue: "default",
			envValue:     "custom",
			setEnv:       true,
			want:         "custom",
		},
		{
			name:         "returns default when env is empty",
			key:          "TEST_VAR_STR",
			defaultValue: "default",
			envValue:     "",
			setEnv:       true,
			want:         "default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Unsetenv(tt.key)
			if tt.setEnv {
				os.Setenv(tt.key, tt.envValue)
				defer os.Unsetenv(tt.key)
			}

			got := getEnvStr(tt.key, tt.defaultValue)
			if got != tt.want {
				t.Errorf("getEnvStr() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetEnvInt(t *testing.T) {
	tests := []struct {
		name         string
		key          string
		defaultValue int
		envValue     string
		setEnv       bool
		want         int
	}{
		{
			name:         "returns default when env not set",
			key:          "TEST_VAR_INT",
			defaultValue: 42,
			setEnv:       false,
			want:         42,
		},
		{
			name:         "returns parsed int when valid",
			key:          "TEST_VAR_INT",
			defaultValue: 42,
			envValue:     "100",
			setEnv:       true,
			want:         100,
		},
		{
			name:         "returns default when env is invalid",
			key:          "TEST_VAR_INT",
			defaultValue: 42,
			envValue:     "not-a-number",
			setEnv:       true,
			want:         42,
		},
		{
			name:         "returns default when env is empty",
			key:          "TEST_VAR_INT",
			defaultValue: 42,
			envValue:     "",
			setEnv:       true,
			want:         42,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Unsetenv(tt.key)
			if tt.setEnv {
				os.Setenv(tt.key, tt.envValue)
				defer os.Unsetenv(tt.key)
			}

			got := getEnvInt(tt.key, tt.defaultValue)
			if got != tt.want {
				t.Errorf("getEnvInt() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestLogConfig(t *testing.T) {
	cfg := &Config{
		Port:              "9000",
		DebugMode:         true,
		ReadTimeout:       30,
		WriteTimeout:      300,
		IdleTimeout:       60,
		MaxUploadSize:     512 << 20,
		MaxExtractedSize:  1024 << 20,
		MaxFileCount:      100000,
		MaxSingleFileSize: 256 << 20,
		ScanTimeout:       5,
	}

	// Just verify it doesn't panic
	cfg.LogConfig()
}

func TestLoadConfig(t *testing.T) {
	// Clear relevant env vars
	envVars := []string{
		EnvPort, EnvLogLevel, EnvReadTimeout, EnvWriteTimeout,
		EnvIdleTimeout, EnvMaxUploadSize, EnvMaxExtractedSize,
		EnvMaxFileCount, EnvMaxSingleFile, EnvScanTimeout,
	}
	for _, v := range envVars {
		os.Unsetenv(v)
	}

	t.Run("loads defaults", func(t *testing.T) {
		cfg := LoadConfig()

		if cfg.Port != DefaultPort {
			t.Errorf("Port = %s, want %s", cfg.Port, DefaultPort)
		}
		if cfg.DebugMode != false {
			t.Errorf("DebugMode = %v, want false", cfg.DebugMode)
		}
		if cfg.ReadTimeout != time.Duration(DefaultReadTimeoutSecs)*time.Second {
			t.Errorf("ReadTimeout = %v, want %v", cfg.ReadTimeout, time.Duration(DefaultReadTimeoutSecs)*time.Second)
		}
		if cfg.MaxFileCount != DefaultMaxFileCount {
			t.Errorf("MaxFileCount = %d, want %d", cfg.MaxFileCount, DefaultMaxFileCount)
		}
	})

	t.Run("loads custom values", func(t *testing.T) {
		os.Setenv(EnvPort, "8080")
		os.Setenv(EnvLogLevel, "debug")
		os.Setenv(EnvMaxFileCount, "500")
		defer func() {
			os.Unsetenv(EnvPort)
			os.Unsetenv(EnvLogLevel)
			os.Unsetenv(EnvMaxFileCount)
		}()

		cfg := LoadConfig()

		if cfg.Port != "8080" {
			t.Errorf("Port = %s, want 8080", cfg.Port)
		}
		if cfg.DebugMode != true {
			t.Errorf("DebugMode = %v, want true", cfg.DebugMode)
		}
		if cfg.MaxFileCount != 500 {
			t.Errorf("MaxFileCount = %d, want 500", cfg.MaxFileCount)
		}
	})
}
