package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseClamAVOutput(t *testing.T) {
	// Use OS-specific path separator for test paths
	sep := string(os.PathSeparator)
	baseDir := sep + "tmp" + sep + "scan"

	tests := []struct {
		name        string
		output      string
		baseDir     string
		wantCount   int
		wantThreats []Threat
	}{
		{
			name:      "empty output",
			output:    "",
			baseDir:   baseDir,
			wantCount: 0,
		},
		{
			name:      "clean scan (no output with --infected)",
			output:    "\n\n",
			baseDir:   baseDir,
			wantCount: 0,
		},
		{
			name:      "single threat",
			output:    baseDir + sep + "malware.exe: Win.Trojan.Test FOUND\n",
			baseDir:   baseDir,
			wantCount: 1,
			wantThreats: []Threat{
				{Name: "Win.Trojan.Test", File: "malware.exe", Severity: "critical"},
			},
		},
		{
			name:      "multiple threats",
			output:    baseDir + sep + "file1.exe: Virus.A FOUND\n" + baseDir + sep + "subdir" + sep + "file2.dll: Virus.B FOUND\n",
			baseDir:   baseDir,
			wantCount: 2,
			wantThreats: []Threat{
				{Name: "Virus.A", File: "file1.exe", Severity: "critical"},
				{Name: "Virus.B", File: "subdir" + sep + "file2.dll", Severity: "critical"},
			},
		},
		{
			name:      "EICAR test signature",
			output:    baseDir + sep + "eicar.txt: Win.Test.EICAR_HDB-1 FOUND\n",
			baseDir:   baseDir,
			wantCount: 1,
			wantThreats: []Threat{
				{Name: "Win.Test.EICAR_HDB-1", File: "eicar.txt", Severity: "critical"},
			},
		},
		{
			name:      "skips summary lines",
			output:    "----------- SCAN SUMMARY -----------\nKnown viruses: 123456\nEngine version: 1.0.0\nScanned files: 10\n" + baseDir + sep + "bad.exe: Malware FOUND\n",
			baseDir:   baseDir,
			wantCount: 1,
			wantThreats: []Threat{
				{Name: "Malware", File: "bad.exe", Severity: "critical"},
			},
		},
		{
			name:      "handles trailing separator in baseDir",
			output:    baseDir + sep + "file.exe: Virus FOUND\n",
			baseDir:   baseDir + sep,
			wantCount: 1,
			wantThreats: []Threat{
				{Name: "Virus", File: "file.exe", Severity: "critical"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			threats := parseClamAVOutput(tt.output, tt.baseDir)

			if len(threats) != tt.wantCount {
				t.Errorf("got %d threats, want %d", len(threats), tt.wantCount)
			}

			for i, want := range tt.wantThreats {
				if i >= len(threats) {
					break
				}
				got := threats[i]
				if got.Name != want.Name {
					t.Errorf("threat[%d].Name = %q, want %q", i, got.Name, want.Name)
				}
				if got.File != want.File {
					t.Errorf("threat[%d].File = %q, want %q", i, got.File, want.File)
				}
				if got.Severity != want.Severity {
					t.Errorf("threat[%d].Severity = %q, want %q", i, got.Severity, want.Severity)
				}
			}
		})
	}
}

func TestComputeFileHash(t *testing.T) {
	// Create temp file with known content
	tmpFile, err := os.CreateTemp("", "hash-test-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	content := []byte("test content for hashing")
	if _, err := tmpFile.Write(content); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	tmpFile.Close()

	hash, err := computeFileHash(tmpFile.Name())
	if err != nil {
		t.Fatalf("computeFileHash() error: %v", err)
	}

	if len(hash) != 64 {
		t.Errorf("hash length = %d, want 64", len(hash))
	}

	// Verify it's a valid hex string
	for _, c := range hash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("hash contains invalid character: %c", c)
		}
	}
}

func TestComputeFileHashNotFound(t *testing.T) {
	_, err := computeFileHash("/nonexistent/file/path")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestExtractZipSafe(t *testing.T) {
	cfg := &Config{
		MaxExtractedSize:  10 << 20, // 10MB
		MaxFileCount:      100,
		MaxSingleFileSize: 5 << 20, // 5MB
	}
	s := NewScanner(cfg)

	t.Run("extracts valid zip", func(t *testing.T) {
		zipPath := createTestZip(t, map[string]string{
			"file1.txt": "content1",
			"file2.txt": "content2",
		})
		defer os.Remove(zipPath)

		targetDir, err := os.MkdirTemp("", "extract-test-*")
		if err != nil {
			t.Fatalf("failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(targetDir)

		count, err := s.extractZipSafe(zipPath, targetDir)
		if err != nil {
			t.Fatalf("extractZipSafe() error: %v", err)
		}
		if count != 2 {
			t.Errorf("file count = %d, want 2", count)
		}

		if _, err := os.Stat(filepath.Join(targetDir, "file1.txt")); os.IsNotExist(err) {
			t.Error("file1.txt not extracted")
		}
		if _, err := os.Stat(filepath.Join(targetDir, "file2.txt")); os.IsNotExist(err) {
			t.Error("file2.txt not extracted")
		}
	})

	t.Run("extracts zip with directories", func(t *testing.T) {
		zipPath := createTestZipWithDirs(t, map[string]string{
			"subdir/file1.txt": "content1",
			"subdir/file2.txt": "content2",
		})
		defer os.Remove(zipPath)

		targetDir, _ := os.MkdirTemp("", "extract-test-*")
		defer os.RemoveAll(targetDir)

		count, err := s.extractZipSafe(zipPath, targetDir)
		if err != nil {
			t.Fatalf("extractZipSafe() error: %v", err)
		}
		// Count includes directory entry + 2 files = 3
		if count != 3 {
			t.Errorf("file count = %d, want 3", count)
		}
	})

	t.Run("rejects too many files", func(t *testing.T) {
		cfg := &Config{
			MaxExtractedSize:  10 << 20,
			MaxFileCount:      2,
			MaxSingleFileSize: 5 << 20,
		}
		s := NewScanner(cfg)

		zipPath := createTestZip(t, map[string]string{
			"file1.txt": "a",
			"file2.txt": "b",
			"file3.txt": "c",
		})
		defer os.Remove(zipPath)

		targetDir, _ := os.MkdirTemp("", "extract-test-*")
		defer os.RemoveAll(targetDir)

		_, err := s.extractZipSafe(zipPath, targetDir)
		if err == nil {
			t.Error("expected error for too many files")
		}
	})

	t.Run("rejects file exceeding size limit", func(t *testing.T) {
		cfg := &Config{
			MaxExtractedSize:  10 << 20,
			MaxFileCount:      100,
			MaxSingleFileSize: 10, // 10 bytes limit
		}
		s := NewScanner(cfg)

		zipPath := createTestZip(t, map[string]string{
			"big.txt": "this content is longer than 10 bytes",
		})
		defer os.Remove(zipPath)

		targetDir, _ := os.MkdirTemp("", "extract-test-*")
		defer os.RemoveAll(targetDir)

		_, err := s.extractZipSafe(zipPath, targetDir)
		if err == nil {
			t.Error("expected error for file exceeding size limit")
		}
	})

	t.Run("rejects archive exceeding total size limit", func(t *testing.T) {
		cfg := &Config{
			MaxExtractedSize:  20, // 20 bytes total
			MaxFileCount:      100,
			MaxSingleFileSize: 50,
		}
		s := NewScanner(cfg)

		zipPath := createTestZip(t, map[string]string{
			"file1.txt": "content1content1",
			"file2.txt": "content2content2",
		})
		defer os.Remove(zipPath)

		targetDir, _ := os.MkdirTemp("", "extract-test-*")
		defer os.RemoveAll(targetDir)

		_, err := s.extractZipSafe(zipPath, targetDir)
		if err == nil {
			t.Error("expected error for archive exceeding total size limit")
		}
	})

	t.Run("returns error for non-zip file", func(t *testing.T) {
		tmpFile, _ := os.CreateTemp("", "not-a-zip-*")
		tmpFile.WriteString("this is not a zip file")
		tmpFile.Close()
		defer os.Remove(tmpFile.Name())

		targetDir, _ := os.MkdirTemp("", "extract-test-*")
		defer os.RemoveAll(targetDir)

		_, err := s.extractZipSafe(tmpFile.Name(), targetDir)
		if err == nil {
			t.Error("expected error for non-zip file")
		}
	})
}

func TestCopySingleFile(t *testing.T) {
	cfg := &Config{
		MaxSingleFileSize: 1024, // 1KB limit
	}
	s := NewScanner(cfg)

	t.Run("copies file within limit", func(t *testing.T) {
		srcFile, _ := os.CreateTemp("", "src-*")
		srcFile.WriteString("small content")
		srcFile.Close()
		defer os.Remove(srcFile.Name())

		targetDir, _ := os.MkdirTemp("", "target-*")
		defer os.RemoveAll(targetDir)

		count, err := s.copySingleFile(srcFile.Name(), targetDir)
		if err != nil {
			t.Fatalf("copySingleFile() error: %v", err)
		}
		if count != 1 {
			t.Errorf("count = %d, want 1", count)
		}

		// Verify file exists
		if _, err := os.Stat(filepath.Join(targetDir, "file")); os.IsNotExist(err) {
			t.Error("file not copied")
		}
	})

	t.Run("rejects file exceeding limit", func(t *testing.T) {
		srcFile, _ := os.CreateTemp("", "src-*")
		// Write more than 1KB
		for i := 0; i < 200; i++ {
			srcFile.WriteString("0123456789")
		}
		srcFile.Close()
		defer os.Remove(srcFile.Name())

		targetDir, _ := os.MkdirTemp("", "target-*")
		defer os.RemoveAll(targetDir)

		_, err := s.copySingleFile(srcFile.Name(), targetDir)
		if err == nil {
			t.Error("expected error for file exceeding limit")
		}
	})

	t.Run("returns error for nonexistent file", func(t *testing.T) {
		targetDir, _ := os.MkdirTemp("", "target-*")
		defer os.RemoveAll(targetDir)

		_, err := s.copySingleFile("/nonexistent/file", targetDir)
		if err == nil {
			t.Error("expected error for nonexistent file")
		}
	})
}

func TestNewScanner(t *testing.T) {
	cfg := &Config{
		Port:        "9000",
		ScanTimeout: 5 * time.Minute,
	}

	s := NewScanner(cfg)

	if s == nil {
		t.Fatal("NewScanner() returned nil")
	}
	if s.config != cfg {
		t.Error("scanner config not set correctly")
	}
}

// Helper function to create a test zip file
func createTestZip(t *testing.T, files map[string]string) string {
	t.Helper()

	tmpFile, err := os.CreateTemp("", "test-*.zip")
	if err != nil {
		t.Fatalf("failed to create temp zip: %v", err)
	}

	w := zip.NewWriter(tmpFile)
	for name, content := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatalf("failed to create file in zip: %v", err)
		}
		f.Write([]byte(content))
	}
	w.Close()
	tmpFile.Close()

	return tmpFile.Name()
}

// Helper function to create a test zip file with directory structure
func createTestZipWithDirs(t *testing.T, files map[string]string) string {
	t.Helper()

	tmpFile, err := os.CreateTemp("", "test-*.zip")
	if err != nil {
		t.Fatalf("failed to create temp zip: %v", err)
	}

	w := zip.NewWriter(tmpFile)

	// Create directories first
	dirs := make(map[string]bool)
	for name := range files {
		dir := filepath.Dir(name)
		if dir != "." && !dirs[dir] {
			_, err := w.Create(dir + "/")
			if err != nil {
				t.Fatalf("failed to create dir in zip: %v", err)
			}
			dirs[dir] = true
		}
	}

	// Create files
	for name, content := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatalf("failed to create file in zip: %v", err)
		}
		f.Write([]byte(content))
	}
	w.Close()
	tmpFile.Close()

	return tmpFile.Name()
}

func TestExtractFileSafe(t *testing.T) {
	cfg := &Config{
		MaxSingleFileSize: 100,
	}
	s := NewScanner(cfg)

	t.Run("extracts file within limit", func(t *testing.T) {
		zipPath := createTestZip(t, map[string]string{
			"test.txt": "small content",
		})
		defer os.Remove(zipPath)

		reader, _ := zip.OpenReader(zipPath)
		defer reader.Close()

		targetDir, _ := os.MkdirTemp("", "extract-test-*")
		defer os.RemoveAll(targetDir)

		targetPath := filepath.Join(targetDir, "test.txt")
		err := s.extractFileSafe(reader.File[0], targetPath)
		if err != nil {
			t.Errorf("extractFileSafe() error: %v", err)
		}

		// Verify content
		content, _ := os.ReadFile(targetPath)
		if string(content) != "small content" {
			t.Errorf("content = %q, want 'small content'", string(content))
		}
	})
}
