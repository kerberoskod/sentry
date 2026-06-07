package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSecretCheck_NoSecrets(t *testing.T) {
	dir := t.TempDir()
	filepath := filepath.Join(dir, "main.go")
	os.WriteFile(filepath, []byte(`package main\n\nfunc main() {}`), 0644)

	check := &SecretCheck{}
	findings, err := check.Run(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestSecretCheck_FindsAWSKey(t *testing.T) {
	dir := t.TempDir()
	filepath := filepath.Join(dir, "config.go")
	content := `const awsKey = "AKIAIOSFODNN7EXAMPLE"`
	os.WriteFile(filepath, []byte(content), 0644)

	check := &SecretCheck{}
	findings, err := check.Run(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Error("expected to find AWS key, got 0 findings")
	}
}

func TestSecretCheck_FindsPrivateKey(t *testing.T) {
	dir := t.TempDir()
	filepath := filepath.Join(dir, "key.pem")
	content := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0gLq
-----END RSA PRIVATE KEY-----`
	os.WriteFile(filepath, []byte(content), 0644)

	check := &SecretCheck{}
	findings, err := check.Run(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Error("expected to find private key, got 0 findings")
	}
}

func TestEnvCheck_MissingExample(t *testing.T) {
	dir := t.TempDir()

	check := &EnvCheck{}
	findings, err := check.Run(dir)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.Title == "Missing .env.example" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'Missing .env.example' finding")
	}
}

func TestDockerfileCheck_RootUser(t *testing.T) {
	dir := t.TempDir()
	dockerfile := filepath.Join(dir, "Dockerfile")
	content := `FROM alpine:3.19
USER root
COPY . /app`
	os.WriteFile(dockerfile, []byte(content), 0644)

	check := &DockerfileCheck{}
	findings, err := check.Run(dir)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.Title == "Container runs as root" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'Container runs as root' finding")
	}
}

func TestGitignoreCheck_MissingFile(t *testing.T) {
	dir := t.TempDir()

	check := &GitignoreCheck{}
	findings, err := check.Run(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Error("expected findings for missing .gitignore")
	}
}
