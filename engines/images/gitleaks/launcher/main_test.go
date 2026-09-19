package main

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// These AWS documentation example values are ignored by upstream's own rule
// allowlist. A fixture built from them can only ever produce zero findings and
// cannot distinguish a working scanner from a broken one.
const (
	awsDocumentationExampleAccessKeyID     = "AKIAIOSFODNN7EXAMPLE"
	awsDocumentationExampleSecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)

func TestFixedArgumentsOwnEveryPolicyAndOutputChoice(t *testing.T) {
	want := []string{
		"dir",
		"--config", configPath,
		"--ignore-gitleaks-allow",
		"--no-source-ignore",
		"--exit-code", "0",
		"--redact=100",
		"--max-decode-depth", "5",
		"--max-archive-depth", "0",
		"--report-format", "json",
		"--report-path", reportPath,
		"--no-banner",
		"--no-color",
		workspaceMountPath,
	}
	if got := fixedArguments(); !reflect.DeepEqual(got, want) {
		t.Fatalf("fixed invocation changed:\n got %#v\nwant %#v", got, want)
	}
}

func TestRedactedEvidenceAcceptsOnlyRedactionSentinels(t *testing.T) {
	root := t.TempDir()
	valid := filepath.Join(root, "valid.json")
	if err := os.WriteFile(valid, []byte(`[{"RuleID":"generic-api-key","Secret":"REDACTED","Match":"api_key = REDACTED"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateRedactedEvidence(valid); err != nil {
		t.Fatalf("valid redacted evidence rejected: %v", err)
	}

	for name, payload := range map[string]string{
		"raw":      `[{"RuleID":"generic-api-key","Secret":"must-not-survive"}]`,
		"missing":  `[{"RuleID":"generic-api-key"}]`,
		"trailing": `[] {}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(root, name+".json")
			if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := validateRedactedEvidence(path); err == nil {
				t.Fatal("unsafe evidence was accepted")
			}
		})
	}
}

func TestArgumentParserRejectsTargetControlledOptions(t *testing.T) {
	err := run([]string{"--workspace", workspaceMountPath, "--output", outputMountPath, "--config", "/workspace/.gitleaks.toml"})
	if err == nil || !strings.Contains(err.Error(), "static launcher contract") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFixtureContainsDetectableSyntheticSecret(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate test source file")
	}
	path := filepath.Join(filepath.Dir(thisFile), "..", "testdata", "fixture.txt")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("fixture missing or unreadable at %s: %v", path, err)
	}
	content := string(body)

	for _, example := range []string{awsDocumentationExampleAccessKeyID, awsDocumentationExampleSecretAccessKey} {
		if strings.Contains(content, example) {
			t.Fatalf("fixture contains upstream documentation example %q, which the scanner is documented to ignore", example)
		}
	}

	hasLiveSecret := false
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.Contains(trimmed, "=") {
			continue
		}
		if strings.Contains(trimmed, "gitleaks:allow") {
			continue
		}
		hasLiveSecret = true
		break
	}
	if !hasLiveSecret {
		t.Fatal("fixture has no credential-bearing line without an inline gitleaks allow directive")
	}
}
