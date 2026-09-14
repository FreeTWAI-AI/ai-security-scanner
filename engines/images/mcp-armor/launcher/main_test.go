package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestFixedArgumentsOwnTheConfigurationOnlyMode(t *testing.T) {
	config := "/workspace/.cursor/mcp.json"
	want := []string{
		"-m", "mcp_armor.cli",
		"scan",
		"--config-only",
		"--config", config,
		"--report-type", "json",
		"--output", reportPath,
	}
	if got := fixedArguments(config); !reflect.DeepEqual(got, want) {
		t.Fatalf("fixed invocation changed:\n got %#v\nwant %#v", got, want)
	}
}

func TestArgumentParserRejectsCallerOptions(t *testing.T) {
	err := run([]string{
		"--engine", engineID,
		"--workspace", workspaceMountPath,
		"--output", outputMountPath,
		"--config", "/workspace/other.json",
	})
	if err == nil || !strings.Contains(err.Error(), "static launcher contract") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestScopeBindsOneExactConfiguration(t *testing.T) {
	root := t.TempDir()
	scope := filepath.Join(root, "scope.json")
	payload := `{
  "schema_version":"1",
  "engine_id":"mcp-armor",
  "generated_at":"2026-09-14T00:00:00Z",
  "assets":[{
    "id":"asset-1","name":"fixture","kind":"repository","provider":null,"region":null,
    "identifiers":[
      {"namespace":"ai-security-scanner:workspace-snapshot-sha256","value":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
      {"namespace":"ai-security-scanner:mcp-configuration-relative-path","value":".cursor/mcp.json"},
      {"namespace":"ai-security-scanner:mcp-configuration-sha256","value":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
    ],
    "grants":[{"id":"grant-1","permission":"local_artifact_read","confirmed_by":"owner","confirmed_at":"2026-09-14T00:00:00Z","expires_at":null,"authorization_reference":null,"external_scope":null}]
  }]
}`
	if err := os.WriteFile(scope, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	selected, err := readSelection(scope)
	if err != nil {
		t.Fatal(err)
	}
	if selected.RelativePath != ".cursor/mcp.json" || selected.SHA256 != strings.Repeat("b", 64) {
		t.Fatalf("unexpected selection: %#v", selected)
	}

	for name, replacement := range map[string]string{
		"wrong-engine": `"engine_id":"garak"`,
		"wrong-grant":  `"permission":"active_external_testing"`,
		"traversal":    `"value":"../mcp.json"`,
		"bad-digest":   `"value":"short"`,
	} {
		t.Run(name, func(t *testing.T) {
			mutated := payload
			switch name {
			case "wrong-engine":
				mutated = strings.Replace(mutated, `"engine_id":"mcp-armor"`, replacement, 1)
			case "wrong-grant":
				mutated = strings.Replace(mutated, `"permission":"local_artifact_read"`, replacement, 1)
			case "traversal":
				mutated = strings.Replace(mutated, `"value":".cursor/mcp.json"`, replacement, 1)
			case "bad-digest":
				mutated = strings.Replace(mutated, `"value":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"`, replacement, 1)
			}
			path := filepath.Join(root, name+".json")
			if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := readSelection(path); err == nil {
				t.Fatal("invalid scope selection was accepted")
			}
		})
	}
}

func TestSelectedConfigurationMustMatchDigestAndContainNoSymlink(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".cursor"), 0o700); err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"mcpServers":{}}`)
	path := filepath.Join(root, ".cursor", "mcp.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	selected := selection{RelativePath: ".cursor/mcp.json", SHA256: hex.EncodeToString(digest[:])}
	if got, err := verifySelectedConfiguration(root, selected); err != nil || got != path {
		t.Fatalf("valid selection rejected: path=%q error=%v", got, err)
	}
	selected.SHA256 = strings.Repeat("0", 64)
	if _, err := verifySelectedConfiguration(root, selected); err == nil {
		t.Fatal("digest mismatch was accepted")
	}

	target := filepath.Join(root, "target.json")
	if err := os.WriteFile(target, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "mcp.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	selected = selection{RelativePath: "mcp.json", SHA256: hex.EncodeToString(digest[:])}
	if _, err := verifySelectedConfiguration(root, selected); err == nil {
		t.Fatal("symlinked selection was accepted")
	}
}

func TestTerminalEvidenceReconcilesOneInput(t *testing.T) {
	root := t.TempDir()
	valid := filepath.Join(root, "valid.json")
	if err := os.WriteFile(valid, []byte(`{"schema_version":"1","scanner_version":"1.0.2","mode":"configuration_only","input_count":1,"evaluated_input_count":1,"complete":false,"warnings":[],"checks":[],"findings":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateTerminalEvidence(valid); err != nil {
		t.Fatalf("valid partial terminal evidence rejected: %v", err)
	}
	invalid := filepath.Join(root, "invalid.json")
	if err := os.WriteFile(invalid, []byte(`{"schema_version":"1","scanner_version":"1.0.2","mode":"configuration_only","input_count":2,"evaluated_input_count":1,"complete":true,"warnings":[],"checks":[],"findings":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateTerminalEvidence(invalid); err == nil {
		t.Fatal("mismatched input count was accepted")
	}
}
