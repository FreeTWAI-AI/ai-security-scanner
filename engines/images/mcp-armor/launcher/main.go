// ai-security-scanner-mcp-armor-launcher is the non-shell capability boundary
// for one exact, immutable MCP configuration file. It never discovers files,
// starts an MCP server, enables a connector, or loads a model-backed check.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const (
	workspaceMountPath             = "/workspace"
	outputMountPath                = "/output"
	scopeDocumentPath              = "/run/ai-security-scanner/scope.json"
	reportPath                     = "/output/mcp-armor.json"
	engineID                       = "mcp-armor"
	selectionPathNamespace         = "ai-security-scanner:mcp-configuration-relative-path"
	selectionSHA256Namespace       = "ai-security-scanner:mcp-configuration-sha256"
	workspaceSHA256Namespace       = "ai-security-scanner:workspace-snapshot-sha256"
	maxScopeBytes            int64 = 1024 * 1024
	maxConfigBytes           int64 = 10 * 1024 * 1024
	maxEvidenceBytes         int64 = 32 * 1024 * 1024
	linuxStatfsReadOnly            = 1
)

type boundedWriter struct {
	buffer bytes.Buffer
	limit  int
}

func (writer *boundedWriter) Write(value []byte) (int, error) {
	original := len(value)
	remaining := writer.limit - writer.buffer.Len()
	if remaining > 0 {
		if len(value) > remaining {
			value = value[:remaining]
		}
		_, _ = writer.buffer.Write(value)
	}
	return original, nil
}

type scopeDocument struct {
	SchemaVersion string       `json:"schema_version"`
	EngineID      string       `json:"engine_id"`
	GeneratedAt   string       `json:"generated_at"`
	Assets        []scopeAsset `json:"assets"`
}

type scopeAsset struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Kind        string            `json:"kind"`
	Provider    *string           `json:"provider"`
	Region      *string           `json:"region"`
	Identifiers []scopeIdentifier `json:"identifiers"`
	Grants      []scopeGrant      `json:"grants"`
}

type scopeIdentifier struct {
	Namespace string `json:"namespace"`
	Value     string `json:"value"`
}

type scopeGrant struct {
	ID                     string          `json:"id"`
	Permission             string          `json:"permission"`
	ConfirmedBy            string          `json:"confirmed_by"`
	ConfirmedAt            string          `json:"confirmed_at"`
	ExpiresAt              *string         `json:"expires_at"`
	AuthorizationReference *string         `json:"authorization_reference"`
	ExternalScope          json.RawMessage `json:"external_scope"`
}

type selection struct {
	RelativePath string
	SHA256       string
}

type terminalEnvelope struct {
	SchemaVersion       string            `json:"schema_version"`
	ScannerVersion      string            `json:"scanner_version"`
	Mode                string            `json:"mode"`
	InputCount          int               `json:"input_count"`
	EvaluatedInputCount int               `json:"evaluated_input_count"`
	Complete            *bool             `json:"complete"`
	Warnings            []json.RawMessage `json:"warnings"`
	Checks              []json.RawMessage `json:"checks"`
	Findings            []json.RawMessage `json:"findings"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "managed MCP Armor launcher: %v\n", err)
		os.Exit(126)
	}
}

func run(arguments []string) error {
	flags := flag.NewFlagSet("ai-security-scanner-mcp-armor-launcher", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	requestedEngine := flags.String("engine", "", "fixed engine identity")
	workspace := flags.String("workspace", "", "read-only repository snapshot")
	output := flags.String("output", "", "runtime-owned evidence directory")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("arguments do not match the static launcher contract")
	}
	if *requestedEngine != engineID || *workspace != workspaceMountPath || *output != outputMountPath {
		return errors.New("engine, workspace, and output must use the runtime-owned contract")
	}
	if err := validateDirectory(*workspace, "workspace"); err != nil {
		return err
	}
	if err := requireReadOnlyWorkspace(*workspace); err != nil {
		return err
	}
	if err := validateDirectory(*output, "output"); err != nil {
		return err
	}
	selected, err := readSelection(scopeDocumentPath)
	if err != nil {
		return err
	}
	configPath, err := verifySelectedConfiguration(*workspace, selected)
	if err != nil {
		return err
	}
	if err := ensureAbsent(reportPath); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/local/bin/python3", fixedArguments(configPath)...)
	command.Dir = workspaceMountPath
	command.Env = []string{
		"HOME=/tmp/ai-security-scanner-home",
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
		"NO_COLOR=1",
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"PYTHONDONTWRITEBYTECODE=1",
		"PYTHONHASHSEED=0",
		"PYTHONNOUSERSITE=1",
		"PYTHONUNBUFFERED=1",
		"TMPDIR=/tmp",
		"XDG_CACHE_HOME=/tmp/ai-security-scanner-cache",
	}
	var diagnostic boundedWriter
	diagnostic.limit = 1024 * 1024
	command.Stdout = &diagnostic
	command.Stderr = &diagnostic
	if err := command.Run(); err != nil {
		_ = os.Remove(reportPath)
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return errors.New("MCP Armor exceeded its fixed ten-minute runtime limit")
		}
		return fmt.Errorf("MCP Armor configuration scan failed: %w", err)
	}
	if err := validateTerminalEvidence(reportPath); err != nil {
		_ = os.Remove(reportPath)
		return err
	}
	return os.Chmod(reportPath, 0o600)
}

func fixedArguments(configPath string) []string {
	return []string{
		"-m", "mcp_armor.cli",
		"scan",
		"--config-only",
		"--config", configPath,
		"--report-type", "json",
		"--output", reportPath,
	}
}

func readSelection(path string) (selection, error) {
	file, err := openBoundedRegularFile(path, maxScopeBytes, "scope document")
	if err != nil {
		return selection{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxScopeBytes+1))
	decoder.DisallowUnknownFields()
	var document scopeDocument
	if err := decoder.Decode(&document); err != nil {
		return selection{}, fmt.Errorf("parse scope document: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return selection{}, errors.New("scope document contains trailing JSON")
	}
	if document.SchemaVersion != "1" || document.EngineID != engineID || len(document.Assets) != 1 {
		return selection{}, errors.New("scope document does not name one MCP Armor repository asset")
	}
	asset := document.Assets[0]
	if asset.ID == "" || asset.Kind != "repository" || len(asset.Grants) != 1 || asset.Grants[0].Permission != "local_artifact_read" {
		return selection{}, errors.New("scope document lacks one exact local-artifact grant")
	}
	if asset.Grants[0].ID == "" || strings.TrimSpace(asset.Grants[0].ConfirmedBy) == "" || asset.Grants[0].ConfirmedAt == "" {
		return selection{}, errors.New("scope document local-artifact grant is incomplete")
	}
	values := make(map[string][]string)
	for _, identifier := range asset.Identifiers {
		values[identifier.Namespace] = append(values[identifier.Namespace], identifier.Value)
	}
	if len(values[workspaceSHA256Namespace]) != 1 || !validSHA256(values[workspaceSHA256Namespace][0]) {
		return selection{}, errors.New("scope document lacks one immutable workspace digest")
	}
	if len(values[selectionPathNamespace]) != 1 || len(values[selectionSHA256Namespace]) != 1 {
		return selection{}, errors.New("scope document lacks one exact MCP configuration selection")
	}
	selected := selection{RelativePath: values[selectionPathNamespace][0], SHA256: values[selectionSHA256Namespace][0]}
	if err := validateRelativeConfigurationPath(selected.RelativePath); err != nil {
		return selection{}, err
	}
	if !validSHA256(selected.SHA256) {
		return selection{}, errors.New("selected MCP configuration digest is invalid")
	}
	return selected, nil
}

func validateRelativeConfigurationPath(value string) error {
	if value == "" || len(value) > 4096 || strings.Contains(value, "\\") || strings.ContainsRune(value, '\x00') {
		return errors.New("selected MCP configuration path is not a bounded POSIX path")
	}
	if filepath.IsAbs(value) || filepath.Clean(value) != value || value == "." || strings.HasPrefix(value, "../") {
		return errors.New("selected MCP configuration path escapes the repository snapshot")
	}
	extension := strings.ToLower(filepath.Ext(value))
	if extension != ".json" && extension != ".yaml" && extension != ".yml" {
		return errors.New("selected MCP configuration path has an unsupported extension")
	}
	return nil
}

func verifySelectedConfiguration(workspace string, selected selection) (string, error) {
	path := filepath.Join(workspace, filepath.FromSlash(selected.RelativePath))
	root, err := filepath.Abs(workspace)
	if err != nil {
		return "", fmt.Errorf("resolve workspace path: %w", err)
	}
	candidate, err := filepath.Abs(path)
	if err != nil || candidate == root || !strings.HasPrefix(candidate, root+string(os.PathSeparator)) {
		return "", errors.New("selected MCP configuration path is outside the workspace")
	}
	relative, err := filepath.Rel(root, candidate)
	if err != nil {
		return "", fmt.Errorf("resolve selected MCP configuration path: %w", err)
	}
	cursor := root
	for _, component := range strings.Split(relative, string(os.PathSeparator)) {
		cursor = filepath.Join(cursor, component)
		info, err := os.Lstat(cursor)
		if err != nil {
			return "", fmt.Errorf("inspect selected MCP configuration path: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("selected MCP configuration path contains a symlink")
		}
	}
	if err := verifyFile(candidate, selected.SHA256, maxConfigBytes); err != nil {
		return "", err
	}
	return candidate, nil
}

func validateDirectory(path string, label string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect %s directory: %w", label, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%s path must be a real directory", label)
	}
	return nil
}

func requireReadOnlyWorkspace(path string) error {
	if runtime.GOOS == "linux" {
		var filesystem syscall.Statfs_t
		if err := syscall.Statfs(path, &filesystem); err != nil {
			return fmt.Errorf("inspect workspace mount flags: %w", err)
		}
		if filesystem.Flags&linuxStatfsReadOnly == 0 {
			return errors.New("workspace mount is writable; refusing to scan")
		}
		return nil
	}
	probe := filepath.Join(path, fmt.Sprintf(".ai-security-scanner-write-probe-%d", os.Getpid()))
	file, err := os.OpenFile(probe, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EROFS) {
			return nil
		}
		return fmt.Errorf("verify read-only workspace: %w", err)
	}
	_ = file.Close()
	_ = os.Remove(probe)
	return errors.New("workspace mount is writable; refusing to scan")
}

func ensureAbsent(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect evidence path: %w", err)
	}
	return fmt.Errorf("evidence path already exists (%s, mode %s)", path, info.Mode())
}

func openBoundedRegularFile(path string, maxBytes int64, label string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", label, err)
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxBytes {
		return nil, fmt.Errorf("%s is not a bounded regular file", label)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", label, err)
	}
	return file, nil
}

func verifyFile(path string, expected string, maxBytes int64) error {
	file, err := openBoundedRegularFile(path, maxBytes, "selected MCP configuration")
	if err != nil {
		return err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, io.LimitReader(file, maxBytes+1)); err != nil {
		return fmt.Errorf("hash selected MCP configuration: %w", err)
	}
	if hex.EncodeToString(digest.Sum(nil)) != expected {
		return errors.New("selected MCP configuration does not match its snapshot digest")
	}
	return nil
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}

func validateTerminalEvidence(path string) error {
	file, err := openBoundedRegularFile(path, maxEvidenceBytes, "MCP Armor evidence")
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxEvidenceBytes+1))
	var envelope terminalEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return fmt.Errorf("parse MCP Armor evidence: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("MCP Armor evidence contains trailing JSON")
	}
	if envelope.SchemaVersion != "1" || envelope.ScannerVersion != "1.0.2" || envelope.Mode != "configuration_only" {
		return errors.New("MCP Armor evidence identity does not match the pinned adapter contract")
	}
	if envelope.InputCount != 1 || envelope.EvaluatedInputCount != 1 || envelope.Complete == nil {
		return errors.New("MCP Armor evidence did not reconcile the one selected configuration")
	}
	if envelope.Warnings == nil || envelope.Checks == nil || envelope.Findings == nil {
		return errors.New("MCP Armor evidence omitted a terminal collection")
	}
	return nil
}
