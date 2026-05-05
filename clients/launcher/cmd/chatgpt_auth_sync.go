package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/PurpleAILAB/Decepticon/clients/launcher/internal/config"
)

type codexAuthFile struct {
	Tokens codexAuthTokens `json:"tokens"`
}

type codexAuthTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	AccountID    string `json:"account_id"`
}

type liteLLMChatGPTAuthFile struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	AccountID    string `json:"account_id,omitempty"`
}

func syncCodexChatGPTAuth(env map[string]string) (bool, string, error) {
	codexPath, err := codexAuthPath(env)
	if err != nil {
		return false, "", err
	}
	raw, err := os.ReadFile(codexPath)
	if os.IsNotExist(err) {
		return false, "", nil
	}
	if err != nil {
		return false, "", fmt.Errorf("read Codex ChatGPT auth %s: %w", codexPath, err)
	}

	litellmAuth, err := codexAuthToLiteLLM(raw, codexPath)
	if err != nil {
		return false, "", err
	}

	tokenDir, err := chatGPTTokenDir(env)
	if err != nil {
		return false, "", err
	}
	if err := os.MkdirAll(tokenDir, 0o700); err != nil {
		return false, "", fmt.Errorf("create ChatGPT token dir %s: %w", tokenDir, err)
	}

	target := filepath.Join(tokenDir, "auth.json")
	body, err := json.MarshalIndent(litellmAuth, "", "  ")
	if err != nil {
		return false, "", fmt.Errorf("encode LiteLLM ChatGPT auth: %w", err)
	}
	body = append(body, '\n')
	if err := os.WriteFile(target, body, 0o600); err != nil {
		return false, "", fmt.Errorf("write LiteLLM ChatGPT auth %s: %w", target, err)
	}
	return true, target, nil
}

func codexAuthPath(env map[string]string) (string, error) {
	codexHome := strings.TrimSpace(config.Get(env, "CODEX_HOME", ""))
	if codexHome == "" {
		codexHome = strings.TrimSpace(os.Getenv("CODEX_HOME"))
	}
	if codexHome != "" {
		return filepath.Join(codexHome, "auth.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory for Codex auth: %w", err)
	}
	return filepath.Join(home, ".codex", "auth.json"), nil
}

func codexAuthToLiteLLM(raw []byte, source string) (liteLLMChatGPTAuthFile, error) {
	var auth codexAuthFile
	if err := json.Unmarshal(raw, &auth); err != nil {
		return liteLLMChatGPTAuthFile{}, fmt.Errorf("parse Codex ChatGPT auth %s: %w", source, err)
	}
	if strings.TrimSpace(auth.Tokens.AccessToken) == "" ||
		strings.TrimSpace(auth.Tokens.RefreshToken) == "" ||
		strings.TrimSpace(auth.Tokens.IDToken) == "" {
		return liteLLMChatGPTAuthFile{}, fmt.Errorf(
			"Codex ChatGPT auth %s is missing tokens.access_token, tokens.refresh_token, or tokens.id_token",
			source,
		)
	}
	return liteLLMChatGPTAuthFile{
		AccessToken:  auth.Tokens.AccessToken,
		RefreshToken: auth.Tokens.RefreshToken,
		IDToken:      auth.Tokens.IDToken,
		AccountID:    auth.Tokens.AccountID,
	}, nil
}
