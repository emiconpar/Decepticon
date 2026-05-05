package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCodexAuthToLiteLLM(t *testing.T) {
	raw := []byte(`{
		"auth_mode": "chatgpt",
		"tokens": {
			"access_token": "access",
			"refresh_token": "refresh",
			"id_token": "id",
			"account_id": "account"
		}
	}`)

	got, err := codexAuthToLiteLLM(raw, "auth.json")
	if err != nil {
		t.Fatalf("codexAuthToLiteLLM() error = %v", err)
	}
	if got.AccessToken != "access" || got.RefreshToken != "refresh" ||
		got.IDToken != "id" || got.AccountID != "account" {
		t.Fatalf("unexpected LiteLLM auth: %#v", got)
	}
}

func TestSyncCodexChatGPTAuth(t *testing.T) {
	codexHome := t.TempDir()
	litellmDir := t.TempDir()
	codexAuth := filepath.Join(codexHome, "auth.json")
	if err := os.WriteFile(codexAuth, []byte(`{
		"tokens": {
			"access_token": "access",
			"refresh_token": "refresh",
			"id_token": "id",
			"account_id": "account"
		}
	}`), 0o600); err != nil {
		t.Fatalf("write Codex auth: %v", err)
	}

	synced, target, err := syncCodexChatGPTAuth(map[string]string{
		"CODEX_HOME":                codexHome,
		"LITELLM_CHATGPT_TOKEN_DIR": litellmDir,
	})
	if err != nil {
		t.Fatalf("syncCodexChatGPTAuth() error = %v", err)
	}
	if !synced {
		t.Fatalf("syncCodexChatGPTAuth() synced = false")
	}
	wantTarget := filepath.Join(litellmDir, "auth.json")
	if target != wantTarget {
		t.Fatalf("target = %q, want %q", target, wantTarget)
	}

	raw, err := os.ReadFile(wantTarget)
	if err != nil {
		t.Fatalf("read LiteLLM auth: %v", err)
	}
	var out map[string]string
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("parse LiteLLM auth: %v", err)
	}
	if out["access_token"] != "access" || out["refresh_token"] != "refresh" ||
		out["id_token"] != "id" || out["account_id"] != "account" {
		t.Fatalf("unexpected synced auth: %#v", out)
	}
}

func TestSyncCodexChatGPTAuthMissingCodexFileIsNoop(t *testing.T) {
	synced, target, err := syncCodexChatGPTAuth(map[string]string{
		"CODEX_HOME":                t.TempDir(),
		"LITELLM_CHATGPT_TOKEN_DIR": t.TempDir(),
	})
	if err != nil {
		t.Fatalf("syncCodexChatGPTAuth() error = %v", err)
	}
	if synced {
		t.Fatalf("syncCodexChatGPTAuth() synced = true, want false")
	}
	if target != "" {
		t.Fatalf("target = %q, want empty", target)
	}
}
