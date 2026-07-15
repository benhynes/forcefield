package headersafety

import "testing"

func TestCredentialBearing(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		"Authorization", "Cookie", "X-Api-Key", "Api_Key", "X-Auth-Token",
		"X-Amz-Security-Token", "Ocp-Apim-Subscription-Key", "X-Hub-Signature-256",
		"X-Vault-Token", "X-Session-ID", "X-Client-Secret", "Private-Token",
	} {
		if !CredentialBearing(name) {
			t.Errorf("credential-bearing header was not classified: %q", name)
		}
	}
	for _, name := range []string{
		"Accept", "Content-Type", "User-Agent", "Idempotency-Key", "X-Idempotency-Key",
		"X-Request-ID", "OpenAI-Organization", "Anthropic-Version",
	} {
		if CredentialBearing(name) {
			t.Errorf("ordinary header was classified as a credential: %q", name)
		}
	}
}
