// Package webhook sends scan alerts to Discord, Slack, or generic HTTP endpoints.
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jojin1709/idoraider/internal/engine"
)

// Send sends a scan summary notification to a Discord, Slack, or generic webhook.
func Send(ctx context.Context, webhookURL string, sum engine.Summary) error {
	if webhookURL == "" {
		return nil
	}

	client := &http.Client{Timeout: 10 * time.Second}

	var payload []byte
	var err error

	lower := strings.ToLower(webhookURL)
	if strings.Contains(lower, "discord.com/api/webhooks") {
		payload, err = buildDiscordPayload(sum)
	} else if strings.Contains(lower, "hooks.slack.com") {
		payload, err = buildSlackPayload(sum)
	} else {
		// Generic JSON webhook
		payload, err = json.Marshal(sum)
	}
	if err != nil {
		return fmt.Errorf("building webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("creating webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "IDORaider-Webhook/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("delivering webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook responded with HTTP %d", resp.StatusCode)
	}
	return nil
}

func buildDiscordPayload(sum engine.Summary) ([]byte, error) {
	statusText := "✅ Scan Completed — No Vulnerabilities"
	color := 3066993 // Green
	if sum.Vulnerable > 0 {
		statusText = fmt.Sprintf("🚨 BOLA / IDOR Detected (%d findings)", sum.Vulnerable)
		color = 15158332 // Red
	}

	var findingsList strings.Builder
	count := 0
	for _, r := range sum.Results {
		if r.Status == engine.StatusVulnerable {
			count++
			if count <= 5 {
				findingsList.WriteString(fmt.Sprintf("• **[%s]** `%s` (%s)\n", r.Severity, r.Endpoint, r.Detail))
			}
		}
	}
	if count > 5 {
		findingsList.WriteString(fmt.Sprintf("...and %d more findings in report.\n", count-5))
	}

	desc := fmt.Sprintf("**Target:** %s\n**Tested:** %d endpoints\n**Duration:** %s\n\n%s",
		sum.Target, sum.TotalTested, sum.Duration.Round(time.Millisecond), findingsList.String())

	payload := map[string]interface{}{
		"username": "IDORaider",
		"embeds": []map[string]interface{}{
			{
				"title":       statusText,
				"description": desc,
				"color":       color,
				"footer": map[string]string{
					"text": "IDORaider by JOJIN JOHN (@jojin1709)",
				},
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			},
		},
	}
	return json.Marshal(payload)
}

func buildSlackPayload(sum engine.Summary) ([]byte, error) {
	statusText := "✅ *IDORaider:* Scan completed — clean."
	if sum.Vulnerable > 0 {
		statusText = fmt.Sprintf("🚨 *IDORaider Alert:* Found %d BOLA / IDOR vulnerabilities on <%s>", sum.Vulnerable, sum.Target)
	}

	text := fmt.Sprintf("%s\n• Tested: %d endpoints\n• Critical: %d, High: %d, Medium: %d\n• Duration: %s",
		statusText, sum.TotalTested, sum.Critical, sum.High, sum.Medium, sum.Duration.Round(time.Millisecond))

	payload := map[string]string{
		"text": text,
	}
	return json.Marshal(payload)
}
