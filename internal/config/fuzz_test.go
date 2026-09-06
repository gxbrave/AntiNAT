package config

import "testing"

// FuzzParseConfigs drives both config parsers with arbitrary bytes; parsing
// must never panic on malformed input.
func FuzzParseConfigs(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"enrollment_token_file":"/t"}`))
	f.Add([]byte(`{"controller_endpoint":"https://x:3111"}`))
	f.Add([]byte(`{"controller_endpoint":"https://x:3111","public_enrollment":true}`))
	f.Add([]byte(`{"enrollment_token_file":"/t","enrollment_token_file":"/x"}`))
	f.Add([]byte(`not json`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseControllerConfig(data)
		_, _ = ParseAgentConfig(data)
	})
}
