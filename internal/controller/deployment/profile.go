package deployment

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// DecodeProfileJSON parses the persisted profile representation with a strict
// object shape. It rejects duplicate keys, unknown fields, trailing JSON and
// semantically invalid values before a profile can be written back.
func DecodeProfileJSON(raw []byte) (Profile, error) {
	if len(raw) > 64*1024 {
		return Profile{}, fmt.Errorf("deployment: profile exceeds 64 KiB")
	}
	if err := rejectDuplicateKeys(raw); err != nil {
		return Profile{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var profile Profile
	if err := dec.Decode(&profile); err != nil {
		return Profile{}, fmt.Errorf("deployment: invalid profile JSON: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return Profile{}, fmt.Errorf("deployment: trailing JSON is not allowed")
		}
		return Profile{}, fmt.Errorf("deployment: trailing JSON is not allowed: %w", err)
	}
	if err := profile.ValidateComplete(); err != nil {
		return Profile{}, err
	}
	profile.ControllerEndpoint, _ = NormalizeOptionalServiceURL(profile.ControllerEndpoint)
	if profile.GitHubProxy != "" {
		profile.GitHubProxy, _ = NormalizeOptionalServiceURL(profile.GitHubProxy)
	}
	return profile, nil
}

// EncodeProfileJSON emits the only representation allowed in the database.
// Marshaling the typed profile drops every field outside the approved shape.
func EncodeProfileJSON(profile Profile) (string, error) {
	if err := profile.ValidateComplete(); err != nil {
		return "", err
	}
	var err error
	profile.ControllerEndpoint, err = NormalizeOptionalServiceURL(profile.ControllerEndpoint)
	if err != nil {
		return "", err
	}
	if profile.GitHubProxy != "" {
		profile.GitHubProxy, err = NormalizeOptionalServiceURL(profile.GitHubProxy)
		if err != nil {
			return "", err
		}
	}
	raw, err := json.Marshal(profile)
	if err != nil {
		return "", fmt.Errorf("deployment: encode profile: %w", err)
	}
	return string(raw), nil
}

func rejectDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := walkJSONValue(dec, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("deployment: trailing JSON is not allowed")
		}
		return fmt.Errorf("deployment: trailing JSON is not allowed: %w", err)
	}
	return nil
}

const maxProfileJSONDepth = 32

func walkJSONValue(dec *json.Decoder, depth int) error {
	if depth > maxProfileJSONDepth {
		return fmt.Errorf("deployment: profile JSON is too deeply nested")
	}
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("deployment: invalid profile JSON: %w", err)
	}
	switch delim := tok.(type) {
	case json.Delim:
		switch delim {
		case '{':
			seen := make(map[string]struct{})
			for dec.More() {
				key, err := dec.Token()
				if err != nil {
					return fmt.Errorf("deployment: invalid object key: %w", err)
				}
				name, ok := key.(string)
				if !ok {
					return fmt.Errorf("deployment: object key is not a string")
				}
				if _, exists := seen[name]; exists {
					return fmt.Errorf("deployment: duplicate object key %q", name)
				}
				seen[name] = struct{}{}
				if err := walkJSONValue(dec, depth+1); err != nil {
					return err
				}
			}
			if end, err := dec.Token(); err != nil || end != json.Delim('}') {
				return fmt.Errorf("deployment: invalid object termination")
			}
		case '[':
			for dec.More() {
				if err := walkJSONValue(dec, depth+1); err != nil {
					return err
				}
			}
			if end, err := dec.Token(); err != nil || end != json.Delim(']') {
				return fmt.Errorf("deployment: invalid array termination")
			}
		case '}', ']':
			return fmt.Errorf("deployment: unexpected closing delimiter")
		}
	}
	return nil
}
