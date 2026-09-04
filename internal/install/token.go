package install

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/term"
)

const (
	maxTokenBytes = 4096
	maxTokenChars = 256
)

// OpenTokenInput opens exactly one token source selected by opts. File-backed
// input is opened with no-follow and identity checks in the platform-specific
// implementation; the descriptor is retained until Commit or Abort.
func OpenTokenInput(opts Options) (*TokenInput, error) {
	return openTokenInput(opts, nil)
}

// OpenTokenInputWithReader is the deterministic equivalent used by installer
// tests. A non-nil reader is only used for the default TTY mode.
func OpenTokenInputWithReader(opts Options, tty io.Reader) (*TokenInput, error) {
	return openTokenInput(opts, tty)
}

func openTokenInput(opts Options, tty io.Reader) (*TokenInput, error) {
	if opts.Command != "" && opts.Command != CommandInstall {
		return nil, tokenError(errors.New("token input is only valid for install"))
	}
	fdSelected := opts.TokenFD != -1 && opts.TokenFD != 0
	if fdSelected && opts.TokenFile != "" {
		return nil, tokenError(errors.New("token fd and token file are mutually exclusive"))
	}
	if fdSelected {
		return openDescriptorToken(opts.TokenFD)
	}
	if opts.TokenFile != "" {
		return openProtectedTokenFile(opts.TokenFile)
	}
	if tty != nil {
		token, err := ReadTokenFromReader(tty)
		if err != nil {
			return nil, err
		}
		return &TokenInput{token: token}, nil
	}
	return openTTYToken()
}

func tokenError(err error) error {
	return &InstallerError{Code: ExitTokenInputFailure, Op: "token", Cause: err}
}

func readTokenBytes(r io.Reader) (string, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxTokenBytes+1))
	if err != nil {
		return "", tokenError(fmt.Errorf("read token: %w", err))
	}
	if len(raw) == 0 || len(raw) > maxTokenBytes {
		return "", tokenError(errors.New("token input exceeds size limit"))
	}
	if !utf8.Valid(raw) {
		return "", tokenError(errors.New("token input is not valid UTF-8"))
	}
	token := strings.TrimSpace(string(raw))
	if token == "" || len(token) > maxTokenChars {
		return "", tokenError(errors.New("token input is empty or too long"))
	}
	for _, r := range token {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r == 0 {
			return "", tokenError(errors.New("token input contains whitespace or control characters"))
		}
	}
	return token, nil
}

func openTTYToken() (*TokenInput, error) {
	// /dev/tty prevents a redirected stdin from unexpectedly becoming the
	// interactive secret channel. Platforms without /dev/tty use stdin only
	// when it is a terminal.
	tty, err := openInstallerTTY()
	if err != nil {
		return nil, tokenError(err)
	}
	defer tty.Close()
	fmt.Fprint(os.Stderr, "Enrollment token: ")
	raw, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, tokenError(fmt.Errorf("hidden TTY read: %w", err))
	}
	token, err := readTokenBytes(strings.NewReader(string(raw)))
	if err != nil {
		return nil, err
	}
	return &TokenInput{token: token}, nil
}
