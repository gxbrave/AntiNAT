package install

import (
	"errors"
	"fmt"
)

// ValidateNMinusOne enforces the frozen expand/contract rule. Equal versions
// are a restart/reinstall; a one-step increase is the only migration allowed.
func ValidateNMinusOne(currentVersion, previousVersion uint64) error {
	if previousVersion == 0 {
		return &InstallerError{Code: ExitUpgradeMigrationBlocked, Op: "compatibility", Cause: errors.New("previous schema version must be non-zero")}
	}
	if currentVersion < previousVersion {
		return &InstallerError{Code: ExitUpgradeMigrationBlocked, Op: "compatibility", Cause: fmt.Errorf("schema regression %d -> %d", previousVersion, currentVersion)}
	}
	if currentVersion-previousVersion > 1 {
		return &InstallerError{Code: ExitUpgradeMigrationBlocked, Op: "compatibility", Cause: fmt.Errorf("schema jump %d -> %d skips an intermediate version", previousVersion, currentVersion)}
	}
	return nil
}

// ValidateSchemaCompatibility is a descriptive alias used by platform code.
func ValidateSchemaCompatibility(currentVersion, previousVersion uint64) error {
	return ValidateNMinusOne(currentVersion, previousVersion)
}
