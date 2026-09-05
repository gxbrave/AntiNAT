//go:build windows

package main

import (
	"runtime"
	"testing"

	"golang.org/x/sys/windows"
)

func tokenACLForTest(t *testing.T, sids ...*windows.SID) *windows.ACL {
	t.Helper()
	var pinner runtime.Pinner
	t.Cleanup(pinner.Unpin)
	entries := make([]windows.EXPLICIT_ACCESS, 0, len(sids))
	for _, sid := range sids {
		pinner.Pin(sid)
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windowsFileFullControl,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatal(err)
	}
	return acl
}

func TestValidateWindowsTokenDACLMatchesInstallerServiceIdentities(t *testing.T) {
	owner, err := windows.StringToSid("S-1-5-19")
	if err != nil {
		t.Fatal(err)
	}
	service, err := windows.StringToSid("S-1-5-80-123-456-789-1011-1213")
	if err != nil {
		t.Fatal(err)
	}
	unrelated, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		t.Fatal(err)
	}

	if err := validateWindowsTokenDACL(tokenACLForTest(t, owner, service), owner, service); err != nil {
		t.Fatalf("installer two-ACE ACL rejected: %v", err)
	}
	if err := validateWindowsTokenDACL(tokenACLForTest(t, owner, service, unrelated), owner, service); err == nil {
		t.Fatal("ACL with unrelated principal accepted")
	}
	if err := validateWindowsTokenDACL(tokenACLForTest(t, owner, owner), owner, service); err == nil {
		t.Fatal("ACL without restricted service SID accepted")
	}
}
