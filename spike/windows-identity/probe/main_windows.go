//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"unsafe"

	windowsidentity "github.com/gxbrave/AntiNAT/spike/windows-identity"
	"golang.org/x/sys/windows"
)

type report struct {
	DPAPIMachineRoundTrip bool   `json:"dpapi_machine_round_trip"`
	ProtectedKeyACL       bool   `json:"protected_key_acl"`
	ServiceSID            string `json:"service_sid,omitempty"`
	DefenderRuleMode      string `json:"defender_rule_mode"`
	NativeValidated       bool   `json:"native_validated"`
	Capability            string `json:"capability"`
	RequiredNextCheck     string `json:"required_next_check"`
}

func main() {
	result := report{
		DefenderRuleMode:  "UNVALIDATED",
		Capability:        "UNSUPPORTED",
		RequiredNextCheck: "run under the installed Windows Service identity and validate managed/manual Defender firewall add, query, restart, upgrade, and cleanup on a native host",
	}
	if err := dpapiRoundTrip(); err != nil {
		fmt.Fprintln(os.Stderr, "DPAPI:", err)
	} else {
		result.DPAPIMachineRoundTrip = true
	}
	if err := protectedACLProbe(); err != nil {
		fmt.Fprintln(os.Stderr, "ACL:", err)
	} else {
		result.ProtectedKeyACL = true
	}
	serviceSID, err := currentServiceSID()
	if err != nil {
		fmt.Fprintln(os.Stderr, "service SID:", err)
	} else {
		result.ServiceSID = serviceSID
	}
	result.NativeValidated = result.DPAPIMachineRoundTrip && result.ProtectedKeyACL && result.ServiceSID != ""
	result.Capability = windowsidentity.ClassifyCapability(
		result.DPAPIMachineRoundTrip,
		result.ProtectedKeyACL,
		result.ServiceSID,
		result.DefenderRuleMode,
	)
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if !result.NativeValidated {
		os.Exit(1)
	}
}

func dpapiRoundTrip() error {
	plain := []byte("AntiNAT Windows identity feasibility")
	input := windows.DataBlob{Size: uint32(len(plain)), Data: &plain[0]}
	var protected windows.DataBlob
	if err := windows.CryptProtectData(
		&input,
		nil,
		nil,
		0,
		nil,
		windows.CRYPTPROTECT_LOCAL_MACHINE|windows.CRYPTPROTECT_UI_FORBIDDEN,
		&protected,
	); err != nil {
		return err
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(protected.Data))))
	var unprotected windows.DataBlob
	if err := windows.CryptUnprotectData(
		&protected,
		nil,
		nil,
		0,
		nil,
		windows.CRYPTPROTECT_UI_FORBIDDEN,
		&unprotected,
	); err != nil {
		return err
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(unprotected.Data))))
	if !bytes.Equal(plain, unsafe.Slice(unprotected.Data, unprotected.Size)) {
		return errors.New("DPAPI round-trip plaintext mismatch")
	}
	return nil
}

func protectedACLProbe() error {
	file, err := os.CreateTemp("", "antinat-key-*.bin")
	if err != nil {
		return err
	}
	path := file.Name()
	defer os.Remove(path)
	if _, err := file.Write([]byte("encrypted-key-fixture")); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}

	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	system, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		return err
	}
	entries := []windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.ACCESS_MASK(windows.GENERIC_ALL),
			AccessMode:        windows.GRANT_ACCESS,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeValue: windows.TrusteeValueFromSID(user.User.Sid),
			},
		},
		{
			AccessPermissions: windows.ACCESS_MASK(windows.GENERIC_ALL),
			AccessMode:        windows.GRANT_ACCESS,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeValue: windows.TrusteeValueFromSID(system),
			},
		},
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		return err
	}
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return err
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("key DACL is not protected from inheritance")
	}
	if dacl, _, err := descriptor.DACL(); err != nil || dacl == nil {
		return fmt.Errorf("key DACL unavailable: %v", err)
	}
	return nil
}

func currentServiceSID() (string, error) {
	groups, err := windows.GetCurrentProcessToken().GetTokenGroups()
	if err != nil {
		return "", err
	}
	for _, group := range groups.AllGroups() {
		sid := group.Sid.String()
		if strings.HasPrefix(sid, "S-1-5-80-") {
			return sid, nil
		}
	}
	return "", errors.New("current token does not contain an NT SERVICE SID")
}
