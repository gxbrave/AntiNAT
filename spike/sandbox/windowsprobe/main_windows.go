//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const disableMaxPrivilege = 0x1

var (
	advapi32                  = windows.NewLazySystemDLL("advapi32.dll")
	createRestrictedTokenProc = advapi32.NewProc("CreateRestrictedToken")
	userenv                   = windows.NewLazySystemDLL("userenv.dll")
	deriveAppContainerSIDProc = userenv.NewProc("DeriveAppContainerSidFromAppContainerName")
)

type probeReport struct {
	RestrictedToken   bool   `json:"restricted_token"`
	JobObject         bool   `json:"job_object"`
	AppContainerAPI   bool   `json:"app_container_api"`
	NativeIsolation   bool   `json:"native_isolation_validated"`
	Capability        string `json:"capability"`
	RequiredNextCheck string `json:"required_next_check"`
}

func main() {
	report := probeReport{
		Capability:        "UNSUPPORTED",
		RequiredNextCheck: "run malicious socket/file/exec/env/inherited-handle/CPU/allocation fixtures under a restricted token or AppContainer on native Windows",
	}
	var failures []error
	if err := probeRestrictedToken(); err != nil {
		failures = append(failures, fmt.Errorf("restricted token: %w", err))
	} else {
		report.RestrictedToken = true
	}
	if err := probeJobObject(); err != nil {
		failures = append(failures, fmt.Errorf("job object: %w", err))
	} else {
		report.JobObject = true
	}
	if err := deriveAppContainerSIDProc.Find(); err != nil {
		failures = append(failures, fmt.Errorf("AppContainer API: %w", err))
	} else {
		report.AppContainerAPI = true
	}
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		failures = append(failures, err)
	}
	if len(failures) != 0 {
		for _, err := range failures {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
}

func probeRestrictedToken() error {
	var restricted windows.Token
	r1, _, callErr := createRestrictedTokenProc.Call(
		uintptr(windows.GetCurrentProcessToken()),
		disableMaxPrivilege,
		0, 0,
		0, 0,
		0, 0,
		uintptr(unsafe.Pointer(&restricted)),
	)
	if r1 == 0 {
		if callErr != syscall.Errno(0) {
			return callErr
		}
		return errors.New("CreateRestrictedToken returned false")
	}
	defer restricted.Close()
	var hasRestrictions uint32
	var returned uint32
	if err := windows.GetTokenInformation(
		restricted,
		windows.TokenHasRestrictions,
		(*byte)(unsafe.Pointer(&hasRestrictions)),
		uint32(unsafe.Sizeof(hasRestrictions)),
		&returned,
	); err != nil {
		return err
	}
	if hasRestrictions == 0 {
		return errors.New("restricted token reports TokenHasRestrictions=0")
	}
	return nil
}

func probeJobObject() error {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return err
	}
	return windows.CloseHandle(job)
}
