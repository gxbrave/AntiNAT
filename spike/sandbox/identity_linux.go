//go:build linux

package sandbox

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// dedicatedIdentity resolves the provisioned service identity from
// ANTINAT_DEDICATED_UID / ANTINAT_DEDICATED_GID and fails closed unless it is
// a unique, non-shared account. The shared nobody/nogroup identity (65534) and
// any UID/GID with more than one /etc/passwd or /etc/group entry are rejected:
// a "dedicated" UID must not be shared with any other process on the host.
func dedicatedIdentity() (uid, gid int, err error) {
	uidText := os.Getenv("ANTINAT_DEDICATED_UID")
	gidText := os.Getenv("ANTINAT_DEDICATED_GID")
	if uidText == "" || gidText == "" {
		return 0, 0, errors.New("ANTINAT_DEDICATED_UID and ANTINAT_DEDICATED_GID must name a provisioned unique service identity")
	}
	uid, err = strconv.Atoi(uidText)
	if err != nil || uid <= 0 {
		return 0, 0, fmt.Errorf("invalid dedicated UID %q", uidText)
	}
	gid, err = strconv.Atoi(gidText)
	if err != nil || gid <= 0 {
		return 0, 0, fmt.Errorf("invalid dedicated GID %q", gidText)
	}
	if uid == 65534 || gid == 65534 {
		return 0, 0, errors.New("UID/GID 65534 is the shared nobody/nogroup identity, not a dedicated service identity")
	}
	passwdName, passwdCount, err := lookupPasswd(uid)
	if err != nil {
		return 0, 0, err
	}
	if passwdCount != 1 {
		return 0, 0, fmt.Errorf("UID %d appears in %d passwd entries; a dedicated service UID must be unique", uid, passwdCount)
	}
	if passwdName == "" || passwdName == "nobody" {
		return 0, 0, fmt.Errorf("UID %d maps to account %q, which is not a dedicated service account", uid, passwdName)
	}
	groupName, groupCount, err := lookupGroup(gid)
	if err != nil {
		return 0, 0, err
	}
	if groupCount != 1 {
		return 0, 0, fmt.Errorf("GID %d appears in %d group entries; a dedicated service GID must be unique", gid, groupCount)
	}
	if groupName == "" || groupName == "nogroup" {
		return 0, 0, fmt.Errorf("GID %d maps to group %q, which is not a dedicated service group", gid, groupName)
	}
	return uid, gid, nil
}

func lookupPasswd(uid int) (name string, count int, err error) {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		entryUID, parseErr := strconv.Atoi(fields[2])
		if parseErr != nil {
			continue
		}
		if entryUID == uid {
			count++
			name = fields[0]
		}
	}
	if err := scanner.Err(); err != nil {
		return "", 0, err
	}
	if count == 0 {
		return "", 0, fmt.Errorf("UID %d has no /etc/passwd entry", uid)
	}
	return name, count, nil
}

func lookupGroup(gid int) (name string, count int, err error) {
	file, err := os.Open("/etc/group")
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		entryGID, parseErr := strconv.Atoi(fields[2])
		if parseErr != nil {
			continue
		}
		if entryGID == gid {
			count++
			name = fields[0]
		}
	}
	if err := scanner.Err(); err != nil {
		return "", 0, err
	}
	if count == 0 {
		return "", 0, fmt.Errorf("GID %d has no /etc/group entry", gid)
	}
	return name, count, nil
}
