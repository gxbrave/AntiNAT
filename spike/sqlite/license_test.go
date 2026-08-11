package sqlite_test

import (
	"encoding/json"
	"os"
	"testing"
)

type licenseInventory struct {
	Driver  string `json:"driver"`
	Modules []struct {
		Module   string `json:"module"`
		Version  string `json:"version"`
		Licenses []struct {
			SPDX   string `json:"spdx"`
			SHA256 string `json:"sha256"`
		} `json:"licenses"`
	} `json:"modules"`
}

func TestLicenseInventoryCoversResolvedModuleGraph(t *testing.T) {
	data, err := os.ReadFile("license-inventory.json")
	if err != nil {
		t.Fatal(err)
	}
	var inventory licenseInventory
	if err := json.Unmarshal(data, &inventory); err != nil {
		t.Fatal(err)
	}
	if inventory.Driver != "modernc.org/sqlite v1.56.0" {
		t.Fatalf("driver = %q", inventory.Driver)
	}
	if len(inventory.Modules) == 0 {
		t.Fatal("license inventory has no modules")
	}
	seenDriver := false
	for _, module := range inventory.Modules {
		if module.Module == "modernc.org/sqlite" && module.Version == "v1.56.0" {
			seenDriver = true
		}
		if len(module.Licenses) == 0 {
			t.Errorf("%s %s has no license file", module.Module, module.Version)
		}
		for _, license := range module.Licenses {
			if license.SPDX == "" || license.SPDX == "UNCLASSIFIED" || len(license.SHA256) != 64 {
				t.Errorf("%s %s has invalid license record: %+v", module.Module, module.Version, license)
			}
		}
	}
	if !seenDriver {
		t.Fatal("modernc.org/sqlite v1.56.0 is missing from license inventory")
	}
}
