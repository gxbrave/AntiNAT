package deployment

import (
	"strings"
	"testing"
)

func TestDecodeProfileJSONRejectsDuplicateTrailingAndDeepInput(t *testing.T) {
	base := `"platform":"linux","controller_endpoint":"https://ctl.example.test","detection_scheduler":"sequential","log_level":"info","auto_update":"disabled"`
	cases := map[string]string{
		"duplicate key":  `{` + base + `,"bind_interface":"eth0","bind_interface":"eth1"}`,
		"trailing value": `{` + base + `} {"extra":true}`,
		"trailing bytes": `{` + base + `} trailing`,
	}
	cases["nullable field"] = `{` + base + `,"bind_interface":null}`
	deep := `{` + base + `,"bind_interface":` + strings.Repeat("[", 40) + `null` + strings.Repeat("]", 40) + `}`
	cases["deep nesting"] = deep

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeProfileJSON([]byte(raw)); err == nil {
				t.Fatalf("DecodeProfileJSON accepted %s", name)
			}
		})
	}
}

func TestValidateCompleteRequiresProfileSchemaFields(t *testing.T) {
	profile := Profile{Platform: PlatformLinux, ControllerEndpoint: "https://ctl.example.test"}
	if err := profile.Validate(); err != nil {
		t.Fatalf("base validation rejected otherwise usable builder profile: %v", err)
	}
	if err := profile.ValidateComplete(); err == nil {
		t.Fatal("ValidateComplete accepted missing required schema fields")
	}
}
