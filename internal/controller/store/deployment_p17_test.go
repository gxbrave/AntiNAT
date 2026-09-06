package store

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestP17DeploymentProfileStrictCAS(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	if err := s.CreateNode(Node{ID: "deployment-node", Name: "deployment-node"}); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}

	valid := `{"platform":"linux","controller_endpoint":"https://ctl.example.test:3111/","detection_scheduler":"sequential","log_level":"info","auto_update":"disabled"}`
	for _, invalid := range []string{
		`{"platform":"linux","controller_endpoint":"https://ctl.example.test","detection_scheduler":"sequential","log_level":"info","auto_update":"disabled","token":"secret"}`,
		`{"platform":"linux","controller_endpoint":"https://ctl.example.test","detection_scheduler":"sequential","log_level":"info","auto_update":"disabled"} trailing`,
		`{"platform":"linux","controller_endpoint":"https://ctl.example.test","detection_scheduler":"sequential","log_level":"info","auto_update":"disabled","secret":"secret"}`,
	} {
		if _, err := s.PutDeploymentProfile("deployment-node", 0, invalid); !errors.Is(err, ErrTrafficInvalid) {
			t.Errorf("invalid profile error = %v, want ErrTrafficInvalid", err)
		}
	}
	first, err := s.PutDeploymentProfile("deployment-node", 0, valid)
	if err != nil {
		t.Fatalf("first PutDeploymentProfile: %v", err)
	}
	if first.Revision != 1 || !strings.Contains(first.JSON, "https://ctl.example.test:3111") {
		t.Fatalf("first profile = %+v, want rev 1 and normalized endpoint", first)
	}
	before, err := s.GetDeploymentProfile("deployment-node")
	if err != nil {
		t.Fatalf("GetDeploymentProfile before stale write: %v", err)
	}
	if _, err := s.PutDeploymentProfile("deployment-node", 0, `{"platform":"linux","controller_endpoint":"https://other.example","detection_scheduler":"parallel","log_level":"warn","auto_update":"stable"}`); !errors.Is(err, ErrCASConflict) {
		t.Fatalf("stale profile error = %v, want ErrCASConflict", err)
	}
	after, err := s.GetDeploymentProfile("deployment-node")
	if err != nil {
		t.Fatalf("GetDeploymentProfile after stale write: %v", err)
	}
	if after.Revision != before.Revision || after.JSON != before.JSON {
		t.Fatalf("stale write changed profile: before=%+v after=%+v", before, after)
	}

	const next = `{"platform":"linux","controller_endpoint":"https://ctl.example.test:3111/next","detection_scheduler":"parallel","log_level":"warn","auto_update":"stable"}`
	results := make(chan struct {
		profile DeploymentProfile
		err     error
	}, 2)
	for i := 0; i < 2; i++ {
		go func() {
			profile, putErr := s.PutDeploymentProfile("deployment-node", 1, next)
			results <- struct {
				profile DeploymentProfile
				err     error
			}{profile: profile, err: putErr}
		}()
	}
	var successes, conflicts int
	for i := 0; i < 2; i++ {
		result := <-results
		if result.err == nil {
			successes++
			if result.profile.Revision != 2 || !strings.Contains(result.profile.JSON, "/next") {
				t.Errorf("successful concurrent writer returned mismatched profile: %+v", result.profile)
			}
			continue
		}
		if errors.Is(result.err, ErrCASConflict) {
			conflicts++
			continue
		}
		t.Fatalf("concurrent profile write error = %v", result.err)
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent same-ETag writes: successes=%d conflicts=%d, want 1/1", successes, conflicts)
	}
	final, err := s.GetDeploymentProfile("deployment-node")
	if err != nil {
		t.Fatalf("GetDeploymentProfile final: %v", err)
	}
	if final.Revision != 2 {
		t.Fatalf("final profile revision = %d, want 2", final.Revision)
	}
}
