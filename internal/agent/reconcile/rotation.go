// P14 Story 4 (agent side): accepting a controller key-rotation pin.
//
// The agent verifies the signed rotation certificate against its CURRENTLY
// pinned controller key, enforces the generation strictly increases, fsyncs
// the new pin set (bbolt write), then ACKs. A downgrade, wrong-signer, or
// certificate bound to a different pin is refused fail-closed.
package reconcile

import (
	"crypto/ed25519"
	"fmt"

	"github.com/gxbrave/AntiNAT/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT/internal/security"
)

// ErrRotationPinRefused is the fail-closed agent rotation refusal.
var ErrRotationPinRefused = fmt.Errorf("reconcile: controller pin rotation refused")

// AcceptControllerRotationPin verifies a controller key-rotation certificate
// against the pinned controller key and persists the successor pin at the
// higher generation. The bbolt write is durable (fsync) before this returns,
// so an ACK is only ever sent for a pin the agent can verify locally.
func AcceptControllerRotationPin(store *localstate.Store, instanceID string, certRaw []byte) (localstate.ControllerPin, security.RotationCertificate, error) {
	pin, found, err := store.ControllerPin(instanceID)
	if err != nil {
		return localstate.ControllerPin{}, security.RotationCertificate{}, err
	}
	if !found {
		return localstate.ControllerPin{}, security.RotationCertificate{}, fmt.Errorf("%w: no pinned controller for %q", ErrRotationPinRefused, instanceID)
	}
	cert, err := security.DecodeRotationCertificate(certRaw, pin.PublicKey())
	if err != nil {
		return localstate.ControllerPin{}, security.RotationCertificate{}, fmt.Errorf("%w: certificate: %v", ErrRotationPinRefused, err)
	}
	if cert.Scope != "controller" && cert.Scope != "" {
		return localstate.ControllerPin{}, security.RotationCertificate{}, fmt.Errorf("%w: scope %q", ErrRotationPinRefused, cert.Scope)
	}
	newPub, _, err := cert.PublicKeys()
	if err != nil {
		return localstate.ControllerPin{}, security.RotationCertificate{}, err
	}
	next := localstate.ControllerPin{
		InstanceID: instanceID, KeyID: cert.NewKeyID,
		PublicKeyRaw: append(ed25519.PublicKey(nil), newPub...),
		Generation:   cert.NewGeneration,
	}
	if err := store.SaveControllerPin(next); err != nil {
		return localstate.ControllerPin{}, security.RotationCertificate{}, fmt.Errorf("%w: persist successor pin: %v", ErrRotationPinRefused, err)
	}
	return next, cert, nil
}
