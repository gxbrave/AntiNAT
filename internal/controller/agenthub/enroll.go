package agenthub

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// Enrollment error codes — stable machine-readable strings returned as JSON
// error bodies. Messages never carry token or key material (frozen §4.4.7).
const (
	codeEnrollNodeUnknown      = "ENROLL_NODE_UNKNOWN"
	codeEnrollMalformed        = "ENROLL_MALFORMED"
	codeEnrollChallenge        = "ENROLL_CHALLENGE_REJECTED"
	codeEnrollTokenNotFound    = "ENROLL_TOKEN_NOT_FOUND"
	codeEnrollTokenExpired     = "ENROLL_TOKEN_EXPIRED"
	codeEnrollTokenConsumed    = "ENROLL_TOKEN_CONSUMED"
	codeEnrollTokenNode        = "ENROLL_TOKEN_NODE_MISMATCH"
	codeEnrollAlreadyBound     = "ENROLL_NODE_CREDENTIAL_CONFLICT"
	codeEnrollPlaintextRefused = "ENROLL_PLAINTEXT_PUBLIC_REFUSED"
	codeEnrollInternal         = "ENROLL_INTERNAL"
)

type enrollError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeEnrollError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(enrollError{Code: code, Message: message})
}

// nodeIDFromBody reads a raw node id body (<= 16 bytes); the store-form node
// id is the unpadded string.
func nodeIDFromBody(r *http.Request) (string, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 17))
	if err != nil {
		return "", fmt.Errorf("read node id: %w", err)
	}
	if len(body) == 0 || len(body) > 16 {
		return "", fmt.Errorf("node id must be 1..16 bytes, got %d", len(body))
	}
	return string(body), nil
}

// handleEnrollChallenge issues a signed EnrollChallenge for the node id in the
// body (frozen protocol.md §4.1). The challenge is cached for replay/expiry
// validation when the EnrollRequest arrives.
func (h *Hub) handleEnrollChallenge(w http.ResponseWriter, r *http.Request) {
	if !h.enrollAllowed(r) {
		writeEnrollError(w, http.StatusForbidden, codeEnrollPlaintextRefused, "enrollment over plaintext from a public address is refused")
		return
	}
	if r.Method != http.MethodPost {
		writeEnrollError(w, http.StatusMethodNotAllowed, codeEnrollMalformed, "method not allowed")
		return
	}
	nodeID, err := nodeIDFromBody(r)
	if err != nil {
		writeEnrollError(w, http.StatusBadRequest, codeEnrollMalformed, "invalid node id")
		return
	}
	// Fail closed on unknown nodes: enrollment exists only for created nodes.
	if _, err := h.store.GetNode(nodeID); err != nil {
		writeEnrollError(w, http.StatusNotFound, codeEnrollNodeUnknown, "unknown node")
		return
	}
	instance, err := h.store.InstanceID()
	if err != nil {
		writeEnrollError(w, http.StatusInternalServerError, codeEnrollInternal, "controller instance unavailable")
		return
	}
	var inst [16]byte
	if decoded, err := hex.DecodeString(instance); err == nil && len(decoded) == 16 {
		copy(inst[:], decoded)
	}
	_, raw, err := h.challenges.Issue(h.keyring, inst, h.keyring.KeyID(), nodeID)
	if err != nil {
		writeEnrollError(w, http.StatusServiceUnavailable, codeEnrollInternal, "challenge unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	w.Write(raw)
}

// challengeHashOf extracts the challenge_hash field (field 1 of 6) from a raw
// EnrollRequest so the server can validate/consume the challenge before the
// full possession check.
func challengeHashOf(raw []byte) ([32]byte, error) {
	var hash [32]byte
	if len(raw) < 64 {
		return hash, errors.New("enroll request shorter than signature")
	}
	fields := raw[:len(raw)-64]
	if len(fields) < 4 {
		return hash, errors.New("enroll request missing fields")
	}
	l := binary.BigEndian.Uint32(fields[:4])
	if uint64(l) != 32 || uint64(l) > uint64(len(fields)-4) {
		return hash, errors.New("enroll request challenge hash field invalid")
	}
	copy(hash[:], fields[4:4+32])
	return hash, nil
}

// handleEnrollRequest consumes an EnrollRequest (possession proof) and returns
// the signed EnrollResult. Response loss is handled idempotently: the same
// node + same key + valid possession returns the ORIGINAL binding result
// (frozen protocol.md §4.4 rule 2).
func (h *Hub) handleEnrollRequest(w http.ResponseWriter, r *http.Request) {
	if !h.enrollAllowed(r) {
		writeEnrollError(w, http.StatusForbidden, codeEnrollPlaintextRefused, "enrollment over plaintext from a public address is refused")
		return
	}
	if r.Method != http.MethodPost {
		writeEnrollError(w, http.StatusMethodNotAllowed, codeEnrollMalformed, "method not allowed")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, h.cfg.MaxEnrollBodyBytes))
	if err != nil {
		writeEnrollError(w, http.StatusBadRequest, codeEnrollMalformed, "unreadable request body")
		return
	}

	// 1. Locate and consume the issued challenge by hash (unknown/replay/
	//    expiry fail closed here; the challenge binds the node identity).
	hash, err := challengeHashOf(body)
	if err != nil {
		writeEnrollError(w, http.StatusBadRequest, codeEnrollMalformed, "malformed enroll request")
		return
	}
	nodeID, err := h.challenges.ValidateAndConsume(hash)
	if err != nil {
		writeEnrollError(w, http.StatusBadRequest, codeEnrollChallenge, "challenge rejected")
		return
	}

	// 2. Full possession verification against the challenge hash.
	req, err := protocol.ParseEnrollRequest(body, hash)
	if err != nil {
		writeEnrollError(w, http.StatusUnauthorized, codeEnrollMalformed, "possession proof invalid")
		return
	}

	// 3. Atomic token consume + credential bind + result (single transaction).
	pubHash := sha256.Sum256(req.PublicKey())
	tokenHash := sha256.Sum256([]byte(req.Token))
	var resultID [16]byte
	if _, err := rand.Read(resultID[:]); err != nil {
		writeEnrollError(w, http.StatusInternalServerError, codeEnrollInternal, "result id unavailable")
		return
	}
	enrollReq := store.EnrollmentRequest{
		NodeID:             nodeID,
		TokenHash:          hex.EncodeToString(tokenHash[:]),
		AgentPublicKeyHash: hex.EncodeToString(pubHash[:]),
		CredentialVersion:  req.AgentCredentialVersion,
		CapabilityHash:     hex.EncodeToString(req.CapabilityHash[:]),
		ControllerKeyID:    h.keyring.KeyID(),
		ResultID:           hex.EncodeToString(resultID[:]),
		ResultExpiryUnix:   h.now() + int64(h.cfg.EnrollResultTTL.Seconds()),
	}
	result, replayed, err := h.store.ConsumeEnrollmentToken(enrollReq)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrEnrollmentTokenNotFound):
			writeEnrollError(w, http.StatusNotFound, codeEnrollTokenNotFound, "token not found")
		case errors.Is(err, store.ErrEnrollmentTokenExpired):
			writeEnrollError(w, http.StatusForbidden, codeEnrollTokenExpired, "token expired")
		case errors.Is(err, store.ErrEnrollmentTokenConsumed):
			writeEnrollError(w, http.StatusConflict, codeEnrollTokenConsumed, "token already consumed")
		case errors.Is(err, store.ErrEnrollmentTokenNodeMismatch):
			writeEnrollError(w, http.StatusForbidden, codeEnrollTokenNode, "token node mismatch")
		case errors.Is(err, store.ErrNodeCredentialConflict):
			writeEnrollError(w, http.StatusConflict, codeEnrollAlreadyBound, "node already bound to a different credential")
		default:
			writeEnrollError(w, http.StatusInternalServerError, codeEnrollInternal, "enrollment failed")
		}
		h.audit("ENROLLMENT_REJECTED", fmt.Sprintf(`{"node_id":%q,"code":%q}`, nodeID, err.Error()))
		return
	}

	// 4. Sign and return the EnrollResult (frozen §4.3). Replays return the
	//    ORIGINAL result id and expiry so the agent converges on one binding.
	resID, err := hex.DecodeString(result.ResultID)
	if err != nil || len(resID) != 16 {
		writeEnrollError(w, http.StatusInternalServerError, codeEnrollInternal, "invalid stored result id")
		return
	}
	var resNode [16]byte
	copy(resNode[:], result.NodeID)
	var resPubHash [32]byte
	if decoded, err := hex.DecodeString(result.AgentPublicKeyHash); err == nil && len(decoded) == 32 {
		copy(resPubHash[:], decoded)
	}
	res := protocol.EnrollResult{
		ControllerInstanceID:   [16]byte{},
		ControllerKeyID:        result.ControllerKeyID,
		NodeID:                 resNode,
		AgentPublicKeyHash:     resPubHash,
		AgentCredentialVersion: result.CredentialVersion,
		EnrollmentResultID:     [16]byte(resID),
		ExpiryUnix:             uint64(result.ExpiryUnix),
	}
	instance, err := h.store.InstanceID()
	if err != nil {
		writeEnrollError(w, http.StatusInternalServerError, codeEnrollInternal, "controller instance unavailable")
		return
	}
	if decoded, err := hex.DecodeString(instance); err == nil && len(decoded) == 16 {
		copy(res.ControllerInstanceID[:], decoded)
	}
	sig, err := h.keyring.Sign(res.SigningBytes())
	if err != nil {
		writeEnrollError(w, http.StatusInternalServerError, codeEnrollInternal, "result signing failed")
		return
	}
	raw := append(res.Canonical(), sig...)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	w.Write(raw)
	if replayed {
		h.audit("ENROLLMENT_REPLAYED", fmt.Sprintf(`{"node_id":%q,"result_id":%q}`, nodeID, result.ResultID))
	}
}
