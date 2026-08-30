// RFC 6887 PCP wire codec: v2 header, MAP opcode payload and the
// PREFER_FAILURE option. Only the v1 AntiNAT subset is encoded; decoding
// rejects everything the client must not accept (wrong version/opcode,
// trailing garbage, non-zero padding) instead of ignoring it.
package pcp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// PCP v2 constants (RFC 6887).
const (
	// Version is the PCP protocol version this client speaks.
	Version byte = 2

	// HeaderSize is the 28-byte PCP header (RFC 6887 §7: 4 bytes
	// version/opcode/reserved/result, 4 lifetime, 4 epoch, 16 client address).
	HeaderSize = 28
	// MapPayloadSize is the 36-byte MAP opcode payload.
	MapPayloadSize = 36

	// OpCodeMap is the MAP opcode (RFC 6887 §11).
	OpCodeMap byte = 1
	// OpCodeAnnounce is the ANNOUNCE opcode (RFC 6887 §8.4): the
	// discovery/reachability probe with no side effects.
	OpCodeAnnounce byte = 0

	// RequestFlag marks an opcode byte as a request (R bit clear).
	RequestFlag byte = 0x00
	// ResponseFlag marks an opcode byte as a response (R bit set).
	ResponseFlag byte = 0x80

	// ProtoTCP and ProtoUDP are the MAP protocol octets.
	ProtoTCP byte = 6
	ProtoUDP byte = 17

	// OptionPreferFailure is the PREFER_FAILURE option code (§11.2.2).
	OptionPreferFailure uint16 = 2

	// DefaultServerPort is the registered PCP port.
	DefaultServerPort uint16 = 5351
)

// Base result codes (RFC 6887 §7.4). Codes 14..31 are further permanent
// failures and codes >= 128 are transient failures.
const (
	ResultSuccess               byte = 0
	ResultUnsupportedVersion    byte = 1
	ResultNotAuthorized         byte = 2
	ResultMalformedRequest      byte = 3
	ResultUnsupportedOpcode     byte = 4
	ResultUnsupportedOption     byte = 5
	ResultMalformedOption       byte = 6
	ResultNetworkFailure        byte = 7
	ResultNoResources           byte = 8
	ResultUnsupportedProtocol   byte = 9
	ResultUserExQuota           byte = 10
	ResultCannotProvideExternal byte = 11
	ResultAddressMismatch       byte = 12
	ResultExcessiveRemotePeers  byte = 13
)

// TransientResult reports whether a PCP result code is transient
// (>= 128 per RFC 6887 §7.4) and may be retried after backoff.
func TransientResult(code byte) bool { return code >= 128 }

// Codec errors.
var (
	ErrTruncated     = errors.New("pcp: response truncated")
	ErrWrongVersion  = errors.New("pcp: response version mismatch")
	ErrWrongOpcode   = errors.New("pcp: response opcode mismatch")
	ErrTrailingBytes = errors.New("pcp: trailing bytes after MAP response")
	ErrInternalPort  = errors.New("pcp: internal port mismatch in response")
	ErrProtocol      = errors.New("pcp: protocol mismatch in response")
	ErrBadMappedAddr = errors.New("pcp: assigned external address is not IPv4")
)

// putUint32/putUint16/readUint32/readUint16 are the little helpers shared by
// the codec and the fake-server tests.
func putUint32(b []byte, v uint32) { binary.BigEndian.PutUint32(b, v) }
func putUint16(b []byte, v uint16) { binary.BigEndian.PutUint16(b, v) }
func readUint32(b []byte) uint32   { return binary.BigEndian.Uint32(b) }
func readUint16(b []byte) uint16   { return binary.BigEndian.Uint16(b) }

// v4Mapped encodes an IPv4 address into the 128-bit IPv6-mapped form PCP
// carries in headers and MAP payloads.
func v4Mapped(addr netip.Addr) []byte {
	b := make([]byte, 16)
	if addr.Is4() {
		b[10], b[11] = 0xff, 0xff
		a4 := addr.As4()
		copy(b[12:16], a4[:])
	}
	return b
}

// mappedToV4 decodes a 128-bit field into an IPv4 address. Only the
// IPv4-mapped form (::ffff:a.b.c.d) PCP gateways must use is accepted.
func mappedToV4(b []byte) (netip.Addr, error) {
	if len(b) != 16 {
		return netip.Addr{}, fmt.Errorf("%w: field is %d bytes", ErrBadMappedAddr, len(b))
	}
	if b[10] == 0xff && b[11] == 0xff {
		return netip.AddrFrom4([4]byte(b[12:16])), nil
	}
	return netip.Addr{}, ErrBadMappedAddr
}

// buildMapRequest encodes one MAP request: 24-byte header, 36-byte MAP
// payload and the PREFER_FAILURE option when exact port is required.
// nonce must already be filled by the caller (ownership state).
func buildMapRequest(req MapRequest, nonce [12]byte) ([]byte, error) {
	if req.Protocol != ProtoTCP && req.Protocol != ProtoUDP {
		return nil, fmt.Errorf("pcp: unsupported MAP protocol %d", req.Protocol)
	}
	if req.PreferFailure && req.SuggestedExternalPort == 0 {
		return nil, ErrPreferFailureRequiresPort
	}
	if !req.InternalAddress.IsValid() || !req.InternalAddress.Is4() {
		return nil, fmt.Errorf("pcp: MAP requires a concrete IPv4 internal address, got %v", req.InternalAddress)
	}

	packet := make([]byte, HeaderSize+MapPayloadSize)
	packet[0] = Version
	packet[1] = RequestFlag | OpCodeMap
	// packet[2] reserved, packet[3] is the response result-code slot only.
	putUint32(packet[4:8], uint32(req.Lifetime/time.Second))
	copy(packet[12:28], v4Mapped(req.InternalAddress))

	payload := packet[HeaderSize:]
	copy(payload[0:12], nonce[:])
	payload[12] = req.Protocol
	// payload[13:16] reserved
	putUint16(payload[16:18], req.InternalPort)
	putUint16(payload[18:20], req.SuggestedExternalPort)
	// payload[20:36] suggested external IP: zero (wildcard) in v1.

	if req.PreferFailure {
		// PREFER_FAILURE is a zero-length option padded to 4 bytes.
		opt := make([]byte, 4)
		putUint16(opt[0:2], OptionPreferFailure)
		putUint16(opt[2:4], 0)
		packet = append(packet, opt...)
	}
	return packet, nil
}

// buildAnnounceRequest encodes one ANNOUNCE request (header only).
func buildAnnounceRequest(clientAddr netip.Addr) ([]byte, error) {
	if !clientAddr.IsValid() || !clientAddr.Is4() {
		return nil, fmt.Errorf("pcp: ANNOUNCE requires a concrete IPv4 client address, got %v", clientAddr)
	}
	packet := make([]byte, HeaderSize)
	packet[0] = Version
	packet[1] = RequestFlag | OpCodeAnnounce
	copy(packet[12:28], v4Mapped(clientAddr))
	return packet, nil
}

// parseAnnounceResponse decodes and validates an ANNOUNCE response.
func parseAnnounceResponse(packet []byte, wantClient netip.Addr) (mapResponse, error) {
	var zero mapResponse
	if len(packet) < HeaderSize {
		return zero, fmt.Errorf("%w: %d bytes", ErrTruncated, len(packet))
	}
	if packet[0] != Version {
		return zero, fmt.Errorf("%w: got %d", ErrWrongVersion, packet[0])
	}
	if packet[1] != ResponseFlag|OpCodeAnnounce {
		return zero, fmt.Errorf("%w: got %02x", ErrWrongOpcode, packet[1])
	}
	if len(packet) != HeaderSize {
		return zero, fmt.Errorf("%w: %d extra bytes", ErrTrailingBytes, len(packet)-HeaderSize)
	}
	response := mapResponse{
		ResultCode:      packet[3],
		LifetimeSeconds: readUint32(packet[4:8]),
		Epoch:           readUint32(packet[8:12]),
	}
	clientAddr, err := mappedToV4(packet[12:28])
	if err != nil {
		return zero, err
	}
	response.ClientAddress = clientAddr
	if response.ResultCode == ResultSuccess && wantClient.IsValid() && response.ClientAddress != wantClient {
		return zero, fmt.Errorf("pcp: response client address %s does not match %s", response.ClientAddress, wantClient)
	}
	return response, nil
}

// mapResponse is the decoded MAP response.
type mapResponse struct {
	ResultCode              byte
	LifetimeSeconds         uint32
	Epoch                   uint32
	ClientAddress           netip.Addr
	Nonce                   [12]byte
	Protocol                byte
	InternalPort            uint16
	AssignedExternalPort    uint16
	AssignedExternalAddress netip.Addr
}

// parseMapResponse decodes and validates a MAP response. Validation is
// strict: exact length, echoed version/opcode, echoed client address, echoed
// nonce (checked by the caller against its own state), echoed protocol and
// internal port.
func parseMapResponse(packet []byte, wantProtocol byte, wantInternalPort uint16, wantClient netip.Addr) (mapResponse, error) {
	var zero mapResponse
	if len(packet) < HeaderSize {
		return zero, fmt.Errorf("%w: %d bytes", ErrTruncated, len(packet))
	}
	if packet[0] != Version {
		return zero, fmt.Errorf("%w: got %d", ErrWrongVersion, packet[0])
	}
	if packet[1] != ResponseFlag|OpCodeMap {
		return zero, fmt.Errorf("%w: got %02x", ErrWrongOpcode, packet[1])
	}
	response := mapResponse{
		ResultCode:      packet[3],
		LifetimeSeconds: readUint32(packet[4:8]),
		Epoch:           readUint32(packet[8:12]),
	}
	clientAddr, err := mappedToV4(packet[12:28])
	if err != nil {
		return zero, err
	}
	response.ClientAddress = clientAddr
	if len(packet) == HeaderSize {
		// Error responses carry no MAP payload.
		return response, nil
	}
	if len(packet) != HeaderSize+MapPayloadSize {
		return zero, fmt.Errorf("%w: %d extra bytes", ErrTrailingBytes, len(packet)-HeaderSize-MapPayloadSize)
	}
	payload := packet[HeaderSize:]
	copy(response.Nonce[:], payload[0:12])
	response.Protocol = payload[12]
	response.InternalPort = readUint16(payload[16:18])
	response.AssignedExternalPort = readUint16(payload[18:20])
	external, err := mappedToV4(payload[20:36])
	if err != nil {
		return zero, err
	}
	response.AssignedExternalAddress = external
	// Strict echo validation for success responses.
	if response.ResultCode == ResultSuccess {
		if response.Protocol != wantProtocol {
			return zero, fmt.Errorf("%w: got %d want %d", ErrProtocol, response.Protocol, wantProtocol)
		}
		if response.InternalPort != wantInternalPort {
			return zero, fmt.Errorf("%w: got %d want %d", ErrInternalPort, response.InternalPort, wantInternalPort)
		}
		if wantClient.IsValid() && response.ClientAddress != wantClient {
			return zero, fmt.Errorf("pcp: response client address %s does not match %s", response.ClientAddress, wantClient)
		}
	}
	return response, nil
}
