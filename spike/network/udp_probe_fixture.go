package network

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"time"
)

const udpProbeFixtureLength = 4 + 16 + 16 + 4 + 2 + 32 + sha256.Size

type UDPProbeFields struct {
	ProbeID    [16]byte
	Activation [16]byte
	Endpoint   *net.UDPAddr
	Challenge  [32]byte
}

type udpProbeExpectation struct {
	provider *net.UDPAddr
	fields   UDPProbeFields
	key      []byte
	deadline time.Time
}

func (demux *UDPDemux) ExpectProbe(provider *net.UDPAddr, fields UDPProbeFields, key []byte, deadline time.Time) error {
	if provider == nil || fields.Endpoint == nil || fields.Endpoint.IP.To4() == nil || fields.Endpoint.Port <= 0 || fields.Endpoint.Port > 65535 || len(key) == 0 || !deadline.After(time.Time{}) {
		return errors.New("probe expectation requires bounded provider, endpoint, key, and deadline")
	}
	fields.Endpoint = cloneUDPAddr(fields.Endpoint)
	demux.mu.Lock()
	defer demux.mu.Unlock()
	demux.purgeLocked(deadline.Add(-time.Nanosecond))
	if len(demux.probes) >= demux.maxProbes {
		return ErrDemuxStateFull
	}
	demux.probes = append(demux.probes, udpProbeExpectation{provider: cloneUDPAddr(provider), fields: fields, key: append([]byte(nil), key...), deadline: deadline})
	return nil
}

func EncodeUDPProbeFixture(fields UDPProbeFields, key []byte) []byte {
	frame, err := encodeUDPProbeFixture(fields, key)
	if err != nil {
		return nil
	}
	return frame
}

func encodeUDPProbeFixture(fields UDPProbeFields, key []byte) ([]byte, error) {
	if fields.Endpoint == nil || fields.Endpoint.IP.To4() == nil || fields.Endpoint.Port <= 0 || fields.Endpoint.Port > 65535 || len(key) == 0 {
		return nil, errors.New("probe fixture requires an IPv4 endpoint, valid port, and non-empty key")
	}
	frame := make([]byte, udpProbeFixtureLength)
	copy(frame[:4], "PRB1")
	copy(frame[4:20], fields.ProbeID[:])
	copy(frame[20:36], fields.Activation[:])
	endpointIP := fields.Endpoint.IP.To4()
	copy(frame[36:40], endpointIP)
	binary.BigEndian.PutUint16(frame[40:42], uint16(fields.Endpoint.Port))
	copy(frame[42:74], fields.Challenge[:])
	signature := hmac.New(sha256.New, key)
	_, _ = signature.Write(frame[:74])
	copy(frame[74:], signature.Sum(nil))
	return frame, nil
}

func parseUDPProbeFixture(payload, key []byte) (UDPProbeFields, bool) {
	var fields UDPProbeFields
	if len(payload) != udpProbeFixtureLength || string(payload[:4]) != "PRB1" || len(key) == 0 {
		return fields, false
	}
	signature := hmac.New(sha256.New, key)
	_, _ = signature.Write(payload[:74])
	if !hmac.Equal(payload[74:], signature.Sum(nil)) {
		return fields, false
	}
	port := int(binary.BigEndian.Uint16(payload[40:42]))
	if port <= 0 {
		return fields, false
	}
	copy(fields.ProbeID[:], payload[4:20])
	copy(fields.Activation[:], payload[20:36])
	fields.Endpoint = &net.UDPAddr{IP: net.IPv4(payload[36], payload[37], payload[38], payload[39]), Port: port}
	copy(fields.Challenge[:], payload[42:74])
	return fields, true
}

func (demux *UDPDemux) consumeProbeLocked(source *net.UDPAddr, payload []byte, now time.Time) bool {
	for index, outstanding := range demux.probes {
		fields, valid := parseUDPProbeFixture(payload, outstanding.key)
		if !valid || !now.Before(outstanding.deadline) || !sameUDPAddr(source, outstanding.provider) || !sameUDPProbeFields(fields, outstanding.fields) {
			continue
		}
		demux.probes = append(demux.probes[:index], demux.probes[index+1:]...)
		return true
	}
	return false
}

func sameUDPProbeFields(left, right UDPProbeFields) bool {
	return left.ProbeID == right.ProbeID && left.Activation == right.Activation && sameUDPAddr(left.Endpoint, right.Endpoint) && left.Challenge == right.Challenge
}
