package network

import (
	"bytes"
	"net"
	"time"
)

type DatagramKind string

const (
	DatagramSTUN    DatagramKind = "STUN"
	DatagramProbe   DatagramKind = "PROBE"
	DatagramData    DatagramKind = "DATA"
	DatagramDropped DatagramKind = "DROPPED"
)

type STUNClass byte

const (
	STUNRequest         STUNClass = 0
	STUNSuccessResponse STUNClass = 1
)

type stunExpectation struct {
	server      *net.UDPAddr
	class       STUNClass
	transaction [12]byte
	deadline    time.Time
}

// UDPDemux is a deliberately fixed-format spike used to prove matching rules;
// it is not an RFC 8489 codec.
type UDPDemux struct {
	stun        []stunExpectation
	probes      []udpProbeExpectation
	maxSessions int
	sessions    map[string]struct{}
}

func NewUDPDemux(maxSessions int) *UDPDemux {
	return &UDPDemux{maxSessions: maxSessions, sessions: make(map[string]struct{})}
}

func (demux *UDPDemux) ExpectSTUN(server *net.UDPAddr, class STUNClass, transaction [12]byte, deadline time.Time) {
	demux.stun = append(demux.stun, stunExpectation{
		server:      cloneUDPAddr(server),
		class:       class,
		transaction: transaction,
		deadline:    deadline,
	})
}

func EncodeSTUNFixture(class STUNClass, transaction [12]byte) []byte {
	frame := make([]byte, 17)
	copy(frame[:4], "STN1")
	frame[4] = byte(class)
	copy(frame[5:], transaction[:])
	return frame
}

func parseSTUNFixture(payload []byte) (STUNClass, [12]byte, bool) {
	var transaction [12]byte
	if len(payload) != 17 || !bytes.Equal(payload[:4], []byte("STN1")) {
		return 0, transaction, false
	}
	copy(transaction[:], payload[5:])
	return STUNClass(payload[4]), transaction, true
}

func (demux *UDPDemux) Classify(source *net.UDPAddr, payload []byte, now time.Time) DatagramKind {
	if demux.consumeProbe(source, payload, now) {
		return DatagramProbe
	}
	class, transaction, looksLikeSTUN := parseSTUNFixture(payload)
	if looksLikeSTUN {
		for index, outstanding := range demux.stun {
			if now.After(outstanding.deadline) || !sameUDPAddr(source, outstanding.server) || class != outstanding.class || transaction != outstanding.transaction {
				continue
			}
			demux.stun = append(demux.stun[:index], demux.stun[index+1:]...)
			return DatagramSTUN
		}
	}
	return demux.classifyData(source)
}

func (demux *UDPDemux) classifyData(source *net.UDPAddr) DatagramKind {
	key := source.String()
	if _, exists := demux.sessions[key]; exists {
		return DatagramData
	}
	if demux.maxSessions <= 0 || len(demux.sessions) >= demux.maxSessions {
		return DatagramDropped
	}
	demux.sessions[key] = struct{}{}
	return DatagramData
}

func sameUDPAddr(left, right *net.UDPAddr) bool {
	return left != nil && right != nil && left.Port == right.Port && left.Zone == right.Zone && left.IP.Equal(right.IP)
}

func cloneUDPAddr(address *net.UDPAddr) *net.UDPAddr {
	if address == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), address.IP...), Port: address.Port, Zone: address.Zone}
}
