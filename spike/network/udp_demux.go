package network

import (
	"bytes"
	"errors"
	"net"
	"sync"
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

type udpSession struct {
	lastSeen time.Time
	sourceIP string
}

var ErrDemuxStateFull = errors.New("UDP demux state capacity exhausted")

// UDPDemux is a deliberately fixed-format spike used to prove matching rules;
// it is not an RFC 8489 codec. All mutable state is protected by mu and has a
// finite capacity plus an expiry path.
type UDPDemux struct {
	mu                   sync.Mutex
	stun                 []stunExpectation
	probes               []udpProbeExpectation
	maxSessions          int
	maxSessionsPerSource int
	maxSTUN              int
	maxProbes            int
	sessionTTL           time.Duration
	sessions             map[string]udpSession
	probeAgent           *ProbeAgent
}

func NewUDPDemux(maxSessions int) *UDPDemux {
	return NewUDPDemuxWithLimits(maxSessions, maxSessions, 128, 128, time.Minute)
}

func NewUDPDemuxWithLimits(maxSessions, maxSessionsPerSource, maxSTUN, maxProbes int, sessionTTL time.Duration) *UDPDemux {
	if maxSessions <= 0 {
		maxSessions = 1
	}
	if maxSessionsPerSource <= 0 {
		maxSessionsPerSource = 1
	}
	if maxSTUN <= 0 {
		maxSTUN = 1
	}
	if maxProbes <= 0 {
		maxProbes = 1
	}
	if sessionTTL <= 0 {
		sessionTTL = time.Minute
	}
	return &UDPDemux{maxSessions: maxSessions, maxSessionsPerSource: maxSessionsPerSource, maxSTUN: maxSTUN, maxProbes: maxProbes, sessionTTL: sessionTTL, sessions: make(map[string]udpSession)}
}

func (demux *UDPDemux) AttachProbeAgent(agent *ProbeAgent) {
	demux.mu.Lock()
	defer demux.mu.Unlock()
	demux.probeAgent = agent
}

func (demux *UDPDemux) ExpectSTUN(server *net.UDPAddr, class STUNClass, transaction [12]byte, deadline time.Time) error {
	if server == nil || !deadline.After(time.Time{}) {
		return errors.New("STUN expectation requires a server and deadline")
	}
	demux.mu.Lock()
	defer demux.mu.Unlock()
	demux.purgeLocked(deadline.Add(-time.Nanosecond))
	if len(demux.stun) >= demux.maxSTUN {
		return ErrDemuxStateFull
	}
	demux.stun = append(demux.stun, stunExpectation{server: cloneUDPAddr(server), class: class, transaction: transaction, deadline: deadline})
	return nil
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
	kind, _, _ := demux.ClassifyWithResponse(source, payload, now)
	return kind
}

// ClassifyWithResponse integrates the provider-hidden challenge ingress path.
// Accepted WAN1 frames return the ACK bytes that must be sent using the same
// unconnected socket and the signed receipt for the control channel.
func (demux *UDPDemux) ClassifyWithResponse(source *net.UDPAddr, payload []byte, now time.Time) (DatagramKind, []byte, *ProbeReceipt) {
	demux.mu.Lock()
	defer demux.mu.Unlock()
	demux.purgeLocked(now)
	if source == nil {
		return DatagramDropped, nil, nil
	}
	if bytes.HasPrefix(payload, []byte("WAN1")) {
		if demux.probeAgent == nil || len(source.IP.To4()) != 4 {
			return DatagramDropped, nil, nil
		}
		frame, err := ParseProviderFrame(payload)
		if err != nil {
			return DatagramDropped, nil, nil
		}
		ip := source.IP.To4()
		var sourceIP [4]byte
		copy(sourceIP[:], ip)
		outcome, ack, receipt := demux.probeAgent.HandleIngress(sourceIP, frame, now)
		if outcome != ProbeAccepted {
			return DatagramDropped, nil, nil
		}
		return DatagramProbe, ack.MarshalBinary(), &receipt
	}
	if demux.consumeProbeLocked(source, payload, now) {
		return DatagramProbe, nil, nil
	}
	if bytes.HasPrefix(payload, []byte("STN1")) {
		class, transaction, valid := parseSTUNFixture(payload)
		if !valid {
			return DatagramDropped, nil, nil
		}
		for index, outstanding := range demux.stun {
			if !now.Before(outstanding.deadline) || !sameUDPAddr(source, outstanding.server) || class != outstanding.class || transaction != outstanding.transaction {
				continue
			}
			demux.stun = append(demux.stun[:index], demux.stun[index+1:]...)
			return DatagramSTUN, nil, nil
		}
		return DatagramDropped, nil, nil
	}
	if bytes.HasPrefix(payload, []byte("PRB1")) || bytes.HasPrefix(payload, []byte("ACK1")) || bytes.HasPrefix(payload, []byte("ARM1")) {
		return DatagramDropped, nil, nil
	}
	return demux.classifyDataLocked(source, now), nil, nil
}

func (demux *UDPDemux) classifyDataLocked(source *net.UDPAddr, now time.Time) DatagramKind {
	key, sourceIP, ok := udpSessionKeys(source)
	if !ok {
		return DatagramDropped
	}
	if session, exists := demux.sessions[key]; exists {
		session.lastSeen = now
		demux.sessions[key] = session
		return DatagramData
	}
	if len(demux.sessions) >= demux.maxSessions || demux.sessionsFromSourceLocked(sourceIP) >= demux.maxSessionsPerSource {
		return DatagramDropped
	}
	demux.sessions[key] = udpSession{lastSeen: now, sourceIP: sourceIP}
	return DatagramData
}

func (demux *UDPDemux) sessionsFromSourceLocked(sourceIP string) int {
	count := 0
	for _, session := range demux.sessions {
		if session.sourceIP == sourceIP {
			count++
		}
	}
	return count
}

func (demux *UDPDemux) purgeLocked(now time.Time) {
	stun := demux.stun[:0]
	for _, expectation := range demux.stun {
		if now.Before(expectation.deadline) {
			stun = append(stun, expectation)
		}
	}
	demux.stun = stun
	probes := demux.probes[:0]
	for _, expectation := range demux.probes {
		if now.Before(expectation.deadline) {
			probes = append(probes, expectation)
		}
	}
	demux.probes = probes
	for key, session := range demux.sessions {
		if !now.Before(session.lastSeen.Add(demux.sessionTTL)) {
			delete(demux.sessions, key)
		}
	}
}

func (demux *UDPDemux) Expire(now time.Time) {
	demux.mu.Lock()
	defer demux.mu.Unlock()
	demux.purgeLocked(now)
}

func (demux *UDPDemux) CloseSession(source *net.UDPAddr) {
	key, _, ok := udpSessionKeys(source)
	if !ok {
		return
	}
	demux.mu.Lock()
	defer demux.mu.Unlock()
	delete(demux.sessions, key)
}

func (demux *UDPDemux) SessionCount() int {
	demux.mu.Lock()
	defer demux.mu.Unlock()
	return len(demux.sessions)
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

func udpSessionKeys(source *net.UDPAddr) (string, string, bool) {
	if source == nil || source.IP == nil || source.Port <= 0 || source.Port > 65535 {
		return "", "", false
	}
	return source.String(), source.IP.String(), true
}
