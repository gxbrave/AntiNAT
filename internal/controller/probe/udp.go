package probe

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"net"
	"net/netip"

	"github.com/gxbrave/AntiNAT/internal/protocol"
)

const ack1WireLen = 4 + 32 + 32 + ed25519.SignatureSize

// executeUDP performs exactly one WAN1 datagram exchange. The socket is bound
// to the authenticated provider source address, accepts exactly one ACK1-sized
// datagram from the requested endpoint, and never sends an ACK or other reply.
func (p *Provider) executeUDP(ctx context.Context, req *providerRequest, frame protocol.ProviderFrame, sourceIP []byte) providerResult {
	select {
	case <-ctx.Done():
		return providerResult{ProbeID: req.ProbeID, Reason: "timeout"}
	default:
	}
	remote, err := net.ResolveUDPAddr("udp4", req.Endpoint)
	if err != nil {
		return providerResult{ProbeID: req.ProbeID, Reason: "invalid_endpoint"}
	}
	listen := p.cfg.ListenUDP
	if listen == nil {
		listen = net.ListenUDP
	}
	conn, err := listen("udp4", &net.UDPAddr{IP: net.IP(sourceIP)})
	if err != nil {
		return providerResult{ProbeID: req.ProbeID, Reason: "unreachable"}
	}
	defer conn.Close()
	deadline := p.cfg.Clock().Add(p.cfg.ExchangeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return providerResult{ProbeID: req.ProbeID, Reason: "deadline_failed"}
	}
	wan1 := append(frame.Canonical(), frame.Signature...)
	if n, err := conn.WriteToUDP(wan1, remote); err != nil || n != len(wan1) {
		return providerResult{ProbeID: req.ProbeID, Reason: "send_failed"}
	}
	// One extra byte makes datagram truncation observable. A short or oversized
	// datagram is rejected rather than combined with any subsequent packet.
	ackBuf := make([]byte, ack1WireLen+1)
	n, peer, err := conn.ReadFromUDP(ackBuf)
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return providerResult{ProbeID: req.ProbeID, Reason: "no_ack"}
		}
		return providerResult{ProbeID: req.ProbeID, Reason: "no_ack"}
	}
	peerAP, remoteAP := netip.AddrPort{}, netip.AddrPortFrom(remote.AddrPort().Addr().Unmap(), remote.AddrPort().Port())
	if peer != nil {
		ap := peer.AddrPort()
		peerAP = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	if n != ack1WireLen || peer == nil || peerAP != remoteAP {
		return providerResult{ProbeID: req.ProbeID, Reason: "bad_ack"}
	}
	ackWire := ackBuf[:n]
	nodePub, err := hex.DecodeString(req.NodePublicKey)
	if err != nil || len(nodePub) != ed25519.PublicKeySize {
		return providerResult{ProbeID: req.ProbeID, Reason: "bad_request"}
	}
	ack, err := protocol.ParseProbeACK(ackWire, ed25519.PublicKey(nodePub))
	if err != nil || !verifyProbeACKBinding(frame, ack) {
		return providerResult{ProbeID: req.ProbeID, Reason: "bad_ack"}
	}
	chash := frame.ChallengeHash()
	return providerResult{
		ProbeID: req.ProbeID, Accepted: true,
		ChallengeHash: hex.EncodeToString(chash[:]),
		WAN1Frame:     hex.EncodeToString(wan1), ACK1Frame: hex.EncodeToString(ackWire),
		Reason: "ack_verified",
	}
}
