# P02 RED evidence log

All failures below were observed before the corresponding GREEN implementation.

| Story | RED command | Expected observed failure |
|---|---|---|
| TCP shared port | `go test ./spike/network -run '^TestTCPSharedPortRoutesListenerAndConnectedSocketsByFourTuple$' -count=1 -v` | build failed: `undefined: OpenTCPSharedPort` |
| TCP exact rebind | `go test ./spike/network -run '^TestTCPSharedPortCloseAllowsExactTupleRebind$' -count=1 -v` | build failed: `undefined: OpenTCPSharedPortAt` |
| TCP Linux option discovery | same focused routing command after the first minimal `SO_REUSEADDR` implementation | runtime failed with `bind: address already in use`; adding Linux `SO_REUSEPORT` to every participant made the four-tuple fixture GREEN, while the process-lock Story fences reuse-group interference |
| PortRegistry | `go test ./spike/network -run '^TestPortRegistryAcquirePortZeroOwnsActualSocketAtomically$' -count=1 -v` | build failed: `undefined: NewPortRegistry` |
| Process ownership | `go test ./spike/network -run '^TestProcessLockBlocksConcurrentInstallerProcess$' -count=1 -v` | build failed: `undefined: AcquireProcessLock`, `undefined: ErrInstanceLocked` |
| UDP STUN demux | `go test ./spike/network -run '^TestUDPDemuxConsumesSTUNOnlyForFullOutstandingMatch$' -count=1 -v` | build failed on missing demux fixture symbols |
| UDP authenticated probe demux | `go test ./spike/network -run '^TestUDPDemuxConsumesProbeOnlyForAuthenticatedOutstandingMatch$' -count=1 -v` | build failed on missing `UDPProbeFields`, encoder, and expectation API |
| UDP exact-source reply | `go test ./spike/network -run '^TestSingleUDPSocketForwardsTargetResponseFromPublishedTuple$' -count=1 -v` | build failed: `undefined: OpenSingleUDPSocket` |
| UDP ICMP observation | `go test ./spike/network -run '^TestSingleUDPSocketContinuesAfterCorrelatedICMPPortUnreachable$' -count=1 -v` | initial assertion failed because this Linux kernel did not surface the localhost ICMP error to the unconnected socket; the test was corrected to assert the required observable behavior: the loop remains alive and receives the following datagram |
| Hidden challenge | `go test ./spike/network -run '^TestHiddenChallengeRequiresWANIngressBeforeAuthenticatedCompletion$' -count=1 -v` | build failed on missing arm/agent/provider-frame/completion APIs |
| Mapping ownership | `go test ./spike/network -run '^(TestFirstHop|TestNATPMP|TestUPnP|TestMappingOwnership)' -count=1 -v` | build failed on missing publication and ownership APIs |
| Layered NAT | `go test -tags=netns ./spike/network -run '^TestLayeredNATWithRealUPnPDaemonAndUpstreamSTUN$' -count=1 -v` | failed because the lab script did not yet exist |
| Layered NAT real result discovery | same netns command after the initial lab | real miniupnpd first rejected an explicitly configured CGN address; with upstream coturn STUN it classified the two-layer topology as restrictive/symmetric and returned UPnP `501 Action Failed`. The final test treats this as the expected `NO_GO` result rather than fabricating a successful mapping |
