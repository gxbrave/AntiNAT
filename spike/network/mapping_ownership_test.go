package network

import (
	"errors"
	"testing"
)

func TestFirstHopMappingNeverPublishesVerifiedWithoutUpstreamVantage(t *testing.T) {
	tests := []struct {
		mapping MappingState
		wan     WANState
		want    PublicationState
	}{
		{mapping: MappingFirstHop, wan: WANNotTested, want: PublicationNone},
		{mapping: MappingFirstHop, wan: WANOpenFromVantage, want: PublicationNone},
		{mapping: MappingPublicCandidate, wan: WANNotTested, want: PublicationUnverified},
		{mapping: MappingPublicCandidate, wan: WANOpenFromVantage, want: PublicationVerified},
	}
	for _, test := range tests {
		if got := ClassifyPublication(test.mapping, test.wan); got != test.want {
			t.Fatalf("mapping=%s wan=%s publication=%s, want %s", test.mapping, test.wan, got, test.want)
		}
	}
}

func TestNATPMPDeleteRejectsInternalPortZero(t *testing.T) {
	if err := ValidateNATPMPDelete(0); !errors.Is(err, ErrNATPMPDeleteAllForbidden) {
		t.Fatalf("port zero delete error = %v, want ErrNATPMPDeleteAllForbidden", err)
	}
	if err := ValidateNATPMPDelete(3111); err != nil {
		t.Fatalf("specific-port delete: %v", err)
	}
}

func TestUPnPDeleteRequiresExactOwnedEntry(t *testing.T) {
	expected := UPnPMapping{ExternalPort: 43111, Protocol: "TCP", InternalClient: "10.0.0.2", InternalPort: 3111, Description: "AntiNAT:node-a:forward-a"}
	if !CanDeleteUPnP(expected, expected) {
		t.Fatal("exact owned entry was not deletable")
	}
	mismatches := []UPnPMapping{
		{ExternalPort: 43112, Protocol: expected.Protocol, InternalClient: expected.InternalClient, InternalPort: expected.InternalPort, Description: expected.Description},
		{ExternalPort: expected.ExternalPort, Protocol: "UDP", InternalClient: expected.InternalClient, InternalPort: expected.InternalPort, Description: expected.Description},
		{ExternalPort: expected.ExternalPort, Protocol: expected.Protocol, InternalClient: "10.0.0.3", InternalPort: expected.InternalPort, Description: expected.Description},
		{ExternalPort: expected.ExternalPort, Protocol: expected.Protocol, InternalClient: expected.InternalClient, InternalPort: 9999, Description: expected.Description},
		{ExternalPort: expected.ExternalPort, Protocol: expected.Protocol, InternalClient: expected.InternalClient, InternalPort: expected.InternalPort, Description: "third-party"},
	}
	for _, observed := range mismatches {
		if CanDeleteUPnP(expected, observed) {
			t.Fatalf("mismatched entry was deletable: %+v", observed)
		}
	}
}

func TestMappingOwnershipStrengthIsProtocolSpecific(t *testing.T) {
	if got := OwnershipFor(ProtocolPCP); got != OwnershipStrongProtocol {
		t.Fatalf("PCP ownership = %s", got)
	}
	if got := OwnershipFor(ProtocolNATPMP); got != OwnershipWeakLease {
		t.Fatalf("NAT-PMP ownership = %s", got)
	}
	if got := OwnershipFor(ProtocolUPnP); got != OwnershipBestEffortQueryThenDelete {
		t.Fatalf("UPnP ownership = %s", got)
	}
}

func TestLayeredObservationRequiresUpstreamOpenForVerifiedPublication(t *testing.T) {
	mapping, wan, publication, err := ClassifyLayeredObservation(LayeredObservation{FirstHopTuple: "100.64.0.2:3111", UpstreamTuple: "11.0.0.2:42000"})
	if err != nil {
		t.Fatal(err)
	}
	if mapping != MappingFirstHop || wan != WANNotTested || publication != PublicationNone {
		t.Fatalf("closed upstream observation = %s/%s/%s", mapping, wan, publication)
	}
	mapping, wan, publication, err = ClassifyLayeredObservation(LayeredObservation{FirstHopTuple: "100.64.0.2:3111", UpstreamTuple: "11.0.0.2:42000", UpstreamOpen: true})
	if err != nil {
		t.Fatal(err)
	}
	if mapping != MappingPublicCandidate || wan != WANOpenFromVantage || publication != PublicationVerified {
		t.Fatalf("open upstream observation = %s/%s/%s", mapping, wan, publication)
	}
	if _, _, _, err := ClassifyLayeredObservation(LayeredObservation{FirstHopTuple: "same", UpstreamTuple: "same", UpstreamOpen: true}); !errors.Is(err, ErrInvalidLayeredObservation) {
		t.Fatalf("same tuple error = %v, want ErrInvalidLayeredObservation", err)
	}
}
