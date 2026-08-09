package network

import "errors"

type MappingState string

const (
	MappingFirstHop        MappingState = "FIRST_HOP_MAPPED"
	MappingPublicCandidate MappingState = "PUBLIC_CANDIDATE"
)

type WANState string

const (
	WANNotTested       WANState = "NOT_TESTED"
	WANOpenFromVantage WANState = "OPEN_FROM_VANTAGE"
)

type PublicationState string

const (
	PublicationNone       PublicationState = "NONE"
	PublicationUnverified PublicationState = "PUBLISHED_UNVERIFIED"
	PublicationVerified   PublicationState = "PUBLISHED_VERIFIED"
)

func ClassifyPublication(mapping MappingState, wan WANState) PublicationState {
	if mapping != MappingPublicCandidate {
		return PublicationNone
	}
	if wan == WANOpenFromVantage {
		return PublicationVerified
	}
	return PublicationUnverified
}

var ErrNATPMPDeleteAllForbidden = errors.New("NAT-PMP internal port 0 delete-all is forbidden")

func ValidateNATPMPDelete(internalPort uint16) error {
	if internalPort == 0 {
		return ErrNATPMPDeleteAllForbidden
	}
	return nil
}

type UPnPMapping struct {
	ExternalPort   uint16
	Protocol       string
	InternalClient string
	InternalPort   uint16
	Description    string
}

func CanDeleteUPnP(expected, observed UPnPMapping) bool {
	return expected == observed
}

type MappingProtocol string

type OwnershipStrength string

const (
	ProtocolPCP    MappingProtocol = "PCP"
	ProtocolNATPMP MappingProtocol = "NAT-PMP"
	ProtocolUPnP   MappingProtocol = "UPnP"

	OwnershipStrongProtocol            OwnershipStrength = "STRONG_PROTOCOL_OWNERSHIP"
	OwnershipWeakLease                 OwnershipStrength = "WEAK_LEASE_OWNERSHIP"
	OwnershipBestEffortQueryThenDelete OwnershipStrength = "BEST_EFFORT_QUERY_THEN_DELETE"
)

func OwnershipFor(protocol MappingProtocol) OwnershipStrength {
	switch protocol {
	case ProtocolPCP:
		return OwnershipStrongProtocol
	case ProtocolNATPMP:
		return OwnershipWeakLease
	case ProtocolUPnP:
		return OwnershipBestEffortQueryThenDelete
	default:
		return ""
	}
}
