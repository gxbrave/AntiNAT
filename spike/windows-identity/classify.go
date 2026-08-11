package windowsidentity

// ClassifyCapability computes the overall Windows-identity capability from the
// individual probe results. It fails closed: DPAPI, a protected key ACL, and a
// service SID alone are not enough. Managed or manual Defender firewall
// ownership must be actually validated before the identity path can be claimed
// supported; until then the capability remains UNSUPPORTED.
func ClassifyCapability(dpapiMachineRoundTrip, protectedKeyACL bool, serviceSID, defenderRuleMode string) string {
	if defenderRuleMode == "UNVALIDATED" || defenderRuleMode == "" {
		return "UNSUPPORTED"
	}
	if dpapiMachineRoundTrip && protectedKeyACL && serviceSID != "" {
		return "SUPPORTED_WITH_LIMITS"
	}
	return "UNSUPPORTED"
}
