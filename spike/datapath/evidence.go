package datapath

const fallbackBufferBytesPerDirection = 32 * 1024

type Evidence struct {
	DataPath                              string `json:"data_path"`
	ZeroCopyEvidence                      string `json:"zero_copy_evidence"`
	PessimisticFallbackBytesPerConnection int    `json:"pessimistic_fallback_bytes_per_connection"`
}

func Classify(spliceEligible bool) Evidence {
	evidence := Evidence{
		DataPath:                              "go_tcp_copy_buffered",
		ZeroCopyEvidence:                      "not_applicable",
		PessimisticFallbackBytesPerConnection: 2 * fallbackBufferBytesPerDirection,
	}
	if spliceEligible {
		evidence.DataPath = "go_tcp_copy_splice_eligible"
		evidence.ZeroCopyEvidence = "eligible"
	}
	return evidence
}
