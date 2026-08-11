package sandbox

type GateResult struct {
	Pass   bool
	Detail string
}

type Result struct {
	Supported bool
	Fallback  string
	Gates     map[string]GateResult
}
