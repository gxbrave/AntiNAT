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

var requiredGateNames = []string{
	"dedicated_uid",
	"sanitized_env",
	"no_inherited_fd",
	"no_new_privileges",
	"network_namespace",
	"mount_namespace_empty_root",
	"seccomp_socket_connect",
	"seccomp_exec",
	"file_denied",
	"cpu_bounded",
	"allocation_bounded",
}

func unsupportedResult(detail string) Result {
	result := Result{
		Supported: false,
		Fallback:  "webhook-only",
		Gates:     make(map[string]GateResult, len(requiredGateNames)),
	}
	for _, name := range requiredGateNames {
		result.Gates[name] = GateResult{Detail: detail}
	}
	return result
}
