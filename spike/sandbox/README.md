# Hook-runner isolation feasibility spike

Question: can an untrusted hook process be prevented from using sockets, host files, process execution, inherited descriptors, secrets, unbounded CPU, and unbounded allocation?

Linux prototype:

- starts a fresh network and mount namespace;
- enters an empty chroot and drops from root to dedicated UID/GID 65534;
- passes a fixed, sanitized environment and no extra descriptors;
- sets `NoNewPrivileges`;
- installs an amd64 seccomp filter denying `socket`, `socketpair`, `connect`, `execve`, `execveat`, `ptrace`, and `mount`;
- validates parent namespace separation, environment/FD isolation, socket/file/exec denial, an `RLIMIT_CPU` loop kill, and an address-space-bounded allocation failure.

The Linux test fails closed: if root, namespace, chroot, seccomp, or either resource bound is unavailable, the reported capability is unsupported with `webhook-only` fallback rather than a skipped PASS.

Windows prototype:

`windowsprobe/` cross-builds a native probe for restricted-token creation, `TokenHasRestrictions`, Job Object availability, and AppContainer API availability. No native Windows host was available, so it does not claim that malicious socket/file/exec/env/inherited-handle/CPU/allocation fixtures are isolated.

Verdict:

- Linux/amd64 isolated-JS feasibility: PASS on the recorded host, with this prototype's root-launch and amd64-seccomp constraints.
- Windows isolated-JS feasibility: NO_GO pending native restricted-token or AppContainer execution of the full malicious fixture matrix. Job Object alone is explicitly insufficient.
- Scope fallback: webhook-only on Windows; Linux isolated JS may proceed to contract freeze only with these minimum gates preserved.
