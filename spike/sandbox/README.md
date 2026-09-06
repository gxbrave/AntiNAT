# Hook-runner isolation feasibility spike

Question: can an untrusted hook process be prevented from using sockets, host files, process execution, inherited descriptors, secrets, unbounded CPU, unbounded allocation, and unbounded output?

Linux prototype:

- starts a fresh network and mount namespace;
- enters an empty chroot and drops from root to a provisioned, unique, non-nobody service UID/GID supplied via `ANTINAT_DEDICATED_UID` / `ANTINAT_DEDICATED_GID`; the shared nobody/nogroup identity (65534) is rejected and a missing or non-unique provision fails the dedicated-UID gate closed;
- passes a fixed, sanitized environment and no extra descriptors;
- sets `NoNewPrivileges`;
- installs an amd64 seccomp filter denying `socket`, `socketpair`, `connect`, `execve`, `execveat`, `ptrace`, `mount`, `fork`, and `vfork`;
- bounds descendants with `RLIMIT_NPROC` and a private process group that the parent kills as a tree after termination;
- caps child stdout/stderr at 64 KiB so unbounded hostile output cannot exhaust the parent;
- validates parent namespace separation, environment/FD isolation, socket/file/exec denial, an `RLIMIT_CPU` soft-limit termination proven by the limit-specific SIGXCPU observable, and an address-space-bounded allocation failure proven by the runtime's observable out-of-memory message. A generic SIGKILL is never accepted as resource-limit evidence.

The Linux test fails closed: if root, namespace, chroot, seccomp, the dedicated identity, or either resource bound is unavailable, the reported capability is unsupported with `webhook-only` fallback rather than a skipped PASS.

Windows prototype:

`windowsprobe/` cross-builds a native probe for restricted-token creation, `TokenHasRestrictions`, Job Object availability, and AppContainer API availability. No native Windows host was available, so it does not claim that malicious socket/file/exec/env/inherited-handle/CPU/allocation fixtures are isolated.

Verdict:

- Linux/amd64 isolated-JS feasibility: PASS on the recorded host, with this prototype's root-launch, dedicated-UID provision, and amd64-seccomp constraints. The recorded evidence names the provisioned dedicated identity (`antinat-sandbox`, UID/GID 12001 on the evidence host) and the limit-specific SIGXCPU/OOM termination proofs.
- Windows isolated-JS feasibility: NO_GO pending native restricted-token or AppContainer execution of the full malicious fixture matrix. Job Object alone is explicitly insufficient.
- Scope fallback: webhook-only on Windows and on any Linux environment missing the dedicated identity or a minimum gate; Linux isolated JS may proceed to contract freeze only with these minimum gates preserved.
