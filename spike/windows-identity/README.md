# Windows service identity, DPAPI, ACL, and Defender feasibility spike

Question: can Windows Agent keys be machine-bound and ACL-restricted under a stable service identity, and can Defender firewall ownership be managed without overclaiming support?

`probe/` cross-builds a native Windows program that, when executed on Windows:

- round-trips test key material through DPAPI with `CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN`;
- writes a temporary key fixture, replaces its inherited DACL with a protected ACL granting only the current token user and LocalSystem, then reads the descriptor back;
- requires an `S-1-5-80-*` NT SERVICE SID in the current process token.

The probe intentionally does not add/remove Defender firewall rules. Native qualification must test both supported deployment modes:

1. managed mode: create an installation-owned rule, query exact protocol/port/program/service ownership, survive service restart/upgrade, and remove only the owned rule;
2. manual mode: make no firewall mutation, report the required rule precisely, and never claim ingress is open.

Verdict: NO_GO for Windows promotion in this run.

The Go probe cross-builds for Windows/amd64, but no native Windows host was provided. Therefore DPAPI behavior, service SID presence, protected ACL semantics, Defender managed/manual rule ownership, restart, upgrade, and cleanup remain unvalidated. Windows identity/firewall capability stays build-only/unsupported rather than beta or GA.
