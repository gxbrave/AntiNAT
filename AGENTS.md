# AntiNAT Agent Rules

## Authority and scope

- Read `.hermes/plans/v1-beta/00-master-orchestration.md` first.
- A worker implements only its assigned child plan. The master plan is orchestration authority, not a production-code task.
- Precedence is: master orchestration plan → assigned child plan → reviewed v0.8 execution plan → frozen contracts → `antinat.txt` product intent.
- On conflict, stop and write a contract-change handoff; never silently reinterpret a frozen contract.

## Startup gate

- `START-GATE` (`t_49810ae1`) is an intentionally unassigned, non-executable root gate. The embedded Dispatcher may show it as `ready`, but it cannot spawn a Worker.
- All 84 real development/review/integration cards depend directly or transitively on this gate and are intentionally `blocked`.
- Never assign or complete START-GATE until the user separately and explicitly approves starting development.
- The first development card allowed to run after that approval is `P01-DEV`.
- Never promote or dispatch `sub-agent-sol` and `sub-agent-luna` at the same time.
- Before every promotion/dispatch, inspect running and ready cards and enforce `.hermes/orchestration/policy.json`.

## Model and role policy

- Every Hermes profile uses `agent.reasoning_effort: xhigh`.
- `sub-agent-sol` is T0 and may implement or inspect core logic.
- `sub-agent-luna` and `sub-agent-deepseek` are T1 and must not implement core production logic.
- `sub-agent-deepseek` is the default specification reviewer.
- Implementers never approve their own work. Use fresh contexts for specification and quality/security review.

## Git isolation

- `integration/v1-beta` is orchestrator-owned.
- Each development card uses branch `ai/PXX-<slug>` in its own Git worktree from an exact integrated base SHA.
- Never let two coding workers share one writable worktree.
- Workers must not merge, rebase, cherry-pick, push, force-push, release, or clean another worker's branch.
- Dependencies are consumed only from integrated commits.
- Undeclared file edits are a specification-review failure.

## Repositories

- `origin` is `gxbrave/AntiNAT`, the primary orchestration and integration repository.
- `agent` is `gxbrave/AntiNAT-Agent`, reserved for the approved Agent deliverable.
- Do not mirror the entire monorepo to `agent`. Define and review a split/export procedure before the first Agent-repository push.
- No remote push is allowed during bootstrap unless the user explicitly requests it.

## Development contract

- Follow strict RED → GREEN → REFACTOR for every behavioral Story.
- No production code before its focused failing test, except explicitly permitted P02/P03 spikes.
- Run focused tests, affected package tests, then the required cumulative suite.
- Never fabricate network, platform, hardware, benchmark, test, or release evidence.
- Missing real infrastructure downgrades capability status; it does not permit fake PASS evidence.

## Handoffs and reviews

- Development writes `.hermes/handoffs/PXX.json` with exact base/head SHAs, commits, changed files, commands, exit codes, evidence, contract hashes, capability result, known limits, and cleanup status.
- A separate specification-review card checks plan compliance and ownership only.
- A separate quality/security-review card checks logic, races, security, leaks, portability, and test quality.
- Integration occurs only after both reviews pass. Maximum two bounded fix cycles before escalation.
- Integration writes `.hermes/handoffs/PXX-integrated.json` and records the integrated SHA.

## Completion reporting

Every task must report:

- changed files;
- exact tests and exit codes;
- branch and commit SHAs;
- evidence paths;
- contract changes or `none`;
- remaining limitations and residual risk;
- any deviation from the assigned plan.
