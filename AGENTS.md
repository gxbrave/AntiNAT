# AntiNAT Agent Rules

## Authority and scope

- Read `.hermes/plans/v1-beta/00-master-orchestration.md` first.
- A worker implements only its assigned child plan. The master plan is orchestration authority, not a production-code task.
- Precedence is: master orchestration plan → assigned child plan → reviewed v0.8 execution plan → frozen contracts → `antinat.txt` product intent.
- On conflict, stop and write a contract-change handoff; never silently reinterpret a frozen contract.

## Startup gate

- `START-GATE` (`t_49810ae1`) is an intentionally unassigned, non-executable root gate. The embedded Dispatcher may show it as `ready`, but it cannot spawn a Worker.
- All 84 real development/review/integration cards depend directly or transitively on this gate and are intentionally `blocked`.
- START-GATE was completed only after the user separately and explicitly approved starting development; never reopen or repurpose it.
- The first development card allowed to run after that approval is `P01-DEV`.
- The `sub-agent-sol` / `sub-agent-luna` mutual exclusion applies only to `*-DEV` implementation cards. Never run a Sol DEV card and a Luna DEV card at the same time. Project-supervisor, specification review, quality/security review, specialist review, and integration activity are not part of that development mutex.
- Before every promotion/dispatch, inspect running and ready cards and enforce `.hermes/orchestration/policy.json`.
- The user has authorized normal Kanban progression without a new user command for every gate. Keep `auto_promote_children: false`: the persistent supervisor must validate each gate and explicitly unblock only eligible cards.

## Model and role policy

- Every development/review/integration Worker profile uses `agent.reasoning_effort: xhigh`.
- The dedicated `sub-agent-sol-supervisor` is a clone of `sub-agent-sol` used only for project control. It uses `medium`, runs outside Kanban Worker concurrency, and must never implement production code, perform a review, approve a review, integrate, push, or release.
- `sub-agent-sol` is T0 and may implement or inspect core logic.
- `sub-agent-luna` and `sub-agent-deepseek` are T1. DeepSeek does not implement core production logic; Luna may implement only the narrowly bounded review-listed remediation exception below, not new core features.
- `sub-agent-deepseek` is the default specification reviewer and the fresh-context specification plus full quality/security reviewer for repair cycles. Separate review cards must use separate fresh sessions and remain subject to per-profile concurrency 1.
- `sub-agent-luna` owns bounded repair cycles 1 through 5, including narrowly scoped core fixes explicitly listed by an independent failed review. This user-authorized exception does not allow new core features, scope broadening, self-review, integration, push, or release.
- `sub-agent-sol` must not be used for remediation before Luna repair cycle 5 has completed and a fresh DeepSeek review still FAILs. After that event, one Sol fallback remediation is authorized; its work still requires fresh DeepSeek reviews.
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
- When a DEV Worker blocks as `review-required`, the supervisor may mark that DEV lifecycle card `done` only after mechanically verifying the candidate branch/head and handoff. This means the implementation stage is complete; it is not review approval.
- A separate specification-review card checks plan compliance and ownership only.
- A separate quality/security-review card checks logic, races, security, leaks, portability, and test quality.
- Integration occurs only after both reviews pass. Up to five bounded Luna repair cycles are authorized, each followed by fresh DeepSeek specification and full quality/security reviews. If cycle 5 still fails, route one fallback remediation to Sol and then rerun fresh DeepSeek reviews. If the Sol fallback still fails, or a true product decision/credential/contract waiver is required, escalate to the user.
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
