# AntiNAT UI Design Direction

> Status: **FROZEN at P17 (Story 1)**. This document is the normative UI/UX
> design contract for the v1.0-beta web UI. It derives from the reviewed v0.8
> plan §9.4 and §11.6 (item 8). Later UI work follows it without
> reinterpretation. UI code that contradicts a token, a state rule, or the
> evidence-chain rail below is a review failure.

## 1. Mode and the jobs the console serves

The whole UI is **Operate** mode: the person on the other side of the screen is
completing a task, not being marketed at. The product slop test applies — a
category-fluent operator must trust the interface immediately, so the interface
disappears into the task, standard affordances are not reinvented, and surprise
is reserved for moments (never for pages).

Three concrete jobs:

1. **Public home (`/`)** — a stranger or a low-engagement visitor finds a
   published service from a flat card directory. The card tells the truth:
   name, one-line description, protocol, and *verification state*. A verified
   link is a normal link. An unverified or stale link is a risk that is shown
   continuously, never silently. A card whose node is offline/removed is grayed
   and red-lined. Nothing on this page implies the operator's identity or the
   controller's internals.
2. **Admin shell (`/admin`, four tabs)** — an operator runs the controller:
   Home Settings (navigation CRUD + preview), Forwards, Nodes, Global Settings.
   This is a dense data surface: every row shows current and last-known
   facts, each with its durable state label.
3. **Deployment flow** — the operator creates a node and gets a secret-safe
   install command plus a one-time token. The token and the command never share
   a surface; the command never contains a secret.

### Status reality check (design critique of product jobs/states)

- A Forward has **nine orthogonal axes** (frozen `docs/state-model.md` §1). No
  single aggregate may replace an axis value, and an aggregate is never a
  protocol fact. Green must mean one exact thing: the axis reached its frozen
  "good" value, *and* when an aggregate is green every contributing axis is
  green or explicitly not-required.
- `UNKNOWN` and `FAILED` are different facts and must read differently.
  `OFFLINE` is a control-plane fact, `STALE` is a publication fact,
  `DELETE_PENDING_OFFLINE` is a deletion-intent fact. The UI distinguishes all
  five in **text and shape**, never color alone.
- A `PUBLISHED_UNVERIFIED` endpoint must never be presented as verified. A
  `FIRST_HOP_MAPPED` mapping must never be presented as a public endpoint.
- Failure and emptiness are moments for direction, not mood. An empty list
  teaches the next action; an error names the problem and the recovery.

## 2. Signature: the evidence-chain rail

The single visual identity of AntiNAT is the **evidence-chain rail** shown in
the Forward detail. It is a pipeline of the six independent facts an operator
actually needs to judge one Forward, in dependency order, with each ring
showing **real orthogonal evidence and its breakpoint**:

```text
Control → Listener → Gateway/Mapping → STUN/Keepalive → WAN Vantage → Target
```

| Rail step | Axis (exact frozen values) | Good | Degraded/working | Broken |
|---|---|---|---|---|
| Control | `control_state` | `ONLINE` | — | `OFFLINE` |
| Listener | `listener_state` | `READY` | `STARTING` | `STOPPED`, `ERROR` |
| Gateway/Mapping | `mapping_state` | `PUBLIC_CANDIDATE`, `NOT_REQUIRED` | `ACQUIRING`, `FIRST_HOP_MAPPED` | `LOST`, `ERROR` |
| STUN/Keepalive | `keepalive_state` | `HEALTHY`, `NOT_REQUIRED` | `DEGRADED` | `LOST` |
| WAN Vantage | `wan_reachability_state` | `OPEN_FROM_VANTAGE` | `PROBING`, `NO_INDEPENDENT_VANTAGE`, `PROBE_INFRA_UNAVAILABLE` | `REJECTED`, `TIMEOUT` |
| Target | `target_health_state` | `PASS` | `SKIPPED` | `FAIL`, `UNSUPPORTED` |

Rules that keep the rail honest:

- Each ring displays its axis **label, value, and evidence source** (the
  durable update time / probe round it came from). A ring with no data shows
  `Not tested`-style value — the neutral shape — never a hollow success.
- The rail is **not a decorative stepper**: a step is reachable only through
  its real data. If a ring has no evidence for the Forward it renders in its
  neutral state, and the "status" summary at the top is derived, labeled
  "derived", and never claims a fact an axis does not hold.
- Pipeline semantics for the derived status line: good only when every ring is
  good or not-required. Otherwise it shows the **first broken ring**.
- No gradient, glass, sparkline, fake metric, or meaningless animation may be
  added around the rail. Motion is permitted only for the low-frequency
  highlight of a ring whose value just changed (≤150 ms, interruptible, and
  also reflected as text/shape).

Advanced NAT evidence (ownership, layer versions, journal refs, per-layer
constraints, probe details) is **progressively disclosed**: collapsed by
default behind `<details>`/disclosure buttons, opened on demand, never
flattened into the main list. Main lists prioritize the current task and
recoverable errors.

## 3. Semantic color tokens (frozen)

Seven semantic tokens, used exactly as named:

| Token | Default | Meaning | Use |
|---|---|---|---|
| `--ac-canvas` | `#FCFCFA` | Page canvas | Body background (white/near-white) |
| `--ac-panel` | `#FFFFFF` | Raised surface | Cards, sidebar/toolbar, table header, dialog |
| `--ac-ink` | `#1B1F23` | Primary text | Body, headings, values |
| `--ac-ink-muted` | `#5A626B` | Secondary text | Labels, captions, timestamps |
| `--ac-line` | `#E3E6EA` | Hairline structure | Dividers, borders of panels & tables |
| `--ac-action` | `#2A5DB0` | Primary action / focus / selection | Primary buttons, active nav, focus ring, links |
| `--ac-danger` | `#B4232C` | Destructive / serious | Destructive buttons, `FAILED`/`OFFLINE`/`DELETE_PENDING_OFFLINE` status |

**Signal tints** (status palette) — derived, low-saturation, dark enough for
4.5:1 on `--ac-canvas`/`--ac-panel`:

| Token | Default | Status meaning |
|---|---|---|
| `--ac-signal-ok` | `#1A6B46` | Verified / healthy / passed |
| `--ac-signal-warn` | `#8A5A00` | Unverified / stale / degraded / risk |
| `--ac-signal-bad` | `#B4232C` (= `--ac-danger`) | Failed / offline / broken |

Only these three signal values exist for status; no other hue may signify
state. Theme does not flip light/dark — v1.0-beta UI is light by contract.
Tints of the tokens for hover surfaces (`--ac-action` at ~6% alpha) and table
zebra are derived in CSS from these tokens only.

## 4. Type

One family carries everything (Operate mode: one well-tuned sans; display
faces are a ban in product UI). Font stacks are system-native (no font CDN, no
self-hosted binary, offline-friendly):

- **Latin / default:** `system-ui, -apple-system, "Segoe UI", Roboto,
  "Helvetica Neue", Arial, "Noto Sans", sans-serif`
- **Chinese (first when `lang="zh"`):** `"PingFang SC", "Hiragino Sans GB",
  "Microsoft YaHei", "Noto Sans CJK SC", "Source Han Sans SC",
  "WenQuanYi Micro Hei", sans-serif`
- **Data / code / command / token display:** `ui-monospace, SFMono-Regular,
  Menlo, Consolas, "Liberation Mono", monospace`

**Type scale** (fixed `rem`, tight ratio ~1.2):

| Step | Size / weight / line-height | Role |
|---|---|---|
| `--ac-type-xs` | 0.75rem / 400 / 1.5 | Captions, metadata |
| `--ac-type-sm` | 0.8125rem / 400 / 1.5 | Labels, table cells, helper text |
| `--ac-type-md` | 0.9375rem / 400 / 1.55 | Body, form values |
| `--ac-type-md-semibold` | 0.9375rem / 600 | Buttons, active tab label |
| `--ac-type-lg` | 1.0625rem / 500 / 1.5 | Card titles, subheaders |
| `--ac-type-xl` | 1.25rem / 600 / 1.4 | Page/tab headings |
| `--ac-type-2xl` | 1.5rem / 600 / 1.35 | Home h1 |

Rules:

- `font-variant-numeric: tabular-nums` on all numerals, rates, counts, times,
  ports, and durations (no layout shift when values change).
- `text-wrap: balance` on headings; `text-wrap: pretty` on body/descriptions.
- Weights are 400 / 500 / 600 only. Never below 400. Headings are 500–600, not
  a bold+uppercase costume.
- The `t` (translate) key function renders system strings; user content is
  single-value and never translated. System strings are bilingual CN=default,
  EN alternate, one string per key.

## 5. Spacing, radius, elevation, motion tokens

**Spacing** (4px grid): `--ac-space-1:4px`, `--ac-space-2:8px`,
`--ac-space-3:12px`, `--ac-space-4:16px`, `--ac-space-5:20px`,
`--ac-space-6:24px`, `--ac-space-8:32px`, `--ac-space-12:48px`.
Groups are tight (1× within a card), separation is generous (3×–4× between
sections), and there is more space above a heading than below it.

**Radius** (concentric: outer = inner + padding):
`--ac-radius-sm:4px` (inputs, chips), `--ac-radius-md:8px` (buttons, cards,
panels), `--ac-radius-lg:12px` (dialogs).

**Elevation** — layered transparent shadows; borders communicate structure, not
depth:
`--ac-shadow-1:0 1px 2px rgb(23 28 33 / 0.06)` (raised panels),
`--ac-shadow-2:0 4px 14px rgb(23 28 33 / 0.10)` (dialogs, dropdowns).
Zero-blur block shadows are a costume and are banned.

**Motion** — for low-frequency state changes only, must be interruptible,
≤150 ms for interactive transitions, and never the only feedback channel (a
static text/shape cue always accompanies it). Easing
`cubic-bezier(0.2, 0, 0, 1)`.

```css
:root {
  --ac-duration: 150ms;
  --ac-ease: cubic-bezier(0.2, 0, 0, 1);
}
@media (prefers-reduced-motion: reduce) {
  :root { --ac-duration: 0ms; }
}
```

No page-load orchestration, no entrance on every section, no hover-driven
animation. Transitions list exact properties (never `transition: all`).

## 6. Durable status labels (no color-only status)

The five distinguish-in-prose states and their required label/shape:

| Durable state | Text label | Shape/icon | Token |
|---|---|---|---|
| `UNKNOWN` | **未知 / Unknown** | hollow dot `○` | `--ac-ink-muted` |
| `FAILED` | **失败 / Failed** | filled square `■` | `--ac-signal-bad` |
| `OFFLINE` | **离线 / Offline** | hollow square `□` | `--ac-signal-bad` |
| `STALE` | **过期 / Stale** | triangle `△` | `--ac-signal-warn` |
| `DELETE_PENDING_OFFLINE` | **待删除(离线) / Delete pending (offline)** | square+slash `□/` | `--ac-danger` |

A status line always reads `<icon> <label> — <evidence detail>`, e.g.
`□ 离线 · Offline — last seen 2026-09-02 09:41`. The label is duplicated text,
so a color-blind or braille user gets the same fact. Screens never rely on
green/red alone.

Other frozen axis values map onto the signal tints (OK/good → `--ac-signal-ok`;
probing/degraded/unverified → `--ac-signal-warn`; broken → `--ac-signal-bad`;
not-tested/not-required/unknown → `--ac-ink-muted`) while **always retaining
the value text**.

## 7. Accessibility floor (mandatory)

- WCAG 2.2 AA: text ≥4.5:1 (muted ink on panel passes), large text ≥3:1, every
  status also conveyed in text, visible focus ring (`--ac-action`,
  2px offset), visible focus for keyboard navigation.
- Hit areas: desktop dense controls ≥40×40px; touch-first controls ≥44×44px
  (practical minimum, per section header "40x40)"). Small visible surfaces
  extend via a pseudo-element. No two hit areas overlap.
- Semantic HTML landmarks; one `<h1>` per page; tables use `th`/`caption`;
  icons are inline SVG with `aria-hidden` when adjacent text exists, else
  `role="img"` + label.
- Dialog focus trap: focus moves in on open, returns to the invoking control
  on close, `Escape` closes, focus is trapped and never escapes to the page.
- `prefers-reduced-motion: reduce` zeroes durations.
- No layout shift during loading: buttons/panels reserve their width
  (`min-width` with `ch` units), numbers use tabular figures, skeletons keep
  height.
- Bilingual strings are tested with long CN and EN values, and narrow
  viewports (`min-width: 0`, `overflow-wrap: anywhere` where needed); the page
  never scrolls horizontally; wide tables scroll inside their own container.
- All destructive actions open a confirmation dialog with **consequence-exact**
  copy (this is also Story 6): Forward immediate delete, normal node delete,
  and force node delete each use their own text; the generic "Are you sure?"
  is banned.

## 8. Layout concept

- **Public home**: left rail of categories at desktop; a horizontal,
  `overflow-x:auto` category strip on mobile. Flat card grid (not nested
  cards); each card is name, description, protocol, open-state, and a single
  "打开/Open" action. Top-right a quiet "管理 / Admin" entry routed to
  `/admin`.
- **Admin shell**: top bar (wordmark, tab row, session), one content column at
  a comfortable data measure (max ~1200px). Four tabs — Home Settings,
  Forwards, Nodes, Global Settings — as a native tablist with keyboard arrows.
- **Forward detail**: the evidence-chain rail sits at the top of the detail
  panel; beneath it the spec/governance facts in a dense two-column grid, and
  the advanced-NAT block behind a disclosure.

## 9. Framework freeze (resolves the P04 prerequisite gap)

The v0.8 plan §11.6 item 8 requires the browser test framework to be frozen at
M0, not decided later. P04 did not document a frozen framework, so **P17 (this
phase) fixes it**:

- **Framework: Playwright**
- **Pin: `playwright@1.62.1` exactly** (npm package), under
  `test/browser/package.json`.
- **Browsers:** the 1.62.x Chromium/headless-shell build
  (`chromium_headless_shell-1234`) is provisioned by the browser harness in
  the configured Playwright cache directory.
- **Single entry command: `./scripts/test-browser.sh`** (build + start
  `cmd/antinat-controller` on an ephemeral port against a temp data dir,
  run the Playwright suite headless, teardown, exit non-zero on any failure).
- The framework/version/command are recorded in `test/browser/README.md` and
  this document; CI retains the browser gate result as a workflow artifact.

## 10. Screenshot evidence

Story 7 captures, as committed evidence (example paths under
`test/browser/evidence/`): public home zh + en, admin shell zh + en, and one
mobile capture per surface. Screenshots accompany the handoff inline as links,
never as replacements for the browser PASS.
