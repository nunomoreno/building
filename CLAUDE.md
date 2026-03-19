# Kerno — Project Brief

## What it is
Kerno is an internal platform for CaixaResearch Core Facilities (Platforms team).
Hosted on GitHub Pages at `https://nunomoreno.github.io/building`.

---

## Stack

| Layer | Technology |
|---|---|
| Frontend | Vanilla HTML + React 18 via CDN + Babel (no build step) |
| Backend | Cloudflare Worker (`morning-mud-283c.moreno-a64.workers.dev`) |
| Database | Supabase (`hyppwlvmwqcjgphhmzwr.supabase.co`) |
| Email | Brevo API from `lists@cirklo.org` |
| AI | Anthropic API (`claude-sonnet-4-20250514`) via the Worker |
| Testing | Vitest (`npm test`) against worker.js |

---

## File structure

```
index.html      Login only (plain JS, no React). On success stores session in
                localStorage under key "kerno_session" as { token, expires,
                username, role, group_id, group_role }. Redirects admins →
                dashboard.html, users → booking.html.

dashboard.html  Stats hub (plain JS). Shows active projects, team members,
                total requests, recent requests, team panel, audit log.
                Financial report: expense table filtered to finalized tasks
                (task.finalized && !task.exclude_from_financial). No React.

kanban.html     React. Per-user Kanban board. Three scope views:
                  - Mine: projects where data.owner_username === me
                  - Mentioned: projects where any task note contains @me
                  - Group: all projects from group members (leader/manager only)
                Right-side panels: AI assistant (active-project scoped), Audit Log.
                Markdown WYSIWYG notes (marked.js CDN, toolbar).
                Billed tasks: col="Billed" is internal — hidden from board grid,
                shown in a separate section below. Per-card "Bill →" button
                (only on cards with store_order items).

booking.html    React. Weekly calendar grid for resource bookings.
                Admin panel: resources, custom fields per resource,
                booking permissions. Overlap prevention (DB + Worker).
                Mobile: resource sidebar is a drawer (☰ hamburger).

requests.html   React. Service request submission and review.
                Types: Genomics, Cell Sorting, Other (configurable).
                On approval → creates a Kanban project with all metadata
                as a single To Do task. Brevo email on approve/reject.

guide.html      Static HTML user guide (plain JS, no React).
                Left sidebar TOC (mobile drawer). Covers all features.

grants.html     React. Grant management (code, name, tier, funds, members).
                Grants can be linked to bookings and store orders.

pricing.html    React. Admin-only pricing configuration.

users.html      React. Admin-only user and group management.

profile.html    React. User profile page.

worker.js       Cloudflare Worker. Single file, all routes.
                Handles: auth, projects, bookings, requests, groups,
                members, logs, settings, resources, grants, AI proxy,
                weekly report cron (Mon 8am UTC).

worker.test.js  Vitest test suite for worker.js (run with `npm test`).
wrangler.toml   Cloudflare Worker config + KV binding.
package.json    Scripts: test (vitest run), deploy (wrangler deploy).
```

---

## Database tables (Supabase)

```
members       id, username, password (sha256), email, role (admin|user),
              permissions (text[]), session_token, session_expires_at

projects      id, project_id (text), data (jsonb), created_at, updated_at
              data shape: { id, name, owner_username, group_id?, source?,
                            archived?: bool,
                            tasks: [{ id, col, title, notes, assignee?,
                                      finalized?, exclude_from_financial?,
                                      store_order?: { items: [], total: number } }] }
              cols: "To Do" | "In Progress" | "Blocked" | "Done" | "Billed"
              Note: "Billed" is internal — not shown in COLUMNS list, tasks
              with col="Billed" are filtered out of the board grid and shown
              in a separate section. finalized=true means the task has been
              billed. exclude_from_financial=true means it won't appear in
              the dashboard expense report.

bookings      id, resource_id (uuid), username, date, start_time, end_time,
              full_day (bool), notes, status (pending|approved|cancelled|rejected),
              metadata (jsonb), created_at
              DB constraint: no_overlapping_bookings (btree_gist exclusion)

resources     id, name, description, type, booking_type (timeslot|fullday|both),
              approval_required (bool), active (bool), created_at

requests      id, type, username, email, status (pending|approved|rejected),
              metadata (jsonb), notes, created_at, reviewed_by, reviewed_at

groups        id, name, description, created_at

group_members id, group_id, member_id, role (member|leader|manager), joined_at
              UNIQUE (member_id) — one group per user

logs          id, username, action, details, timestamp

settings      key (text PK), value (jsonb), updated_at
              Important keys:
                "booking-fields"  → { [resource_id]: Field[] }
                "request-types"   → { [typeKey]: { label, approver_role, fields: Field[] } }
              Field shape: { id, label, type (text|dropdown|multiselect), options[] }

grants        id, code, name, tier (internal|cracs|academia|industry),
              funds (numeric), members (text[]), created_at
```

---

## Auth & session

- SHA-256 hashed passwords stored in `members.password`
- On login, Worker issues a `session_token` (UUID) + `session_expires_at` (8h)
- Frontend stores full session in `localStorage["kerno_session"]`
- Every authenticated request sends `X-Session-Token` header
- Worker validates token on every route except `/login` and `/register`
- 401 → frontend clears session and redirects to `index.html?expired=1`
- Rate limiting via Cloudflare KV (`RATE_LIMIT_KV`): 5 req/min on `/login`, 60 elsewhere

---

## Roles & permissions

| Role | Can do |
|---|---|
| `admin` | Everything. Manages groups, approves bookings, reviews requests |
| `leader` | Group scientist. Sees group projects/bookings/requests. AI group queries |
| `manager` | Lab operations. Same permissions as leader |
| `user` | Own projects + mentioned projects. Own bookings/requests |

Booking permission is also controlled per-user via `members.permissions` array (must include `"bookings"`).

---

## Key patterns

**API calls (frontend)**
All authenticated calls go through `apiFetch(path, opts)` which injects
`X-Session-Token` and handles 401 redirects automatically.

**Project scoping**
`GET /projects?scope=mine|mentioned|group|all`
Worker filters by `data.owner_username`. Legacy projects with no owner
are treated as owned by the requesting user.

**AI scoping**
`AIChat` receives `activeProject` prop. When a project is open, the system
prompt contains only that project's non-Billed tasks. Falls back to a compact
list of all scoped projects if no project is active.
Worker is a pure proxy for `/ai` — no server-side project injection.

**Billing flow (per task)**
1. Task card shows "Bill →" button only if `task.store_order?.items?.length > 0`
2. Click opens `FinalizeTaskModal` with toggle: "Include in financial report" (default ON)
3. On confirm: `task.col = "Billed"`, `task.finalized = true`,
   `task.exclude_from_financial = !includeFinancial`
4. Billed tasks move out of the board grid into a "Billed" section below.
5. "↩ reopen" restores `col = "Done"`, clears finalized flags.

**Dashboard financial report**
Reads `task.finalized && !task.exclude_from_financial && task.store_order?.items?.length`
across ALL projects. Filterable by year and scope (mine/group/all).

**Project archiving**
Sidebar "Finalize project →" sets `data.archived = true` — removes from active
board (no financial aspect; financial is per-task).

**Markdown notes**
Notes field uses `marked.js` CDN (global `marked`, not `window.marked`).
Configured with `marked.use({ gfm: true })`. `==text==` → `<mark>` highlight.
Toolbar uses `onMouseDown={e => e.preventDefault()}` to preserve textarea
selection when clicking buttons. List buttons use text labels ("• —", "1. —")
— avoid SVG `<line>` inside Babel standalone (causes silent parse failures).

**Overlap prevention (bookings)**
Two-layer: Worker pre-check query + Postgres `EXCLUDE USING gist` constraint.
Error code `OVERLAP` (409) shown inline in booking modal.

**Request → Kanban flow**
On approval: Worker creates a `projects` row with one "To Do" task.
Task notes = all metadata fields as `Key: Value\n` lines + submitter + approver.
Brevo email fires to requester's email.

**Weekly report**
Cloudflare Cron: `0 8 * * 1` (Monday 8am UTC).
Fetches blocked tasks + last week's logs → Claude generates HTML email →
Brevo sends to all members with an email address.

**Mobile responsiveness**
All pages are responsive. Key patterns used:
- Navbars: nav links hidden on mobile (`hidden sm:inline-flex`), accessible via user dropdown
- Sidebars (kanban, booking): mobile drawer pattern — fixed overlay + slide-in panel,
  toggled by `☰` button in the sub-bar
- Kanban board grid: `overflow-x-auto` wrapper, `minWidth: 720` on grid
- Kanban AI/Log panels: full-screen overlay on mobile (`fixed inset-0`), `md:relative`
- guide.html sidebar: CSS `transform: translateX(-100%)` drawer with `.open` class

---

## Testing

```bash
npm install        # first time only (installs vitest + wrangler)
npm test           # runs vitest against worker.test.js
npm run deploy     # deploys worker.js via wrangler
```

Previously identified bugs — all fixed:
1. `DELETE /projects/:id` — now checks ownership (owner or admin only)
2. `/test-store` — added to `bypassRoutes`
3. `getGroupUsernames` — removed redundant `&members.select=username` param

---

## Environment variables (Cloudflare Worker secrets)
```
SUPABASE_API_KEY    Supabase service role key
ANTHROPIC_API_KEY   Anthropic API key
BREVO_API_KEY       Brevo SMTP API key
RATE_LIMIT_KV       KV namespace binding (wrangler.toml)
```
