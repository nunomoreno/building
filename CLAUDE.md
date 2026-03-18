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

---

## File structure

```
index.html      Login only (plain JS, no React). On success stores session in
                localStorage under key "kerno_session" as { token, expires,
                username, role, group_id, group_role }. Redirects admins →
                dashboard.html, users → booking.html.

dashboard.html  Stats hub (plain JS). Shows active projects, team members,
                total requests, recent requests, team panel, audit log.
                No React.

kanban.html     React. Per-user Kanban board. Three scope views:
                  - Mine: projects where data.owner_username === me
                  - Mentioned: projects where any task note contains @me
                  - Group: all projects from group members (leader/manager only)
                Right-side panels: AI assistant (scope-aware), Audit Log,
                Users & Groups (admin only).

booking.html    React. Weekly calendar grid for resource bookings.
                Admin panel: resources, custom fields per resource,
                booking permissions. Overlap prevention (DB + Worker).

requests.html   React. Service request submission and review.
                Types: Genomics, Cell Sorting, Other (configurable).
                On approval → creates a Kanban project with all metadata
                as a single To Do task. Brevo email on approve/reject.

worker.js       Cloudflare Worker. Single file, all routes.
                Handles: auth, projects, bookings, requests, groups,
                members, logs, settings, resources, AI proxy,
                weekly report cron (Mon 8am UTC).
```

---

## Database tables (Supabase)

```
members       id, username, password (sha256), email, role (admin|user),
              permissions (text[]), session_token, session_expires_at

projects      id, project_id (text), data (jsonb), created_at, updated_at
              data shape: { id, name, owner_username, group_id?, source?,
                            tasks: [{ id, col, title, notes }] }
              cols: "To Do" | "In Progress" | "Blocked" | "Done"

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
`AIChat` component fetches `api.getProjects(scope)` independently on mount.
Only the scoped project list is sent in the Claude system prompt.
Worker is a pure proxy for `/ai` — no server-side project injection.

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

---

## Environment variables (Cloudflare Worker secrets)
```
SUPABASE_API_KEY    Supabase service role key
ANTHROPIC_API_KEY   Anthropic API key
BREVO_API_KEY       Brevo SMTP API key
RATE_LIMIT_KV       KV namespace binding (wrangler.toml)
```