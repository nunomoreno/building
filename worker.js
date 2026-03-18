const SUPABASE_URL = "https://hyppwlvmwqcjgphhmzwr.supabase.co";
const CORS_ORIGIN  = "https://nunomoreno.github.io";
const SESSION_TTL  = 8 * 60 * 60 * 1000;

// ── Utilities ────────────────────────────────────────────────────────────────

async function sha256(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
  return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, "0")).join("");
}

const errRes = (ch, message, status = 400, code = "ERROR") =>
  new Response(JSON.stringify({ error: message, code }), {
    status, headers: { ...ch, "Content-Type": "application/json" }
  });

// ── Rate limiter ─────────────────────────────────────────────────────────────
async function checkRateLimit(env, ip, route) {
  if (!env.RATE_LIMIT_KV) return true;
  const limit  = route === "/login" ? 5 : 60;
  const window = Math.floor(Date.now() / 60000);
  const key    = `rl:${ip}:${route}:${window}`;
  const count  = parseInt(await env.RATE_LIMIT_KV.get(key) || "0", 10);
  if (count >= limit) return false;
  await env.RATE_LIMIT_KV.put(key, count + 1, { expirationTtl: 120 });
  return true;
}

// ── Session ──────────────────────────────────────────────────────────────────
async function validateSession(sb, token) {
  if (!token) return null;
  const data = await sb(`members?select=id,username,role,permissions,session_expires_at&session_token=eq.${encodeURIComponent(token)}&limit=1`);
  if (!Array.isArray(data) || !data.length) return null;
  const m = data[0];
  if (!m.session_expires_at || Date.now() > new Date(m.session_expires_at).getTime()) return null;
  return m;
}

// ── Group helpers ─────────────────────────────────────────────────────────────
// Returns the group_members row for a user, or null
async function getMembership(sb, memberId) {
  const rows = await sb(`group_members?member_id=eq.${memberId}&select=group_id,role&limit=1`);
  return Array.isArray(rows) && rows.length ? rows[0] : null;
}

// Returns array of member_ids in the same group as memberId
async function getGroupMemberIds(sb, groupId) {
  const rows = await sb(`group_members?group_id=eq.${groupId}&select=member_id`);
  return Array.isArray(rows) ? rows.map(r => r.member_id) : [];
}

// Returns array of usernames in a group
async function getGroupUsernames(sb, groupId) {
  const rows = await sb(
    `group_members?group_id=eq.${groupId}&select=members(username)&members.select=username`
  );
  // Supabase embedded resource
  if (Array.isArray(rows)) return rows.map(r => r.members?.username).filter(Boolean);
  return [];
}

// ── Password strength ─────────────────────────────────────────────────────
function checkPasswordStrength(password) {
  if (!password || password.length < 10)
    return "Password must be at least 10 characters";
  if (!/[A-Z]/.test(password))
    return "Password must contain at least one uppercase letter";
  if (!/[a-z]/.test(password))
    return "Password must contain at least one lowercase letter";
  if (!/[0-9]/.test(password))
    return "Password must contain at least one number";
  if (!/[^A-Za-z0-9]/.test(password))
    return "Password must contain at least one special character";
  return null; // valid
}
const UUID_RE    = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ISO_RE  = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/;
const TIME_RE = /^\d{2}:\d{2}(:\d{2})?$/; // plain HH:MM or HH:MM:SS
const EMAIL_RE   = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const STATUS_SET = new Set(["pending", "approved", "cancelled", "rejected"]);

function sanitiseBooking(body) {
  const { resource_id, start_time, end_time, status, notes } = body;
  if (resource_id && !UUID_RE.test(resource_id))                        return "Invalid resource_id";
  if (start_time  && !ISO_RE.test(start_time) && !TIME_RE.test(start_time)) return "Invalid start_time";
  if (end_time    && !ISO_RE.test(end_time)   && !TIME_RE.test(end_time))   return "Invalid end_time";
  if (status      && !STATUS_SET.has(status))                           return "Invalid status";
  if (notes       && notes.length > 1000)                               return "Notes too long";
  return null;
}

// ── Overlap check ─────────────────────────────────────────────────────────────
async function hasOverlap(sb, resource_id, date, start_time, end_time, exclude_id = null) {
  let url = `bookings?resource_id=eq.${resource_id}&date=eq.${encodeURIComponent(date)}&status=in.(pending,approved)` +
    `&start_time=lt.${encodeURIComponent(end_time)}&end_time=gt.${encodeURIComponent(start_time)}&select=id&limit=1`;
  if (exclude_id) url += `&id=neq.${exclude_id}`;
  const data = await sb(url);
  return Array.isArray(data) && data.length > 0;
}

// ── Email ─────────────────────────────────────────────────────────────────────
async function sendEmail(apiKey, to, subject, htmlContent) {
  await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: { "Content-Type": "application/json", "api-key": apiKey },
    body: JSON.stringify({
      sender: { name: "Kerno", email: "lists@cirklo.org" },
      to: [{ email: to }], subject, htmlContent,
    }),
  });
}

// ── Weekly report ─────────────────────────────────────────────────────────────
async function generateWeeklyReport(env) {
  const sbH = {
    "Content-Type": "application/json",
    "apikey": env.SUPABASE_API_KEY,
    "Authorization": `Bearer ${env.SUPABASE_API_KEY}`,
    "Prefer": "return=representation"
  };
  const sb = async (p) => {
    const res = await fetch(`${SUPABASE_URL}/rest/v1/${p}`, { headers: sbH });
    const t   = await res.text(); return t ? JSON.parse(t) : {};
  };
  const oneWeekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
  const [projects, logs, members] = await Promise.all([
    sb("projects?select=id,data"),
    sb(`logs?timestamp=gte.${oneWeekAgo}&limit=100`),
    sb("members?select=username,email")
  ]);
  const blocked = projects.flatMap(r =>
    (r.data?.tasks || []).filter(t => t.col === "Blocked").map(t => ({ task: t.title, project: r.data?.name }))
  );
  const aiRes = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-api-key": env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01" },
    body: JSON.stringify({
      model: "claude-sonnet-4-20250514", max_tokens: 1000,
      messages: [{ role: "user", content: `Generate a concise weekly report for a building issues Kanban board.\n\nBlocked tasks:\n${blocked.map(b => `- "${b.task}" in project "${b.project}"`).join("\n") || "None"}\n\nActivity last week:\n${logs.map(l => `- ${l.username} ${l.action}: ${l.details}`).join("\n") || "No activity"}\n\nWrite a short friendly HTML email. Use simple inline styles.` }]
    })
  });
  const aiData     = await aiRes.json();
  const reportHtml = aiData.content?.[0]?.text || "<p>Could not generate report.</p>";
  for (const m of members) {
    if (m.email) await sendEmail(env.BREVO_API_KEY, m.email, "⚙️ Kerno — Weekly Report", reportHtml);
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────
export default {
  async scheduled(event, env, ctx) { ctx.waitUntil(generateWeeklyReport(env)); },

  async fetch(request, env) {
    const ch = {
      "Access-Control-Allow-Origin":  CORS_ORIGIN,
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, PATCH",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Session-Token",
      "Access-Control-Max-Age":       "86400",
    };
    if (request.method === "OPTIONS") return new Response(null, { headers: ch });

    const url    = new URL(request.url);
    const path   = url.pathname;
    const method = request.method;

    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    if (!await checkRateLimit(env, ip, path)) return errRes(ch, "Too many requests", 429, "RATE_LIMITED");

    const sbH = {
      "Content-Type": "application/json",
      "apikey":        env.SUPABASE_API_KEY,
      "Authorization": `Bearer ${env.SUPABASE_API_KEY}`,
      "Prefer":        "return=representation"
    };
    const sb = async (p, m = "GET", body = null) => {
      const res  = await fetch(`${SUPABASE_URL}/rest/v1/${p}`, {
        method: m, headers: sbH, body: body ? JSON.stringify(body) : undefined
      });
      const text = await res.text();
      return text ? JSON.parse(text) : {};
    };

    const json = (data, status = 200) => new Response(JSON.stringify(data), {
      status, headers: { ...ch, "Content-Type": "application/json" }
    });

    // ── Session gate ─────────────────────────────────────────────────────────
    const publicRoutes = new Set(["/login", "/register"]);
    const bypassRoutes = new Set(["/debug", "/test-report", "/test-email", "/test-bookings"]);
    let sessionUser = null;
    if (!publicRoutes.has(path)) {
      sessionUser = await validateSession(sb, request.headers.get("X-Session-Token"));
      if (!sessionUser && !bypassRoutes.has(path))
        return errRes(ch, "Session expired — please log in again", 401, "UNAUTHENTICATED");
    }

    // ── POST /login ───────────────────────────────────────────────────────────
    if (path === "/login" && method === "POST") {
      try {
        const { username, password } = await request.json();
        if (!username || !password) return errRes(ch, "Username and password required", 400);
        const hashed = await sha256(password);
        const data   = await sb(`members?username=eq.${encodeURIComponent(username)}&password=eq.${encodeURIComponent(hashed)}`);
        if (!data.length) return errRes(ch, "Invalid username or password", 401, "AUTH_FAILED");

        const token   = crypto.randomUUID();
        const expires = new Date(Date.now() + SESSION_TTL).toISOString();
        await sb(`members?id=eq.${data[0].id}`, "PATCH", { session_token: token, session_expires_at: expires });

        // Attach group info to login response
        const membership = await getMembership(sb, data[0].id);

        return json({
          success: true, token, expires,
          username: data[0].username,
          role:     data[0].role || "user",
          group_id:   membership?.group_id   || null,
          group_role: membership?.role        || null,
        });
      } catch (e) { return errRes(ch, e.message, 500); }
    }

    // ── POST /register ────────────────────────────────────────────────────────
    if (path === "/register" && method === "POST") {
      try {
        const { username, password, email } = await request.json();
        if (!username || !password) return errRes(ch, "Username and password required", 400);
        if (username.length > 50) return errRes(ch, "Username too long", 400);
        if (email && !EMAIL_RE.test(email)) return errRes(ch, "Invalid email", 400);
        const pwErr = checkPasswordStrength(password);
        if (pwErr) return errRes(ch, pwErr, 400, "WEAK_PASSWORD");
        const check = await sb(`members?username=eq.${encodeURIComponent(username)}`);
        if (check.length) return errRes(ch, "Username already exists", 409);
        const hashed = await sha256(password);
        await sb("members", "POST", { username, password: hashed, email: email || null, role: "user" });
        return json({ success: true, username });
      } catch (e) { return errRes(ch, e.message, 500); }
    }

    // ── GET /members ──────────────────────────────────────────────────────────
    if (path === "/members" && method === "GET") {
      try {
        const members = await sb("members?select=id,username,email,role,permissions");
        // Attach group membership to each member
        const memberships = await sb("group_members?select=member_id,group_id,role");
        const byMember = Object.fromEntries((Array.isArray(memberships) ? memberships : []).map(m => [m.member_id, m]));
        return json((Array.isArray(members) ? members : []).map(m => ({
          ...m,
          group_id:   byMember[m.id]?.group_id   || null,
          group_role: byMember[m.id]?.role        || null,
        })));
      } catch (e) { return errRes(ch, e.message, 500); }
    }

    // ── PUT /members/:id ──────────────────────────────────────────────────────
    if (path.startsWith("/members/") && !path.includes("/group") && method === "PUT") {
      try {
        const id   = path.split("/").pop();
        const body = await request.json();

        // Non-admins can only update their own record
        if (sessionUser.id !== id && sessionUser.role !== "admin")
          return errRes(ch, "Forbidden", 403, "FORBIDDEN");

        // Strip role change unless admin
        if (body.role && sessionUser.role !== "admin") delete body.role;

        // Always hash password server-side regardless of what the client sent.
        // This covers both the admin reset (users.html sends plaintext) and
        // the profile page (profile.html sends a pre-hashed value — we
        // detect a raw SHA-256 hex string and skip re-hashing to avoid
        // double-hashing).
        if (body.password) {
          const isAlreadyHashed = /^[a-f0-9]{64}$/.test(body.password);
          if (!isAlreadyHashed) {
            const pwErr = checkPasswordStrength(body.password);
            if (pwErr) return errRes(ch, pwErr, 400, "WEAK_PASSWORD");
          }
          body.password = isAlreadyHashed ? body.password : await sha256(body.password);
        }

        await sb(`members?id=eq.${id}`, "PATCH", body);
        return json({ success: true });
      } catch (e) { return errRes(ch, e.message, 500); }
    }

    // ── DELETE /members/:id ───────────────────────────────────────────────────
    if (path.startsWith("/members/") && method === "DELETE") {
      try {
        if (sessionUser?.role !== "admin") return errRes(ch, "Forbidden", 403, "FORBIDDEN");
        const id = path.split("/").pop();
        await sb(`members?id=eq.${id}`, "DELETE");
        return json({ success: true });
      } catch (e) { return errRes(ch, e.message, 500); }
    }

    // ── GET /groups ───────────────────────────────────────────────────────────
    if (path === "/groups" && method === "GET") {
      try {
        const groups = await sb("groups?select=id,name,description,created_at&order=name");
        const memberships = await sb("group_members?select=group_id,member_id,role,members(username,email)");
        const byGroup = {};
        for (const m of (Array.isArray(memberships) ? memberships : [])) {
          if (!byGroup[m.group_id]) byGroup[m.group_id] = [];
          byGroup[m.group_id].push({ member_id: m.member_id, role: m.role, username: m.members?.username, email: m.members?.email });
        }
        return json((Array.isArray(groups) ? groups : []).map(g => ({ ...g, members: byGroup[g.id] || [] })));
      } catch (e) { return errRes(ch, e.message, 500); }
    }

    // ── POST /groups ──────────────────────────────────────────────────────────
    if (path === "/groups" && method === "POST") {
      try {
        if (sessionUser.role !== "admin") return errRes(ch, "Forbidden", 403, "FORBIDDEN");
        const { name, description } = await request.json();
        if (!name?.trim()) return errRes(ch, "name is required", 400);
        const data = await sb("groups", "POST", { name: name.trim(), description: description || null });
        return json(Array.isArray(data) ? data[0] : data, 201);
      } catch (e) { return errRes(ch, e.message, 500); }
    }

    // ── PUT /groups/:id ───────────────────────────────────────────────────────
    if (path.match(/^\/groups\/[^/]+$/) && method === "PUT") {
      try {
        if (sessionUser.role !== "admin") return errRes(ch, "Forbidden", 403, "FORBIDDEN");
        const id   = path.split("/").pop();
        const body = await request.json();
        await sb(`groups?id=eq.${id}`, "PATCH", { name: body.name, description: body.description });
        return json({ success: true });
      } catch (e) { return errRes(ch, e.message, 500); }
    }

    // ── DELETE /groups/:id ────────────────────────────────────────────────────
    if (path.match(/^\/groups\/[^/]+$/) && method === "DELETE") {
      try {
        if (sessionUser.role !== "admin") return errRes(ch, "Forbidden", 403, "FORBIDDEN");
        const id = path.split("/").pop();
        await sb(`groups?id=eq.${id}`, "DELETE");
        return json({ success: true });
      } catch (e) { return errRes(ch, e.message, 500); }
    }

    // ── POST /groups/:id/members — add or update a member's role in a group ──
    if (path.match(/^\/groups\/[^/]+\/members$/) && method === "POST") {
      try {
        if (sessionUser.role !== "admin") return errRes(ch, "Forbidden", 403, "FORBIDDEN");
        const groupId  = path.split("/")[2];
        const { member_id, role } = await request.json();
        if (!member_id || !UUID_RE.test(member_id)) return errRes(ch, "Invalid member_id", 400);
        const validRoles = new Set(["member", "leader", "manager"]);
        if (role && !validRoles.has(role)) return errRes(ch, "Invalid role", 400);

        // Upsert — remove from any existing group first (one group per user)
        await sb(`group_members?member_id=eq.${member_id}`, "DELETE");
        await sb("group_members", "POST", { group_id: groupId, member_id, role: role || "member" });
        return json({ success: true });
      } catch (e) { return errRes(ch, e.message, 500); }
    }

    // ── DELETE /groups/:id/members/:memberId ──────────────────────────────────
    if (path.match(/^\/groups\/[^/]+\/members\/[^/]+$/) && method === "DELETE") {
      try {
        if (sessionUser.role !== "admin") return errRes(ch, "Forbidden", 403, "FORBIDDEN");
        const parts    = path.split("/");
        const memberId = parts[4];
        await sb(`group_members?member_id=eq.${memberId}`, "DELETE");
        return json({ success: true });
      } catch (e) { return errRes(ch, e.message, 500); }
    }

    if (path === "/projects" && method === "GET") {
      try {
        const scope    = url.searchParams.get("scope");
        const isAdmin  = sessionUser.role === "admin";
        const allProjs = await sb("projects?select=id,project_id,data");
        const projList = Array.isArray(allProjs)
          ? allProjs.map(r => ({ ...r.data, _id: r.id, project_id: r.project_id }))
          : [];

        // Admin with no scope sees everything
        if (!scope && isAdmin) return json(projList);
        if (scope === "all")   return json(projList);

        const me = sessionUser.username;

        // Group scope
        if (scope === "group") {
          let membership = null;
          try { membership = await getMembership(sb, sessionUser.id); } catch {}
          const isLeaderOrManager = membership && ["leader", "manager"].includes(membership.role);
          if (!isLeaderOrManager) return json([]);
          let usernames = [];
          try { usernames = await getGroupUsernames(sb, membership.group_id); } catch {}
          return json(projList.filter(p => usernames.includes(p.owner_username)));
        }

        // Mentioned scope — flat list of tasks that mention @me
        if (scope === "mentioned") {
          const mentionedTasks = [];
          for (const p of projList) {
            for (const t of (p.tasks || [])) {
              if ((t.notes || "").includes(`@${me}`)) {
                mentionedTasks.push({ ...t, _projectName: p.name, _projectId: p._id });
              }
            }
          }
          return json([{
            _id: "__mentioned__", id: "__mentioned__",
            name: `Tasks mentioning @${me}`,
            _virtual: true,
            tasks: mentionedTasks,
          }]);
        }

        // Mine: I own it OR I'm assigned to at least one task
        const mine = projList.filter(p =>
          p.owner_username === me ||
          (p.tasks || []).some(t => t.assignee?.toLowerCase() === me.toLowerCase())
        );

        if (scope === "mine") return json(mine);

        // Default (no scope, non-admin): mine + projects where mentioned
        const mentionedProjs = projList.filter(p =>
          p.owner_username !== me &&
          (p.tasks || []).some(t => (t.notes || "").includes(`@${me}`))
        );
        const seen = new Set();
        return json([...mine, ...mentionedProjs].filter(p => {
          if (seen.has(p._id)) return false;
          seen.add(p._id);
          return true;
        }));
      } catch (e) { return errRes(ch, e.message, 500); }
    }

    // ── POST /projects ────────────────────────────────────────────────────────
    if (path === "/projects" && method === "POST") {
      try {
        const project = await request.json();
        // Stamp owner if not already set (approval flow sets it explicitly)
        if (!project.owner_username) project.owner_username = sessionUser.username;
        const data = await sb("projects", "POST", { project_id: project.id, data: project });
        return json({ _id: Array.isArray(data) ? data[0]?.id : null });
      } catch (e) { return errRes(ch, e.message, 500); }
    }

    // ── PUT /projects/:id ─────────────────────────────────────────────────────
    if (path.startsWith("/projects/") && method === "PUT") {
      try {
        const id      = path.split("/").pop();
        const project = await request.json();
        const existing = await sb(`projects?id=eq.${id}&select=data&limit=1`);
        const oldData  = existing[0]?.data;
        const owner    = oldData?.owner_username;
        const me       = sessionUser.username;
        const isOwner  = !owner || owner === me;
        const isAdmin  = sessionUser.role === "admin";

        if (!isOwner && !isAdmin) {
          // Assignee: only allowed to modify tasks assigned to them
          // All other fields (name, owner, etc.) and other tasks must be unchanged
          const oldTasks = oldData?.tasks || [];
          const newTasks = project?.tasks || [];

          // Reject if project-level fields changed
          if (project.name !== oldData?.name)
            return errRes(ch, "Forbidden — cannot rename project", 403, "FORBIDDEN");

          // Reject if any task NOT assigned to me was changed
          for (const newTask of newTasks) {
            const oldTask = oldTasks.find(t => t.id === newTask.id);
            if (!oldTask) return errRes(ch, "Forbidden — cannot add tasks", 403, "FORBIDDEN");
            const assignedToMe = newTask.assignee?.toLowerCase() === me.toLowerCase()
              || oldTask.assignee?.toLowerCase() === me.toLowerCase();
            if (!assignedToMe) {
              // Task not assigned to me — must be identical
              if (JSON.stringify(oldTask) !== JSON.stringify(newTask))
                return errRes(ch, "Forbidden — cannot modify tasks not assigned to you", 403, "FORBIDDEN");
            }
          }
          // Reject if tasks were deleted (only owner can delete)
          if (newTasks.length < oldTasks.length)
            return errRes(ch, "Forbidden — cannot delete tasks", 403, "FORBIDDEN");
        }

        await sb(`projects?id=eq.${id}`, "PATCH", { data: project });
        return json({ success: true });
      } catch (e) { return errRes(ch, e.message, 500); }
    }

    // ── DELETE /projects/:id ──────────────────────────────────────────────────
    if (path.startsWith("/projects/") && method === "DELETE") {
      try {
        const id = path.split("/").pop();
        await sb(`projects?id=eq.${id}`, "DELETE");
        return json({ success: true });
      } catch (e) { return errRes(ch, e.message, 500); }
    }

    // ── POST /logs ────────────────────────────────────────────────────────────
    if (path === "/logs" && method === "POST") {
      try {
        const { username, action, details, timestamp } = await request.json();
        await sb("logs", "POST", { username, action, details, timestamp });
        return json({ success: true });
      } catch (e) { return errRes(ch, e.message, 500); }
    }

    // ── GET /logs ─────────────────────────────────────────────────────────────
    if (path === "/logs" && method === "GET") {
      try {
        const limit = url.searchParams.get("limit") || "50";
        return json(await sb(`logs?order=timestamp.desc&limit=${limit}`));
      } catch (e) { return errRes(ch, e.message, 500); }
    }

    // ── POST /notify ──────────────────────────────────────────────────────────
    if (path === "/notify" && method === "POST") {
      try {
        const { actor, taskTitle, projectName, mentionsWithEmails } = await request.json();
        const results = [];
        for (const { username, email } of (mentionsWithEmails || [])) {
          if (!email) { results.push({ username, skipped: "no email" }); continue; }
          const res = await fetch("https://api.brevo.com/v3/smtp/email", {
            method: "POST",
            headers: { "Content-Type": "application/json", "api-key": env.BREVO_API_KEY },
            body: JSON.stringify({
              sender: { name: "Kerno", email: "lists@cirklo.org" },
              to: [{ email }],
              subject: `You were mentioned in "${taskTitle}"`,
              htmlContent: `<p>Hi <strong>${username}</strong>,</p><p><strong>${actor}</strong> mentioned you in <strong>"${taskTitle}"</strong> in project <strong>${projectName}</strong>.</p><p><a href="https://nunomoreno.github.io/building/kanban.html">Open Kerno →</a></p>`
            })
          });
          results.push({ username, email, brevoStatus: res.status });
        }
        return json({ success: true, results });
      } catch (e) { return errRes(ch, e.message, 500); }
    }

    // ── GET /settings/:key ────────────────────────────────────────────────────
    if (path.startsWith("/settings/") && method === "GET") {
      try {
        const key  = path.split("/").pop();
        const data = await sb(`settings?key=eq.${key}`);
        return json(data[0]?.value || null);
      } catch (e) { return errRes(ch, e.message, 500); }
    }

    // ── POST /settings/:key ───────────────────────────────────────────────────
    if (path.startsWith("/settings/") && method === "POST") {
      try {
        const key      = path.split("/").pop();
        const value    = await request.json();
        const existing = await sb(`settings?key=eq.${key}`);
        if (existing.length) {
          await sb(`settings?key=eq.${key}`, "PATCH", { value, updated_at: new Date().toISOString() });
        } else {
          await sb("settings", "POST", { key, value });
        }
        return json({ success: true });
      } catch (e) { return errRes(ch, e.message, 500); }
    }

    // ── GET /resources ────────────────────────────────────────────────────────
    if (path === "/resources" && method === "GET") {
      try { return json(await sb("resources?active=eq.true&limit=100")); }
      catch (e) { return errRes(ch, e.message, 500); }
    }

    // ── POST /resources ───────────────────────────────────────────────────────
    if (path === "/resources" && method === "POST") {
      try {
        const body = await request.json();
        const data = await sb("resources", "POST", body);
        return json(Array.isArray(data) ? (data[0] || { success: true }) : { success: true });
      } catch (e) { return errRes(ch, e.message, 500); }
    }

    // ── PUT /resources/:id ────────────────────────────────────────────────────
    if (path.match(/^\/resources\/[^/]+$/) && method === "PUT") {
      try {
        const id = path.split("/")[2];
        await sb(`resources?id=eq.${id}`, "PATCH", await request.json());
        return json({ success: true });
      } catch (e) { return errRes(ch, e.message, 500); }
    }

    // ── DELETE /resources/:id ─────────────────────────────────────────────────
    if (path.match(/^\/resources\/[^/]+$/) && method === "DELETE") {
      try {
        const id = path.split("/")[2];
        await sb(`resources?id=eq.${id}`, "PATCH", { active: false });
        return json({ success: true });
      } catch (e) { return errRes(ch, e.message, 500); }
    }

    // ── GET /bookings ─────────────────────────────────────────────────────────
    // Leaders/managers can see their group's bookings via ?scope=group
    if (path === "/bookings" && method === "GET") {
      try {
        const scope      = url.searchParams.get("scope");
        const membership = sessionUser ? await getMembership(sb, sessionUser.id) : null;
        const isElevated = sessionUser?.role === "admin" ||
          (membership && ["leader", "manager"].includes(membership.role));

        if (scope === "group" && membership && isElevated) {
          const usernames = await getGroupUsernames(sb, membership.group_id);
          if (!usernames.length) return json([]);
          // Filter bookings by username — fetch all and filter (Supabase IN syntax)
          const all = await sb("bookings?limit=500");
          return json((Array.isArray(all) ? all : []).filter(b => usernames.includes(b.username)));
        }

        return json(await sb("bookings?limit=200"));
      } catch (e) { return errRes(ch, e.message, 500); }
    }

    // ── POST /bookings ────────────────────────────────────────────────────────
    if (path === "/bookings" && method === "POST") {
      try {
        const body    = await request.json();
        const invalid = sanitiseBooking(body);
        if (invalid) return errRes(ch, invalid, 400, "VALIDATION_ERROR");
        const { resource_id, date, start_time, end_time } = body;
        const canBook = sessionUser.role === "admin" ||
          (Array.isArray(sessionUser.permissions) && sessionUser.permissions.includes(resource_id));
        if (!canBook) return errRes(ch, "You do not have permission to book this resource", 403, "FORBIDDEN");
        if (new Date(start_time) < new Date()) return errRes(ch, "Cannot book in the past", 400, "PAST_BOOKING");
        if (await hasOverlap(sb, resource_id, date, start_time, end_time)) return errRes(ch, "This time slot is already booked", 409, "OVERLAP");
        const resource        = await sb(`resources?id=eq.${resource_id}&select=approval_required,max_days_ahead&limit=1`);
        const approvalRequired = resource[0]?.approval_required ?? true;
        const maxDaysAhead = resource[0]?.max_days_ahead;
        if (maxDaysAhead) {
          const maxDate = new Date();
          maxDate.setDate(maxDate.getDate() + maxDaysAhead);
          if (new Date(date) > maxDate)
            return errRes(ch, `Cannot book more than ${maxDaysAhead} days in advance`, 400, "TOO_FAR_AHEAD");
        }
        const status = sessionUser?.role === "admin" || !approvalRequired ? "approved" : "pending";
        const data   = await sb("bookings", "POST", { ...body, username: sessionUser.username, status });
        if (data?.code === "23P01") return errRes(ch, "Time slot was just taken", 409, "OVERLAP");
        return json(Array.isArray(data) ? (data[0] || { success: true }) : { success: true }, 201);
      } catch (e) { return errRes(ch, e.message, 500); }
    }

    // ── PUT /bookings/:id ─────────────────────────────────────────────────────
    if (path.startsWith("/bookings/") && method === "PUT") {
      try {
        const id   = path.split("/").pop();
        const body = await request.json();
        delete body.username; // never allow changing the original booker
        if (body.status && !["cancelled"].includes(body.status) && sessionUser?.role !== "admin")
          return errRes(ch, "Only admins can approve or reject bookings", 403, "FORBIDDEN");
        if (body.start_time || body.end_time) {
          const existing = await sb(`bookings?id=eq.${id}&select=resource_id,date,start_time,end_time&limit=1`);
          const cur = Array.isArray(existing) && existing[0];
          if (!cur) return errRes(ch, "Booking not found", 404, "NOT_FOUND");
          const date  = body.date       || cur.date;
          const start = body.start_time || cur.start_time;
          const end   = body.end_time   || cur.end_time;
          if (await hasOverlap(sb, cur.resource_id, date, start, end, id)) return errRes(ch, "Overlaps existing booking", 409, "OVERLAP");
        }
        await sb(`bookings?id=eq.${id}`, "PATCH", body);
        return json({ success: true });
      } catch (e) { return errRes(ch, e.message, 500); }
    }

    // ── DELETE /bookings/:id ──────────────────────────────────────────────────
    if (path.startsWith("/bookings/") && method === "DELETE") {
      try {
        await sb(`bookings?id=eq.${path.split("/").pop()}`, "DELETE");
        return json({ success: true });
      } catch (e) { return errRes(ch, e.message, 500); }
    }

    // ── GET /requests ─────────────────────────────────────────────────────────
    // Leaders/managers see their group's requests via ?scope=group
    if (path === "/requests" && method === "GET") {
      try {
        const scope      = url.searchParams.get("scope");
        const membership = await getMembership(sb, sessionUser.id);
        const isElevated = sessionUser.role === "admin" ||
          (membership && ["leader", "manager"].includes(membership.role));

        if (scope === "group" && membership && isElevated) {
          const usernames = await getGroupUsernames(sb, membership.group_id);
          const all = await sb("requests?order=created_at.desc&limit=200");
          return json((Array.isArray(all) ? all : []).filter(r => usernames.includes(r.username)));
        }

        if (sessionUser.role === "admin")
          return json(await sb("requests?order=created_at.desc&limit=200"));

        return json(await sb(`requests?username=eq.${encodeURIComponent(sessionUser.username)}&order=created_at.desc&limit=200`));
      } catch (e) { return errRes(ch, e.message, 500); }
    }

    // ── POST /requests ────────────────────────────────────────────────────────
    if (path === "/requests" && method === "POST") {
      try {
        const body = await request.json();
        const { type, metadata, notes } = body;
        if (!type) return errRes(ch, "type is required", 400);
        if (notes && notes.length > 2000) return errRes(ch, "Notes too long", 400);
        const settingsRow = await sb("settings?key=eq.request-types&limit=1");
        const typeConfig  = settingsRow[0]?.value?.[type];
        if (!typeConfig) return errRes(ch, "Unknown request type", 400);
        const data = await sb("requests", "POST", {
          type, username: sessionUser.username, email: body.email || null,
          status: "pending", metadata: metadata || {}, notes: notes || null,
        });
        return json(Array.isArray(data) ? data[0] : data, 201);
      } catch (e) { return errRes(ch, e.message, 500); }
    }

    // ── PUT /requests/:id ─────────────────────────────────────────────────────
    if (path.match(/^\/requests\/[^/]+$/) && method === "PUT") {
      try {
        const id   = path.split("/").pop();
        const body = await request.json();
        const { status, rejection_reason } = body;
        if (!["approved", "rejected"].includes(status)) return errRes(ch, "Invalid status", 400);
        const rows = await sb(`requests?id=eq.${id}&limit=1`);
        if (!rows?.length) return errRes(ch, "Request not found", 404, "NOT_FOUND");
        const req = rows[0];
        const settingsRow  = await sb("settings?key=eq.request-types&limit=1");
        const typeConfig   = settingsRow[0]?.value?.[req.type];
        const requiredRole = typeConfig?.approver_role || "admin";
        if (sessionUser.role !== requiredRole && sessionUser.role !== "admin")
          return errRes(ch, "Insufficient permissions", 403, "FORBIDDEN");
        await sb(`requests?id=eq.${id}`, "PATCH", { status, reviewed_by: sessionUser.username, reviewed_at: new Date().toISOString() });
        if (status === "approved") {
          const projectId = `req-${id}`;
          const label     = typeConfig?.label || req.type;
          const fields    = typeConfig?.fields || [];
          const metaLines = fields.map(f => {
            const val = req.metadata?.[f.id];
            if (!val || (Array.isArray(val) && !val.length)) return null;
            return `${f.label}: ${Array.isArray(val) ? val.join(", ") : val}`;
          }).filter(Boolean);
          if (req.notes) metaLines.push(`Notes: ${req.notes}`);
          metaLines.push(`Submitted by: ${req.username}`);
          metaLines.push(`Approved by: ${sessionUser.username}`);
          await sb("projects", "POST", {
            project_id: projectId,
            data: {
              id: projectId, name: `[${label}] ${req.username} — ${new Date(req.created_at).toLocaleDateString("en-GB")}`,
              owner_username: sessionUser.username, source: "request",
              tasks: [{ id: Date.now(), col: "To Do", title: `${label} request`, notes: metaLines.join("\n") }],
            }
          });
          await sb("logs", "POST", { username: sessionUser.username, action: "approve_request", details: `Approved ${label} request from ${req.username}`, timestamp: new Date().toISOString() });
        } else {
          await sb("logs", "POST", { username: sessionUser.username, action: "reject_request", details: `Rejected ${req.type} request from ${req.username}`, timestamp: new Date().toISOString() });
        }
        if (req.email) {
          const isApproved = status === "approved";
          const label = typeConfig?.label || req.type;
          await sendEmail(env.BREVO_API_KEY, req.email,
            isApproved ? `✅ Your ${label} request has been approved` : `❌ Your ${label} request was not approved`,
            isApproved
              ? `<p>Hi <strong>${req.username}</strong>,</p><p>Your <strong>${label}</strong> request has been <strong style="color:#16a34a">approved</strong> by ${sessionUser.username}.</p><p><a href="https://nunomoreno.github.io/building/kanban.html">View Kanban →</a></p>`
              : `<p>Hi <strong>${req.username}</strong>,</p><p>Your <strong>${label}</strong> request has been <strong style="color:#dc2626">rejected</strong>.</p>${rejection_reason ? `<p><strong>Reason:</strong> ${rejection_reason}</p>` : ""}<p><a href="https://nunomoreno.github.io/building/requests.html">Submit a new request →</a></p>`
          );
        }
        return json({ success: true, status });
      } catch (e) { return errRes(ch, e.message, 500); }
    }

    // ── POST /resources/:id/grant — calendar admin or global admin grants access
    if (path.match(/^\/resources\/[^/]+\/grant$/) && method === "POST") {
      try {
        const resourceId = path.split("/")[2];
        const { member_id } = await request.json();
        if (!member_id || !UUID_RE.test(member_id)) return errRes(ch, "Invalid member_id", 400);
        const res = await sb(`resources?id=eq.${resourceId}&select=admin_username&limit=1`);
        const resource = res[0];
        if (!resource) return errRes(ch, "Resource not found", 404, "NOT_FOUND");
        if (sessionUser.role !== "admin" && resource.admin_username !== sessionUser.username)
          return errRes(ch, "Forbidden", 403, "FORBIDDEN");
        const mems = await sb(`members?id=eq.${member_id}&select=permissions&limit=1`);
        const member = mems[0];
        if (!member) return errRes(ch, "Member not found", 404, "NOT_FOUND");
        const perms = Array.isArray(member.permissions) ? member.permissions : [];
        if (!perms.includes(resourceId))
          await sb(`members?id=eq.${member_id}`, "PATCH", { permissions: [...perms, resourceId] });
        return json({ success: true });
      } catch(e) { return errRes(ch, e.message, 500); }
    }

    // ── DELETE /resources/:id/grant/:memberId — revoke access ─────────────────
    if (path.match(/^\/resources\/[^/]+\/grant\/[^/]+$/) && method === "DELETE") {
      try {
        const parts      = path.split("/");
        const resourceId = parts[2];
        const memberId   = parts[4];
        const res = await sb(`resources?id=eq.${resourceId}&select=admin_username&limit=1`);
        const resource = res[0];
        if (!resource) return errRes(ch, "Resource not found", 404, "NOT_FOUND");
        if (sessionUser.role !== "admin" && resource.admin_username !== sessionUser.username)
          return errRes(ch, "Forbidden", 403, "FORBIDDEN");
        const mems = await sb(`members?id=eq.${memberId}&select=permissions&limit=1`);
        const member = mems[0];
        if (!member) return errRes(ch, "Member not found", 404, "NOT_FOUND");
        const perms = Array.isArray(member.permissions) ? member.permissions : [];
        await sb(`members?id=eq.${memberId}`, "PATCH", { permissions: perms.filter(p => p !== resourceId) });
        return json({ success: true });
      } catch(e) { return errRes(ch, e.message, 500); }
    }

    // ── POST /request-access ─────────────────────────────────────────────────
    if (path === "/request-access" && method === "POST") {
      try {
        const { resource_id } = await request.json();
        const resources = await sb(`resources?id=eq.${resource_id}&select=name,admin_username&limit=1`);
        const resource  = resources[0];
        if (!resource) return errRes(ch, "Resource not found", 404, "NOT_FOUND");
        const adminUsername = resource.admin_username;
        let admin;
        if (adminUsername) {
          const admins = await sb(`members?username=eq.${encodeURIComponent(adminUsername)}&select=email,username&limit=1`);
          admin = admins[0];
        }
        // Fall back to any global admin if no calendar admin is assigned
        if (!admin) {
          const admins = await sb(`members?role=eq.admin&select=email,username&limit=1`);
          admin = admins[0];
        }
        if (!admin?.email) return errRes(ch, "Calendar admin has no email on file", 400);
        await sendEmail(env.BREVO_API_KEY, admin.email,
          `🔑 Booking access request for "${resource.name}"`,
          `<p>Hi <strong>${admin.username}</strong>,</p>
           <p><strong>${sessionUser.username}</strong> is requesting booking access to <strong>${resource.name}</strong>.</p>
           <p>Log in and go to Admin → Permissions to grant access:</p>
           <p><a href="https://nunomoreno.github.io/building/booking.html">Open Bookings →</a></p>`
        );
        return json({ success: true });
      } catch(e) { return errRes(ch, e.message, 500); }
    }

    // ── POST /ai ──────────────────────────────────────────────────────────────
    // The frontend sends an already-scoped project list in the system prompt.
    // The worker just proxies to Claude — no server-side project fetching.
    if (path === "/ai" && method === "POST") {
      try {
        const body = await request.json();
        const res  = await fetch("https://api.anthropic.com/v1/messages", {
          method: "POST",
          headers: { "Content-Type": "application/json", "x-api-key": env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01" },
          body: JSON.stringify(body),
        });
        return json(await res.json());
      } catch (e) { return errRes(ch, e.message, 500); }
    }

    // ── Debug routes ──────────────────────────────────────────────────────────
    if (path === "/debug") {
      try {
        const data = await sb("bookings?limit=5");
        return json({ count: Array.isArray(data) ? data.length : 0 });
      } catch (e) { return json({ error: e.message }); }
    }
    if (path === "/test-bookings") { return json(await sb("bookings?limit=200")); }
    if (path === "/test-email") {
      try {
        const res = await fetch("https://api.brevo.com/v3/smtp/email", {
          method: "POST",
          headers: { "Content-Type": "application/json", "api-key": env.BREVO_API_KEY },
          body: JSON.stringify({ sender: { name: "Kerno", email: "lists@cirklo.org" }, to: [{ email: "moreno@agendoscience.com" }], subject: "Test from Kerno", htmlContent: "<p>Test!</p>" })
        });
        return json({ status: res.status, data: await res.json() });
      } catch (e) { return json({ error: e.message }); }
    }

    return new Response("Not found", { status: 404, headers: ch });
  }
};