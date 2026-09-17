const REQUIRED = ["c0", "c1", "c2", "c3", "c4", "c5", "overall"];
const MAX_COMMENT = 2000;
const MAX_BODY_BYTES = 10000;
const PAGE_SIZE_DEFAULT = 50;
const PAGE_SIZE_MAX = 100;
const RATE_WINDOW_SECONDS = 60 * 60;
const RATE_MAX = 100;
const ADMIN_RATE_WINDOW_SECONDS = 15 * 60;
const ADMIN_RATE_MAX = 10;
const COOKIE_NAME = "dp_admin";

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
      ...extraHeaders
    }
  });
}

async function sha256(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function hashClient(request, env) {
  if (!env.RATE_LIMIT_SALT) throw new Error("RATE_LIMIT_SALT is not configured");
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const ua = request.headers.get("User-Agent") || "";
  return {
    ipHash: await sha256(`${env.RATE_LIMIT_SALT}:ip:${ip}`),
    uaHash: await sha256(`${env.RATE_LIMIT_SALT}:ua:${ua.slice(0, 500)}`)
  };
}

async function adminRateLimited(ipHash, env) {
  const cutoff = new Date(Date.now() - ADMIN_RATE_WINDOW_SECONDS * 1000)
    .toISOString().replace("T", " ").replace("Z", "");
  const result = await env.DB.prepare(
    "SELECT COUNT(*) AS count FROM admin_attempts WHERE ip_hash = ? AND success = 0 AND created_at >= ?"
  ).bind(ipHash, cutoff).first();
  return Number(result?.count || 0) >= ADMIN_RATE_MAX;
}

async function getRateLimit(ipHash, env) {
  const cutoff = new Date(Date.now() - RATE_WINDOW_SECONDS * 1000)
    .toISOString().replace("T", " ").replace("Z", "");
  const result = await env.DB.prepare(
    "SELECT COUNT(*) AS count, MIN(created_at) AS oldest FROM reviews WHERE ip_hash = ? AND created_at >= ?"
  ).bind(ipHash, cutoff).first();
  const count = Number(result?.count || 0);
  if (count < RATE_MAX) return { limited: false, retryAfter: 0 };
  return { limited: true, retryAfter: retryAfterFromOldest(result?.oldest) };
}

function retryAfterFromOldest(oldest) {
  let retryAfter = RATE_WINDOW_SECONDS;
  if (oldest) {
    const oldestMs = Date.parse(oldest.replace(" ", "T") + "Z");
    if (Number.isFinite(oldestMs)) {
      retryAfter = Math.max(1, Math.ceil((oldestMs + RATE_WINDOW_SECONDS * 1000 - Date.now()) / 1000));
    }
  }
  return retryAfter;
}

async function insertReviewWithRateLimit(ipHash, uaHash, ratingsJson, comment, env) {
  const cutoff = new Date(Date.now() - RATE_WINDOW_SECONDS * 1000)
    .toISOString().replace("T", " ").replace("Z", "");

  // The INSERT ... SELECT condition is evaluated inside the same SQLite write
  // transaction as the insert, so concurrent requests cannot both pass a
  // separate COUNT(*) check and exceed the 100/IP/hour limit.
  const result = await env.DB.prepare(
    `INSERT INTO reviews (ratings_json, comment, ip_hash, user_agent_hash)
     SELECT ?, ?, ?, ?
     WHERE (SELECT COUNT(*) FROM reviews WHERE ip_hash = ? AND created_at >= ?) < ?`
  ).bind(ratingsJson, comment, ipHash, uaHash, ipHash, cutoff, RATE_MAX).run();

  return Number(result?.meta?.changes || 0) === 1;
}

async function verifyTurnstile(token, request, env) {
  if (!env.TURNSTILE_SECRET_KEY) return false;
  if (!token || typeof token !== "string") return false;
  const ip = request.headers.get("CF-Connecting-IP") || "";
  const form = new URLSearchParams();
  form.set("secret", env.TURNSTILE_SECRET_KEY);
  form.set("response", token);
  if (ip) form.set("remoteip", ip);
  const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form.toString()
  });
  if (!r.ok) return false;
  const result = await r.json();
  return result.success === true;
}

function parseCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return match ? decodeURIComponent(match[1]) : "";
}

async function signAdminToken(env, expires) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(env.ADMIN_KEY),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const data = `admin:${expires}`;
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  const b64 = btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  return `${expires}.${b64}`;
}

async function validAdminCookie(request, env) {
  if (!env.ADMIN_KEY) return false;
  const token = parseCookie(request, COOKIE_NAME);
  const [expires, sig] = token.split(".");
  if (!expires || !sig || !/^\d+$/.test(expires) || Number(expires) < Date.now()) return false;
  const expected = await signAdminToken(env, Number(expires));
  return token === expected;
}

async function readJsonBody(request) {
  const contentLength = Number(request.headers.get("Content-Length") || 0);
  if (Number.isFinite(contentLength) && contentLength > MAX_BODY_BYTES) {
    const error = new Error("BODY_TOO_LARGE");
    error.status = 413;
    throw error;
  }
  const bytes = await request.arrayBuffer();
  if (bytes.byteLength > MAX_BODY_BYTES) {
    const error = new Error("BODY_TOO_LARGE");
    error.status = 413;
    throw error;
  }
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch (_) {
    const error = new Error("INVALID_JSON");
    error.status = 400;
    throw error;
  }
}

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  if (request.method === "POST" && path === "/api/reviews") {
    try {
      const body = await readJsonBody(request);
      if (!body || typeof body !== "object" || !body.ratings ||
          REQUIRED.some(k => !Number.isInteger(body.ratings[k]) || body.ratings[k] < 1 || body.ratings[k] > 5)) {
        return json({ error: "Đánh giá không hợp lệ." }, 400);
      }

      const comment = typeof body.comment === "string" ? body.comment.trim().slice(0, MAX_COMMENT) : "";
      if (!env.TURNSTILE_SECRET_KEY) {
        return json({ error: "Hệ thống chống spam chưa được cấu hình." }, 503, { "Cache-Control": "no-store" });
      }
      if (!(await verifyTurnstile(body.turnstileToken, request, env))) {
        return json({ error: "Xác minh chống spam thất bại. Vui lòng thử lại." }, 403, { "Cache-Control": "no-store" });
      }

      const { ipHash, uaHash } = await hashClient(request, env);
      const ratingsJson = JSON.stringify(Object.fromEntries(REQUIRED.map(k => [k, body.ratings[k]])));
      const inserted = await insertReviewWithRateLimit(ipHash, uaHash, ratingsJson, comment, env);

      if (!inserted) {
        const rate = await getRateLimit(ipHash, env);
        return json({ error: "IP này đã đạt giới hạn 100 đánh giá trong 1 giờ. Vui lòng thử lại sau." }, 429, {
          "Retry-After": String(rate.retryAfter),
          "Cache-Control": "no-store"
        });
      }

      return json({ ok: true }, 201, { "Cache-Control": "no-store" });
    } catch (e) {
      console.error(e);
      if (e?.status === 413) return json({ error: "Dữ liệu gửi lên quá lớn." }, 413, { "Cache-Control": "no-store" });
      if (e?.status === 400) return json({ error: "Dữ liệu JSON không hợp lệ." }, 400, { "Cache-Control": "no-store" });
      return json({ error: "Không thể lưu đánh giá." }, 500, { "Cache-Control": "no-store" });
    }
  }

  if (request.method === "GET" && path === "/api/config") {
    return json({ turnstileSiteKey: env.TURNSTILE_SITE_KEY || "" }, 200, { "Cache-Control": "public, max-age=300" });
  }

  if (request.method === "POST" && path === "/api/admin-login") {
    try {
      const body = await readJsonBody(request);
      const { ipHash } = await hashClient(request, env);
      if (await adminRateLimited(ipHash, env)) {
        return json({ error: "Quá nhiều lần đăng nhập thất bại. Vui lòng thử lại sau 15 phút." }, 429, {
          "Retry-After": String(ADMIN_RATE_WINDOW_SECONDS),
          "Cache-Control": "no-store"
        });
      }
      const ok = !!env.ADMIN_KEY && typeof body?.key === "string" && body.key.length > 0 && body.key === env.ADMIN_KEY;
      await env.DB.prepare("INSERT INTO admin_attempts (ip_hash, success) VALUES (?, ?)").bind(ipHash, ok ? 1 : 0).run();
      if (!ok) return json({ error: "Mã quản trị không đúng." }, 401, { "Cache-Control": "no-store" });

      const expires = Date.now() + 8 * 60 * 60 * 1000;
      const token = await signAdminToken(env, expires);
      return json({ ok: true }, 200, {
        "Set-Cookie": `${COOKIE_NAME}=${encodeURIComponent(token)}; Max-Age=28800; Path=/api; HttpOnly; Secure; SameSite=Strict`,
        "Cache-Control": "no-store"
      });
    } catch (e) {
      if (e?.status === 413) return json({ error: "Dữ liệu gửi lên quá lớn." }, 413, { "Cache-Control": "no-store" });
      if (e?.status === 400) return json({ error: "Dữ liệu JSON không hợp lệ." }, 400, { "Cache-Control": "no-store" });
      console.error(e);
      return json({ error: "Không thể xử lý đăng nhập." }, 500, { "Cache-Control": "no-store" });
    }
  }

  if (request.method === "POST" && path === "/api/admin-logout") {
    return json({ ok: true }, 200, {
      "Set-Cookie": `${COOKIE_NAME}=; Max-Age=0; Path=/api; HttpOnly; Secure; SameSite=Strict`,
      "Cache-Control": "no-store"
    });
  }

  if (request.method === "GET" && path === "/api/reviews" && url.searchParams.get("admin") === "1") {
    if (!(await validAdminCookie(request, env))) {
      return json({ error: "Phiên quản trị không hợp lệ hoặc đã hết hạn." }, 401, { "Cache-Control": "no-store" });
    }

    const page = Math.max(1, Number.parseInt(url.searchParams.get("page") || "1", 10) || 1);
    const limit = Math.min(PAGE_SIZE_MAX, Math.max(1, Number.parseInt(url.searchParams.get("limit") || String(PAGE_SIZE_DEFAULT), 10) || PAGE_SIZE_DEFAULT));
    const offset = (page - 1) * limit;

    const [rows, totalRow, statsRow] = await Promise.all([
      env.DB.prepare("SELECT id, ratings_json, comment, created_at FROM reviews ORDER BY id DESC LIMIT ? OFFSET ?").bind(limit, offset).all(),
      env.DB.prepare("SELECT COUNT(*) AS total FROM reviews").first(),
      env.DB.prepare(`SELECT
        AVG(CAST(json_extract(ratings_json, '$.overall') AS REAL)) AS avg_overall,
        SUM(CASE WHEN json_extract(ratings_json, '$.overall') <= 2 THEN 1 ELSE 0 END) AS low_count,
        SUM(CASE WHEN json_extract(ratings_json, '$.overall') >= 4 THEN 1 ELSE 0 END) AS high_count,
        AVG(CAST(json_extract(ratings_json, '$.c0') AS REAL)) AS c0,
        AVG(CAST(json_extract(ratings_json, '$.c1') AS REAL)) AS c1,
        AVG(CAST(json_extract(ratings_json, '$.c2') AS REAL)) AS c2,
        AVG(CAST(json_extract(ratings_json, '$.c3') AS REAL)) AS c3,
        AVG(CAST(json_extract(ratings_json, '$.c4') AS REAL)) AS c4,
        AVG(CAST(json_extract(ratings_json, '$.c5') AS REAL)) AS c5
        FROM reviews`).first()
    ]);

    const reviews = (rows.results || []).map(r => {
      let ratings = {};
      try { ratings = JSON.parse(r.ratings_json); } catch (_) {}
      return { id: r.id, ratings, comment: r.comment, created_at: r.created_at };
    });

    return json({
      reviews,
      pagination: {
        page,
        limit,
        total: Number(totalRow?.total || 0),
        pages: Math.ceil(Number(totalRow?.total || 0) / limit)
      },
      stats: {
        avg_overall: Number(statsRow?.avg_overall || 0),
        low_count: Number(statsRow?.low_count || 0),
        high_count: Number(statsRow?.high_count || 0),
        criteria: REQUIRED.filter(k => k !== "overall").reduce((o, k) => {
          o[k] = Number(statsRow?.[k] || 0);
          return o;
        }, {})
      }
    }, 200, { "Cache-Control": "no-store" });
  }

  return json({ error: "Method not allowed." }, 405, { Allow: "GET, POST" });
}
