#!/usr/bin/env node
/**
 * 折鹊的小屋 — 内容后台服务
 *
 * 零外部依赖（仅 Node 内置模块），常驻内存占用约 40-60MB。
 * 提供：文章管理、音乐配置、站点信息、一键构建发布。
 *
 * 安全设计：
 *   - 仅监听 127.0.0.1，不直接暴露公网，由 nginx 反向代理
 *   - 登录失败按 IP 限速，防暴力破解
 *   - 会话 Cookie 为 HttpOnly + SameSite=Strict
 *   - 文件名白名单校验，防路径穿越
 *
 * 运行：node server.js
 * 环境变量：
 *   ADMIN_PASSWORD  登录密码（必填）
 *   BIND_HOST       监听地址（默认 127.0.0.1）
 *   PORT            监听端口（默认 8091）
 *   SRC_DIR         源码目录（默认 /opt/blog-src）
 *   SITE_DIR        站点发布目录（默认 /var/www/firefly/current）
 */

"use strict";

const http = require("node:http");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");
const crypto = require("node:crypto");
const { execFile } = require("node:child_process");

const BIND_HOST = process.env.BIND_HOST || "127.0.0.1";
const PORT = Number(process.env.PORT || 8091);
const SRC_DIR = process.env.SRC_DIR || "/opt/blog-src";
const SITE_DIR = process.env.SITE_DIR || "/var/www/firefly/current";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const SESSION_TTL_MS = 7 * 24 * 3600 * 1000;

const POSTS_DIR = path.join(SRC_DIR, "src/content/posts");
const DYNAMIC_DIR = path.join(SRC_DIR, "src/content/dynamic");
const MUSIC_JSON = path.join(SRC_DIR, "src/data/music.json");
const FRIENDS_JSON = path.join(SRC_DIR, "src/data/friends.json");
const PROFILE_JSON = path.join(SRC_DIR, "src/data/profile.json");

const SESSION_FILE = path.join(DATA_DIR, "sessions.json");
const BUILD_LOG = "/var/log/dsh-build.log";
const BUILD_SCRIPT = "/usr/local/bin/dsh-build-publish.sh";

if (!ADMIN_PASSWORD) {
  console.error("FATAL: ADMIN_PASSWORD is not set");
  process.exit(1);
}

fs.mkdirSync(DATA_DIR, { recursive: true });

/* ───────────────────────── 会话管理 ───────────────────────── */

let sessions = {};
try {
  sessions = JSON.parse(fs.readFileSync(SESSION_FILE, "utf8"));
} catch {
  sessions = {};
}
let saveTimer = null;
function saveSessions() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    try {
      fs.writeFileSync(SESSION_FILE, JSON.stringify(sessions), { mode: 0o600 });
    } catch (e) {
      console.error("save sessions failed:", e.message);
    }
  }, 500);
}
function pruneSessions() {
  const now = Date.now();
  let changed = false;
  for (const [k, v] of Object.entries(sessions)) {
    if (!v || now - v.created > SESSION_TTL_MS) {
      delete sessions[k];
      changed = true;
    }
  }
  if (changed) saveSessions();
}
setInterval(pruneSessions, 3600 * 1000).unref();

function verifyPassword(input) {
  const a = crypto.createHash("sha256").update(String(input)).digest();
  const b = crypto.createHash("sha256").update(ADMIN_PASSWORD).digest();
  return crypto.timingSafeEqual(a, b);
}

/* ───────────────────────── 登录限速（防暴力破解） ───────────────────────── */

const LOGIN_MAX_FAILS = 5;              // 允许的连续失败次数
const LOGIN_LOCK_MS = 15 * 60 * 1000;   // 锁定时长
const loginFails = new Map();           // ip -> { count, first, lockedUntil }

function clientIp(req) {
  // 优先级：X-Client-IP（nginx 专为本站添加的真实客户端 IP）
  //   > X-Real-IP > X-Forwarded-For 首段 > socket 地址
  // 注意：nginx 的 proxy_set_header X-Real-IP $remote_addr 会覆盖客户端传入的同名头，
  //       所以必须依赖自定义头 X-Client-IP 才能拿到真实来源 IP。
  const xc = req.headers["x-client-ip"];
  if (xc) return String(xc).trim();
  const xr = req.headers["x-real-ip"];
  if (xr) return String(xr).trim();
  const xff = req.headers["x-forwarded-for"];
  if (xff) return String(xff).split(",")[0].trim();
  return req.socket.remoteAddress || "unknown";
}

/**
 * 生成供 fail2ban 识别的日志行。
 *
 * 要点：后台监听 127.0.0.1，所有连接都来自 nginx（127.0.0.1）。
 * fail2ban 的 `<HOST>` 会优先匹配日志行前部的 IP，而 systemd 格式
 * （`Sep 25 22:51:00 hostname blog-admin[pid]: ...`）没有 IP，于是它会用
 * "连接来源 IP" 127.0.0.1，进而触发 ignoreself 规则永不封禁。
 *
 * 因此这里把真实客户端 IP 作为【日志行的第一个 token】，且不在前面出现任何 IP。
 */
function authLog(message, ip) {
  process.stderr.write(`[blog-admin-auth] ${ip} - ${message}\n`);
}

function loginLockRemaining(ip) {
  const rec = loginFails.get(ip);
  if (!rec || !rec.lockedUntil) return 0;
  const left = rec.lockedUntil - Date.now();
  if (left <= 0) {
    loginFails.delete(ip);
    return 0;
  }
  return left;
}

function recordLoginFail(ip) {
  const now = Date.now();
  const rec = loginFails.get(ip) || { count: 0, first: now, lockedUntil: 0 };
  if (now - rec.first > LOGIN_LOCK_MS) {
    rec.count = 0;
    rec.first = now;
    rec.lockedUntil = 0;
  }
  rec.count += 1;
  if (rec.count >= LOGIN_MAX_FAILS) rec.lockedUntil = now + LOGIN_LOCK_MS;
  loginFails.set(ip, rec);
  // 这行日志格式与 /etc/fail2ban/filter.d/blog-admin.conf 的正则严格对应，勿随意改动
  authLog(`failed password attempt (count=${rec.count}${rec.lockedUntil ? ", locked" : ""})`, ip);
}

function clearLoginFails(ip) {
  loginFails.delete(ip);
}

// 定期清理过期限速记录，避免内存无限增长
setInterval(() => {
  const now = Date.now();
  for (const [ip, rec] of loginFails) {
    if (now - rec.first > LOGIN_LOCK_MS && (!rec.lockedUntil || rec.lockedUntil < now)) loginFails.delete(ip);
  }
}, 10 * 60 * 1000).unref();

function parseCookies(req) {
  const out = {};
  const raw = req.headers.cookie;
  if (!raw) return out;
  for (const part of raw.split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function currentSession(req) {
  const sid = parseCookies(req).sid;
  if (!sid) return null;
  const s = sessions[sid];
  if (!s) return null;
  if (Date.now() - s.created > SESSION_TTL_MS) {
    delete sessions[sid];
    saveSessions();
    return null;
  }
  return sid;
}

/* ───────────────────────── 工具函数 ───────────────────────── */

function json(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Length": Buffer.byteLength(body),
  });
  res.end(body);
}

function readBody(req, limit = 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > limit) {
        reject(new Error("payload too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

/** 仅允许在指定根目录内操作，防止路径穿越 */
function safeJoin(root, rel) {
  const p = path.resolve(root, rel);
  if (p !== root && !p.startsWith(root + path.sep)) {
    throw new Error("path escapes root: " + rel);
  }
  return p;
}

/** slug 只允许字母数字、连字符、下划线、点，以及中文 */
function sanitizeSlug(slug) {
  const s = String(slug || "").trim();
  if (!s) throw new Error("slug 不能为空");
  if (s.length > 120) throw new Error("slug 过长");
  if (!/^[\p{L}\p{N}\-_.]+$/u.test(s)) throw new Error("slug 含有非法字符");
  if (s.includes("..")) throw new Error("slug 非法");
  return s;
}

function yamlEscape(v) {
  const s = String(v ?? "");
  return '"' + s.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n") + '"';
}

/** 解析 markdown 文件的 YAML frontmatter（只支持后台写出的简单标量/数组格式） */
function parseFrontmatter(text) {
  const m = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?/.exec(text);
  if (!m) return { data: {}, content: text, hasFm: false };
  const data = {};
  for (const line of m[1].split(/\r?\n/)) {
    const mm = /^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$/.exec(line);
    if (!mm) continue;
    let val = mm[2].trim();
    if (val === "" ) { data[mm[1]] = ""; continue; }
    if (val.startsWith("[") && val.endsWith("]")) {
      data[mm[1]] = val
        .slice(1, -1)
        .split(",")
        .map((x) => x.trim().replace(/^["']|["']$/g, ""))
        .filter(Boolean);
      continue;
    }
    if (val.startsWith('"') && val.endsWith('"')) {
      val = val.slice(1, -1).replace(/\\"/g, '"').replace(/\\n/g, "\n").replace(/\\\\/g, "\\");
    } else if (val === "true") { data[mm[1]] = true; continue; }
    else if (val === "false") { data[mm[1]] = false; continue; }
    else if (/^-?\d+$/.test(val)) { data[mm[1]] = Number(val); continue; }
    data[mm[1]] = val;
  }
  return { data, content: text.slice(m[0].length), hasFm: true };
}

function buildFrontmatter(d) {
  const lines = ["---"];
  const push = (k, v) => { if (v !== undefined && v !== null && v !== "") lines.push(`${k}: ${v}`); };
  push("title", yamlEscape(d.title || ""));
  push("published", yamlEscape(d.published || new Date().toISOString().slice(0, 10)));
  if (d.updated) push("updated", yamlEscape(d.updated));
  lines.push(`draft: ${d.draft ? "true" : "false"}`);
  if (d.pinned) lines.push("pinned: true");
  push("description", yamlEscape(d.description || ""));
  push("image", yamlEscape(d.image || ""));
  if (Array.isArray(d.tags) && d.tags.length) {
    lines.push("tags: [" + d.tags.map((t) => yamlEscape(t)).join(", ") + "]");
  }
  push("category", yamlEscape(d.category || ""));
  push("lang", yamlEscape(d.lang || ""));
  push("author", yamlEscape(d.author || ""));
  push("series", yamlEscape(d.series || ""));
  if (d.seriesOrder !== undefined && d.seriesOrder !== "") lines.push(`seriesOrder: ${Number(d.seriesOrder)}`);
  if (d.comment === false) lines.push("comment: false");
  push("password", yamlEscape(d.password || ""));
  push("passwordHint", yamlEscape(d.passwordHint || ""));
  push("sourceLink", yamlEscape(d.sourceLink || ""));
  push("licenseName", yamlEscape(d.licenseName || ""));
  push("licenseUrl", yamlEscape(d.licenseUrl || ""));
  lines.push("---", "");
  return lines.join("\n");
}

async function readJsonFile(file, fallback) {
  try {
    return JSON.parse(await fsp.readFile(file, "utf8"));
  } catch {
    return fallback;
  }
}

async function writeJsonFile(file, obj) {
  await fsp.mkdir(path.dirname(file), { recursive: true });
  const tmp = file + ".tmp";
  await fsp.writeFile(tmp, JSON.stringify(obj, null, "\t") + "\n", "utf8");
  await fsp.rename(tmp, file);
}

/* ───────────────────────── 构建 ───────────────────────── */

let buildState = { running: false, startedAt: null, lastResult: null, lastFinishedAt: null };

function runBuild() {
  if (buildState.running) return { started: false, reason: "构建正在进行中" };
  buildState.running = true;
  buildState.startedAt = Date.now();
  execFile("/bin/bash", [BUILD_SCRIPT], { timeout: 15 * 60 * 1000 }, (err, stdout, stderr) => {
    buildState.running = false;
    buildState.lastFinishedAt = Date.now();
    buildState.lastResult = {
      ok: !err,
      code: err ? err.code || 1 : 0,
      tail: String(stdout || "").slice(-4000) + String(stderr || "").slice(-2000),
    };
  });
  return { started: true };
}

/* ───────────────────────── 路由 ───────────────────────── */

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
};

async function serveStatic(req, res, urlPath) {
  const rel = urlPath === "/" ? "index.html" : urlPath.replace(/^\/+/, "");
  const base = path.resolve(__dirname, "public");
  let file;
  try {
    file = safeJoin(base, rel);
  } catch {
    res.writeHead(403).end("forbidden");
    return;
  }
  try {
    const st = await fsp.stat(file);
    if (st.isDirectory()) throw new Error("dir");
    const ext = path.extname(file).toLowerCase();
    res.writeHead(200, {
      "Content-Type": MIME[ext] || "application/octet-stream",
      "Cache-Control": "no-cache",
    });
    fs.createReadStream(file).pipe(res);
  } catch {
    // SPA 回退
    const index = path.join(base, "index.html");
    try {
      const html = await fsp.readFile(index);
      res.writeHead(200, { "Content-Type": MIME[".html"], "Cache-Control": "no-cache" });
      res.end(html);
    } catch {
      res.writeHead(404).end("not found");
    }
  }
}

async function handleApi(req, res, urlPath, query) {
  const sid = currentSession(req);

  /* --- 登录 --- */
  if (urlPath === "/api/login" && req.method === "POST") {
    const ip = clientIp(req);
    const left = loginLockRemaining(ip);
    if (left > 0) {
      return json(res, 429, { error: `尝试次数过多，请 ${Math.ceil(left / 60000)} 分钟后再试` });
    }
    const body = JSON.parse((await readBody(req)) || "{}");
    if (!verifyPassword(body.password || "")) {
      recordLoginFail(ip);
      await new Promise((r) => setTimeout(r, 600)); // 拖慢暴力破解
      const rec = loginFails.get(ip);
      const remain = rec ? LOGIN_MAX_FAILS - rec.count : 0;
      return json(res, 401, { error: remain > 0 ? `密码错误，还可尝试 ${remain} 次` : "尝试次数过多，已锁定 15 分钟" });
    }
    clearLoginFails(ip);
    const token = crypto.randomBytes(32).toString("hex");
    sessions[token] = { created: Date.now(), ip };
    saveSessions();
    res.writeHead(200, {
      "Content-Type": "application/json; charset=utf-8",
      "Set-Cookie": `sid=${token}; HttpOnly; Path=/; SameSite=Strict; Max-Age=${SESSION_TTL_MS / 1000}`,
    });
    return res.end(JSON.stringify({ ok: true }));
  }

  if (urlPath === "/api/logout" && req.method === "POST") {
    if (sid) {
      delete sessions[sid];
      saveSessions();
    }
    res.writeHead(200, {
      "Content-Type": "application/json; charset=utf-8",
      "Set-Cookie": "sid=; HttpOnly; Path=/; Max-Age=0",
    });
    return res.end(JSON.stringify({ ok: true }));
  }

  if (urlPath === "/api/me") {
    return json(res, 200, { authenticated: !!sid });
  }

  /* --- 以下均需登录 --- */
  if (!sid) return json(res, 401, { error: "未登录" });

  /* 文章列表 */
  if (urlPath === "/api/posts" && req.method === "GET") {
    const list = [];
    for (const dir of [POSTS_DIR, DYNAMIC_DIR]) {
      let names = [];
      try {
        names = await fsp.readdir(dir);
      } catch {
        continue;
      }
      const isDynamic = dir === DYNAMIC_DIR;
      for (const name of names) {
        if (!/\.(md|mdx)$/i.test(name)) continue;
        const full = path.join(dir, name);
        try {
          const text = await fsp.readFile(full, "utf8");
          const { data } = parseFrontmatter(text);
          const st = await fsp.stat(full);
          list.push({
            kind: isDynamic ? "dynamic" : "post",
            slug: name.replace(/\.(md|mdx)$/i, ""),
            file: name,
            title: data.title || name.replace(/\.(md|mdx)$/i, ""),
            published: data.published || "",
            draft: !!data.draft,
            pinned: !!data.pinned,
            category: data.category || "",
            tags: data.tags || [],
            size: st.size,
            mtime: st.mtimeMs,
          });
        } catch {
          /* 跳过无法解析的文件 */
        }
      }
    }
    list.sort((a, b) => String(b.mtime).localeCompare(String(a.mtime)));
    return json(res, 200, { posts: list });
  }

  /* 读取单篇 */
  if (urlPath === "/api/post" && req.method === "GET") {
    const kind = query.get("kind") === "dynamic" ? "dynamic" : "post";
    const slug = sanitizeSlug(query.get("slug"));
    const dir = kind === "dynamic" ? DYNAMIC_DIR : POSTS_DIR;
    let full = safeJoin(dir, slug + ".md");
    if (!fs.existsSync(full)) full = safeJoin(dir, slug + ".mdx");
    if (!fs.existsSync(full)) return json(res, 404, { error: "文章不存在" });
    const text = await fsp.readFile(full, "utf8");
    const { data, content } = parseFrontmatter(text);
    return json(res, 200, { kind, slug, data, content, file: path.basename(full) });
  }

  /* 保存（新建或更新） */
  if (urlPath === "/api/post" && req.method === "POST") {
    const body = JSON.parse((await readBody(req, 4 * 1024 * 1024)) || "{}");
    const kind = body.kind === "dynamic" ? "dynamic" : "post";
    const slug = sanitizeSlug(body.slug);
    const dir = kind === "dynamic" ? DYNAMIC_DIR : POSTS_DIR;
    await fsp.mkdir(dir, { recursive: true });

    if (kind === "dynamic") {
      const fm = ["---", `published: ${yamlEscape(body.published || new Date().toISOString())}`];
      if (body.pinned) fm.push("pinned: true");
      if (body.location) fm.push(`location: ${yamlEscape(body.location)}`);
      fm.push("---", "");
      await fsp.writeFile(path.join(dir, slug + ".md"), fm.join("\n") + (body.content || ""), "utf8");
    } else {
      const fm = buildFrontmatter(body);
      const ext = body.mdx ? ".mdx" : ".md";
      await fsp.writeFile(path.join(dir, slug + ext), fm + (body.content || ""), "utf8");
      // 若扩展名变了，清掉旧的
      const other = path.join(dir, slug + (ext === ".md" ? ".mdx" : ".md"));
      if (fs.existsSync(other)) await fsp.unlink(other);
    }
    return json(res, 200, { ok: true, slug });
  }

  /* 删除 */
  if (urlPath === "/api/post" && req.method === "DELETE") {
    const slug = sanitizeSlug(query.get("slug"));
    const kind = query.get("kind") === "dynamic" ? "dynamic" : "post";
    const dir = kind === "dynamic" ? DYNAMIC_DIR : POSTS_DIR;
    let removed = false;
    for (const ext of [".md", ".mdx"]) {
      const full = safeJoin(dir, slug + ext);
      if (fs.existsSync(full)) {
        await fsp.unlink(full);
        removed = true;
      }
    }
    return json(res, removed ? 200 : 404, removed ? { ok: true } : { error: "文件不存在" });
  }

  /* JSON 数据文件（音乐 / 友链 / 站点资料） */
  if (urlPath === "/api/data" && req.method === "GET") {
    const which = query.get("name");
    const map = { music: MUSIC_JSON, friends: FRIENDS_JSON, profile: PROFILE_JSON };
    if (!map[which]) return json(res, 400, { error: "未知数据文件" });
    const data = await readJsonFile(map[which], which === "music" ? { tracks: [] } : {});
    return json(res, 200, { name: which, data });
  }

  if (urlPath === "/api/data" && req.method === "POST") {
    const body = JSON.parse((await readBody(req, 1024 * 1024)) || "{}");
    const map = { music: MUSIC_JSON, friends: FRIENDS_JSON, profile: PROFILE_JSON };
    if (!map[body.name]) return json(res, 400, { error: "未知数据文件" });
    await writeJsonFile(map[body.name], body.data ?? {});
    return json(res, 200, { ok: true });
  }

  /* 站点信息（从 siteConfig.ts 里读标题等只读信息） */
  if (urlPath === "/api/site" && req.method === "GET") {
    let title = "";
    try {
      const t = await fsp.readFile(path.join(SRC_DIR, "src/config/siteConfig.ts"), "utf8");
      const m = /title:\s*"([^"]*)"/.exec(t);
      if (m) title = m[1];
    } catch { /* ignore */ }
    let releases = [];
    try {
      releases = (await fsp.readdir("/var/www/firefly/releases")).sort().reverse().slice(0, 5);
    } catch { /* ignore */ }
    let disk = "";
    try {
      const st = fs.statfsSync("/");
      disk = `${(((st.blocks - st.bfree) * st.bsize) / 1e9).toFixed(1)}G / ${((st.blocks * st.bsize) / 1e9).toFixed(1)}G`;
    } catch { /* ignore */ }
    const mem = process.memoryUsage();
    return json(res, 200, {
      title,
      srcDir: SRC_DIR,
      siteDir: SITE_DIR,
      releases,
      disk,
      build: buildState,
      uptime: process.uptime(),
      rssMB: Math.round(mem.rss / 1048576),
    });
  }

  /* 构建 */
  if (urlPath === "/api/build" && req.method === "POST") {
    const r = runBuild();
    return json(res, r.started ? 200 : 409, r);
  }

  if (urlPath === "/api/build/status" && req.method === "GET") {
    return json(res, 200, buildState);
  }

  if (urlPath === "/api/build/log" && req.method === "GET") {
    try {
      const txt = await fsp.readFile(BUILD_LOG, "utf8");
      return json(res, 200, { log: txt.split("\n").slice(-200).join("\n") });
    } catch {
      return json(res, 200, { log: "(暂无构建日志)" });
    }
  }

  return json(res, 404, { error: "接口不存在" });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://localhost");
  const urlPath = decodeURIComponent(url.pathname);

  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");

  try {
    if (urlPath.startsWith("/api/")) {
      await handleApi(req, res, urlPath, url.searchParams);
    } else {
      await serveStatic(req, res, urlPath);
    }
  } catch (err) {
    console.error("request error:", err);
    if (!res.headersSent) json(res, 500, { error: String(err.message || err) });
    else res.end();
  }
});

server.listen(PORT, BIND_HOST, () => {
  console.log(`[blog-admin] listening on ${BIND_HOST}:${PORT}`);
  console.log(`[blog-admin] src=${SRC_DIR} site=${SITE_DIR}`);
  console.log(`[blog-admin] login protection: ${LOGIN_MAX_FAILS} fails -> ${LOGIN_LOCK_MS / 60000}min lock`);
});
