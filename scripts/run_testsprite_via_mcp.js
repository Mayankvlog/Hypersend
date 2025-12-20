/**
 * Run TestSprite MCP tools using the MCP stdio protocol (Content-Length framing).
 *
 * Usage (PowerShell, from repo root):
 *   node scripts/run_testsprite_via_mcp.js frontend
 *   node scripts/run_testsprite_via_mcp.js backend
 *
 * Prereqs:
 * - Backend running locally on 127.0.0.1:8000 for backend tests
 * - Frontend served locally on 127.0.0.1:64216 for frontend tests
 * - TestSprite API key available via %USERPROFILE%\\.cursor\\mcp.json (Cursor config)
 *
 * Output:
 * - testsprite_tests/testsprite-mcp-test-report.md (and .html) under project root
 */

const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");

const PROJECT_PATH = path.resolve(__dirname, "..");
const PROJECT_NAME = path.basename(PROJECT_PATH);

function readApiKeyFromCursorConfig() {
  const p = path.join(process.env.USERPROFILE || "", ".cursor", "mcp.json");
  const raw = fs.readFileSync(p, "utf8");
  const obj = JSON.parse(raw);
  const key = obj?.mcpServers?.TestSprite?.env?.API_KEY;
  if (!key) throw new Error("API_KEY not found in ~/.cursor/mcp.json");
  return key;
}

function frame(obj) {
  const json = JSON.stringify(obj);
  const bytes = Buffer.from(json, "utf8");
  const header = Buffer.from(`Content-Length: ${bytes.length}\r\n\r\n`, "utf8");
  return Buffer.concat([header, bytes]);
}

function parseFrames(buffer) {
  const messages = [];
  let offset = 0;
  while (true) {
    let headerEnd = buffer.indexOf("\r\n\r\n", offset);
    let headerSepLen = 4;
    if (headerEnd === -1) {
      headerEnd = buffer.indexOf("\n\n", offset);
      headerSepLen = 2;
    }
    if (headerEnd === -1) break;

    const headerText = buffer.slice(offset, headerEnd).toString("utf8");
    const match = headerText.match(/Content-Length:\s*(\d+)/i);
    if (!match) break;
    const len = parseInt(match[1], 10);
    const bodyStart = headerEnd + headerSepLen;
    const bodyEnd = bodyStart + len;
    if (buffer.length < bodyEnd) break;
    const body = buffer.slice(bodyStart, bodyEnd).toString("utf8");
    try {
      messages.push(JSON.parse(body));
    } catch {
      // ignore
    }
    offset = bodyEnd;
  }
  return { messages, rest: buffer.slice(offset) };
}

function spawnTestspriteMcpServer() {
  const apiKey = readApiKeyFromCursorConfig();
  const isWin = process.platform === "win32";
  const cmd = isWin ? "cmd.exe" : "npx";
  const args = isWin
    ? ["/c", "npx", "--yes", "@testsprite/testsprite-mcp@latest", "server"]
    : ["--yes", "@testsprite/testsprite-mcp@latest", "server"];

  return spawn(cmd, args, {
    stdio: ["pipe", "pipe", "pipe"],
    env: {
      ...process.env,
      API_KEY: apiKey,
      // Important: let tool run tests directly and produce report (no extra "run in terminal" step)
      EXECUTION_TYPE: "tool",
    },
  });
}

class McpClient {
  constructor(proc) {
    this.proc = proc;
    this.buf = Buffer.alloc(0);
    this.pending = new Map();

    proc.stdout.on("data", (chunk) => {
      this.buf = Buffer.concat([this.buf, chunk]);
      const parsed = parseFrames(this.buf);
      this.buf = parsed.rest;
      for (const msg of parsed.messages) {
        if (typeof msg.id !== "undefined" && this.pending.has(msg.id)) {
          const { resolve, reject } = this.pending.get(msg.id);
          this.pending.delete(msg.id);
          if (msg.error) reject(msg.error);
          else resolve(msg.result);
        }
      }
    });

    proc.stderr.on("data", (chunk) => {
      // forward server errors to stdout so Cursor terminal capture shows progress
      process.stdout.write(chunk.toString("utf8"));
    });

    proc.on("exit", (code, signal) => {
      const err = new Error(`TestSprite MCP server exited (code=${code}, signal=${signal})`);
      for (const [, { reject }] of this.pending.entries()) reject(err);
      this.pending.clear();
    });
  }

  request(method, params) {
    const id = Math.floor(Math.random() * 1e9);
    const msg = { jsonrpc: "2.0", id, method, params };
    this.proc.stdin.write(frame(msg));
    return new Promise((resolve, reject) => {
      const timeoutMs = 30 * 60 * 1000; // long-running tool calls (test gen/exec) can take a while
      const t = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`Timed out waiting for response to ${method}`));
      }, timeoutMs);
      this.pending.set(id, {
        resolve: (v) => {
          clearTimeout(t);
          resolve(v);
        },
        reject: (e) => {
          clearTimeout(t);
          reject(e);
        },
      });
    });
  }

  notify(method, params) {
    const msg = { jsonrpc: "2.0", method, params };
    this.proc.stdin.write(frame(msg));
  }
}

async function callTool(client, name, args) {
  return await client.request("tools/call", { name, arguments: args });
}

async function run(mode) {
  const proc = spawnTestspriteMcpServer();
  const client = new McpClient(proc);

  const log = (s) => process.stdout.write(`[testsprite:${mode}] ${s}\n`);

  log("initialize...");
  await client.request("initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "zaply-testsprite-runner", version: "1.0.0" },
  });
  client.notify("notifications/initialized", {});
  log("initialized");

  if (mode === "ping") {
    log("tools/list...");
    const res = await client.request("tools/list", {});
    const names = (res?.tools || []).map((t) => t.name).filter(Boolean);
    log(`tools: ${names.join(", ")}`);
    proc.kill();
    return;
  }

  if (mode === "frontend") {
    log("bootstrap frontend...");
    await callTool(client, "testsprite_bootstrap_tests", {
      localPort: 64216,
      pathname: "/#/auth",
      type: "frontend",
      projectPath: PROJECT_PATH,
      testScope: "codebase",
    });

    log("code summary...");
    await callTool(client, "testsprite_generate_code_summary", {
      projectRootPath: PROJECT_PATH,
    });

    log("standard PRD...");
    await callTool(client, "testsprite_generate_standardized_prd", {
      projectPath: PROJECT_PATH,
    });

    log("frontend test plan...");
    await callTool(client, "testsprite_generate_frontend_test_plan", {
      projectPath: PROJECT_PATH,
      needLogin: false,
    });

    log("generate + execute frontend tests...");
    await callTool(client, "testsprite_generate_code_and_execute", {
      projectName: PROJECT_NAME,
      projectPath: PROJECT_PATH,
      testIds: [],
      additionalInstruction:
        "App URL is http://127.0.0.1:64216/#/auth. Create a new account (random email), login, allow permissions, open chats list, open a chat, send message, long-press message for react/pin/edit/delete, create group and add members, open group info, toggle mute, and logout.",
    });
    log("frontend done");
  } else if (mode === "backend") {
    log("bootstrap backend...");
    await callTool(client, "testsprite_bootstrap_tests", {
      localPort: 8000,
      pathname: "/health",
      type: "backend",
      projectPath: PROJECT_PATH,
      testScope: "codebase",
    });

    log("code summary...");
    await callTool(client, "testsprite_generate_code_summary", {
      projectRootPath: PROJECT_PATH,
    });

    log("standard PRD...");
    await callTool(client, "testsprite_generate_standardized_prd", {
      projectPath: PROJECT_PATH,
    });

    log("backend test plan...");
    await callTool(client, "testsprite_generate_backend_test_plan", {
      projectPath: PROJECT_PATH,
    });

    log("generate + execute backend tests...");
    await callTool(client, "testsprite_generate_code_and_execute", {
      projectName: PROJECT_NAME,
      projectPath: PROJECT_PATH,
      testIds: [],
      additionalInstruction:
        "Base URL is http://127.0.0.1:8000. Validate /health, then full auth flow (/api/v1/auth/register, /login, /logout), /api/v1/users/me, /api/v1/users/contacts, /api/v1/chats list/create/messages, group APIs under /api/v1/groups, and file resumable upload init/chunk/complete for a small test file.",
    });
    log("backend done");
  } else {
    throw new Error("Usage: node scripts/run_testsprite_via_mcp.js <frontend|backend|ping>");
  }

  proc.kill();
}

async function main() {
  const mode = (process.argv[2] || "").toLowerCase();
  await run(mode);
  process.stdout.write("OK\n");
}

main().catch((e) => {
  process.stdout.write(`${e?.message || String(e)}\n`);
  process.exit(1);
});


