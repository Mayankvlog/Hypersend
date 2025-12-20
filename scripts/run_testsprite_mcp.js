/**
 * Run TestSprite MCP tools non-interactively by speaking MCP (JSON-RPC) over stdio.
 *
 * Usage (PowerShell):
 *   $env:API_KEY = (Get-Content "$env:USERPROFILE\\.cursor\\mcp.json" | ConvertFrom-Json).mcpServers.TestSprite.env.API_KEY
 *   node scripts/run_testsprite_mcp.js frontend
 *   node scripts/run_testsprite_mcp.js backend
 *
 * Notes:
 * - Requires API_KEY in env (do NOT print it).
 * - Uses local services:
 *   - frontend: http://127.0.0.1:64216/#/chats
 *   - backend:  http://127.0.0.1:8000/health
 */

const { spawn } = require("child_process");
const path = require("path");

const PROJECT_PATH = path.resolve(__dirname, "..");
const PROJECT_NAME = path.basename(PROJECT_PATH);

function assertApiKey() {
  if (!process.env.API_KEY) {
    throw new Error("Missing API_KEY env var. Please set it from ~/.cursor/mcp.json.");
  }
}

function spawnMcpServer() {
  // No args => testsprite-mcp starts MCP server on stdio.
  // On Windows, spawn via cmd.exe to avoid EINVAL when executing .cmd shims.
  const isWin = process.platform === "win32";
  const cmd = isWin ? "cmd.exe" : "npx";
  const args = isWin
    ? ["/c", "npx", "--yes", "@testsprite/testsprite-mcp@latest"]
    : ["--yes", "@testsprite/testsprite-mcp@latest"];

  const child = spawn(cmd, args, {
    stdio: ["pipe", "pipe", "pipe"],
    env: {
      ...process.env,
      // Keep output quiet; do not print secrets
      EXECUTION_TYPE: process.env.EXECUTION_TYPE || "console",
    },
  });

  return child;
}

function makeJsonRpc(id, method, params) {
  return JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n";
}

function makeJsonRpcNotification(method, params) {
  return JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n";
}

function createClient(child) {
  let buf = "";
  const pending = new Map();

  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    buf += chunk;
    while (true) {
      const idx = buf.indexOf("\n");
      if (idx < 0) break;
      const line = buf.slice(0, idx).trim();
      buf = buf.slice(idx + 1);
      if (!line) continue;
      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        // Ignore non-JSON lines
        continue;
      }
      if (msg && typeof msg.id !== "undefined" && pending.has(msg.id)) {
        const { resolve, reject } = pending.get(msg.id);
        pending.delete(msg.id);
        if (msg.error) reject(msg.error);
        else resolve(msg.result);
      }
    }
  });

  // Don't spam logs, but keep stderr for debugging if needed
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", () => {});

  function request(method, params) {
    const id = Math.floor(Math.random() * 1e9);
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      child.stdin.write(makeJsonRpc(id, method, params));
    });
  }

  function notify(method, params) {
    child.stdin.write(makeJsonRpcNotification(method, params));
  }

  return { request, notify };
}

async function mcpInitialize(client) {
  const init = await client.request("initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "zaply-testsprite-runner", version: "1.0.0" },
  });
  // Follow-up notification (some servers expect it)
  client.notify("notifications/initialized", {});
  return init;
}

async function callTool(client, name, args) {
  return await client.request("tools/call", { name, arguments: args });
}

async function runFrontendSetup() {
  const child = spawnMcpServer();
  const client = createClient(child);
  await mcpInitialize(client);

  await callTool(client, "testsprite_bootstrap_tests", {
    localPort: 64216,
    pathname: "/#/chats",
    type: "frontend",
    projectPath: PROJECT_PATH,
    testScope: "codebase",
  });

  await callTool(client, "testsprite_generate_code_summary", {
    projectRootPath: PROJECT_PATH,
  });

  await callTool(client, "testsprite_generate_standardized_prd", {
    projectPath: PROJECT_PATH,
  });

  await callTool(client, "testsprite_generate_frontend_test_plan", {
    projectPath: PROJECT_PATH,
    needLogin: false,
  });

  await callTool(client, "testsprite_generate_code_and_execute", {
    projectName: PROJECT_NAME,
    projectPath: PROJECT_PATH,
    testIds: [],
    additionalInstruction:
      "Test the Flutter web UI on http://127.0.0.1:64216/#/chats. Cover: open chats list, search field, open a chat, long-press message -> react/pin/edit/delete, open group info, create group, add members, mute notifications, logout from menu/settings.",
  });

  child.kill();
}

async function runBackendSetup() {
  const child = spawnMcpServer();
  const client = createClient(child);
  await mcpInitialize(client);

  await callTool(client, "testsprite_bootstrap_tests", {
    localPort: 8000,
    pathname: "/health",
    type: "backend",
    projectPath: PROJECT_PATH,
    testScope: "codebase",
  });

  await callTool(client, "testsprite_generate_code_summary", {
    projectRootPath: PROJECT_PATH,
  });

  await callTool(client, "testsprite_generate_standardized_prd", {
    projectPath: PROJECT_PATH,
  });

  await callTool(client, "testsprite_generate_backend_test_plan", {
    projectPath: PROJECT_PATH,
  });

  await callTool(client, "testsprite_generate_code_and_execute", {
    projectName: PROJECT_NAME,
    projectPath: PROJECT_PATH,
    testIds: [],
    additionalInstruction:
      "Test FastAPI on http://127.0.0.1:8000. Create a user via /api/v1/auth/register, login via /api/v1/auth/login, then test authorized flows: /api/v1/chats, create group chat, send message, edit within 24h, soft-delete, toggle reactions, pin/unpin, mark read, groups endpoints /api/v1/groups for create/update/members/leave/activity, and ensure unauthorized requests are rejected.",
  });

  child.kill();
}

async function main() {
  assertApiKey();
  const mode = (process.argv[2] || "").toLowerCase();
  if (!["frontend", "backend"].includes(mode)) {
    console.error("Usage: node scripts/run_testsprite_mcp.js <frontend|backend>");
    process.exit(2);
  }
  if (mode === "frontend") await runFrontendSetup();
  else await runBackendSetup();
  process.stdout.write("OK\n");
}

main().catch((e) => {
  console.error(String(e && e.message ? e.message : e));
  process.exit(1);
});


