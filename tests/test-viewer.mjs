// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Nieuwsma Services LLC
import fs from "fs";
import path from "path";
import vm from "vm";
import { fileURLToPath } from "url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const html = fs.readFileSync(path.join(root, "viewer/index.html"), "utf8");
const match = html.match(/<script>([\s\S]*?)<\/script>/);
if (!match) {
  console.error("viewer script missing");
  process.exit(1);
}

class El {
  constructor(id) {
    this.id = id;
    this.innerHTML = "";
    this.textContent = "";
    this.classList = { add() {}, remove() {} };
  }
  addEventListener() {}
}

const report = new El("report");
const error = new El("error");
const file = new El("file");
const drop = new El("drop");
const documentShim = {
  readyState: "complete",
  getElementById(id) {
    return { file, drop, report, error }[id] || null;
  },
  addEventListener() {},
};
const context = {
  console,
  URLSearchParams,
  document: documentShim,
  location: { search: "" },
  window: { addEventListener() {} },
};
context.globalThis = context;
vm.createContext(context);
vm.runInContext(match[1], context, { filename: "viewer/index.html" });
if (typeof context.renderAudit !== "function") {
  console.error("renderAudit was not exported");
  process.exit(1);
}

const audit = JSON.parse(fs.readFileSync(path.join(root, "examples/fixtures/audit.example.json"), "utf8"));
context.renderAudit(audit);
const rendered = report.innerHTML;
const text = rendered.replace(/<[^>]+>/g, " ");
function assert(condition, message) {
  if (!condition) {
    console.error(message);
    process.exit(1);
  }
}
assert(text.includes("example-mac"), "hostname");
assert(text.includes("Effective Codex posture"), "posture section");
assert(text.includes("Trusted projects"), "projects section");
assert(text.includes("Auto-allow rules"), "rules section");
assert(text.includes("MCP servers"), "mcp section");
assert(text.includes("High-privilege feature flags"), "features section");
assert(text.includes("Scanner findings"), "tools section");
assert(text.includes("Privilege matrix"), "matrix section");
assert(text.includes("Recommendations"), "recommendations section");
assert(text.includes("Skipped and not covered"), "skipped section");
assert(text.includes("Read-only verification"), "verification section");
assert(text.includes("Kit matrix"), "matrix attribution");
assert(text.includes("mcp-audit") || text.includes("Synthetic high finding"), "mcp finding");
assert(text.includes("AI Access Auditor"), "access auditor");
assert(text.includes("Codex Security Audit"), "aisec");
assert(rendered.includes('class="pill gap"'), "gap pill");
assert(text.includes("no changes") || text.includes("unchanged"), "verification ok");

const hostile = structuredClone(audit);
hostile.summary.headline = '<img src=x onerror=alert(1)>';
context.renderAudit(hostile);
assert(report.innerHTML.includes("&lt;img"), "headline is escaped");
assert(!report.innerHTML.includes("<img"), "raw img tag is not injected");
console.log("viewer fixture rendered");
