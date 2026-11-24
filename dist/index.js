// --- shared: identical in every action, checked by test/actions.test.mjs ---
import { appendFileSync } from "node:fs";
import { randomUUID } from "node:crypto";

const env = process.env;

class Fail extends Error {}
const fail = (message) => {
  throw new Fail(message);
};
const escapeCommand = (s) => String(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");

// GitHub passes input "keep-days" as INPUT_KEEP-DAYS: upper-cased, dashes kept.
const input = (name, fallback = "") => (env[`INPUT_${name.toUpperCase()}`] ?? "").trim() || fallback;

const setOutput = (name, value) => {
  const text = String(value);
  if (!env.GITHUB_OUTPUT) {
    console.log(`output ${name}=${text}`);
    return;
  }
  const delimiter = `ghadelimiter_${randomUUID()}`;
  appendFileSync(env.GITHUB_OUTPUT, `${name}<<${delimiter}\n${text}\n${delimiter}\n`);
};

// Hosted Releng.dev. A team that runs its own server names it with RELENG_URL or the server input.
const HOSTED_URL = "https://api.releng.dev";

const serverUrl = () => (env.RELENG_URL || input("server") || HOSTED_URL).replace(/\/+$/, "");

// The job's OIDC token, audience "releng". Never printed; masked in the log.
const getToken = async () => {
  const requestUrl = env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const requestToken = env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!requestUrl || !requestToken) {
    fail("This job can't get an OIDC token. Add `permissions: id-token: write` to the job (or the workflow).");
  }
  const url = new URL(requestUrl);
  url.searchParams.set("audience", "releng");
  const res = await fetch(url, { headers: { authorization: `Bearer ${requestToken}` } });
  if (!res.ok) fail(`GitHub would not give an OIDC token (${res.status}): ${(await res.text()).slice(0, 200)}`);
  const { value } = await res.json();
  if (!value) fail("GitHub answered the OIDC request without a token.");
  console.log(`::add-mask::${value}`);
  return value;
};

// Calls Releng.dev's runner API. Fails on any status not in `allow`.
const call = async (method, path, { json, body, query, allow = [] } = {}) => {
  const base = serverUrl();
  const token = await getToken();
  const url = new URL(`${base}${path}`);
  for (const [k, v] of Object.entries(query ?? {})) if (v) url.searchParams.set(k, v);
  const headers = { authorization: `Bearer ${token}` };
  if (json !== undefined) headers["content-type"] = "application/json";
  let res;
  try {
    res = await fetch(url, { method, headers, body: json !== undefined ? JSON.stringify(json) : body });
  } catch (e) {
    fail(`Could not reach Releng.dev at ${base}: ${e.cause?.message ?? e.message}`);
  }
  if (res.ok || allow.includes(res.status)) return res;
  const text = (await res.text()).slice(0, 500);
  let message = text;
  try {
    const parsed = JSON.parse(text);
    message = parsed.error ?? parsed.message ?? text;
  } catch {}
  fail(`Releng.dev answered ${res.status} on ${method} ${path}: ${message || res.statusText}`);
};

const run = (main) =>
  main().catch((e) => {
    console.log(`::error::${escapeCommand(e instanceof Fail ? e.message : `Unexpected failure: ${e.stack ?? e}`)}`);
    process.exit(1);
  });
// --- end shared ---

import { createHash } from "node:crypto";
import { createWriteStream } from "node:fs";
import { mkdir } from "node:fs/promises";
import { dirname, resolve, sep } from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";

run(async () => {
  const dir = resolve(input("path", "build/"));
  const from = input("from");
  const stop = input("stop");
  const sbom = input("sbom", "false") === "true";
  const optional = input("optional", "false") === "true";
  if (optional && !stop) fail("`optional` goes with `stop`: only a stop can have nothing yet.");

  const res = await call("GET", "/runner/v1/builds", {
    query: { from, stop, role: sbom ? "sbom" : "", optional: optional ? "true" : "" },
  });
  const answer = await res.json();
  const files = answer.files ?? [];
  const where = stop ? `${stop}${from ? ` of ${from}` : ""}` : "this run";
  if (answer.found === false || files.length === 0) {
    const what = answer.found === false ? `${where} has no build yet` : `the build of ${where} kept ${sbom ? "no SBOM" : "no files"}`;
    if (!optional) fail(`Nothing to fetch: ${what}.${sbom ? " Keep one with releng-dev/upload and role: sbom." : ""}`);
    console.log(`Nothing to fetch: ${what}.`);
    setOutput("found", "false");
    setOutput("path", dir);
    return;
  }

  console.log(`Fetching ${sbom ? "the SBOM of " : ""}build ${answer.build} of ${answer.version}, from ${where}, into ${dir}.`);
  for (const f of files) {
    const target = resolve(dir, f.name);
    if (!target.startsWith(dir + sep)) fail(`${f.name} would land outside ${dir}.`);
    await mkdir(dirname(target), { recursive: true });
    const file = await call("GET", `/runner/v1/files/${f.sha256}`, { query: { from, stop } });
    const hash = createHash("sha256");
    let size = 0;
    const counted = Readable.fromWeb(file.body);
    counted.on("data", (chunk) => {
      hash.update(chunk);
      size += chunk.length;
    });
    await pipeline(counted, createWriteStream(target));
    const got = hash.digest("hex");
    if (got !== f.sha256) fail(`${f.name} came back with sha256 ${got}, not ${f.sha256}.`);
    console.log(`  ${got}  ${f.name} (${size} bytes)`);
  }
  setOutput("found", "true");
  setOutput("version", answer.version);
  setOutput("build", answer.build);
  setOutput("path", dir);
});
