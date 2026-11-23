import { type ChildProcess, execFile, spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import type { Stigmer, WaitOptions, WaitResult } from "../src/index.js";

const execFileAsync = promisify(execFile);
const START_TIMEOUT_MS = 15_000;

// Compiled tests live in dist/test, sources in test; both are two levels below the sdk dir.
const SDK_DIR = resolve(fileURLToPath(new URL("../..", import.meta.url)));

export function stigmerdPath(): string {
  const bin = process.env["STIGMERD_BIN"] ?? resolve(SDK_DIR, "../../target/debug/stigmerd");
  if (!existsSync(bin)) {
    throw new Error(
      `stigmerd binary not found at ${bin}. Run \`cargo build -p stigmerd\` from the repository root, or set STIGMERD_BIN.`,
    );
  }
  return bin;
}

const children = new Set<ChildProcess>();
const dirs = new Set<string>();

function killAll(): void {
  for (const child of children) child.kill("SIGKILL");
  children.clear();
}
process.on("exit", killAll);
for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    killAll();
    process.exit(1);
  });
}

export interface TestServer {
  /** Base URL, for example http://127.0.0.1:41234. */
  url: string;
  dataDir: string;
  stop(): Promise<void>;
}

export async function makeDataDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "stigmer-sdk-test-"));
  dirs.add(dir);
  return dir;
}

/** Starts stigmerd on an ephemeral loopback port. Call `stop` in an `after` hook. */
export async function startServer(dataDir?: string): Promise<TestServer> {
  const bin = stigmerdPath();
  const dir = dataDir ?? (await makeDataDir());
  const child = spawn(bin, ["serve", "--bind", "127.0.0.1:0", "--data-dir", dir], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  children.add(child);
  const exited = new Promise<void>((done) => child.once("exit", () => done()));

  const url = await new Promise<string>((resolveUrl, reject) => {
    let out = "";
    let err = "";
    const timer = setTimeout(() => fail(new Error("stigmerd did not print its listening line in time")), START_TIMEOUT_MS);
    const fail = (error: Error) => {
      clearTimeout(timer);
      child.kill("SIGKILL");
      reject(new Error(`${error.message}; stderr: ${err.slice(-500)}`));
    };
    child.stderr?.on("data", (chunk: Buffer) => {
      err += chunk.toString();
    });
    child.stdout?.on("data", (chunk: Buffer) => {
      out += chunk.toString();
      const match = /^listening on (https?:\/\/\S+)[^\n]*\n/m.exec(out);
      if (match?.[1]) {
        clearTimeout(timer);
        resolveUrl(match[1]);
      }
    });
    child.once("error", fail);
    child.once("exit", (code) => fail(new Error(`stigmerd exited early with code ${code}`)));
  });
  // Keep draining so a full pipe never blocks the server.
  child.stdout?.resume();
  child.stderr?.resume();

  return {
    url,
    dataDir: dir,
    async stop() {
      child.kill("SIGTERM");
      const hard = setTimeout(() => child.kill("SIGKILL"), 5_000);
      await exited;
      clearTimeout(hard);
      children.delete(child);
      dirs.delete(dir);
      await rm(dir, { recursive: true, force: true });
    },
  };
}

/**
 * Starts a wait that cannot miss a post made after this function resolves: it takes the board's
 * head first and waits `after` it (from the start when the board is empty). No sleeping needed.
 */
export async function waitFromHead(client: Stigmer, opts: Omit<WaitOptions, "after" | "fromNow"> = {}): Promise<{ done: Promise<WaitResult> }> {
  const head = await client.events({ fromNow: true, timeoutS: 0 });
  // Wrapped: returning the promise itself from an async function would await the whole wait.
  return { done: client.wait({ ...opts, ...(head.cursor === null ? {} : { after: head.cursor }) }) };
}

export interface Secrets {
  instanceToken: string;
  mainAdminInvite: string;
}

/** Runs `stigmerd admin enable-auth` on a data directory and returns the secrets it prints. Never log them. */
export async function enableAuth(dataDir: string): Promise<Secrets> {
  const { stdout } = await execFileAsync(stigmerdPath(), ["admin", "enable-auth", "--data-dir", dataDir], {
    timeout: START_TIMEOUT_MS,
  });
  const instanceToken = /^instance token: (\S+)$/m.exec(stdout)?.[1];
  const mainAdminInvite = /^main admin invite: (\S+)$/m.exec(stdout)?.[1];
  if (!instanceToken || !mainAdminInvite) throw new Error("enable-auth output had an unexpected shape");
  return { instanceToken, mainAdminInvite };
}

/** Removes any temp dirs left by a crashed run (called from after hooks as a safety net). */
export async function cleanup(): Promise<void> {
  killAll();
  await Promise.all([...dirs].map((d) => rm(d, { recursive: true, force: true })));
  dirs.clear();
}
