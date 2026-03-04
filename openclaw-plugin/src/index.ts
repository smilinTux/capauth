/**
 * CapAuth — OpenClaw Plugin
 *
 * Registers agent tools that wrap the capauth CLI so Lumina and other
 * OpenClaw agents can use sovereign identity and PMA authentication
 * as first-class tools.
 *
 * Requires: capauth CLI on PATH (typically via ~/.skenv/bin/capauth)
 */

import { execSync } from "node:child_process";
import type { OpenClawPluginApi, AnyAgentTool } from "openclaw/plugin-sdk";
import { emptyPluginConfigSchema } from "openclaw/plugin-sdk";

const CAPAUTH_BIN = process.env.CAPAUTH_BIN || "capauth";
const EXEC_TIMEOUT = 30_000;

function runCli(args: string): { ok: boolean; output: string } {
  try {
    const raw = execSync(`${CAPAUTH_BIN} ${args}`, {
      encoding: "utf-8",
      timeout: EXEC_TIMEOUT,
      env: {
        ...process.env,
        PATH: `${process.env.HOME}/.local/bin:${process.env.HOME}/.skenv/bin:${process.env.PATH}`,
      },
    }).trim();
    return { ok: true, output: raw };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { ok: false, output: msg };
  }
}

function textResult(text: string) {
  return { content: [{ type: "text" as const, text }] };
}

function escapeShellArg(s: string): string {
  return `'${s.replace(/'/g, "'\\''")}'`;
}

// ── Tool definitions ────────────────────────────────────────────────────

function createCapauthProfileTool() {
  return {
    name: "capauth_profile",
    label: "CapAuth Profile",
    description:
      "Show the sovereign identity profile — DID, display name, PMA membership, and capabilities.",
    parameters: { type: "object", properties: {} },
    async execute() {
      const result = runCli("profile show");
      return textResult(result.output);
    },
  };
}

function createCapauthVerifyTool() {
  return {
    name: "capauth_verify",
    label: "CapAuth Verify",
    description:
      "Challenge-response identity verification against a peer's public key.",
    parameters: {
      type: "object",
      required: ["pubkey"],
      properties: {
        pubkey: { type: "string", description: "Path to the peer's public key file." },
      },
    },
    async execute(_id: string, params: Record<string, unknown>) {
      const pubkey = escapeShellArg(String(params.pubkey ?? ""));
      const result = runCli(`verify --pubkey ${pubkey}`);
      return textResult(result.output);
    },
  };
}

function createCapauthPmaStatusTool() {
  return {
    name: "capauth_pma_status",
    label: "CapAuth PMA Status",
    description:
      "Check PMA (Private Membership Association) membership status.",
    parameters: { type: "object", properties: {} },
    async execute() {
      const result = runCli("pma status");
      return textResult(result.output);
    },
  };
}

function createCapauthMeshPeersTool() {
  return {
    name: "capauth_mesh_peers",
    label: "CapAuth Mesh Peers",
    description:
      "List known peers from the identity registry.",
    parameters: { type: "object", properties: {} },
    async execute() {
      const result = runCli("mesh peers");
      return textResult(result.output);
    },
  };
}

function createCapauthMeshStatusTool() {
  return {
    name: "capauth_mesh_status",
    label: "CapAuth Mesh Status",
    description:
      "Show mesh network status — connectivity, peer count, and health.",
    parameters: { type: "object", properties: {} },
    async execute() {
      const result = runCli("mesh status");
      return textResult(result.output);
    },
  };
}

function createCapauthMeshDiscoverTool() {
  return {
    name: "capauth_mesh_discover",
    label: "CapAuth Mesh Discover",
    description:
      "Discover peers on all available networks.",
    parameters: { type: "object", properties: {} },
    async execute() {
      const result = runCli("mesh discover");
      return textResult(result.output);
    },
  };
}

// ── Plugin registration ─────────────────────────────────────────────────

const capauthPlugin = {
  id: "capauth",
  name: "CapAuth",
  description:
    "Sovereign identity and PMA authentication — profiles, verification, mesh networking, and peer discovery.",
  configSchema: emptyPluginConfigSchema(),

  register(api: OpenClawPluginApi) {
    const tools = [
      createCapauthProfileTool(),
      createCapauthVerifyTool(),
      createCapauthPmaStatusTool(),
      createCapauthMeshPeersTool(),
      createCapauthMeshStatusTool(),
      createCapauthMeshDiscoverTool(),
    ];

    for (const tool of tools) {
      api.registerTool(tool as unknown as AnyAgentTool, {
        names: [tool.name],
        optional: true,
      });
    }

    api.registerCommand({
      name: "capauth",
      description: "Run capauth CLI commands. Usage: /capauth <subcommand> [args]",
      acceptsArgs: true,
      handler: async (ctx) => {
        const args = ctx.args?.trim() ?? "profile show";
        const result = runCli(args);
        return { text: result.output };
      },
    });

    api.logger.info?.("CapAuth plugin registered (6 tools + /capauth command)");
  },
};

export default capauthPlugin;
