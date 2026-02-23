#!/usr/bin/env node
/**
 * CLI bridge: forwards commands to the Python capauth CLI.
 * Usage: capauth-js init
 */

const { execSync } = require("child_process");

const args = process.argv.slice(2).join(" ");

try {
  const output = execSync(`capauth ${args}`, {
    encoding: "utf-8",
    stdio: "inherit",
  });
} catch (err) {
  process.exit(err.status || 1);
}
