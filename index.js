/**
 * @smilintux/capauth
 *
 * CapAuth - Sovereign capability-based authentication protocol.
 * This is a JS/TS bridge to the Python capauth package.
 * Install the Python package for full functionality: pip install capauth
 */

const { execSync } = require("child_process");

const VERSION = "0.1.0";
const PYTHON_PACKAGE = "capauth";

function checkInstalled() {
  try {
    execSync(`python3 -c "import capauth"`, { stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}

function run(args) {
  return execSync(`capauth ${args}`, { encoding: "utf-8" });
}

module.exports = {
  VERSION,
  PYTHON_PACKAGE,
  checkInstalled,
  run,
};
