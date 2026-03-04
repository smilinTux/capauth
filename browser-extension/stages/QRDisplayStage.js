/**
 * QRDisplayStage — mobile-to-desktop QR authentication.
 *
 * Flow:
 *   1. Request a QR session token from the CapAuth service via background.js
 *   2. Display a QR code that encodes the session URL
 *   3. Poll the background for token acquisition (mobile app signs the challenge)
 *   4. On success, populate context.authResult with the received token
 *
 * Only runs when context.authMethod === 'qr'.
 *
 * The QR code is rendered onto a <canvas> element using a self-contained
 * minimal QR generator (byte mode, version 1–9, error correction L).
 *
 * @module stages/QRDisplayStage
 */

import { CapAuthStage, CapAuthStageError } from "./CapAuthStage.js";

// ---------------------------------------------------------------------------
// Minimal QR code generator (byte mode, versions 1-9, EC level L)
// Based on the ISO/IEC 18004:2015 standard.
// ---------------------------------------------------------------------------

/** GF(256) exponent and log tables (primitive polynomial 0x11D). */
const _GF_EXP = new Uint8Array(512);
const _GF_LOG = new Uint8Array(256);

(function initGF() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    _GF_EXP[i] = x;
    _GF_LOG[x] = i;
    x = (x << 1) ^ (x & 0x80 ? 0x11d : 0);
  }
  for (let i = 255; i < 512; i++) {
    _GF_EXP[i] = _GF_EXP[i - 255];
  }
})();

function _gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]];
}

function _rsGeneratorPoly(degree) {
  let g = [1];
  for (let i = 0; i < degree; i++) {
    const factor = [1, _GF_EXP[i]];
    const res = new Array(g.length + factor.length - 1).fill(0);
    for (let j = 0; j < g.length; j++) {
      for (let k = 0; k < factor.length; k++) {
        res[j + k] ^= _gfMul(g[j], factor[k]);
      }
    }
    g = res;
  }
  return g;
}

function _rsEncode(data, nsym) {
  const gen = _rsGeneratorPoly(nsym);
  const msg = [...data, ...new Array(nsym).fill(0)];
  for (let i = 0; i < data.length; i++) {
    const c = msg[i];
    if (c !== 0) {
      for (let j = 0; j < gen.length; j++) {
        msg[i + j] ^= _gfMul(gen[j], c);
      }
    }
  }
  return msg.slice(data.length);
}

// Version data for L error correction: [maxBytes, ecPerBlock, block1Count, block1Data]
// Versions 1–9, single-block and two-block configurations.
const _VER_L = [
  null,
  [17,   7,  1, 17],   // v1: 21×21, 19 data cw (minus mode+len overhead)
  [32,  10,  1, 34],   // v2: 25×25
  [53,  15,  1, 55],   // v3: 29×29
  [78,  20,  1, 80],   // v4: 33×33
  [106, 26,  1, 108],  // v5: 37×37
  [134, 18,  2, 68],   // v6: 41×41 (2×68 data cw + 9 ec each)
  [154, 20,  2, 78],   // v7: 45×45 (2×78 + 10 ec each)
  [192, 24,  2, 97],   // v8: 49×49 (2×97 + 12 ec each)
  [230, 30,  2, 116],  // v9: 53×53 (2×116 + 15 ec each)
];

// Alignment pattern centers (version → row/col positions, empty for v1-v2)
const _ALIGN = [null, [], [], [6,22], [6,26], [6,30], [6,34], [6,22,38], [6,24,42], [6,28,46]];

/**
 * Generate a QR code matrix for the given text.
 *
 * @param {string} text - Text to encode (ASCII/UTF-8).
 * @returns {{ matrix: Uint8Array[], size: number } | null} QR matrix or null if too long.
 */
function makeQRMatrix(text) {
  const bytes = new TextEncoder().encode(text);
  const len = bytes.length;

  // Find minimum version
  let version = null;
  for (let v = 1; v <= 9; v++) {
    if (len <= _VER_L[v][0]) { version = v; break; }
  }
  if (version === null) return null; // too long for version 9

  const [, ecPerBlock, numBlocks, dataPerBlock] = _VER_L[version];
  const totalData = dataPerBlock * numBlocks;
  const size = version * 4 + 17;

  // --- Build data bitstream ---
  const bits = [];
  const push = (val, n) => { for (let i = n - 1; i >= 0; i--) bits.push((val >> i) & 1); };

  // Byte mode indicator + char count
  push(0b0100, 4);
  push(len, 8);
  for (const b of bytes) push(b, 8);

  // Terminator + padding to byte boundary
  for (let i = 0; i < 4 && bits.length < totalData * 8; i++) bits.push(0);
  while (bits.length % 8) bits.push(0);

  // Pad bytes
  const PAD = [0xEC, 0x11];
  let pi = 0;
  while (bits.length < totalData * 8) { push(PAD[pi++ % 2], 8); }

  // Convert bits to codewords
  const codewords = [];
  for (let i = 0; i < bits.length; i += 8) {
    let b = 0;
    for (let j = 0; j < 8; j++) b = (b << 1) | (bits[i + j] || 0);
    codewords.push(b);
  }

  // --- Reed-Solomon error correction ---
  const blocks = [];
  for (let b = 0; b < numBlocks; b++) {
    const dc = codewords.slice(b * dataPerBlock, (b + 1) * dataPerBlock);
    const ec = _rsEncode(dc, ecPerBlock);
    blocks.push({ dc, ec });
  }

  // Interleave data, then EC codewords
  const final = [];
  const maxDC = Math.max(...blocks.map((b) => b.dc.length));
  for (let i = 0; i < maxDC; i++) for (const blk of blocks) if (i < blk.dc.length) final.push(blk.dc[i]);
  const maxEC = ecPerBlock;
  for (let i = 0; i < maxEC; i++) for (const blk of blocks) if (i < blk.ec.length) final.push(blk.ec[i]);

  // Convert final sequence to a bitstream
  const dataBits = [];
  for (const cw of final) push(cw, 8);  // reuse push against dataBits is wrong — rebuild
  // Rebuild properly:
  const allBits = [];
  for (const cw of final) {
    for (let i = 7; i >= 0; i--) allBits.push((cw >> i) & 1);
  }
  // Remainder bits (version-dependent, all 0)
  const REM = [0, 0, 7, 7, 7, 7, 0, 0, 0, 0];
  for (let i = 0; i < REM[version]; i++) allBits.push(0);

  // --- Build matrix ---
  // Allocate: 0=light, 1=dark, 2=reserved(used for data), 3=function(fixed)
  const mat = Array.from({ length: size }, () => new Uint8Array(size).fill(255));

  const set = (r, c, v) => { if (r >= 0 && r < size && c >= 0 && c < size) mat[r][c] = v; };
  const setFunc = (r, c, dark) => set(r, c, dark ? 3 : 2); // function modules

  // Finder patterns (7×7) at top-left, top-right, bottom-left
  const finder = (tr, tc) => {
    for (let r = -1; r <= 7; r++) for (let c = -1; c <= 7; c++) {
      const dark = r === -1 || r === 7 || c === -1 || c === 7 ||
        (r >= 1 && r <= 5 && c >= 1 && c <= 5 && !(r >= 2 && r <= 4 && c >= 2 && c <= 4));
      setFunc(tr + r, tc + c, dark);
    }
  };
  finder(0, 0); finder(0, size - 7); finder(size - 7, 0);

  // Timing patterns
  for (let i = 6; i < size - 6; i++) {
    setFunc(6, i, i % 2 === 0);
    setFunc(i, 6, i % 2 === 0);
  }

  // Dark module
  setFunc(size - 8, 8, true);

  // Alignment patterns (version >= 2)
  const ap = _ALIGN[version];
  for (const r of ap) for (const c of ap) {
    if (mat[r][c] < 2) continue; // skip if occupied by finder
    for (let dr = -2; dr <= 2; dr++) for (let dc2 = -2; dc2 <= 2; dc2++) {
      const dark = dr === -2 || dr === 2 || dc2 === -2 || dc2 === 2 || (dr === 0 && dc2 === 0);
      setFunc(r + dr, c + dc2, dark);
    }
  }

  // Reserve format information areas
  for (let i = 0; i < 9; i++) {
    if (mat[8][i] >= 2) mat[8][i] = 0; // top-left row
    if (mat[i][8] >= 2) mat[i][8] = 0; // top-left col
    if (mat[8][size - 1 - i] >= 2) mat[8][size - 1 - i] = 0; // top-right
    if (mat[size - 1 - i][8] >= 2) mat[size - 1 - i][8] = 0; // bottom-left
  }

  // --- Place data bits (zigzag reading order) ---
  let bitIdx = 0;
  let up = true;
  for (let rightCol = size - 1; rightCol >= 1; rightCol -= 2) {
    if (rightCol === 6) rightCol--; // skip timing column
    for (let row = up ? size - 1 : 0; up ? row >= 0 : row < size; up ? row-- : row++) {
      for (let k = 0; k < 2; k++) {
        const col = rightCol - k;
        if (mat[row][col] >= 2) continue; // function module
        mat[row][col] = bitIdx < allBits.length ? allBits[bitIdx++] : 0;
      }
    }
    up = !up;
  }

  // --- Apply mask pattern 0: (row+col) % 2 === 0 ---
  const MASK = 0; // mask pattern 0 for simplicity
  const maskFn = (r, c) => (r + c) % 2 === 0;
  for (let r = 0; r < size; r++) for (let c = 0; c < size; c++) {
    if (mat[r][c] <= 1 && maskFn(r, c)) mat[r][c] ^= 1;
  }

  // --- Write format information (EC=L=01, mask=000, with mask pattern) ---
  // Format string for L-01 + mask-0 = 010111101011001 XOR 101010000010010 = 111101101001011
  // Pre-computed format bits for EC=L, mask=0: 111101101001011
  const FMT = [1,1,1,1,0,1,1,0,1,0,0,1,0,1,1];
  const fmtPos = [
    [[8,0],[8,1],[8,2],[8,3],[8,4],[8,5],[8,7],[8,8],[7,8],[5,8],[4,8],[3,8],[2,8],[1,8],[0,8]],
    [[size-1,8],[size-2,8],[size-3,8],[size-4,8],[size-5,8],[size-6,8],[size-7,8],[8,size-8],[8,size-7],[8,size-6],[8,size-5],[8,size-4],[8,size-3],[8,size-2],[8,size-1]],
  ];
  for (let i = 0; i < 15; i++) {
    mat[fmtPos[0][i][0]][fmtPos[0][i][1]] = FMT[i] ? 3 : 2;
    mat[fmtPos[1][i][0]][fmtPos[1][i][1]] = FMT[i] ? 3 : 2;
  }

  // Normalize: 3,2 → true/false, 1,0 → data
  const result = Array.from({ length: size }, () => new Uint8Array(size));
  for (let r = 0; r < size; r++) for (let c = 0; c < size; c++) {
    result[r][c] = (mat[r][c] === 1 || mat[r][c] === 3) ? 1 : 0;
  }

  return { matrix: result, size };
}

/**
 * Render a QR matrix to a canvas element.
 *
 * @param {HTMLCanvasElement} canvas
 * @param {{ matrix: Uint8Array[], size: number }} qr
 * @param {number} [moduleSize=5] - Pixels per module.
 */
function renderQRToCanvas(canvas, qr, moduleSize = 5) {
  const { matrix, size } = qr;
  const quietZone = 4;
  const total = (size + quietZone * 2) * moduleSize;
  canvas.width = total;
  canvas.height = total;
  const ctx = canvas.getContext("2d");
  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, total, total);
  ctx.fillStyle = "#000000";
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (matrix[r][c]) {
        ctx.fillRect(
          (c + quietZone) * moduleSize,
          (r + quietZone) * moduleSize,
          moduleSize,
          moduleSize
        );
      }
    }
  }
}

// ---------------------------------------------------------------------------
// QR Display Stage
// ---------------------------------------------------------------------------

const POLL_INTERVAL_MS = 2000;
const POLL_MAX_ATTEMPTS = 90; // 3 minutes
const SESSION_EXPIRY_S = 180;

export class QRDisplayStage extends CapAuthStage {
  constructor() {
    super();
    this._pollTimer = null;
    this._resolve = null;
    this._reject = null;
    this._destroyed = false;
  }

  get name() {
    return "QR Sign";
  }

  canHandle(context) {
    return context.authMethod === "qr";
  }

  async execute(context) {
    const { serviceUrl } = context;
    if (!serviceUrl) {
      throw new CapAuthStageError("No service URL in context", true);
    }

    return new Promise((resolve, reject) => {
      this._resolve = resolve;
      this._reject = reject;
      this._startPolling(context, resolve, reject);
    });
  }

  render(container, context) {
    const wrapper = this._makeWrapper(
      "Scan with your mobile device",
      "Open the CapAuth app on your phone and scan the QR code below."
    );
    wrapper.id = "qr-stage-wrapper";

    // QR canvas container
    const qrBox = document.createElement("div");
    qrBox.className = "stage-qr-box";
    qrBox.id = "qr-stage-box";

    // Loading placeholder
    const spinner = document.createElement("div");
    spinner.className = "stage-spinner";
    spinner.id = "qr-stage-spinner";
    qrBox.appendChild(spinner);

    wrapper.appendChild(qrBox);

    // Status line
    const statusLine = document.createElement("div");
    statusLine.className = "stage-qr-status";
    statusLine.id = "qr-stage-status";
    statusLine.textContent = "Generating session…";
    wrapper.appendChild(statusLine);

    // Timer bar
    const timerBar = document.createElement("div");
    timerBar.className = "stage-timer-bar";
    const timerFill = document.createElement("div");
    timerFill.className = "stage-timer-fill";
    timerFill.id = "qr-stage-timer";
    timerBar.appendChild(timerFill);
    wrapper.appendChild(timerBar);

    // Fallback: open in tab
    const openBtn = this._makeButton("Open QR page in tab", "secondary");
    openBtn.id = "qr-open-tab-btn";
    openBtn.disabled = true;
    openBtn.addEventListener("click", () => {
      chrome.runtime.sendMessage({ action: "QR_LOGIN", payload: {} });
    });
    wrapper.appendChild(openBtn);

    const cancelBtn = this._makeButton("Cancel", "secondary");
    cancelBtn.addEventListener("click", () => {
      this._reject?.(new CapAuthStageError("User cancelled QR sign", true));
    });
    wrapper.appendChild(cancelBtn);

    container.appendChild(wrapper);
  }

  destroy() {
    this._destroyed = true;
    clearInterval(this._pollTimer);
    this._pollTimer = null;
    this._resolve = null;
    this._reject = null;
  }

  // ---------------------------------------------------------------------------

  async _startPolling(context, resolve, reject) {
    const { serviceUrl } = context;

    // Step 1: Request a QR session token from the service
    let session;
    try {
      session = await this._requestQRSession(serviceUrl);
    } catch (err) {
      // Fall back to opening the QR page in a tab
      this._updateStatus("Cannot contact service. Opening QR page in tab…");
      await this._bg("QR_LOGIN", {});
      // We can't poll here without a session — fail gracefully
      reject(new CapAuthStageError(`QR session failed: ${err.message}`, false));
      return;
    }

    const sessionUrl = session.url;
    const sessionToken = session.session_token || session.token;

    // Step 2: Render QR code
    this._renderQR(sessionUrl);
    this._updateStatus("Waiting for mobile sign…");
    this._startTimer(SESSION_EXPIRY_S);

    // Enable open-in-tab button
    const openBtn = document.getElementById("qr-open-tab-btn");
    if (openBtn) openBtn.disabled = false;

    // Step 3: Poll for completion
    let attempts = 0;
    this._pollTimer = setInterval(async () => {
      if (this._destroyed) return;
      attempts++;

      if (attempts > POLL_MAX_ATTEMPTS) {
        clearInterval(this._pollTimer);
        reject(new CapAuthStageError("QR session timed out. Please try again.", false));
        return;
      }

      try {
        const result = await this._pollSession(serviceUrl, sessionToken);
        if (result.status === "authenticated") {
          clearInterval(this._pollTimer);
          this._updateStatus("Mobile signed successfully!");

          // Cache the token via background.js
          await this._bg("GET_CACHED_TOKEN", { serviceUrl });

          resolve({
            ...context,
            authResult: {
              success: true,
              source: "qr",
              access_token: result.access_token,
              oidc_claims: result.oidc_claims || {},
              fingerprint: result.fingerprint || "",
              expires_in: result.expires_in || 3600,
            },
          });
        }
        // status === 'pending': keep polling
      } catch {
        // Network blip — keep polling
      }
    }, POLL_INTERVAL_MS);
  }

  async _requestQRSession(serviceUrl) {
    const url = `${serviceUrl.replace(/\/$/, "")}/capauth/v1/qr-session`;
    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ expires_in: SESSION_EXPIRY_S }),
    });
    if (!resp.ok) throw new Error(`QR session request failed (${resp.status})`);
    return resp.json();
  }

  async _pollSession(serviceUrl, sessionToken) {
    const url = `${serviceUrl.replace(/\/$/, "")}/capauth/v1/qr-poll?token=${encodeURIComponent(sessionToken)}`;
    const resp = await fetch(url);
    if (!resp.ok) throw new Error(`Poll failed (${resp.status})`);
    return resp.json();
  }

  _renderQR(url) {
    const box = document.getElementById("qr-stage-box");
    if (!box) return;

    const qr = makeQRMatrix(url);
    if (!qr) {
      box.innerHTML = `<div class="stage-qr-error">URL too long for QR</div>`;
      return;
    }

    const canvas = document.createElement("canvas");
    canvas.className = "stage-qr-canvas";
    // Fit within ~150px for the popup
    const moduleSize = Math.max(2, Math.floor(150 / (qr.size + 8)));
    renderQRToCanvas(canvas, qr, moduleSize);

    box.innerHTML = "";
    box.appendChild(canvas);
  }

  _updateStatus(text) {
    const el = document.getElementById("qr-stage-status");
    if (el) el.textContent = text;
  }

  _startTimer(totalSeconds) {
    const fill = document.getElementById("qr-stage-timer");
    if (!fill) return;

    const startTime = Date.now();
    const update = () => {
      if (this._destroyed) return;
      const elapsed = (Date.now() - startTime) / 1000;
      const pct = Math.max(0, 100 - (elapsed / totalSeconds) * 100);
      fill.style.width = `${pct}%`;
      if (pct > 0) requestAnimationFrame(update);
    };
    requestAnimationFrame(update);
  }
}
