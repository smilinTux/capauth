/**
 * CapAuth Stage Pipeline — Base Stage class.
 *
 * Each authentication stage represents one step in the CapAuth sign-in
 * pipeline. Stages are chained by StagePipeline, which passes a shared
 * context object through each stage in sequence.
 *
 * A stage can:
 *   - Render UI into a container element (for user-facing steps)
 *   - Perform async operations (API calls, crypto)
 *   - Skip itself if canHandle() returns false
 *   - Signal an abort by throwing a CapAuthStageError with abort=true
 *
 * Context shape (common fields, stages may add more):
 * {
 *   serviceUrl:     string  — target CapAuth service base URL
 *   fingerprint:    string  — user's PGP fingerprint
 *   authMethod:     string  — 'pgp-key' | 'hardware' | 'qr'
 *   challenge:      Object  — challenge response from server
 *   signature:      string  — ASCII-armored PGP signature
 *   authResult:     Object  — final token response
 *   localVerified:  boolean — whether signature was locally pre-verified
 *   aborted:        boolean — set true by user cancellation
 * }
 *
 * @module stages/CapAuthStage
 */

export class CapAuthStageError extends Error {
  /**
   * @param {string} message - Human-readable error description.
   * @param {boolean} [abort=false] - If true, the pipeline stops immediately.
   */
  constructor(message, abort = false) {
    super(message);
    this.name = "CapAuthStageError";
    this.abort = abort;
  }
}

export class CapAuthStage {
  /**
   * Human-readable name for this stage (used in logging and the UI breadcrumb).
   *
   * @returns {string}
   */
  get name() {
    return "unnamed";
  }

  /**
   * Determine whether this stage should run given the current context.
   *
   * Return false to skip the stage entirely (execute() will not be called).
   *
   * @param {Object} context - Current pipeline context.
   * @returns {boolean}
   */
  canHandle(context) {
    return true;
  }

  /**
   * Run the stage's primary logic.
   *
   * May be async. Must return the (possibly modified) context object.
   * Throw a CapAuthStageError to signal failure; set abort=true to halt
   * the pipeline immediately.
   *
   * @param {Object} context - Current pipeline context.
   * @returns {Promise<Object>} Updated context.
   */
  async execute(context) {
    throw new CapAuthStageError(`${this.name}: execute() not implemented`, true);
  }

  /**
   * Render stage UI into the provided container element.
   *
   * Called before execute() when the pipeline wants to display something
   * to the user. Use this for interactive steps (selection, confirmation).
   * For background-only stages, this can be a no-op.
   *
   * @param {HTMLElement} container - DOM element to render into.
   * @param {Object} context - Current pipeline context.
   */
  render(container, context) {
    // Default: no UI. Override in interactive stages.
  }

  /**
   * Clean up any resources created during render().
   *
   * Called after execute() completes (success or failure).
   */
  destroy() {
    // Override if the stage creates event listeners, timers, etc.
  }

  // ---------------------------------------------------------------------------
  // Helpers for subclasses
  // ---------------------------------------------------------------------------

  /**
   * Send a message to the background service worker.
   *
   * @param {string} action - Action name (e.g. "INITIATE_AUTH").
   * @param {Object} [payload={}] - Action-specific data.
   * @returns {Promise<any>} Background response.
   */
  _bg(action, payload = {}) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({ action, payload }, (response) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
        } else {
          resolve(response);
        }
      });
    });
  }

  /**
   * Build a simple stage UI wrapper with a title and optional description.
   *
   * @param {string} title - Stage heading.
   * @param {string} [description=''] - Optional body text.
   * @returns {HTMLElement} Wrapper div.
   */
  _makeWrapper(title, description = "") {
    const wrapper = document.createElement("div");
    wrapper.className = "stage-wrapper";

    const h = document.createElement("div");
    h.className = "stage-title";
    h.textContent = title;
    wrapper.appendChild(h);

    if (description) {
      const p = document.createElement("div");
      p.className = "stage-desc";
      p.textContent = description;
      wrapper.appendChild(p);
    }

    return wrapper;
  }

  /**
   * Create a button styled for the stage pipeline.
   *
   * @param {string} label - Button text.
   * @param {'primary'|'secondary'|'danger'} [variant='primary'] - Visual style.
   * @returns {HTMLButtonElement}
   */
  _makeButton(label, variant = "primary") {
    const btn = document.createElement("button");
    btn.className = `stage-btn stage-btn--${variant}`;
    btn.textContent = label;
    return btn;
  }
}
