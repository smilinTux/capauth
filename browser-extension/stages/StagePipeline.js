/**
 * CapAuth Stage Pipeline — orchestrator.
 *
 * Runs a sequence of CapAuthStage instances, threading a context object
 * through each one. Stages that return canHandle(context)=false are skipped.
 * Any stage may abort the pipeline by throwing a CapAuthStageError with abort=true.
 *
 * Usage:
 *   const pipeline = new StagePipeline(containerEl, [
 *     new AuthenticatorSelectionStage(),
 *     new QRDisplayStage(),
 *     new SignatureVerificationStage(),
 *   ]);
 *   const result = await pipeline.run({ serviceUrl, fingerprint });
 *
 * @module stages/StagePipeline
 */

import { CapAuthStageError } from "./CapAuthStage.js";

export class StagePipeline {
  /**
   * @param {HTMLElement} container - Element where stage UIs are rendered.
   * @param {CapAuthStage[]} stages - Ordered list of stages to execute.
   */
  constructor(container, stages = []) {
    this.container = container;
    this.stages = stages;
    this._currentStage = null;
    this._aborted = false;
    this._onProgress = null;
    this._onComplete = null;
    this._onError = null;
  }

  /**
   * Register a progress callback invoked before each stage runs.
   *
   * @param {Function} fn - Called with (stageName, stageIndex, totalStages).
   * @returns {this}
   */
  onProgress(fn) {
    this._onProgress = fn;
    return this;
  }

  /**
   * Register a completion callback invoked when all stages finish.
   *
   * @param {Function} fn - Called with final context object.
   * @returns {this}
   */
  onComplete(fn) {
    this._onComplete = fn;
    return this;
  }

  /**
   * Register an error callback.
   *
   * @param {Function} fn - Called with (error, stageName).
   * @returns {this}
   */
  onError(fn) {
    this._onError = fn;
    return this;
  }

  /**
   * Run the pipeline with an initial context.
   *
   * @param {Object} [initialContext={}] - Seed data for the pipeline context.
   * @returns {Promise<Object>} Final context after all stages complete.
   */
  async run(initialContext = {}) {
    let context = { ...initialContext };
    this._aborted = false;

    const eligible = this.stages.filter((s) => s.canHandle(context));
    const total = eligible.length;

    for (let i = 0; i < this.stages.length; i++) {
      const stage = this.stages[i];

      // Skip stages that can't handle the current context
      if (!stage.canHandle(context)) continue;

      this._currentStage = stage;
      const stageIndex = eligible.indexOf(stage);

      // Progress notification
      this._onProgress?.(stage.name, stageIndex, total);

      // Render stage UI into the container
      this._clearContainer();
      stage.render(this.container, context);

      // Show breadcrumb progress
      this._renderBreadcrumb(stage.name, stageIndex, total);

      try {
        context = await stage.execute(context);
      } catch (err) {
        stage.destroy?.();
        this._currentStage = null;

        const isAbort = err instanceof CapAuthStageError && err.abort;
        this._onError?.(err, stage.name);

        if (isAbort || context.aborted) {
          this._aborted = true;
          this._renderAborted(err.message);
          return { ...context, aborted: true, error: err.message };
        }

        // Non-fatal: continue to next stage with error in context
        context = { ...context, stageError: err.message };
      }

      stage.destroy?.();
    }

    this._currentStage = null;

    if (!this._aborted) {
      this._onComplete?.(context);
    }

    return context;
  }

  /**
   * Abort the pipeline from outside (e.g. user closed the popup).
   */
  abort() {
    this._aborted = true;
    this._currentStage?.destroy?.();
  }

  // ---------------------------------------------------------------------------
  // Internal helpers
  // ---------------------------------------------------------------------------

  _clearContainer() {
    // Preserve the breadcrumb element if present
    const breadcrumb = this.container.querySelector(".stage-breadcrumb");
    this.container.innerHTML = "";
    if (breadcrumb) this.container.prepend(breadcrumb);
  }

  _renderBreadcrumb(currentName, index, total) {
    let breadcrumb = this.container.querySelector(".stage-breadcrumb");
    if (!breadcrumb) {
      breadcrumb = document.createElement("div");
      breadcrumb.className = "stage-breadcrumb";
      this.container.prepend(breadcrumb);
    }
    breadcrumb.innerHTML = "";

    for (let i = 0; i < total; i++) {
      const dot = document.createElement("span");
      dot.className = `stage-dot${i < index ? " done" : i === index ? " active" : ""}`;
      breadcrumb.appendChild(dot);
    }

    const label = document.createElement("span");
    label.className = "stage-breadcrumb-label";
    label.textContent = currentName;
    breadcrumb.appendChild(label);
  }

  _renderAborted(message) {
    this.container.innerHTML = "";
    const wrapper = document.createElement("div");
    wrapper.className = "stage-wrapper stage-aborted";
    wrapper.innerHTML = `
      <div class="stage-icon stage-icon--error">✕</div>
      <div class="stage-title">Cancelled</div>
      <div class="stage-desc">${message || "Authentication was cancelled."}</div>
    `;
    this.container.appendChild(wrapper);
  }
}
