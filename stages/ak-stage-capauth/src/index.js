/**
 * ak-stage-capauth — Authentik custom stage web component.
 *
 * Registers `<ak-stage-capauth>` as a native custom element using
 * Vue 3's defineCustomElement. Drop the built JS file into Authentik's
 * static assets and reference it in a custom stage flow.
 *
 * Attributes / Properties:
 *   service-url     — CapAuth service base URL (default: current origin)
 *   next-url        — Redirect URL after successful authentication
 *   extension-url   — Browser extension install page URL
 *
 * Events:
 *   authenticated   — Fired with { fingerprint, access_token, oidc_claims }
 *   error           — Fired with the error message string
 *
 * Usage in Authentik HTML template:
 *   <script src="/static/dist/ak-stage-capauth.es.js" type="module"><\/script>
 *   <ak-stage-capauth
 *     service-url="https://auth.skworld.io"
 *     next-url="{{ next_url }}"
 *   ></ak-stage-capauth>
 */

import { defineCustomElement } from "vue";
import CapAuthStageVue from "./CapAuthStage.vue";

// Wrap the Vue component as a native custom element
const CapAuthStageElement = defineCustomElement(CapAuthStageVue);

// Register globally so Authentik's stage loader can find it
customElements.define("ak-stage-capauth", CapAuthStageElement);

export { CapAuthStageElement };
