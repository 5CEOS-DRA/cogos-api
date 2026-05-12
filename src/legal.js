'use strict';

// Terms of Service / Privacy Policy / Acceptable Use Policy
// served as plain styled HTML from the gateway itself. No third-party
// markdown library needed; the docs are short and we control the source.
//
// These are TEMPLATED v1 drafts. Operator should review with counsel
// before relying on them for material customer disputes. They are
// nevertheless defensible-enough for launch + Stripe activation, which
// require public URLs.

const COMPANY_LEGAL_NAME = '5CEOs, Inc.';
const COMPANY_DISPLAY_NAME = '5CEOs';
const PRODUCT_NAME = 'CogOS';
const SERVICE_DOMAIN = 'cogos.5ceos.com';
const SUPPORT_EMAIL = 'support@5ceos.com';
const LEGAL_EMAIL = 'legal@5ceos.com';
const PRIVACY_EMAIL = 'privacy@5ceos.com';
const GOVERNING_LAW = 'the State of Florida, United States of America';
const LAST_UPDATED = '2026-05-12';

const STYLE_BLOCK = `<style>
*{box-sizing:border-box}
body{font-family:ui-monospace,SF Mono,Menlo,monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:32px 20px;line-height:1.6}
main{max-width:760px;margin:0 auto}
h1{color:#58a6ff;font-size:24px;margin:0 0 6px}
h2{color:#58a6ff;font-size:16px;margin:28px 0 8px;border-bottom:1px solid #30363d;padding-bottom:6px}
h3{color:#79c0ff;font-size:13px;margin:18px 0 4px}
p{margin:0 0 12px;font-size:13px}
ul, ol{font-size:13px;margin:0 0 12px;padding-left:22px}
li{margin:0 0 4px}
code{background:#161b22;padding:2px 5px;border-radius:3px;font-size:12px}
.meta{color:#6e7681;font-size:11px;margin-bottom:24px}
.callout{background:#161b22;border:1px solid #30363d;border-left:3px solid #58a6ff;padding:12px 14px;margin:14px 0;font-size:13px;border-radius:0 6px 6px 0}
a{color:#58a6ff}
footer{color:#6e7681;font-size:11px;margin-top:48px;padding-top:18px;border-top:1px solid #21262d}
nav a{margin-right:14px}
</style>`;

const NAV = `<nav style="margin-bottom:18px;font-size:11px">
  <a href="/">Home</a>
  <a href="/terms">Terms</a>
  <a href="/privacy">Privacy</a>
  <a href="/aup">Acceptable Use</a>
</nav>`;

function wrapHtml(title, bodyHtml) {
  return `<!DOCTYPE html>
<html>
<head>
  <title>${title} · ${PRODUCT_NAME}</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  ${STYLE_BLOCK}
</head>
<body>
<main>
  ${NAV}
  ${bodyHtml}
  <footer>
    ${PRODUCT_NAME} is operated by ${COMPANY_LEGAL_NAME}. Questions:
    <a href="mailto:${SUPPORT_EMAIL}">${SUPPORT_EMAIL}</a> ·
    <a href="mailto:${LEGAL_EMAIL}">${LEGAL_EMAIL}</a> ·
    <a href="mailto:${PRIVACY_EMAIL}">${PRIVACY_EMAIL}</a>
  </footer>
</main>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// Terms of Service
// ---------------------------------------------------------------------------

const TERMS_BODY = `
<h1>Terms of Service</h1>
<div class="meta">Last updated: ${LAST_UPDATED}</div>

<p>These Terms of Service ("<strong>Terms</strong>") govern your access to and use
of the ${PRODUCT_NAME} API and related services (the "<strong>Service</strong>")
operated by ${COMPANY_LEGAL_NAME} ("<strong>${COMPANY_DISPLAY_NAME}</strong>",
"<strong>we</strong>", or "<strong>us</strong>"). By creating an account, issuing
an API key, or otherwise using the Service, you ("<strong>Customer</strong>")
agree to be bound by these Terms.</p>

<h2>1. Definitions</h2>
<ul>
  <li><strong>Service</strong> means the ${PRODUCT_NAME} gateway, inference engine, audit-bench, and supporting infrastructure operated by ${COMPANY_DISPLAY_NAME} at ${SERVICE_DOMAIN}.</li>
  <li><strong>API Key</strong> means the customer-issued bearer credential beginning with <code>sk-cogos-</code>.</li>
  <li><strong>Inputs</strong> means data Customer submits to the Service, including prompts, messages, and schemas.</li>
  <li><strong>Outputs</strong> means data the Service returns in response to Inputs.</li>
  <li><strong>Subscription Plan</strong> means the package (Operator Starter, Operator Pro, Operator Team, Compliance, or Enterprise) Customer has selected, with its associated monthly request quota and permitted model tiers.</li>
</ul>

<h2>2. Account and Access</h2>
<p>Customer is responsible for safeguarding API Keys. API Keys are issued
once and not retrievable; Customer must securely store the plaintext value
at issuance. Customer is responsible for all activity occurring under
their API Keys. ${COMPANY_DISPLAY_NAME} may revoke any API Key for
violation of these Terms or the Acceptable Use Policy.</p>

<h2>3. Acceptable Use</h2>
<p>Customer agrees to comply with the
<a href="/aup">Acceptable Use Policy</a>, which is incorporated by reference
into these Terms. ${COMPANY_DISPLAY_NAME} may suspend or terminate access
for violations of the Acceptable Use Policy.</p>

<h2>4. Subscription, Billing, and Cancellation</h2>
<ul>
  <li><strong>Billing cycle.</strong> Subscriptions are billed monthly in advance via Stripe (Operator Starter through Compliance) or via invoice (Enterprise).</li>
  <li><strong>Quota and overage.</strong> If Customer's monthly request volume exceeds the Subscription Plan's quota, the Service returns HTTP 429 with an <code>X-Cogos-Quota-Reset</code> header indicating the start of the next billing cycle. ${COMPANY_DISPLAY_NAME} does not bill for overage; quotas are hard ceilings within a billing cycle.</li>
  <li><strong>Plan changes.</strong> Customer may upgrade or downgrade at any time. Upgrades take effect immediately; downgrades take effect at the next billing cycle.</li>
  <li><strong>Cancellation.</strong> Customer may cancel at any time. Cancellation takes effect at the end of the then-current billing cycle. No partial refunds are issued for monthly subscriptions. Enterprise subscriptions are governed by the executed order form and/or master services agreement.</li>
  <li><strong>Failed payment.</strong> If a payment fails, ${COMPANY_DISPLAY_NAME} will attempt re-collection for 14 days. If unsuccessful, the API Keys associated with the subscription are revoked.</li>
  <li><strong>Taxes.</strong> Subscription fees are exclusive of applicable taxes; Customer is responsible for any sales, use, value-added, or similar taxes.</li>
</ul>

<h2>5. Intellectual Property</h2>
<ul>
  <li><strong>Customer Inputs.</strong> Customer retains all rights, title, and interest in Inputs. Customer grants ${COMPANY_DISPLAY_NAME} a limited, non-exclusive license to process Inputs solely to provide the Service.</li>
  <li><strong>Customer Outputs.</strong> As between the parties, Customer owns the Outputs produced from Customer's Inputs. ${COMPANY_DISPLAY_NAME} makes no claim to Outputs and does not retain them after the response is delivered (other than the audit log fields recorded under our Privacy Policy).</li>
  <li><strong>Service IP.</strong> ${COMPANY_DISPLAY_NAME} retains all rights, title, and interest in the Service, including the gateway software, deployment topology, and ${PRODUCT_NAME} architecture.</li>
  <li><strong>Model weights.</strong> The open-weight language models served by the Service (such as Qwen 2.5) are governed by their respective open-source licenses. ${COMPANY_DISPLAY_NAME} does not grant Customer any redistributable rights to model weights.</li>
</ul>

<h2>6. Service Availability</h2>
<p>${COMPANY_DISPLAY_NAME} provides the Service on a best-effort basis for
Operator Starter, Operator Pro, and Operator Team plans. Operator Team
includes a 99.0% uptime target measured monthly. Compliance includes a
99.5% uptime SLA with the credit schedule set forth in the Compliance Plan
documentation. Enterprise SLAs (99.9% or higher) are governed by the
executed order form. Scheduled maintenance with at least 48 hours' notice
does not count against uptime calculations.</p>

<h2>7. Data Processing</h2>
<p>Customer's use of the Service is subject to the
<a href="/privacy">Privacy Policy</a>. For customers subject to GDPR, CCPA, or
similar privacy regulations, ${COMPANY_DISPLAY_NAME} acts as a Processor
on Customer's behalf and offers a Data Processing Addendum
(<a href="mailto:${LEGAL_EMAIL}">${LEGAL_EMAIL}</a>) on request, included as
part of Compliance and Enterprise plans by default.</p>

<h2>8. Disclaimers</h2>
<p>THE SERVICE IS PROVIDED "AS IS" AND "AS AVAILABLE" WITHOUT WARRANTIES
OF ANY KIND, WHETHER EXPRESS, IMPLIED, OR STATUTORY, INCLUDING WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT,
OR THE ACCURACY OF OUTPUTS. LANGUAGE MODEL OUTPUTS MAY CONTAIN ERRORS,
FABRICATIONS, OR OMISSIONS; CUSTOMER IS RESPONSIBLE FOR INDEPENDENTLY
VERIFYING OUTPUTS BEFORE RELYING ON THEM IN PRODUCTION, REGULATORY,
LEGAL, MEDICAL, OR FINANCIAL CONTEXTS. ${COMPANY_DISPLAY_NAME} DOES NOT
WARRANT THAT THE SERVICE WILL BE UNINTERRUPTED OR ERROR-FREE.</p>

<h2>9. Limitation of Liability</h2>
<p>EXCEPT FOR LIABILITY ARISING FROM (i) CUSTOMER'S BREACH OF THE
ACCEPTABLE USE POLICY, (ii) WILLFUL MISCONDUCT, OR (iii) INDEMNIFICATION
OBLIGATIONS, NEITHER PARTY WILL BE LIABLE FOR INDIRECT, INCIDENTAL,
SPECIAL, CONSEQUENTIAL, OR EXEMPLARY DAMAGES. EACH PARTY'S TOTAL
LIABILITY UNDER THESE TERMS WILL NOT EXCEED THE FEES PAID BY CUSTOMER
TO ${COMPANY_DISPLAY_NAME} DURING THE TWELVE (12) MONTHS PRECEDING THE
EVENT GIVING RISE TO THE CLAIM.</p>

<h2>10. Indemnification</h2>
<p>Each party will indemnify, defend, and hold harmless the other party
from third-party claims arising from (i) breach of these Terms by the
indemnifying party, (ii) infringement claims arising from the
indemnifying party's intellectual property, or (iii) the indemnifying
party's gross negligence or willful misconduct. The indemnifying
party's obligations are conditioned on prompt written notice, sole
control of the defense, and reasonable cooperation by the indemnified
party.</p>

<h2>11. Termination</h2>
<p>${COMPANY_DISPLAY_NAME} may suspend or terminate Customer's access for
material breach of these Terms (including breach of the Acceptable Use
Policy) immediately upon written notice. Customer may terminate at any
time by cancelling the subscription as described in Section 4.</p>

<h2>12. Governing Law</h2>
<p>These Terms are governed by and construed in accordance with the laws
of ${GOVERNING_LAW}, without regard to its conflict of law principles.
Any disputes will be resolved exclusively in the state or federal
courts located in ${GOVERNING_LAW}, and the parties consent to the
personal jurisdiction of such courts.</p>

<h2>13. Modifications</h2>
<p>${COMPANY_DISPLAY_NAME} may update these Terms by posting the revised
version at this URL and updating the "Last updated" date. Material
changes will be communicated by email to the address on file at least
thirty (30) days in advance. Continued use of the Service after the
effective date of changes constitutes acceptance.</p>

<h2>14. Entire Agreement</h2>
<p>These Terms, together with the Acceptable Use Policy, Privacy Policy,
and any executed order form, constitute the entire agreement between
the parties with respect to the Service and supersede all prior
agreements.</p>

<h2>15. Contact</h2>
<p>Questions about these Terms:
<a href="mailto:${LEGAL_EMAIL}">${LEGAL_EMAIL}</a>.</p>
`;

// ---------------------------------------------------------------------------
// Privacy Policy
// ---------------------------------------------------------------------------

const PRIVACY_BODY = `
<h1>Privacy Policy</h1>
<div class="meta">Last updated: ${LAST_UPDATED}</div>

<p>This Privacy Policy describes how ${COMPANY_LEGAL_NAME}
("<strong>${COMPANY_DISPLAY_NAME}</strong>", "<strong>we</strong>") collects,
uses, and discloses information when you use the ${PRODUCT_NAME} Service.</p>

<div class="callout">
<strong>The ${PRODUCT_NAME} architectural commitment:</strong> the inference
engine that processes your prompts is deployed as a sibling container to
the gateway, in the same managed environment of a single cloud hosting
provider, with internal-only ingress. <strong>Your prompt contents and
model outputs are not transmitted to any third-party language-model API
provider</strong> (such as OpenAI, Anthropic, Google, Cohere, Mistral,
Fireworks, Together, DeepInfra, Modal, Replicate, Groq, or similar) as
part of providing the Service. The vendor-exclusion property is enforced
at deployment-policy level; see the open-source
<a href="https://github.com/5CEOS-DRA/llm-determinism-bench">determinism
bench</a> for the externally verifiable evidence layer.
</div>

<h2>1. Information We Collect</h2>
<ul>
  <li><strong>Account information</strong>: name, email, and billing details collected by our payments processor (Stripe).</li>
  <li><strong>API requests</strong>: the prompts, messages, schemas, and other request fields you submit to <code>/v1/chat/completions</code>.</li>
  <li><strong>API responses</strong>: the outputs returned by the inference engine.</li>
  <li><strong>Telemetry</strong>: request timestamp, API key identifier, tenant identifier, model identifier, token counts, latency, schema-enforcement flag, request ID, HTTP status.</li>
  <li><strong>Audit log</strong>: append-only record of metering events (the fields above) for billing reconciliation and operational diagnostics.</li>
  <li><strong>Server logs</strong>: IP address, user-agent, and HTTP request metadata, retained for security and operational purposes.</li>
</ul>

<h2>2. How We Use Information</h2>
<ul>
  <li>To provide the Service (route requests to the inference engine, enforce quotas, return responses).</li>
  <li>To bill for usage (via Stripe; Compliance and Enterprise plans are invoiced separately).</li>
  <li>To detect and mitigate abuse, including violations of the Acceptable Use Policy.</li>
  <li>To diagnose operational issues, including correlating individual requests with system-level events.</li>
  <li>To publish aggregated, de-identified determinism and reliability metrics via the open-source bench (no individual request content is included).</li>
</ul>

<h2>3. What We Do NOT Do</h2>
<ul>
  <li>We do not train language models on Customer prompts or outputs.</li>
  <li>We do not sell or rent Customer data.</li>
  <li>We do not transmit Customer prompts or outputs to any third-party language-model API provider.</li>
  <li>We do not retain raw prompt or response bodies after the response is delivered to the Customer, with the exception of operational debugging windows described below.</li>
</ul>

<h2>4. Retention</h2>
<ul>
  <li><strong>Prompt and response bodies</strong>: not retained after delivery to the Customer. (Operational note: anonymized request-level entries may exist in transient debug logs for up to 7 days for diagnostics.)</li>
  <li><strong>Audit log (telemetry only)</strong>: retained for 24 months for billing reconciliation. No prompt content is in the audit log.</li>
  <li><strong>Server logs</strong>: retained for 90 days, then purged.</li>
  <li><strong>Account and billing records</strong>: retained for the longer of the duration of the subscription plus 7 years, or as required by applicable tax or financial regulations.</li>
</ul>

<h2>5. Sub-processors</h2>
<p>The following sub-processors receive Customer data in the course of providing the Service:</p>
<ul>
  <li><strong>Microsoft Azure</strong> (East US, or Customer-selected region for Enterprise) — hosts the gateway and inference engine. All Customer prompts and outputs are processed within the Azure infrastructure under our account.</li>
  <li><strong>Stripe</strong> — processes subscription payments and stores billing details. Subject to Stripe's privacy policy.</li>
  <li><strong>GitHub</strong> — hosts the open-source determinism bench and publishes aggregated reliability metrics. No Customer prompt or response content is published.</li>
</ul>
<p>${COMPANY_DISPLAY_NAME} will provide thirty (30) days' notice of any new
sub-processor by updating this policy and notifying Compliance and
Enterprise customers via email.</p>

<h2>6. International Transfers</h2>
<p>By default, Customer data is processed in Microsoft Azure's East US
region. Enterprise customers may select an alternative region (US-West,
EU, APAC) under their order form. We do not transfer Customer prompts or
outputs across regions without explicit Customer instruction.</p>

<h2>7. Security</h2>
<ul>
  <li>All connections to the Service use TLS 1.2 or higher.</li>
  <li>API Keys are stored as SHA-256 hashes; plaintext values are only displayed once at issuance.</li>
  <li>Administrative credentials are stored in Azure Container Apps secrets and not exposed in environment variables or source code.</li>
  <li>The inference engine has internal-only ingress; it is not reachable from the public internet.</li>
  <li>Compliance plans include SOC 2 Type II reports on request; Enterprise plans include the SOC 2 report and additional security review documentation under NDA.</li>
</ul>

<h2>8. Customer Rights</h2>
<p>You have the right to:</p>
<ul>
  <li>Access the personal information we hold about you.</li>
  <li>Correct inaccurate information.</li>
  <li>Request deletion of your account and associated data (subject to legal retention requirements).</li>
  <li>Export your usage records.</li>
  <li>Object to or restrict processing (which may require account cancellation).</li>
  <li>Lodge a complaint with a supervisory authority (for GDPR jurisdictions).</li>
</ul>
<p>To exercise these rights, contact <a href="mailto:${PRIVACY_EMAIL}">${PRIVACY_EMAIL}</a>.</p>

<h2>9. Children's Privacy</h2>
<p>The Service is not directed to children under 16, and we do not knowingly
collect information from children.</p>

<h2>10. Changes to This Policy</h2>
<p>We will post material changes here with a new "Last updated" date and
notify Compliance/Enterprise customers via email at least 30 days in
advance.</p>

<h2>11. Contact</h2>
<p>Privacy questions: <a href="mailto:${PRIVACY_EMAIL}">${PRIVACY_EMAIL}</a>.<br>
Data Protection Officer / DPA requests: <a href="mailto:${LEGAL_EMAIL}">${LEGAL_EMAIL}</a>.</p>
`;

// ---------------------------------------------------------------------------
// Acceptable Use Policy
// ---------------------------------------------------------------------------

const AUP_BODY = `
<h1>Acceptable Use Policy</h1>
<div class="meta">Last updated: ${LAST_UPDATED}</div>

<p>This Acceptable Use Policy ("<strong>AUP</strong>") governs your use of
${PRODUCT_NAME}. It is incorporated by reference into the
<a href="/terms">Terms of Service</a>. Violations may result in suspension
or termination of your account without refund.</p>

<h2>1. Prohibited Content and Use Cases</h2>
<p>You must not use the Service to generate, transmit, store, or facilitate:</p>
<ul>
  <li>Child sexual abuse material (CSAM) or any sexually explicit content involving minors.</li>
  <li>Material that incites violence, terrorism, or imminent lawless action.</li>
  <li>Detailed instructions for the synthesis of biological, chemical, nuclear, or radiological weapons; instructions for circumventing nuclear safeguards; or material support for proliferation.</li>
  <li>Targeted harassment, stalking, or threats against identifiable individuals or groups.</li>
  <li>Disinformation campaigns intended to undermine elections, public health, or democratic processes, including the generation of fake personas, fabricated quotes attributed to real persons, or AI-generated voice/likeness impersonation without the impersonated party's consent.</li>
  <li>Fraud, identity theft, phishing, or other schemes designed to deceive and obtain value.</li>
  <li>Content that violates applicable laws in your jurisdiction or the jurisdictions in which your outputs will be distributed.</li>
</ul>

<h2>2. Prohibited Technical Conduct</h2>
<p>You must not:</p>
<ul>
  <li>Attempt to circumvent rate limits, quotas, or other access controls (including by registering multiple accounts to evade quota enforcement).</li>
  <li>Reverse-engineer, decompile, or attempt to extract model weights from the Service.</li>
  <li>Probe, scan, or test the vulnerability of the Service or any associated network without prior written authorization.</li>
  <li>Use the Service to attack, disrupt, or overload any third-party system.</li>
  <li>Use the Service to scrape, copy, or otherwise extract content from third parties in violation of those parties' terms of service.</li>
  <li>Resell, sublicense, or wrap the Service under a different brand without an executed reseller agreement.</li>
  <li>Use the Service to develop a competing product (this prohibition is narrow: customers may build products that use the Service as a component, but may not wholesale rebrand the Service itself).</li>
</ul>

<h2>3. Output Disclosure to End-Users</h2>
<p>If you incorporate Service outputs into a product that interacts with
end-users, you should disclose to those end-users that the output is
generated by an AI system. This is particularly important for outputs
that may be mistaken for human-produced content in contexts such as
journalism, medical information, legal information, or financial advice.</p>

<h2>4. Regulated Use Cases</h2>
<p>The Service is not certified, indemnified, or otherwise validated for
use as a medical device, financial advisor, or legal counsel. If you use
the Service in any regulated context (HIPAA, GLBA, FCRA, SOX, etc.), you
are responsible for performing your own due diligence and implementing
appropriate human-in-the-loop review. Compliance and Enterprise plans
include a Data Processing Addendum and (for HIPAA) a Business Associate
Agreement on request.</p>

<h2>5. Reporting Violations</h2>
<p>If you believe another user is violating this AUP, or if you encounter
Service output that violates this AUP, please report it to
<a href="mailto:abuse@5ceos.com">abuse@5ceos.com</a> with relevant evidence
(request IDs from the <code>X-Cogos-Request-Id</code> response header are
sufficient for our investigation).</p>

<h2>6. Enforcement</h2>
<p>${COMPANY_DISPLAY_NAME} may, at its sole discretion:</p>
<ul>
  <li>Issue a warning to the offending account.</li>
  <li>Suspend the offending API Keys pending investigation.</li>
  <li>Terminate the offending account without refund.</li>
  <li>Report criminal violations (e.g., CSAM) to appropriate law enforcement.</li>
  <li>Cooperate with valid legal process (subpoenas, warrants) related to AUP violations.</li>
</ul>
<p>${COMPANY_DISPLAY_NAME} reserves the right to update this AUP from time
to time to address new categories of misuse.</p>

<h2>7. Contact</h2>
<p>Questions about acceptable use:
<a href="mailto:${SUPPORT_EMAIL}">${SUPPORT_EMAIL}</a>.<br>
Abuse reports: <a href="mailto:abuse@5ceos.com">abuse@5ceos.com</a>.</p>
`;

module.exports = {
  termsHtml: () => wrapHtml('Terms of Service', TERMS_BODY),
  privacyHtml: () => wrapHtml('Privacy Policy', PRIVACY_BODY),
  aupHtml: () => wrapHtml('Acceptable Use Policy', AUP_BODY),
};
