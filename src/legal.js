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
// Single customer-facing inbox at v1. Routing legal/privacy/abuse to the
// same address until staffing/volume justifies separating them. Customer
// can still reach us via the canonical support@5ceos.com from anywhere
// these legal docs are linked.
const SUPPORT_EMAIL = 'support@5ceos.com';
const LEGAL_EMAIL = 'support@5ceos.com';
const PRIVACY_EMAIL = 'support@5ceos.com';
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
  <a href="/dpa">DPA</a>
  <a href="/baa">BAA</a>
  <a href="/gdpr">GDPR Art. 28</a>
  <a href="/sub-processors">Sub-processors</a>
</nav>`;

// Banner reused on every counsel-review-required template.
const TEMPLATE_BANNER = `<div class="callout" style="border-left-color:#f0883e;background:#1f1305">
<strong>TEMPLATE — execution requires counsel review on both sides.</strong>
This document is a draft template provided by ${COMPANY_DISPLAY_NAME} for
review by Customer's legal counsel and ${COMPANY_DISPLAY_NAME}'s legal
counsel. It is not a binding agreement until signed by authorized
signatories of both parties. Bracketed fields (e.g. <code>[Customer Legal
Name]</code>, <code>[Effective Date]</code>) must be completed before
execution.
</div>`;

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
    <a href="mailto:${SUPPORT_EMAIL}">${SUPPORT_EMAIL}</a>
    (support, legal, privacy, abuse — all routed to one inbox while we're early)
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
<a href="mailto:support@5ceos.com">support@5ceos.com</a> with relevant evidence
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
Abuse reports: <a href="mailto:support@5ceos.com">support@5ceos.com</a>.</p>
`;

// ---------------------------------------------------------------------------
// Data Processing Addendum (DPA)
// ---------------------------------------------------------------------------
//
// Read-only template. Counsel must complete bracketed fields and reconcile
// against the executed Master Agreement before signature.

const DPA_BODY = `
<h1>Data Processing Addendum</h1>
<div class="meta">Last updated: ${LAST_UPDATED} · Template v1</div>

${TEMPLATE_BANNER}

<p>This Data Processing Addendum ("<strong>DPA</strong>") forms part of the
agreement between <strong>[Customer Legal Name]</strong>
("<strong>Customer</strong>") and ${COMPANY_LEGAL_NAME}
("<strong>${COMPANY_DISPLAY_NAME}</strong>") for Customer's use of the
${PRODUCT_NAME} Service (the "<strong>Master Agreement</strong>" — see
<a href="/terms">Terms of Service</a> or the executed order form). It
supplements the Master Agreement and governs ${COMPANY_DISPLAY_NAME}'s
processing of Personal Data on Customer's behalf. In the event of a
conflict between this DPA and the Master Agreement with respect to data
protection, this DPA controls.</p>

<p><strong>Effective Date:</strong> [Effective Date — typically the date
of the last signature below, or the Master Agreement effective date,
whichever is later].</p>

<h2>Definitions</h2>
<ul>
  <li><strong>Customer Data</strong> means all data, including Personal Data, that Customer submits to the Service or that the Service generates on Customer's behalf.</li>
  <li><strong>Personal Data</strong> means any information relating to an identified or identifiable natural person, as defined under GDPR Art. 4(1), CCPA Cal. Civ. Code §1798.140, or equivalent applicable law.</li>
  <li><strong>Processing</strong> has the meaning given in GDPR Art. 4(2): any operation performed on Personal Data, including collection, storage, transmission, and erasure.</li>
  <li><strong>Sub-processor</strong> means any third party engaged by ${COMPANY_DISPLAY_NAME} that Processes Personal Data on ${COMPANY_DISPLAY_NAME}'s behalf in the course of providing the Service.</li>
  <li><strong>Authorized User</strong> means an individual to whom Customer has issued credentials to use the Service.</li>
  <li><strong>Service</strong> has the meaning given in the <a href="/terms">Terms of Service</a>: the ${PRODUCT_NAME} gateway, inference engine, audit-bench, and supporting infrastructure operated by ${COMPANY_DISPLAY_NAME} at ${SERVICE_DOMAIN}.</li>
  <li><strong>Standard Contractual Clauses</strong> or <strong>SCCs</strong> means the European Commission's standard contractual clauses for the transfer of personal data to third countries (Decision (EU) 2021/914) and, where applicable, the UK International Data Transfer Addendum.</li>
</ul>

<h2>1. Scope of Processing</h2>
<p>${COMPANY_DISPLAY_NAME} Processes Customer Data only to the extent
necessary to provide the Service to Customer in accordance with the
Master Agreement. The categories of Personal Data Processed and the
categories of data subjects are set out below:</p>
<ul>
  <li><strong>Categories of Personal Data:</strong> identifiers and account metadata of Authorized Users (name, email, billing details collected by Stripe); any Personal Data that Customer elects to include in API requests submitted to <code>/v1/chat/completions</code> (prompts, messages, schemas); operational telemetry tied to the Authorized User identifier (timestamp, IP address, request ID, token counts, HTTP status).</li>
  <li><strong>Categories of data subjects:</strong> Customer's Authorized Users; end-users of Customer-built products whose data Customer elects to include in Inputs to the Service.</li>
  <li><strong>Nature and purpose of Processing:</strong> routing requests to the inference engine, returning Outputs to Customer, enforcing quotas, billing reconciliation, abuse detection, and operational diagnostics.</li>
  <li><strong>Duration:</strong> for the term of the Master Agreement, plus the retention windows in §9.</li>
</ul>

<h2>2. Roles of the Parties</h2>
<p>With respect to Personal Data Processed under this DPA:</p>
<ul>
  <li><strong>Customer is the Controller</strong> (GDPR Art. 4(7)) or the equivalent (e.g., "Business" under CCPA). Customer determines the purposes and means of the Processing.</li>
  <li><strong>${COMPANY_DISPLAY_NAME} is the Processor</strong> (GDPR Art. 4(8)) or the equivalent (e.g., "Service Provider" under CCPA). ${COMPANY_DISPLAY_NAME} Processes Personal Data only on Customer's documented instructions, as reflected in the Master Agreement, this DPA, and Customer's use of the Service.</li>
</ul>

<h2>3. Sub-processors</h2>
<p>${COMPANY_DISPLAY_NAME} maintains a current list of sub-processors at
<a href="/sub-processors">${SERVICE_DOMAIN}/sub-processors</a>. By executing
this DPA, Customer grants ${COMPANY_DISPLAY_NAME} a general authorization
to engage the sub-processors listed at that URL and any future
sub-processors added in accordance with the notice procedure below.</p>
<p>${COMPANY_DISPLAY_NAME} will:</p>
<ul>
  <li>Impose data protection obligations on each sub-processor that are no less protective than those in this DPA;</li>
  <li>Remain liable to Customer for the acts and omissions of each sub-processor to the same extent as if those acts and omissions were ${COMPANY_DISPLAY_NAME}'s own;</li>
  <li>Provide Customer with at least thirty (30) days' prior written notice (which may be by email to Customer's notice address or by updating <a href="/sub-processors">/sub-processors</a>) of the addition or replacement of a sub-processor. Customer may object on reasonable data-protection grounds within fifteen (15) days. The parties will work in good faith to address the objection; if not resolved, Customer may terminate the affected portion of the Service for convenience without penalty.</li>
</ul>

<h2>4. Security Measures</h2>
<p>${COMPANY_DISPLAY_NAME} implements and maintains the technical and
organizational measures listed below. These measures correspond to the
verifiable security claims published at <a href="/SECURITY.md">SECURITY.md
§3</a>; the claims are reproduced here so counsel does not have to
follow a link.</p>
<ul>
  <li><strong>Image signing (cosign):</strong> every deployed image is signed with a ${COMPANY_DISPLAY_NAME}-controlled cosign key before rollout to the production Container App. The public key is published at <code>https://${SERVICE_DOMAIN}/cosign.pub</code> for customer/auditor verification.</li>
  <li><strong>Response signature (HMAC):</strong> every successful <code>/v1/*</code> response carries an <code>X-Cogos-Signature</code> header — an HMAC-SHA256 over the response body, keyed by a per-tenant secret issued at the same time as the Customer's API key. Customer can verify that the response was emitted by ${COMPANY_DISPLAY_NAME} and not a man-in-the-middle.</li>
  <li><strong>Open determinism bench:</strong> the "same call in, same bytes out" property of the Service is auditable against the live endpoint via the open-source bench published at <code>https://github.com/5CEOS-DRA/llm-determinism-bench</code>.</li>
  <li><strong>API key handling:</strong> Customer API keys are stored as SHA-256 hashes; the plaintext key is shown to the Customer exactly once at issuance. A database leak of the key store does not leak usable keys.</li>
  <li><strong>Admin auth:</strong> administrative operations require a separate admin key carried in the <code>X-Admin-Key</code> header; rotation is a single environment-variable change; revocation is immediate.</li>
  <li><strong>Stripe webhook verification:</strong> inbound webhooks at <code>POST /stripe/webhook</code> are signature-verified against <code>STRIPE_WEBHOOK_SECRET</code>; an attacker cannot forge a billing event.</li>
  <li><strong>Schema-enforced output:</strong> when a request includes <code>response_format: { type: "json_schema", ... }</code>, the output is grammar-constrained at the token level by the inference engine — non-conforming output is physically impossible, not retried or filtered after the fact.</li>
  <li><strong>Transport encryption:</strong> all connections to the Service use TLS 1.2 or higher.</li>
  <li><strong>Network segmentation:</strong> the inference engine has internal-only ingress; it is not reachable from the public internet.</li>
  <li><strong>Secrets storage:</strong> administrative credentials are stored in Azure Container Apps secrets and are not exposed in environment variables visible to non-privileged personnel or in source code.</li>
  <li><strong>Vendor exclusion:</strong> Customer prompts and Outputs are not transmitted to any third-party language-model API provider (OpenAI, Anthropic, Google, Cohere, Mistral, Fireworks, Together, DeepInfra, Modal, Replicate, Groq, or similar). The inference engine is deployed as a sibling container within the same managed environment as the gateway.</li>
  <li><strong>Audit engagement:</strong> ${COMPANY_DISPLAY_NAME} has engaged for a SOC 2 Type II audit; report expected [TBD — completion date]. Until the report is published, ${COMPANY_DISPLAY_NAME} will provide a written security attestation to Customers with executed DPAs on request.</li>
</ul>

<h2>5. Data Location</h2>
<p>By default, Customer Data is Processed in Microsoft Azure's East US
region (United States). For current location details, see
<a href="/SECURITY.md">SECURITY.md</a> and <a href="/privacy">Privacy Policy
§6</a>. Enterprise customers may select an alternative region (US-West,
EU, APAC) under an executed order form. ${COMPANY_DISPLAY_NAME} will not
transfer Customer prompts or Outputs across regions without explicit
Customer instruction or as required by applicable law.</p>

<h2>6. Data Subject Rights</h2>
<p>Customer, as Controller, is responsible for responding to requests
from data subjects (access, rectification, erasure, restriction,
portability, objection — "<strong>DSARs</strong>"). ${COMPANY_DISPLAY_NAME},
as Processor, will:</p>
<ul>
  <li>Forward to Customer any DSAR received directly by ${COMPANY_DISPLAY_NAME} that relates to Customer's data, without independently responding (except as required by law);</li>
  <li>Assist Customer, by appropriate technical and organizational measures and insofar as reasonably possible, in fulfilling Customer's obligation to respond to DSARs under applicable law;</li>
  <li>On Customer's documented instruction, retrieve, correct, or delete Personal Data associated with a specific data subject within fifteen (15) business days, subject to the legal retention obligations in §9.</li>
</ul>

<h2>7. Personal Data Breach Notification</h2>
<p>${COMPANY_DISPLAY_NAME} will notify Customer of any confirmed Personal
Data Breach (as defined in GDPR Art. 4(12)) affecting Customer Data
without undue delay and in any event within <strong>seventy-two (72) hours</strong>
of becoming aware of it. The notification will include, to the extent
known at the time of notification:</p>
<ul>
  <li>The nature of the breach, categories of Personal Data, and approximate number of data subjects affected;</li>
  <li>The likely consequences of the breach;</li>
  <li>Measures taken or proposed to be taken to address the breach;</li>
  <li>A point of contact for further information.</li>
</ul>
<p>Customer's designated breach-notification contact is:
<strong>[Customer Security Contact — Name, Title, Email]</strong>.
${COMPANY_DISPLAY_NAME}'s breach-notification contact is
<a href="mailto:${LEGAL_EMAIL}">${LEGAL_EMAIL}</a> (subject prefix
<code>[SECURITY]</code> per <a href="/SECURITY.md">SECURITY.md §1</a>).
Notification will be by email and will not be conditioned on a finding
that the breach is reportable under applicable law; reportability is a
question for Customer as Controller.</p>

<h2>8. Audit Rights</h2>
<p>Customer may request, no more than once per twelve-month period and
on at least thirty (30) days' written notice, evidence of
${COMPANY_DISPLAY_NAME}'s compliance with this DPA. ${COMPANY_DISPLAY_NAME}
will satisfy this obligation by providing:</p>
<ul>
  <li>The then-current SOC 2 Type II report, once published, under a customary confidentiality undertaking; or</li>
  <li>Until the SOC 2 Type II report is published, a written attestation describing the security measures in §4, signed by an officer of ${COMPANY_DISPLAY_NAME}; and</li>
  <li>Responses to a reasonable security questionnaire (CAIQ, SIG Lite, or equivalent).</li>
</ul>
<p>On-site audit by Customer or its independent auditor is subject to
(i) mutual scheduling, (ii) a customary non-disclosure agreement, (iii)
Customer paying ${COMPANY_DISPLAY_NAME}'s reasonable costs for audit
support, and (iv) the auditor not being a competitor of
${COMPANY_DISPLAY_NAME}. On-site audit will not extend to ${COMPANY_DISPLAY_NAME}'s
multi-tenant infrastructure to the extent that access would compromise
the security of other customers; in such cases the SOC 2 report or
attestation is the sole audit deliverable.</p>

<h2>9. Term, Termination, and Deletion</h2>
<p>This DPA is effective on the Effective Date and continues for the
term of the Master Agreement. Upon termination of the Master Agreement,
${COMPANY_DISPLAY_NAME} will, at Customer's election:</p>
<ul>
  <li>Return Customer Data in a structured, commonly used format (JSONL export of the audit log; CSV export of usage records) within thirty (30) days of termination; or</li>
  <li>Delete Customer Data within thirty (30) days of termination.</li>
</ul>
<p>${COMPANY_DISPLAY_NAME} will issue a written certificate of deletion to
Customer's notice address on request following completion of deletion.
${COMPANY_DISPLAY_NAME} may retain Customer Data after termination only
(i) as required by applicable law (e.g., tax, financial recordkeeping)
and (ii) in secure backups that are isolated from production systems
and overwritten in the ordinary course; such retained data remains
subject to the confidentiality and security obligations of this DPA.</p>

<h2>10. International Transfers</h2>
<p>To the extent ${COMPANY_DISPLAY_NAME}'s Processing of Customer's
Personal Data involves a transfer of Personal Data out of the European
Economic Area, the United Kingdom, or Switzerland to a country not
covered by an adequacy decision, the parties incorporate the
<strong>Standard Contractual Clauses</strong> by reference, with the
following selections:</p>
<ul>
  <li>Module Two (Controller-to-Processor) applies between Customer (data exporter) and ${COMPANY_DISPLAY_NAME} (data importer);</li>
  <li>Clause 7 (docking clause) applies;</li>
  <li>Clause 9(a), Option 2 (general written authorization for sub-processors) applies, with the notice period as set out in §3;</li>
  <li>Clause 11(a) (independent dispute resolution) does not apply;</li>
  <li>Clause 17 (governing law): the law of the Republic of Ireland;</li>
  <li>Clause 18 (forum and jurisdiction): the courts of the Republic of Ireland;</li>
  <li>Annex I (parties, categories of data, data subjects, purposes): completed by reference to §1 of this DPA;</li>
  <li>Annex II (technical and organizational measures): completed by reference to §4 of this DPA;</li>
  <li>Annex III (sub-processors): completed by reference to <a href="/sub-processors">/sub-processors</a>.</li>
</ul>
<p>For UK transfers, the parties incorporate the UK International Data
Transfer Addendum (issued by the UK Information Commissioner) to the
SCCs, with the tables completed by reference to the corresponding
annexes above. For Swiss transfers, the SCCs apply with the
modifications set out in the FDPIC's guidance.</p>

<h2>11. Liability</h2>
<p>Each party's liability under this DPA, taken together with the
Master Agreement, is subject to the limitations of liability and the
liability cap set forth in the Master Agreement. Nothing in this DPA
expands either party's liability beyond what the Master Agreement
provides, except to the extent applicable data protection law requires
otherwise (in which case the statutory minimum applies).</p>

<h2>12. Order of Precedence</h2>
<p>In the event of any conflict between (i) this DPA, (ii) the
Standard Contractual Clauses incorporated under §10, and (iii) the
Master Agreement, the order of precedence is (ii) > (i) > (iii) with
respect to data protection matters.</p>

<h2>13. Signatures</h2>
<p>The parties have caused this DPA to be executed by their authorized
representatives as of the Effective Date.</p>

<div class="callout">
<strong>Customer</strong> ([Customer Legal Name])<br>
By: ________________________________________<br>
Name: [Customer Authorized Signer]<br>
Title: [Title]<br>
Date: ____________
</div>

<div class="callout">
<strong>${COMPANY_LEGAL_NAME}</strong>${'​'}<br>
By: ________________________________________<br>
Name: [${COMPANY_DISPLAY_NAME} Authorized Signer]<br>
Title: [Title]<br>
Date: ____________
</div>
`;

// ---------------------------------------------------------------------------
// HIPAA Business Associate Agreement (BAA) Template
// ---------------------------------------------------------------------------

const BAA_BODY = `
<h1>Business Associate Agreement (HIPAA)</h1>
<div class="meta">Last updated: ${LAST_UPDATED} · Template v1</div>

${TEMPLATE_BANNER}

<p>This Business Associate Agreement ("<strong>BAA</strong>") supplements
and is made part of the agreement (the "<strong>Master Agreement</strong>"
— see <a href="/terms">Terms of Service</a> or the executed order form)
between <strong>[Customer Legal Name]</strong>, a Covered Entity under
the Health Insurance Portability and Accountability Act of 1996 and its
implementing regulations ("<strong>Covered Entity</strong>"), and
${COMPANY_LEGAL_NAME} ("<strong>Business Associate</strong>" or
"<strong>${COMPANY_DISPLAY_NAME}</strong>"). This BAA is required by the
HIPAA Privacy Rule, Security Rule, and Breach Notification Rule
(collectively, the "<strong>HIPAA Rules</strong>") and is intended to
satisfy the contract requirements of 45 CFR §164.504(e) and §164.314(a).</p>

<p><strong>Effective Date:</strong> [Effective Date — typically the date
of the last signature below, or the Master Agreement effective date,
whichever is later].</p>

<h2>Definitions</h2>
<p>Capitalized terms not defined in this BAA have the meaning given in
the HIPAA Rules. The following are restated here for clarity:</p>
<ul>
  <li><strong>PHI</strong> means Protected Health Information, as defined at 45 CFR §160.103, limited to PHI that Business Associate creates, receives, maintains, or transmits on behalf of Covered Entity.</li>
  <li><strong>Electronic PHI</strong> or <strong>ePHI</strong> means PHI that is transmitted by or maintained in electronic media (45 CFR §160.103).</li>
  <li><strong>Required by Law</strong> has the meaning given at 45 CFR §164.103.</li>
  <li><strong>Security Incident</strong> has the meaning given at 45 CFR §164.304.</li>
  <li><strong>Subcontractor</strong> means a person to whom Business Associate delegates a function, activity, or service, other than in the capacity of a member of Business Associate's workforce.</li>
  <li><strong>Service</strong> means the ${PRODUCT_NAME} Service described in the Master Agreement and at <a href="/">${SERVICE_DOMAIN}</a>.</li>
</ul>

<h2>1. Permitted Uses and Disclosures of PHI</h2>
<p>Business Associate may use and disclose PHI only as follows:</p>
<ul>
  <li><strong>To provide the Service:</strong> Business Associate may use and disclose PHI only as necessary to perform the services set forth in the Master Agreement and described at <a href="/">${SERVICE_DOMAIN}</a>, and as Covered Entity instructs in its use of the Service.</li>
  <li><strong>Business Associate's own management and administration:</strong> Business Associate may use PHI for the proper management and administration of Business Associate or to carry out Business Associate's legal responsibilities, provided that any disclosure is Required by Law or the recipient agrees in writing (i) to hold the PHI confidentially and (ii) to notify Business Associate of any breach.</li>
  <li><strong>Data aggregation:</strong> Business Associate may aggregate PHI received from Covered Entity for the data aggregation services relating to the health care operations of Covered Entity, as permitted by 45 CFR §164.504(e)(2)(i)(B).</li>
  <li><strong>De-identification:</strong> Business Associate may de-identify PHI in accordance with 45 CFR §164.514(a)-(c), and the resulting de-identified information is no longer PHI.</li>
</ul>
<p>Business Associate will not use or further disclose PHI other than as
permitted or required by this BAA or as Required by Law.</p>

<h2>2. Safeguards for PHI</h2>
<p>Business Associate will use appropriate <strong>administrative, physical,
and technical safeguards</strong>, and comply with Subpart C of 45 CFR
Part 164 (the HIPAA Security Rule) with respect to ePHI, to prevent use
or disclosure of PHI other than as provided by this BAA. The safeguards
correspond to the measures described in <a href="/dpa">DPA §4</a> and
the verifiable claims at <a href="/SECURITY.md">SECURITY.md §3</a>,
including:</p>
<ul>
  <li><strong>Access control</strong> (45 CFR §164.312(a)(1)) — workforce access to PHI is granted on a need-to-know basis; administrative endpoints are gated by a separate <code>X-Admin-Key</code>; customer API keys are stored as SHA-256 hashes.</li>
  <li><strong>Audit controls</strong> (45 CFR §164.312(b)) — every API request emits an audit-log entry (timestamp, tenant identifier, request ID, status); the log is append-only.</li>
  <li><strong>Integrity</strong> (45 CFR §164.312(c)(1)) — response bodies are signed with an HMAC-SHA256 keyed by a per-tenant secret; Covered Entity can verify the integrity of any response.</li>
  <li><strong>Transmission security</strong> (45 CFR §164.312(e)(1)) — all connections use TLS 1.2 or higher; the inference engine has internal-only ingress.</li>
  <li><strong>Person or entity authentication</strong> (45 CFR §164.312(d)) — API keys are individually issued and revocable; admin keys are separate from customer keys.</li>
</ul>

<h2>3. Mitigation</h2>
<p>Business Associate will mitigate, to the extent practicable, any
harmful effect that is known to Business Associate of a use or
disclosure of PHI by Business Associate in violation of this BAA. This
includes immediate API-key revocation, restoration of integrity from
audit logs, and coordination with Covered Entity on data-subject
remediation.</p>

<h2>4. Reporting Uses and Disclosures Not Provided for by the BAA</h2>
<p>Business Associate will report to Covered Entity:</p>
<ul>
  <li>Any use or disclosure of PHI not provided for by this BAA of which it becomes aware, including breaches of unsecured PHI as required by 45 CFR §164.410, <strong>without unreasonable delay and in no event later than seventy-two (72) hours after discovery</strong>;</li>
  <li>Any Security Incident (45 CFR §164.314(a)(2)(i)(C)) of which it becomes aware. The parties acknowledge that unsuccessful Security Incidents (e.g., pings, port scans, denied login attempts) occur frequently and that reporting of these is satisfied by this paragraph as a single ongoing notice; Business Associate will provide specific notice of successful Security Incidents.</li>
</ul>
<p>The report will include, to the extent known: the identification of
each individual whose PHI was or is reasonably believed to have been
accessed, acquired, used, or disclosed; the nature of the unauthorized
use or disclosure; the corrective action taken; and the steps Covered
Entity may take in response. Covered Entity's designated breach contact
is: <strong>[Covered Entity Privacy Officer — Name, Title, Email,
Phone]</strong>.</p>

<h2>5. Subcontractors</h2>
<p>In accordance with 45 CFR §164.502(e)(1)(ii) and §164.308(b)(2),
Business Associate will require any Subcontractor to whom it provides
PHI to enter into a written agreement that imposes on the Subcontractor
the same restrictions and conditions that apply to Business Associate
under this BAA. The current list of Subcontractors that may receive PHI
is maintained at <a href="/sub-processors">${SERVICE_DOMAIN}/sub-processors</a>.</p>

<h2>6. Access to PHI by Individuals (45 CFR §164.524)</h2>
<p>Within fifteen (15) business days of a written request from Covered
Entity, Business Associate will provide access to PHI in a Designated
Record Set to enable Covered Entity to meet its obligations under 45 CFR
§164.524. If an individual requests access directly to Business
Associate, Business Associate will forward the request to Covered Entity
without independently responding.</p>

<h2>7. Amendment of PHI (45 CFR §164.526)</h2>
<p>Within fifteen (15) business days of a written request from Covered
Entity, Business Associate will make any amendment to PHI in a
Designated Record Set that Covered Entity directs or agrees to, to
enable Covered Entity to meet its obligations under 45 CFR §164.526.</p>

<h2>8. Accounting of Disclosures (45 CFR §164.528)</h2>
<p>Business Associate will document disclosures of PHI and information
related to such disclosures as would be required for Covered Entity to
respond to a request by an individual for an accounting of disclosures
under 45 CFR §164.528. Within thirty (30) business days of a written
request from Covered Entity, Business Associate will provide an
accounting of disclosures from the preceding six (6) years.</p>

<h2>9. HHS Access</h2>
<p>Business Associate will make its internal practices, books, and
records, including policies and procedures and PHI, relating to the use
and disclosure of PHI received from Covered Entity, available to the
Secretary of the U.S. Department of Health and Human Services
("<strong>HHS</strong>") for purposes of determining Covered Entity's
compliance with the HIPAA Rules. Business Associate will promptly notify
Covered Entity of any such request, unless prohibited by law.</p>

<h2>10. Compliance with Covered Entity's Obligations</h2>
<p>To the extent Business Associate is required to carry out one or
more of Covered Entity's obligations under Subpart E of 45 CFR Part 164,
Business Associate will comply with the requirements of Subpart E that
apply to Covered Entity in the performance of such obligation. Business
Associate is not, by virtue of this BAA, performing any function of
Covered Entity not specifically delegated in the Master Agreement.</p>

<h2>11. Term and Termination</h2>
<ul>
  <li><strong>Term.</strong> This BAA is effective on the Effective Date and continues for the term of the Master Agreement.</li>
  <li><strong>Termination for cause.</strong> Upon Covered Entity's knowledge of a material breach by Business Associate, Covered Entity will provide a reasonable opportunity to cure (not less than thirty (30) days). If Business Associate does not cure, Covered Entity may terminate the Master Agreement, this BAA, or both. If termination is not feasible, Covered Entity will report the violation to the Secretary of HHS.</li>
  <li><strong>Return or destruction of PHI at termination.</strong> Upon termination of this BAA for any reason, Business Associate will return or destroy all PHI received from, or created or received by Business Associate on behalf of, Covered Entity. This applies to PHI in the possession of Business Associate's Subcontractors. If return or destruction is not feasible, the protections of this BAA will extend to such PHI and further use or disclosure will be limited to those purposes that make return or destruction infeasible. Destruction will be carried out in a manner consistent with 45 CFR §164.310(d)(2) and HHS guidance. A certificate of destruction will be provided to Covered Entity on request.</li>
</ul>

<h2>12. Indemnification</h2>
<p>Indemnification obligations of the parties with respect to breaches
of this BAA are governed by the Master Agreement. Nothing in this BAA
expands either party's indemnification obligations beyond what the
Master Agreement provides, except to the extent applicable law requires
otherwise.</p>

<h2>13. Miscellaneous</h2>
<ul>
  <li><strong>Regulatory amendments.</strong> The parties agree to take such action as is necessary to amend this BAA from time to time as is necessary for the parties to comply with the HIPAA Rules as they may be amended.</li>
  <li><strong>Interpretation.</strong> Any ambiguity in this BAA will be resolved to permit the parties to comply with the HIPAA Rules.</li>
  <li><strong>No third-party beneficiaries.</strong> Nothing in this BAA confers any rights upon any person other than the parties and their respective successors and permitted assigns.</li>
  <li><strong>Order of precedence.</strong> In the event of a conflict between this BAA and the Master Agreement with respect to PHI, this BAA controls. In the event of a conflict between this BAA and the HIPAA Rules, the HIPAA Rules control.</li>
</ul>

<h2>14. Signatures</h2>
<p>The parties have caused this BAA to be executed by their authorized
representatives as of the Effective Date.</p>

<div class="callout">
<strong>Covered Entity</strong> ([Customer Legal Name])<br>
By: ________________________________________<br>
Name: [Authorized Signer]<br>
Title: [Title]<br>
Date: ____________
</div>

<div class="callout">
<strong>${COMPANY_LEGAL_NAME}</strong> (Business Associate)<br>
By: ________________________________________<br>
Name: [${COMPANY_DISPLAY_NAME} Authorized Signer]<br>
Title: [Title]<br>
Date: ____________
</div>
`;

// ---------------------------------------------------------------------------
// GDPR Article 28 — Processor Commitments Addendum
// ---------------------------------------------------------------------------

const GDPR_ART28_BODY = `
<h1>GDPR Article 28 — Processor Commitments</h1>
<div class="meta">Last updated: ${LAST_UPDATED} · Template v1</div>

${TEMPLATE_BANNER}

<div class="callout">
<strong>Recital — GDPR Article 28(3).</strong> Processing by a processor
shall be governed by a contract or other legal act under Union or
Member State law, that is binding on the processor with regard to the
controller and that sets out the subject-matter and duration of the
processing, the nature and purpose of the processing, the type of
personal data and categories of data subjects, and the obligations and
rights of the controller. That contract or other legal act shall
stipulate, in particular, that the processor (a)–(h) below. This
addendum is intended to satisfy that requirement between
<strong>[Customer Legal Name]</strong> ("<strong>Controller</strong>") and
${COMPANY_LEGAL_NAME} ("<strong>${COMPANY_DISPLAY_NAME}</strong>" or
"<strong>Processor</strong>").
</div>

<p><strong>Effective Date:</strong> [Effective Date — typically the date
of the last signature below, or the Master Agreement effective date,
whichever is later].</p>

<h2>Subject Matter, Duration, Nature, and Purpose of Processing</h2>
<ul>
  <li><strong>Subject matter.</strong> Provision by Processor to Controller of the ${PRODUCT_NAME} Service — a gateway, inference engine, and audit-bench operated at ${SERVICE_DOMAIN}.</li>
  <li><strong>Duration.</strong> For the term of the Master Agreement (see <a href="/terms">Terms of Service</a> or the executed order form) plus the retention windows set out in §(g) below.</li>
  <li><strong>Nature.</strong> Routing API requests to the inference engine, returning Outputs to Controller, enforcing quotas, billing reconciliation, abuse detection, and operational diagnostics.</li>
  <li><strong>Purpose.</strong> To enable Controller to use the Service for Controller's own lawful purposes, as Controller determines.</li>
</ul>

<h2>Type of Personal Data</h2>
<ul>
  <li>Identifiers and account metadata of Controller's authorized users: name, email, billing details (collected by Stripe);</li>
  <li>Any Personal Data that Controller elects to include in API request payloads (prompts, messages, schemas) submitted to <code>/v1/chat/completions</code>;</li>
  <li>Operational telemetry tied to authorized-user identifiers (timestamp, IP address, request ID, token counts, HTTP status).</li>
</ul>
<p>Processor does not require Controller to include any special
categories of data (GDPR Art. 9) or data relating to criminal
convictions and offences (GDPR Art. 10) in order to use the Service.
Controller is responsible for the lawful basis of any such data it
elects to include.</p>

<h2>Categories of Data Subjects</h2>
<ul>
  <li>Controller's authorized users;</li>
  <li>End-users of Controller-built products whose data Controller elects to include in Inputs to the Service.</li>
</ul>

<h2>Obligations and Rights of the Controller</h2>
<ul>
  <li>Controller warrants that it has a lawful basis under GDPR Art. 6 (and, where applicable, Art. 9) for the Processing it instructs Processor to perform.</li>
  <li>Controller is responsible for issuing documented instructions to Processor (the use of the Service in accordance with the Master Agreement constitutes such instructions).</li>
  <li>Controller is responsible for responding to data-subject rights requests, with Processor's assistance as set out in (e) below.</li>
  <li>Controller retains the right to audit Processor in accordance with §(h) below.</li>
</ul>

<h2>Processor Obligations under GDPR Art. 28(3)(a)–(h)</h2>

<h3>(a) Documented Instructions</h3>
<p>Processor shall process the Personal Data only on documented
instructions from Controller, including with regard to transfers of
Personal Data to a third country or an international organisation,
unless required to do so by Union or Member State law to which the
Processor is subject; in such a case, the Processor shall inform the
Controller of that legal requirement before processing, unless that
law prohibits such information on important grounds of public interest.
The Master Agreement, the use of the Service in accordance with its
documentation, and any specific written instructions issued by
Controller through the channels in <a href="/dpa">DPA §6</a> constitute
documented instructions.</p>

<h3>(b) Confidentiality of Personnel</h3>
<p>Processor shall ensure that persons authorised to process the
Personal Data have committed themselves to confidentiality or are
under an appropriate statutory obligation of confidentiality. All
Processor personnel with access to Controller's Personal Data are
bound by written confidentiality obligations as a condition of
employment or contract, surviving termination.</p>

<h3>(c) Security Measures (Art. 32)</h3>
<p>Processor shall take all measures required pursuant to Article 32
(security of processing). Processor's technical and organisational
measures are set out in <a href="/dpa">DPA §4</a> and are made
verifiable in <a href="/SECURITY.md">SECURITY.md §3</a>:</p>
<ul>
  <li>Pseudonymisation and encryption of personal data, where appropriate (TLS 1.2+ in transit; API keys stored as SHA-256 hashes);</li>
  <li>Ability to ensure the ongoing confidentiality, integrity, availability, and resilience of processing systems (response signature HMAC, append-only audit log, cosign-signed deployments, internal-only ingress for the inference engine);</li>
  <li>Ability to restore the availability and access to personal data in a timely manner in the event of a physical or technical incident (Azure platform redundancy + Processor's documented incident response);</li>
  <li>A process for regularly testing, assessing, and evaluating the effectiveness of technical and organisational measures (open determinism bench published at <code>github.com/5CEOS-DRA/llm-determinism-bench</code>; SOC 2 Type II audit engaged, report expected [TBD]).</li>
</ul>

<h3>(d) Sub-processor Restrictions</h3>
<p>Processor shall not engage another processor without prior specific
or general written authorisation of the Controller. By executing this
addendum, Controller grants general written authorisation for Processor
to engage the sub-processors listed at
<a href="/sub-processors">${SERVICE_DOMAIN}/sub-processors</a>. In the
case of general written authorisation, Processor shall inform Controller
of any intended changes concerning the addition or replacement of other
processors, thereby giving Controller the opportunity to object to such
changes. The notice procedure and objection right are set out in
<a href="/dpa">DPA §3</a> (thirty (30) days' prior notice; fifteen (15)
days for Controller to object).</p>
<p>Where Processor engages another processor, the same data-protection
obligations as set out in this addendum shall be imposed on that other
processor by way of a contract or other legal act under Union or Member
State law. Where that other processor fails to fulfil its data
protection obligations, the initial Processor shall remain fully liable
to the Controller for the performance of that other processor's
obligations.</p>

<h3>(e) Assistance with Data-Subject Rights (Chapter III)</h3>
<p>Processor shall, taking into account the nature of the processing,
assist Controller by appropriate technical and organisational measures,
insofar as this is possible, for the fulfilment of Controller's
obligation to respond to requests for exercising the data subject's
rights laid down in Chapter III of the GDPR (access, rectification,
erasure, restriction, portability, objection, automated
decision-making). The assistance procedure is set out in
<a href="/dpa">DPA §6</a> (forward DSARs to Controller; on Controller's
documented instruction, retrieve/correct/delete Personal Data within
fifteen (15) business days).</p>

<h3>(f) Assistance with Security and Notification Obligations (Arts. 32–36)</h3>
<p>Processor shall assist Controller in ensuring compliance with the
obligations pursuant to Articles 32 to 36 of the GDPR taking into
account the nature of processing and the information available to
Processor. In particular:</p>
<ul>
  <li><strong>Art. 33 (notification to supervisory authority):</strong> Processor will notify Controller of any Personal Data Breach without undue delay and in any event within seventy-two (72) hours of becoming aware of it (<a href="/dpa">DPA §7</a>), so that Controller can comply with its 72-hour notification obligation to the supervisory authority.</li>
  <li><strong>Art. 34 (communication to data subject):</strong> Processor will provide Controller with the information necessary to assess whether the breach is likely to result in a high risk to data subjects and, if so, to communicate the breach to data subjects.</li>
  <li><strong>Art. 35 (data protection impact assessment):</strong> on Controller's reasonable request, Processor will provide information about the Service's processing operations, security measures, and sub-processors sufficient to enable Controller to conduct a DPIA.</li>
  <li><strong>Art. 36 (prior consultation):</strong> Processor will cooperate with Controller's prior consultation with the supervisory authority, where applicable.</li>
</ul>

<h3>(g) Deletion or Return at End of Processing</h3>
<p>At the choice of the Controller, Processor shall delete or return all
the personal data to the Controller after the end of the provision of
services relating to processing, and delete existing copies unless Union
or Member State law requires storage of the personal data. The deletion
procedure is set out in <a href="/dpa">DPA §9</a> (return or delete
within thirty (30) days of termination; certificate of deletion on
request; permitted retention only as Required by Law and in
isolated/overwritten backups).</p>

<h3>(h) Audit and Information Rights</h3>
<p>Processor shall make available to Controller all information
necessary to demonstrate compliance with the obligations laid down in
Article 28 of the GDPR and allow for and contribute to audits, including
inspections, conducted by Controller or another auditor mandated by
Controller. The audit procedure, frequency, and conditions are set out
in <a href="/dpa">DPA §8</a>. Processor shall immediately inform
Controller if, in its opinion, an instruction infringes the GDPR or
other Union or Member State data-protection provisions.</p>

<h2>International Transfers</h2>
<p>To the extent Processor's Processing of Controller's Personal Data
involves a transfer of Personal Data out of the European Economic Area,
the United Kingdom, or Switzerland to a country not covered by an
adequacy decision, the parties incorporate the European Commission's
<strong>Standard Contractual Clauses</strong> (Decision (EU) 2021/914),
Module Two (Controller-to-Processor), and, for UK transfers, the UK
International Data Transfer Addendum, on the terms set out in
<a href="/dpa">DPA §10</a>.</p>

<h2>Term and Termination</h2>
<p>This addendum is effective on the Effective Date and continues for
the term of the Master Agreement. Upon termination of the Master
Agreement, the obligations of §(g) (deletion or return) and any
obligation that by its nature survives termination (confidentiality,
audit cooperation with respect to past Processing, breach notification
for breaches occurring during the term but discovered after) will
survive.</p>

<h2>Order of Precedence</h2>
<p>In the event of any conflict between (i) this addendum, (ii) the
Standard Contractual Clauses incorporated by reference, (iii) the
<a href="/dpa">Data Processing Addendum</a>, and (iv) the Master
Agreement, the order of precedence is (ii) > (i) > (iii) > (iv) with
respect to GDPR matters.</p>

<h2>Signatures</h2>
<p>The parties have caused this addendum to be executed by their
authorized representatives as of the Effective Date.</p>

<div class="callout">
<strong>Controller</strong> ([Customer Legal Name])<br>
By: ________________________________________<br>
Name: [Authorized Signer]<br>
Title: [Title]<br>
Date: ____________
</div>

<div class="callout">
<strong>${COMPANY_LEGAL_NAME}</strong> (Processor)<br>
By: ________________________________________<br>
Name: [${COMPANY_DISPLAY_NAME} Authorized Signer]<br>
Title: [Title]<br>
Date: ____________
</div>
`;

// ---------------------------------------------------------------------------
// Sub-processors list
// ---------------------------------------------------------------------------

const SUB_PROCESSORS_BODY = `
<h1>Sub-processors</h1>
<div class="meta">Last updated: ${LAST_UPDATED}</div>

<p>This page lists the third-party sub-processors that ${COMPANY_DISPLAY_NAME}
engages in the course of providing the ${PRODUCT_NAME} Service. The
<a href="/dpa">Data Processing Addendum</a> and the
<a href="/gdpr">GDPR Art. 28 addendum</a> incorporate this list by
reference. ${COMPANY_DISPLAY_NAME} will provide at least thirty (30)
days' notice of any addition or replacement by updating this page (and,
for Compliance and Enterprise customers, by email).</p>

<h2>Current sub-processors</h2>
<ul>
  <li><strong>Microsoft Azure</strong> (Microsoft Corporation, headquartered in the United States; default region East US) — hosts the gateway, the inference engine, and the audit log. All Customer prompts and Outputs are Processed within Azure infrastructure under ${COMPANY_DISPLAY_NAME}'s account; the inference engine is deployed as a sibling container with internal-only ingress. Enterprise customers may select an alternative region.</li>
  <li><strong>Stripe</strong> (Stripe, Inc., headquartered in the United States) — processes subscription payments and stores billing details. Customer-prompt content is never transmitted to Stripe. Stripe's processing is governed by its own Data Processing Addendum, available at <a href="https://stripe.com/legal/dpa">stripe.com/legal/dpa</a>.</li>
  <li><strong>GitHub</strong> (GitHub, Inc., a subsidiary of Microsoft Corporation, headquartered in the United States) — hosts the open-source determinism bench (<code>github.com/5CEOS-DRA/llm-determinism-bench</code>) and the public artifacts published by ${COMPANY_DISPLAY_NAME}. No Customer prompt or response content is published to GitHub.</li>
</ul>

<h2>Change history</h2>
<p>Material changes to this list will be timestamped here.</p>
<ul>
  <li>${LAST_UPDATED} — initial publication.</li>
</ul>

<h2>Questions</h2>
<p>Sub-processor questions: <a href="mailto:${LEGAL_EMAIL}">${LEGAL_EMAIL}</a>.</p>
`;

module.exports = {
  termsHtml: () => wrapHtml('Terms of Service', TERMS_BODY),
  privacyHtml: () => wrapHtml('Privacy Policy', PRIVACY_BODY),
  aupHtml: () => wrapHtml('Acceptable Use Policy', AUP_BODY),
  dpaHtml: () => wrapHtml('Data Processing Addendum', DPA_BODY),
  baaHtml: () => wrapHtml('Business Associate Agreement', BAA_BODY),
  gdprArt28Html: () => wrapHtml('GDPR Article 28 Commitments', GDPR_ART28_BODY),
  subProcessorsHtml: () => wrapHtml('Sub-processors', SUB_PROCESSORS_BODY),
};
