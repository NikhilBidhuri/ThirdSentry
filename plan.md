Project: ScriptDrift — Third-Party JavaScript Security Monitoring Platform

1. Your Role

Act as a Senior Software Architect, Senior TypeScript Engineer, Application Security Engineer, and Open-Source Maintainer.

Your responsibility is to design and implement a production-quality, open-source tool called ScriptDrift.

Do not just generate a basic proof of concept. Build a reliable, maintainable, secure, extensible application that developers can install in their repositories or run independently using Docker.

Work incrementally. First inspect the existing repository, understand its structure, and prepare an implementation plan. Then implement the application in logical phases, running tests and fixing problems as you go.

Do not leave core functionality as TODOs or fake implementations.

When a feature cannot be implemented completely, clearly document its limitations rather than pretending it works.

⸻

2. Product Vision

ScriptDrift is an open-source, self-hostable security monitoring tool that detects unexpected or suspicious changes in third-party JavaScript running on websites.

Modern websites load JavaScript from external vendors such as:

* Google Analytics
* Google Tag Manager
* Meta Pixel
* Optimizely
* Intercom
* Hotjar
* Payment gateways
* Advertising networks
* Customer support widgets
* Marketing and experimentation platforms

Website developers do not directly control the JavaScript hosted by these third-party vendors.

A trusted vendor could accidentally introduce a vulnerable update, have its infrastructure compromised, or serve malicious JavaScript.

This creates a security risk even when the website’s own source code has not changed.

ScriptDrift should continuously monitor these external scripts and identify unexpected changes.

Main objective

Build a security guard for third-party JavaScript.

ScriptDrift should:

1. Visit configured websites using a real browser.
2. Discover JavaScript resources loaded by those websites.
3. Record their URLs, origins, hashes, and relevant metadata.
4. Maintain an approved baseline.
5. Periodically scan websites again.
6. Compare current resources with the approved baseline.
7. Identify unexpected additions, removals, and modifications.
8. Analyse JavaScript for suspicious behaviours.
9. Identify unexpected outbound network destinations.
10. Generate understandable security findings.
11. Notify developers about important changes.

ScriptDrift must not automatically approve suspicious changes.

⸻

3. Technology Stack

Use the following stack unless there is a compelling technical reason to change it.

* Language: TypeScript
* Runtime: Node.js
* Browser automation: Playwright
* CLI framework: Commander.js
* Configuration: YAML
* Configuration validation: Zod
* JavaScript parsing: @babel/parser
* JavaScript traversal: @babel/traverse
* JavaScript generation/normalisation: Babel tooling where appropriate
* Diff engine: jsdiff
* Domain parsing: tldts
* Cryptographic hashing: Node.js crypto
* Testing: Vitest
* Logging: Pino
* Containerisation: Docker
* CI/CD: GitHub Actions
* Reporting: JSON and SARIF
* Initial persistence: Local filesystem with JSON metadata and Git-managed baselines

Use strict TypeScript settings.

Prefer small, focused modules and clear interfaces.

Avoid unnecessary dependencies.

⸻

4. Product Architecture

Build ScriptDrift as a modular application.

Suggested architecture:

src/
cli/
commands/
init.ts
scan.ts
baseline.ts
diff.ts
report.ts
csp-lint.ts

config/
schema.ts
loader.ts
defaults.ts

browser/
browser-manager.ts
page-scanner.ts
network-collector.ts
resource-collector.ts
browser-profiles.ts

discovery/
script-discovery.ts
iframe-discovery.ts
inline-script-discovery.ts
worker-discovery.ts
resource-classifier.ts

analysis/
hashing.ts
normalizer.ts
structural-diff.ts
ast-analyzer.ts
indicator-rules.ts
domain-analyzer.ts
risk-scoring.ts

baseline/
baseline-manager.ts
baseline-schema.ts
baseline-validator.ts

monitoring/
scan-manager.ts
comparison-engine.ts
finding-engine.ts

alerts/
alert-manager.ts
slack.ts
webhook.ts
github-issues.ts
email.ts

csp/
csp-parser.ts
csp-analyzer.ts
csp-recommendations.ts

reporting/
json-reporter.ts
sarif-reporter.ts
html-reporter.ts

security/
browser-isolation.ts
network-policy.ts
url-validator.ts
limits.ts

storage/
filesystem-store.ts
metadata-store.ts

types/
index.ts

utils/
logger.ts
errors.ts

tests/
unit/
integration/
fixtures/

docs/
installation.md
configuration.md
security.md
architecture.md
github-actions.md
docker.md
troubleshooting.md

This is a suggested structure. Improve it when necessary, but preserve separation of responsibilities.

⸻

5. Core Feature 1: Website Scanning

Implement a real-browser scanner using Playwright.

A user should be able to configure multiple websites and pages.

Example configuration:

sites:

* name: production-store
    url: https://example.com
    enabled: true
    pages:
    * /
    * /checkout
    * /contact
    browser:
    profile: desktop-chromium
    scan:
    timeout: 60000
    waitUntil: networkidle
    captureScreenshots: false

Support the following browser profiles:

* Desktop Chromium
* Desktop Firefox
* Desktop WebKit
* Mobile-emulated Chromium
* Mobile-emulated WebKit

Important: Clearly describe browser emulation. Do not claim that WebKit with a mobile user agent is equivalent to a real iOS device.

The scanner must:

1. Launch a browser.
2. Open the configured URL.
3. Collect page information.
4. Observe network requests and responses.
5. Identify JavaScript resources.
6. Capture inline scripts.
7. Identify scripts loaded dynamically.
8. Record relevant resource metadata.
9. Capture JavaScript response bodies where permitted.
10. Record browser errors and failed requests.
11. Save scan results.
12. Close the browser safely.

Support multiple pages and websites in a single scan.

Handle navigation errors, timeouts, unavailable websites, and partial scans gracefully.

Do not silently report an incomplete scan as successful.

⸻

6. Core Feature 2: JavaScript Resource Discovery

Discover as many relevant JavaScript execution resources as reasonably possible.

Include:

* External script tags.
* Inline script blocks.
* ES modules.
* Dynamically inserted script elements.
* JavaScript loaded through import().
* Relevant iframe scripts.
* Web workers.
* Service workers where observable.
* JavaScript loaded through blob URLs where observable.
* WebAssembly resources as a separately classified resource type.

Capture:

* Original URL.
* Canonical resource identity.
* Final response URL after redirects.
* Parent page URL.
* Resource type.
* HTTP status.
* Content type.
* Response size.
* First-party or third-party classification.
* Hostname.
* Registrable domain.
* SHA-256 hash of original bytes.
* SHA-256 hash of normalised content, when available.
* Discovery timestamp.
* Relevant request and response metadata.

Preserve the original URL and original content hash.

Do not discard query parameters or URL information that may be relevant to security analysis.

Do not assume that a URL alone uniquely identifies a resource.

Handle duplicate resources correctly.

Document resources that cannot be captured and explain the scanner’s coverage limitations.

Explicitly address Playwright service-worker visibility limitations. Where necessary, provide a configurable strategy for handling service workers and document any behavioural differences.

⸻

7. Core Feature 3: Hashing and Content Normalisation

Implement secure and reliable hashing.

Use SHA-256 for raw resource content.

Maintain separate values for:

1. Original resource URL.
2. Canonical resource identity.
3. Raw content hash.
4. Normalised content hash.

Normalisation should help identify meaningful code changes while reducing irrelevant differences.

Possible normalisation operations:

* Consistent line endings.
* Removal of insignificant whitespace where safe.
* Stable formatting of parsed syntax trees.
* Consistent representation of source code.

Never replace or discard the original captured content.

Avoid aggressive normalisation that could hide meaningful changes.

If JavaScript parsing fails, preserve the original content and fall back to raw-content comparison.

⸻

8. Core Feature 4: Approved Baselines

Implement an approval-based baseline system.

The initial baseline should be generated by the developer.

Example:

npx scriptdrift baseline

Store baseline metadata in a Git-friendly format.

Suggested structure:

.scriptdrift/
config.yml
baselines/
production-store/
baseline.json
reports/
cache/

The baseline should record approved resource identities, hashes, domains, and metadata.

When a resource changes, ScriptDrift must not automatically approve the new version.

Instead:

* Mark the resource as changed.
* Generate a finding.
* Include the previous and current hashes.
* Include a meaningful diff where possible.
* Explain why the change matters.
* Allow the developer to review it.
* Provide an explicit baseline-update command after review.

Never automatically overwrite approved baselines during normal scans.

Provide safe baseline update functionality with clear confirmation.

⸻

9. Core Feature 5: Change Detection

Implement a comparison engine.

Detect:

* New JavaScript resources.
* Removed JavaScript resources.
* Modified JavaScript resources.
* Changed resource origins.
* Redirect destination changes.
* New third-party domains.
* Changed inline scripts.
* Changed iframe origins.
* Changed network destinations.
* Unexpected resource types.

Generate findings with:

* Finding ID.
* Website.
* Page.
* Resource URL.
* Resource type.
* Previous hash.
* Current hash.
* Detection time.
* Severity.
* Confidence.
* Reason.
* Evidence.
* Recommended action.

Distinguish between:

* Informational changes.
* Changes requiring review.
* Suspicious changes.
* High-priority security findings.

A changed hash alone must not be treated as proof of malicious activity.

⸻

10. Core Feature 6: JavaScript Security Analysis

Implement static JavaScript analysis using Babel AST parsing.

Avoid relying exclusively on regular expressions.

Create a modular rule engine.

Initially support detection of patterns such as:

* Unexpected eval() usage.
* new Function() usage.
* Dynamic script injection.
* Suspicious external script loading.
* Unexpected document.cookie access.
* Access to localStorage and sessionStorage.
* Unexpected form-field access.
* Clipboard access.
* Unexpected beacon requests.
* Suspicious data collection.
* Obfuscated or heavily encoded code.
* Unexpected WebSocket connections.
* Unexpected remote endpoint communication.
* Suspicious combinations of sensitive data access and external transmission.

Important security requirement:

These indicators are not automatically malicious.

For example, analytics libraries legitimately access browser storage and collect telemetry.

Use contextual analysis, configurable rules, and multiple indicators.

Each rule should include:

* Rule ID.
* Rule name.
* Description.
* Severity.
* Confidence.
* Detection logic.
* Evidence.
* Explanation.
* Recommended investigation steps.
* False-positive notes.

Make rules configurable.

Allow developers to suppress a finding with a documented reason.

Provide a mechanism to avoid repeatedly reporting the same unchanged finding.

⸻

11. Core Feature 7: Outbound Network Monitoring

Monitor network destinations contacted by scripts during browser execution.

Capture:

* Request URL.
* Request method.
* Destination hostname.
* Registrable domain.
* Resource initiator where observable.
* Request type.
* Parent page.
* Timestamp.
* Response status where available.

Compare observed domains with approved domains.

Detect:

* New outbound domains.
* Unexpected changes in existing destinations.
* Requests to suspicious or unapproved destinations.
* Unexpected cross-origin communication.

Support allowlists and denylists.

Do not claim that browser network monitoring captures every possible data transmission mechanism.

Clearly document coverage limitations.

⸻

12. Core Feature 8: Risk Scoring

Implement an explainable risk scoring system.

Use signals such as:

* Resource hash changes.
* New third-party domains.
* Unexpected resource injection.
* AST rule matches.
* Sensitive browser API usage.
* New outbound requests.
* Domain reputation indicators when configured.
* Multiple correlated suspicious behaviours.

The scoring system must be transparent.

For every finding, explain which signals contributed to its score.

Do not label a resource as confirmed malware solely because it triggered a rule.

Allow configurable thresholds.

Keep severity and confidence separate.

Example:

Severity: High
Confidence: Medium

Reason:
A previously approved payment-page script changed and now communicates with a previously unseen external domain.

⸻

13. Core Feature 9: Alerting

Implement a modular alerting system.

Initial integrations:

1. Slack webhook.
2. Generic HTTP webhook.
3. GitHub Issues.
4. Email.

Alert configuration example:

alerts:
slack:
enabled: true
webhookUrl: ${SCRIPTDRIFT_SLACK_WEBHOOK}

webhook:
enabled: false
url: ${SCRIPTDRIFT_WEBHOOK_URL}

github:
enabled: false
createIssues: true

Use environment variables for credentials.

Never store secrets in the Git repository.

Do not expose credentials to the browser process.

Avoid sending entire third-party scripts in alerts.

Include:

* Website.
* Affected resource.
* Severity.
* Finding explanation.
* Previous and current hashes.
* Relevant evidence.
* Report location.
* Suggested investigation steps.

Support deduplication to prevent alert spam.

Alert delivery failures must not destroy scan results.

⸻

14. Core Feature 10: CSP Linter

Build a separate CSP analysis command.

Example:

npx scriptdrift csp-lint https://example.com

Analyse Content-Security-Policy response headers.

Check for:

* Missing default-src.
* Unsafe-inline.
* Unsafe-eval.
* Wildcard sources.
* Overly broad script-src.
* Missing object-src restrictions.
* Missing base-uri restrictions.
* Missing form-action restrictions.
* Weak or missing nonce/hash policies.
* Risky third-party script allowances.
* Missing reporting configuration.

Correctly account for CSP directive inheritance and fallback behaviour.

Support multiple CSP headers.

Do not treat every use of strict-dynamic as inherently insecure.

Provide recommendations and explanations.

Distinguish between actual policy errors and recommendations requiring review.

The CSP linter should not claim to guarantee protection.

⸻

15. Core Feature 11: Reports

Generate:

1. JSON reports.
2. SARIF reports compatible with GitHub Code Scanning.
3. Human-readable HTML reports.

Reports should contain:

* Scan summary.
* Websites scanned.
* Pages scanned.
* Total JavaScript resources.
* First-party resources.
* Third-party resources.
* New resources.
* Modified resources.
* Removed resources.
* New domains.
* Security findings.
* Risk levels.
* Scan failures.
* Coverage limitations.

Create a clear summary for developers who are not security specialists.

⸻

16. Core Feature 12: CLI Experience

The CLI must be simple.

Support the following commands:

Initialize:

npx scriptdrift init

Scan:

npx scriptdrift scan

Scan a specific website:

npx scriptdrift scan –site production-store

Create baseline:

npx scriptdrift baseline

Compare with baseline:

npx scriptdrift diff

Generate report:

npx scriptdrift report

Run CSP analysis:

npx scriptdrift csp-lint https://example.com

Support:

–config
–output
–format
–verbose
–json
–site
–fail-on

Provide helpful error messages.

Use appropriate exit codes so GitHub Actions can fail when configured security thresholds are exceeded.

⸻

17. Core Feature 13: GitHub Actions

Provide an official reusable GitHub Action.

Developers should be able to integrate ScriptDrift into their existing repositories.

Example workflow:

name: ScriptDrift Security Monitoring

on:
schedule:
- cron: “0 */6 * * *”
workflow_dispatch:
push:
branches:
- main

jobs:
scriptdrift:
runs-on: ubuntu-latest

steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-node@v4
    with:
      node-version: 22
  - name: Install ScriptDrift
    run: npm install
  - name: Run security scan
    run: npx scriptdrift scan
  - name: Upload SARIF
    if: always()
    uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: .scriptdrift/reports/report.sarif

This is an illustrative workflow. Implement and document a reliable official integration.

Important:

* Do not commit scan results containing sensitive data unintentionally.
* Do not automatically commit or approve changed baselines.
* Keep secrets out of logs.
* Use least-privilege GitHub permissions.
* Explain GitHub scheduled workflow delays.
* Allow developers to configure scan frequency.
* Support manual scans.

⸻

18. Core Feature 14: Docker and Cron

Provide a Docker deployment option.

Developers should be able to run ScriptDrift independently of GitHub Actions.

Create:

* Dockerfile.
* .dockerignore.
* Docker Compose example.
* Persistent storage configuration.
* Environment variable documentation.
* Cron deployment example.

Support scheduled scans on self-hosted infrastructure.

Ensure that browser execution and alert delivery have separate security boundaries.

⸻

19. CRITICAL: Browser Security and Isolation

This is one of the most important parts of the project.

ScriptDrift visits websites and executes third-party JavaScript.

The websites being scanned are not necessarily trustworthy.

Treat browser execution as potentially hostile.

Implement the following security protections:

1. Run browser workers in isolated disposable containers or equivalent isolated processes.
2. Do not expose Git credentials to browser processes.
3. Do not expose Slack, email, or webhook secrets to browser processes.
4. Restrict browser resource consumption.
5. Set navigation, execution, and network timeouts.
6. Limit response sizes and captured resource sizes.
7. Block access to loopback addresses.
8. Block private network ranges.
9. Block link-local addresses.
10. Block cloud metadata endpoints.
11. Validate redirects and resolved IP addresses.
12. Protect against DNS rebinding and time-of-check/time-of-use issues.
13. Prevent browser access to internal infrastructure.
14. Restrict unnecessary protocols.
15. Avoid mounting sensitive host directories into browser containers.
16. Ensure browser workers cannot modify approved baselines.
17. Validate user-supplied URLs.
18. Apply network restrictions at the container/network layer, not just through URL checks.

Be particularly careful about SSRF.

Do not assume checking a hostname once is sufficient.

Implement a secure architecture in which:

* A trusted coordinator manages scans.
* An isolated browser worker collects evidence.
* A trusted analysis process validates and processes the collected evidence.
* A separate alert publisher handles notification credentials.

Document the threat model and security boundaries.

⸻

20. Privacy and Data Retention

Third-party scripts may contain proprietary code, user-specific information, or sensitive configuration.

Therefore:

* Do not store complete script bodies by default.
* Store hashes and metadata by default.
* Make content retention optional.
* Allow maximum resource-size limits.
* Allow retention limits.
* Redact sensitive values from reports.
* Never include cookies, authentication headers, or session tokens in reports.
* Do not include request bodies by default.
* Make screenshot capture optional.
* Provide a clear cleanup mechanism.

Document exactly what ScriptDrift collects and stores.

⸻

21. Testing Requirements

Write meaningful automated tests.

Unit tests:

* URL validation.
* Domain classification.
* Hash generation.
* Normalisation.
* Baseline management.
* Change detection.
* AST rules.
* Risk scoring.
* CSP parsing.
* Configuration validation.
* Report generation.

Integration tests:

* Local test website with multiple third-party scripts.
* Dynamically injected script.
* Modified script.
* New outbound domain.
* Removed resource.
* Inline JavaScript modification.
* Browser timeout.
* Invalid website.
* Redirect handling.
* Malformed JavaScript.
* CSP response headers.

Use local fixtures and controlled mock servers.

Never use a real production website as a required test dependency.

Add tests for security-sensitive URL validation and network restrictions.

Test false-positive behaviour.

⸻

22. Development Phases

Do not attempt to build every feature simultaneously.

Implement in these phases.

Phase 1: Working Scanner MVP

Implement:

* TypeScript project setup.
* CLI.
* YAML configuration.
* Playwright browser management.
* Website scanning.
* JavaScript resource discovery.
* Network request collection.
* SHA-256 hashing.
* Local JSON scan output.
* Basic unit and integration tests.

At the end of Phase 1, I should be able to scan a website and see its discovered JavaScript resources and hashes.

Phase 2: Baseline and Change Detection

Implement:

* Baseline creation.
* Baseline storage.
* Baseline comparison.
* Added resources.
* Removed resources.
* Modified resources.
* Domain changes.
* Human-readable diff output.
* Baseline approval workflow.

At the end of Phase 2, I should be able to detect when third-party JavaScript changes between scans.

Phase 3: Security Analysis

Implement:

* Babel AST parsing.
* Configurable detection rules.
* Suspicious behaviour indicators.
* Outbound domain monitoring.
* Explainable risk scoring.
* Finding deduplication.
* False-positive suppression.

Phase 4: Reporting and Alerts

Implement:

* JSON reports.
* SARIF reports.
* HTML reports.
* Slack notifications.
* Generic webhooks.
* GitHub Issues.
* Email integration.

Phase 5: Deployment

Implement:

* Docker.
* Docker Compose.
* GitHub Actions.
* Cron examples.
* Environment variable handling.
* Deployment documentation.

Phase 6: CSP Analysis and Hardening

Implement:

* CSP parser.
* CSP linting.
* Security recommendations.
* Browser isolation hardening.
* SSRF protections.
* Privacy and retention controls.
* Full security documentation.

Do not move to the next phase until the previous phase has working tests and documentation.

⸻

23. User Experience

The ideal developer experience should be:

Step 1:

npx scriptdrift init

Step 2:

Configure websites in scriptdrift.yml.

Step 3:

npx scriptdrift scan

Step 4:

npx scriptdrift baseline

Step 5:

Configure GitHub Actions or Docker/Cron.

Step 6:

Receive alerts when unexpected changes occur.

A developer should not need to understand advanced security concepts to use the basic features.

Make reports understandable to ordinary developers.

⸻

24. Documentation Requirements

Create professional open-source documentation.

Include:

* Project overview.
* Problem being solved.
* Architecture.
* Installation.
* Quick start.
* Configuration reference.
* CLI reference.
* Baseline management.
* Detection rules.
* Alert configuration.
* GitHub Actions integration.
* Docker deployment.
* Cron deployment.
* CSP analysis.
* Security model.
* Privacy and data retention.
* Known limitations.
* Troubleshooting.
* Contributing guide.

Include practical examples.

Clearly explain that ScriptDrift is a monitoring and detection tool, not an automatic malware removal system or a guarantee of PCI DSS compliance.

⸻

25. Engineering Standards

Follow these principles:

* Production-quality TypeScript.
* Strict typing.
* Modular architecture.
* Small reusable functions.
* Clear naming conventions.
* Consistent error handling.
* Structured logging.
* No hardcoded secrets.
* No unnecessary dependencies.
* No fake integrations.
* No silent failures.
* No automatic baseline approvals.
* No unbounded browser execution.
* No unnecessary storage of third-party code.
* Meaningful tests for important behaviour.

Avoid overengineering the initial release.

Prioritise a dependable scanner and accurate change detection over a large number of superficial features.

⸻

26. How You Should Work

Before implementing:

1. Inspect the current repository.
2. Identify existing files and dependencies.
3. Prepare a clear architecture and implementation plan.
4. Identify security-sensitive components.
5. Identify the first deliverable.

Then start Phase 1.

For every phase:

1. Explain what you are implementing.
2. Implement the feature.
3. Run type checking.
4. Run linting.
5. Run automated tests.
6. Fix failures.
7. Update documentation.
8. Summarise completed work.
9. Identify remaining limitations.

Do not merely give me code snippets. Implement the actual project files.

Do not ask me to manually create files that you can create yourself.

If an external credential or integration is required, create the integration structure and document the exact environment variable needed.

Do not pretend an external integration has been tested without actually testing it.

Final objective: Build ScriptDrift into a trustworthy, developer-friendly, open-source security monitoring tool that organisations can use to continuously detect unexpected or suspicious third-party JavaScript changes on their websites.Project: ScriptDrift — Third-Party JavaScript Security Monitoring Platform

1. Your Role

Act as a Senior Software Architect, Senior TypeScript Engineer, Application Security Engineer, and Open-Source Maintainer.

Your responsibility is to design and implement a production-quality, open-source tool called ScriptDrift.

Do not just generate a basic proof of concept. Build a reliable, maintainable, secure, extensible application that developers can install in their repositories or run independently using Docker.

Work incrementally. First inspect the existing repository, understand its structure, and prepare an implementation plan. Then implement the application in logical phases, running tests and fixing problems as you go.

Do not leave core functionality as TODOs or fake implementations.

When a feature cannot be implemented completely, clearly document its limitations rather than pretending it works.

⸻

2. Product Vision

ScriptDrift is an open-source, self-hostable security monitoring tool that detects unexpected or suspicious changes in third-party JavaScript running on websites.

Modern websites load JavaScript from external vendors such as:

* Google Analytics
* Google Tag Manager
* Meta Pixel
* Optimizely
* Intercom
* Hotjar
* Payment gateways
* Advertising networks
* Customer support widgets
* Marketing and experimentation platforms

Website developers do not directly control the JavaScript hosted by these third-party vendors.

A trusted vendor could accidentally introduce a vulnerable update, have its infrastructure compromised, or serve malicious JavaScript.

This creates a security risk even when the website’s own source code has not changed.

ScriptDrift should continuously monitor these external scripts and identify unexpected changes.

Main objective

Build a security guard for third-party JavaScript.

ScriptDrift should:

1. Visit configured websites using a real browser.
2. Discover JavaScript resources loaded by those websites.
3. Record their URLs, origins, hashes, and relevant metadata.
4. Maintain an approved baseline.
5. Periodically scan websites again.
6. Compare current resources with the approved baseline.
7. Identify unexpected additions, removals, and modifications.
8. Analyse JavaScript for suspicious behaviours.
9. Identify unexpected outbound network destinations.
10. Generate understandable security findings.
11. Notify developers about important changes.

ScriptDrift must not automatically approve suspicious changes.

⸻

3. Technology Stack

Use the following stack unless there is a compelling technical reason to change it.

* Language: TypeScript
* Runtime: Node.js
* Browser automation: Playwright
* CLI framework: Commander.js
* Configuration: YAML
* Configuration validation: Zod
* JavaScript parsing: @babel/parser
* JavaScript traversal: @babel/traverse
* JavaScript generation/normalisation: Babel tooling where appropriate
* Diff engine: jsdiff
* Domain parsing: tldts
* Cryptographic hashing: Node.js crypto
* Testing: Vitest
* Logging: Pino
* Containerisation: Docker
* CI/CD: GitHub Actions
* Reporting: JSON and SARIF
* Initial persistence: Local filesystem with JSON metadata and Git-managed baselines

Use strict TypeScript settings.

Prefer small, focused modules and clear interfaces.

Avoid unnecessary dependencies.

⸻

4. Product Architecture

Build ScriptDrift as a modular application.

Suggested architecture:

src/
cli/
commands/
init.ts
scan.ts
baseline.ts
diff.ts
report.ts
csp-lint.ts

config/
schema.ts
loader.ts
defaults.ts

browser/
browser-manager.ts
page-scanner.ts
network-collector.ts
resource-collector.ts
browser-profiles.ts

discovery/
script-discovery.ts
iframe-discovery.ts
inline-script-discovery.ts
worker-discovery.ts
resource-classifier.ts

analysis/
hashing.ts
normalizer.ts
structural-diff.ts
ast-analyzer.ts
indicator-rules.ts
domain-analyzer.ts
risk-scoring.ts

baseline/
baseline-manager.ts
baseline-schema.ts
baseline-validator.ts

monitoring/
scan-manager.ts
comparison-engine.ts
finding-engine.ts

alerts/
alert-manager.ts
slack.ts
webhook.ts
github-issues.ts
email.ts

csp/
csp-parser.ts
csp-analyzer.ts
csp-recommendations.ts

reporting/
json-reporter.ts
sarif-reporter.ts
html-reporter.ts

security/
browser-isolation.ts
network-policy.ts
url-validator.ts
limits.ts

storage/
filesystem-store.ts
metadata-store.ts

types/
index.ts

utils/
logger.ts
errors.ts

tests/
unit/
integration/
fixtures/

docs/
installation.md
configuration.md
security.md
architecture.md
github-actions.md
docker.md
troubleshooting.md

This is a suggested structure. Improve it when necessary, but preserve separation of responsibilities.

⸻

5. Core Feature 1: Website Scanning

Implement a real-browser scanner using Playwright.

A user should be able to configure multiple websites and pages.

Example configuration:

sites:

* name: production-store
    url: https://example.com
    enabled: true
    pages:
    * /
    * /checkout
    * /contact
    browser:
    profile: desktop-chromium
    scan:
    timeout: 60000
    waitUntil: networkidle
    captureScreenshots: false

Support the following browser profiles:

* Desktop Chromium
* Desktop Firefox
* Desktop WebKit
* Mobile-emulated Chromium
* Mobile-emulated WebKit

Important: Clearly describe browser emulation. Do not claim that WebKit with a mobile user agent is equivalent to a real iOS device.

The scanner must:

1. Launch a browser.
2. Open the configured URL.
3. Collect page information.
4. Observe network requests and responses.
5. Identify JavaScript resources.
6. Capture inline scripts.
7. Identify scripts loaded dynamically.
8. Record relevant resource metadata.
9. Capture JavaScript response bodies where permitted.
10. Record browser errors and failed requests.
11. Save scan results.
12. Close the browser safely.

Support multiple pages and websites in a single scan.

Handle navigation errors, timeouts, unavailable websites, and partial scans gracefully.

Do not silently report an incomplete scan as successful.

⸻

6. Core Feature 2: JavaScript Resource Discovery

Discover as many relevant JavaScript execution resources as reasonably possible.

Include:

* External script tags.
* Inline script blocks.
* ES modules.
* Dynamically inserted script elements.
* JavaScript loaded through import().
* Relevant iframe scripts.
* Web workers.
* Service workers where observable.
* JavaScript loaded through blob URLs where observable.
* WebAssembly resources as a separately classified resource type.

Capture:

* Original URL.
* Canonical resource identity.
* Final response URL after redirects.
* Parent page URL.
* Resource type.
* HTTP status.
* Content type.
* Response size.
* First-party or third-party classification.
* Hostname.
* Registrable domain.
* SHA-256 hash of original bytes.
* SHA-256 hash of normalised content, when available.
* Discovery timestamp.
* Relevant request and response metadata.

Preserve the original URL and original content hash.

Do not discard query parameters or URL information that may be relevant to security analysis.

Do not assume that a URL alone uniquely identifies a resource.

Handle duplicate resources correctly.

Document resources that cannot be captured and explain the scanner’s coverage limitations.

Explicitly address Playwright service-worker visibility limitations. Where necessary, provide a configurable strategy for handling service workers and document any behavioural differences.

⸻

7. Core Feature 3: Hashing and Content Normalisation

Implement secure and reliable hashing.

Use SHA-256 for raw resource content.

Maintain separate values for:

1. Original resource URL.
2. Canonical resource identity.
3. Raw content hash.
4. Normalised content hash.

Normalisation should help identify meaningful code changes while reducing irrelevant differences.

Possible normalisation operations:

* Consistent line endings.
* Removal of insignificant whitespace where safe.
* Stable formatting of parsed syntax trees.
* Consistent representation of source code.

Never replace or discard the original captured content.

Avoid aggressive normalisation that could hide meaningful changes.

If JavaScript parsing fails, preserve the original content and fall back to raw-content comparison.

⸻

8. Core Feature 4: Approved Baselines

Implement an approval-based baseline system.

The initial baseline should be generated by the developer.

Example:

npx scriptdrift baseline

Store baseline metadata in a Git-friendly format.

Suggested structure:

.scriptdrift/
config.yml
baselines/
production-store/
baseline.json
reports/
cache/

The baseline should record approved resource identities, hashes, domains, and metadata.

When a resource changes, ScriptDrift must not automatically approve the new version.

Instead:

* Mark the resource as changed.
* Generate a finding.
* Include the previous and current hashes.
* Include a meaningful diff where possible.
* Explain why the change matters.
* Allow the developer to review it.
* Provide an explicit baseline-update command after review.

Never automatically overwrite approved baselines during normal scans.

Provide safe baseline update functionality with clear confirmation.

⸻

9. Core Feature 5: Change Detection

Implement a comparison engine.

Detect:

* New JavaScript resources.
* Removed JavaScript resources.
* Modified JavaScript resources.
* Changed resource origins.
* Redirect destination changes.
* New third-party domains.
* Changed inline scripts.
* Changed iframe origins.
* Changed network destinations.
* Unexpected resource types.

Generate findings with:

* Finding ID.
* Website.
* Page.
* Resource URL.
* Resource type.
* Previous hash.
* Current hash.
* Detection time.
* Severity.
* Confidence.
* Reason.
* Evidence.
* Recommended action.

Distinguish between:

* Informational changes.
* Changes requiring review.
* Suspicious changes.
* High-priority security findings.

A changed hash alone must not be treated as proof of malicious activity.

⸻

10. Core Feature 6: JavaScript Security Analysis

Implement static JavaScript analysis using Babel AST parsing.

Avoid relying exclusively on regular expressions.

Create a modular rule engine.

Initially support detection of patterns such as:

* Unexpected eval() usage.
* new Function() usage.
* Dynamic script injection.
* Suspicious external script loading.
* Unexpected document.cookie access.
* Access to localStorage and sessionStorage.
* Unexpected form-field access.
* Clipboard access.
* Unexpected beacon requests.
* Suspicious data collection.
* Obfuscated or heavily encoded code.
* Unexpected WebSocket connections.
* Unexpected remote endpoint communication.
* Suspicious combinations of sensitive data access and external transmission.

Important security requirement:

These indicators are not automatically malicious.

For example, analytics libraries legitimately access browser storage and collect telemetry.

Use contextual analysis, configurable rules, and multiple indicators.

Each rule should include:

* Rule ID.
* Rule name.
* Description.
* Severity.
* Confidence.
* Detection logic.
* Evidence.
* Explanation.
* Recommended investigation steps.
* False-positive notes.

Make rules configurable.

Allow developers to suppress a finding with a documented reason.

Provide a mechanism to avoid repeatedly reporting the same unchanged finding.

⸻

11. Core Feature 7: Outbound Network Monitoring

Monitor network destinations contacted by scripts during browser execution.

Capture:

* Request URL.
* Request method.
* Destination hostname.
* Registrable domain.
* Resource initiator where observable.
* Request type.
* Parent page.
* Timestamp.
* Response status where available.

Compare observed domains with approved domains.

Detect:

* New outbound domains.
* Unexpected changes in existing destinations.
* Requests to suspicious or unapproved destinations.
* Unexpected cross-origin communication.

Support allowlists and denylists.

Do not claim that browser network monitoring captures every possible data transmission mechanism.

Clearly document coverage limitations.

⸻

12. Core Feature 8: Risk Scoring

Implement an explainable risk scoring system.

Use signals such as:

* Resource hash changes.
* New third-party domains.
* Unexpected resource injection.
* AST rule matches.
* Sensitive browser API usage.
* New outbound requests.
* Domain reputation indicators when configured.
* Multiple correlated suspicious behaviours.

The scoring system must be transparent.

For every finding, explain which signals contributed to its score.

Do not label a resource as confirmed malware solely because it triggered a rule.

Allow configurable thresholds.

Keep severity and confidence separate.

Example:

Severity: High
Confidence: Medium

Reason:
A previously approved payment-page script changed and now communicates with a previously unseen external domain.

⸻

13. Core Feature 9: Alerting

Implement a modular alerting system.

Initial integrations:

1. Slack webhook.
2. Generic HTTP webhook.
3. GitHub Issues.
4. Email.

Alert configuration example:

alerts:
slack:
enabled: true
webhookUrl: ${SCRIPTDRIFT_SLACK_WEBHOOK}

webhook:
enabled: false
url: ${SCRIPTDRIFT_WEBHOOK_URL}

github:
enabled: false
createIssues: true

Use environment variables for credentials.

Never store secrets in the Git repository.

Do not expose credentials to the browser process.

Avoid sending entire third-party scripts in alerts.

Include:

* Website.
* Affected resource.
* Severity.
* Finding explanation.
* Previous and current hashes.
* Relevant evidence.
* Report location.
* Suggested investigation steps.

Support deduplication to prevent alert spam.

Alert delivery failures must not destroy scan results.

⸻

14. Core Feature 10: CSP Linter

Build a separate CSP analysis command.

Example:

npx scriptdrift csp-lint https://example.com

Analyse Content-Security-Policy response headers.

Check for:

* Missing default-src.
* Unsafe-inline.
* Unsafe-eval.
* Wildcard sources.
* Overly broad script-src.
* Missing object-src restrictions.
* Missing base-uri restrictions.
* Missing form-action restrictions.
* Weak or missing nonce/hash policies.
* Risky third-party script allowances.
* Missing reporting configuration.

Correctly account for CSP directive inheritance and fallback behaviour.

Support multiple CSP headers.

Do not treat every use of strict-dynamic as inherently insecure.

Provide recommendations and explanations.

Distinguish between actual policy errors and recommendations requiring review.

The CSP linter should not claim to guarantee protection.

⸻

15. Core Feature 11: Reports

Generate:

1. JSON reports.
2. SARIF reports compatible with GitHub Code Scanning.
3. Human-readable HTML reports.

Reports should contain:

* Scan summary.
* Websites scanned.
* Pages scanned.
* Total JavaScript resources.
* First-party resources.
* Third-party resources.
* New resources.
* Modified resources.
* Removed resources.
* New domains.
* Security findings.
* Risk levels.
* Scan failures.
* Coverage limitations.

Create a clear summary for developers who are not security specialists.

⸻

16. Core Feature 12: CLI Experience

The CLI must be simple.

Support the following commands:

Initialize:

npx scriptdrift init

Scan:

npx scriptdrift scan

Scan a specific website:

npx scriptdrift scan –site production-store

Create baseline:

npx scriptdrift baseline

Compare with baseline:

npx scriptdrift diff

Generate report:

npx scriptdrift report

Run CSP analysis:

npx scriptdrift csp-lint https://example.com

Support:

–config
–output
–format
–verbose
–json
–site
–fail-on

Provide helpful error messages.

Use appropriate exit codes so GitHub Actions can fail when configured security thresholds are exceeded.

⸻

17. Core Feature 13: GitHub Actions

Provide an official reusable GitHub Action.

Developers should be able to integrate ScriptDrift into their existing repositories.

Example workflow:

name: ScriptDrift Security Monitoring

on:
schedule:
- cron: “0 */6 * * *”
workflow_dispatch:
push:
branches:
- main

jobs:
scriptdrift:
runs-on: ubuntu-latest

steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-node@v4
    with:
      node-version: 22
  - name: Install ScriptDrift
    run: npm install
  - name: Run security scan
    run: npx scriptdrift scan
  - name: Upload SARIF
    if: always()
    uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: .scriptdrift/reports/report.sarif

This is an illustrative workflow. Implement and document a reliable official integration.

Important:

* Do not commit scan results containing sensitive data unintentionally.
* Do not automatically commit or approve changed baselines.
* Keep secrets out of logs.
* Use least-privilege GitHub permissions.
* Explain GitHub scheduled workflow delays.
* Allow developers to configure scan frequency.
* Support manual scans.

⸻

18. Core Feature 14: Docker and Cron

Provide a Docker deployment option.

Developers should be able to run ScriptDrift independently of GitHub Actions.

Create:

* Dockerfile.
* .dockerignore.
* Docker Compose example.
* Persistent storage configuration.
* Environment variable documentation.
* Cron deployment example.

Support scheduled scans on self-hosted infrastructure.

Ensure that browser execution and alert delivery have separate security boundaries.

⸻

19. CRITICAL: Browser Security and Isolation

This is one of the most important parts of the project.

ScriptDrift visits websites and executes third-party JavaScript.

The websites being scanned are not necessarily trustworthy.

Treat browser execution as potentially hostile.

Implement the following security protections:

1. Run browser workers in isolated disposable containers or equivalent isolated processes.
2. Do not expose Git credentials to browser processes.
3. Do not expose Slack, email, or webhook secrets to browser processes.
4. Restrict browser resource consumption.
5. Set navigation, execution, and network timeouts.
6. Limit response sizes and captured resource sizes.
7. Block access to loopback addresses.
8. Block private network ranges.
9. Block link-local addresses.
10. Block cloud metadata endpoints.
11. Validate redirects and resolved IP addresses.
12. Protect against DNS rebinding and time-of-check/time-of-use issues.
13. Prevent browser access to internal infrastructure.
14. Restrict unnecessary protocols.
15. Avoid mounting sensitive host directories into browser containers.
16. Ensure browser workers cannot modify approved baselines.
17. Validate user-supplied URLs.
18. Apply network restrictions at the container/network layer, not just through URL checks.

Be particularly careful about SSRF.

Do not assume checking a hostname once is sufficient.

Implement a secure architecture in which:

* A trusted coordinator manages scans.
* An isolated browser worker collects evidence.
* A trusted analysis process validates and processes the collected evidence.
* A separate alert publisher handles notification credentials.

Document the threat model and security boundaries.

⸻

20. Privacy and Data Retention

Third-party scripts may contain proprietary code, user-specific information, or sensitive configuration.

Therefore:

* Do not store complete script bodies by default.
* Store hashes and metadata by default.
* Make content retention optional.
* Allow maximum resource-size limits.
* Allow retention limits.
* Redact sensitive values from reports.
* Never include cookies, authentication headers, or session tokens in reports.
* Do not include request bodies by default.
* Make screenshot capture optional.
* Provide a clear cleanup mechanism.

Document exactly what ScriptDrift collects and stores.

⸻

21. Testing Requirements

Write meaningful automated tests.

Unit tests:

* URL validation.
* Domain classification.
* Hash generation.
* Normalisation.
* Baseline management.
* Change detection.
* AST rules.
* Risk scoring.
* CSP parsing.
* Configuration validation.
* Report generation.

Integration tests:

* Local test website with multiple third-party scripts.
* Dynamically injected script.
* Modified script.
* New outbound domain.
* Removed resource.
* Inline JavaScript modification.
* Browser timeout.
* Invalid website.
* Redirect handling.
* Malformed JavaScript.
* CSP response headers.

Use local fixtures and controlled mock servers.

Never use a real production website as a required test dependency.

Add tests for security-sensitive URL validation and network restrictions.

Test false-positive behaviour.

⸻

22. Development Phases

Do not attempt to build every feature simultaneously.

Implement in these phases.

Phase 1: Working Scanner MVP

Implement:

* TypeScript project setup.
* CLI.
* YAML configuration.
* Playwright browser management.
* Website scanning.
* JavaScript resource discovery.
* Network request collection.
* SHA-256 hashing.
* Local JSON scan output.
* Basic unit and integration tests.

At the end of Phase 1, I should be able to scan a website and see its discovered JavaScript resources and hashes.

Phase 2: Baseline and Change Detection

Implement:

* Baseline creation.
* Baseline storage.
* Baseline comparison.
* Added resources.
* Removed resources.
* Modified resources.
* Domain changes.
* Human-readable diff output.
* Baseline approval workflow.

At the end of Phase 2, I should be able to detect when third-party JavaScript changes between scans.

Phase 3: Security Analysis

Implement:

* Babel AST parsing.
* Configurable detection rules.
* Suspicious behaviour indicators.
* Outbound domain monitoring.
* Explainable risk scoring.
* Finding deduplication.
* False-positive suppression.

Phase 4: Reporting and Alerts

Implement:

* JSON reports.
* SARIF reports.
* HTML reports.
* Slack notifications.
* Generic webhooks.
* GitHub Issues.
* Email integration.

Phase 5: Deployment

Implement:

* Docker.
* Docker Compose.
* GitHub Actions.
* Cron examples.
* Environment variable handling.
* Deployment documentation.

Phase 6: CSP Analysis and Hardening

Implement:

* CSP parser.
* CSP linting.
* Security recommendations.
* Browser isolation hardening.
* SSRF protections.
* Privacy and retention controls.
* Full security documentation.

Do not move to the next phase until the previous phase has working tests and documentation.

⸻

23. User Experience

The ideal developer experience should be:

Step 1:

npx scriptdrift init

Step 2:

Configure websites in scriptdrift.yml.

Step 3:

npx scriptdrift scan

Step 4:

npx scriptdrift baseline

Step 5:

Configure GitHub Actions or Docker/Cron.

Step 6:

Receive alerts when unexpected changes occur.

A developer should not need to understand advanced security concepts to use the basic features.

Make reports understandable to ordinary developers.

⸻

24. Documentation Requirements

Create professional open-source documentation.

Include:

* Project overview.
* Problem being solved.
* Architecture.
* Installation.
* Quick start.
* Configuration reference.
* CLI reference.
* Baseline management.
* Detection rules.
* Alert configuration.
* GitHub Actions integration.
* Docker deployment.
* Cron deployment.
* CSP analysis.
* Security model.
* Privacy and data retention.
* Known limitations.
* Troubleshooting.
* Contributing guide.

Include practical examples.

Clearly explain that ScriptDrift is a monitoring and detection tool, not an automatic malware removal system or a guarantee of PCI DSS compliance.

⸻

25. Engineering Standards

Follow these principles:

* Production-quality TypeScript.
* Strict typing.
* Modular architecture.
* Small reusable functions.
* Clear naming conventions.
* Consistent error handling.
* Structured logging.
* No hardcoded secrets.
* No unnecessary dependencies.
* No fake integrations.
* No silent failures.
* No automatic baseline approvals.
* No unbounded browser execution.
* No unnecessary storage of third-party code.
* Meaningful tests for important behaviour.

Avoid overengineering the initial release.

Prioritise a dependable scanner and accurate change detection over a large number of superficial features.

⸻

26. How You Should Work

Before implementing:

1. Inspect the current repository.
2. Identify existing files and dependencies.
3. Prepare a clear architecture and implementation plan.
4. Identify security-sensitive components.
5. Identify the first deliverable.

Then start Phase 1.

For every phase:

1. Explain what you are implementing.
2. Implement the feature.
3. Run type checking.
4. Run linting.
5. Run automated tests.
6. Fix failures.
7. Update documentation.
8. Summarise completed work.
9. Identify remaining limitations.

Do not merely give me code snippets. Implement the actual project files.

Do not ask me to manually create files that you can create yourself.

If an external credential or integration is required, create the integration structure and document the exact environment variable needed.

Do not pretend an external integration has been tested without actually testing it.

Final objective: Build ScriptDrift into a trustworthy, developer-friendly, open-source security monitoring tool that organisations can use to continuously detect unexpected or suspicious third-party JavaScript changes on their websites.