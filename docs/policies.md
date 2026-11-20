# Script policies

Some vendors ship a new file name or new content on every release (`https://cdn.vendor.com/sdk/v3/main.ab12cd.js`), or A/B-test bundles. Without help, every release is a `resource-added` plus a `resource-removed` (or a `resource-modified`), and teams stop reading the alerts.

`scriptPolicies` are explicit, reviewable statements that reduce that noise **without hiding suspicious behaviour**. They are never created automatically: you write them in `thirdsentry.yml`, with a reason, and they can expire.

```yaml
scriptPolicies:                       # global: apply to every site
  - name: vendor-sdk
    match:
      urlPrefix: https://cdn.vendor.com/sdk/v3/
      pages: [/checkout]              # optional: only scripts seen on these pages (globs allowed)
    mode: path-versions
    reason: Vendor ships a hash-named bundle on every release
    owner: web-platform               # optional
    expires: 2027-06-30               # optional: stops applying (and is reported) after this day (UTC)

  - name: payments-sdk
    match: { url: https://js.payments.example/v3/ }
    mode: pin
    reason: Payment SDK must never change silently
    hashes:
      - 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08   # SHA-256 hex
      - sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC  # SRI

sites:
  - name: production-store
    url: https://www.example.com
    scriptPolicies:                   # per site: same fields, win over a global policy of equal specificity
      - name: tag-manager
        match: { domain: tagmanager.example }
        mode: domain-only
        reason: Tag manager that rotates constantly; we only track where it loads from
```

## Fields

| Field | Required | Meaning |
| --- | --- | --- |
| `name` | yes | Unique per site (global and site policies share one namespace). Becomes the identity `policy:<name>`. |
| `match` | yes | One or more matchers (below). Matchers are alternatives (OR); `pages` is an extra restriction (AND). |
| `mode` | yes | `pin`, `path-versions` or `domain-only`. |
| `reason` | yes | Why the policy exists. Shown in findings and reports. |
| `expires` | no | ISO date. A date without a time is valid through the end of that day (UTC). |
| `owner` | no | Who to ask before changing it. |
| `hashes` | `pin` only | Allowed content hashes: SHA-256 hex or SRI `sha256-...` / `sha384-...`. |

### Matchers

Every matcher is bound to a host or domain, and each accepts a string or a list.

| Matcher | Matches |
| --- | --- |
| `url` | the exact canonical URL (query parameters listed in the site's `ignoreQueryParams` are ignored, on both sides) |
| `urlPrefix` | same origin, and the path (plus query) starts with the prefix's path. `https://cdn.vendor.com/sdk/v3/main.` matches `main.ab12cd.js` |
| `glob` | `https://<host or *.domain>/<path glob>`, e.g. `https://cdn.vendor.com/sdk/*/main.*.js`. Wildcards are only allowed in the path and as a leading `*.` on a registrable domain |
| `identity` | an exact resource identity (`url:https://...`) as printed in findings |
| `host` | a hostname (`cdn.vendor.com`) or `*.vendor.com` |
| `domain` | a registrable domain (`vendor.com`), covering every host below it |
| `pages` | restriction to page keys (`/checkout`, `/shop/*`). A script seen on any page outside the list is not covered |

Matching is against the canonical identity URL (the URL the page requested, first redirect hop). **Policies are for URL-identified scripts only.** Inline, `blob:` and `data:` matchers are rejected when the configuration is loaded, and inline, blob and data scripts are never covered by a policy; their position-independent content matching is unchanged.

## Modes

### `pin`: allowed hashes

Content must be one of `hashes`. Any other content (including a hash that someone approved in the baseline) is a `pinned-hash-mismatch` finding, **high severity**, even on sensitive pages. A script whose content could not be captured completely, or an SRI pin for a scan that did not record SHA-384, cannot be verified and is reported as a mismatch too (`verdict: unverifiable`).

- Content that matches a pinned hash is accepted without a `resource-modified` finding, so you can pin two or three known variants.
- Pinned findings cannot be approved into the baseline; after review, add the new hash to `hashes`.
- The absence of a pinned script is still reported normally (`resource-removed`), and a new script domain, outbound domain or SRI mismatch is unaffected.
- Pin checks run for **every** matching pin policy, even if a more specific policy of another mode wins the identity.

Use it for payment SDKs and anything else that must never change silently.

### `path-versions`: accept any version from a path

All scripts matching the policy are tracked under **one stable identity**, `policy:<name>`. A renamed or hash-named bundle is therefore not a new + removed pair, and a content change is reported as `policy-accepted-update` (informational).

**It never hides suspicious behaviour.** For each accepted update ThirdSentry still analyses the new code against the approved version (the baseline's recorded behaviour). A finding is raised at the severity the change would have had **without** the policy (the same hash-change weight plus the behaviour signals) when the new version:

- adds a behaviour that was not there (exfiltration or beacons, script injection, form/sensitive-field access, cookie access, keystroke capture, network API hooks, obfuscation, ...), or increases medium-or-higher-severity behaviour;
- can no longer be analysed although the approved version could (`analysis-regression`);
- references or contacts a new outbound destination (`new-outbound-domain`, `new-outbound-host`, `script-references-new-destination` and `correlated-new-destination` work exactly as before);
- is loaded from a new script domain (`new-script-domain`).

Routine growth of low-risk behaviour that already existed (for example more `localStorage` calls) is ignored; that is the noise the policy exists to remove.

Because the reference is the *approved* version, an accepted update with new behaviour keeps being reported until you approve it (`thirdsentry baseline --approve <finding-id>`), which makes the new behaviour the reference. Approving under a policy approves the policy identity.

Requests that match the domain but fall outside the path are not covered and are reported normally.

### `domain-only`: weakest mode

Only the fact that scripts load from the domain is tracked. URL changes, new bundles from the same policy and content changes produce **no findings** (they are counted in the report).

Not hidden, even in this mode, and at normal weight (there is no reduction): new security-relevant behaviour signals (same rules as `path-versions`), new script domains, new outbound domains and hosts, SRI mismatches, type changes, and the removal of everything that the policy covered.

Use `domain-only` only for vendors you cannot pin or version-scope, such as tag managers that inject changing code by design, and prefer a narrow `host`/`urlPrefix` over a whole `domain`. Because many different scripts share one identity, behaviour that one of them always had is not "new" for another: this mode has the least precise behaviour reference. Prefer `path-versions` whenever the vendor has a stable path.

## Precedence

When several policies match one script, the most specific wins:

1. exact `url` / `identity`
2. `urlPrefix` (the longer prefix wins)
3. `glob` (more literal characters win)
4. `host`
5. `domain`

then: a policy with `pages` beats one without, a site policy beats a global one, and finally the policy declared first wins. Only the winner decides the identity and the accept/ignore behaviour. The exception is `pin`: every matching pin policy is enforced regardless of the winner, so a broad pin cannot be silenced by a narrower, looser policy.

## Safety rules

- **Domain bound.** A policy never applies to a script on another registrable domain. Matchers are structurally bound to a host or domain (lookalikes such as `cdn.vendor.com.evil.example` or `*` hosts in globs are rejected or not matched), and a script that was **redirected** to another registrable domain is not covered.
- **Explicit.** Policies are never created automatically, and `reason` is mandatory.
- **Expiry.** Expired policies stop applying (their scripts are compared normally again, which usually shows new and removed resources until the baseline is refreshed) and are listed as expired in the report and in a log warning.
- **Baselines.** A baseline written without the policy keeps working: matching baseline resources are merged into the policy identity when comparing, and the next `thirdsentry baseline` stores the policy identity. Removing or expiring a policy later means the next baseline approval stores URL identities again.
- **Suppressions.** Suppressions work on policy findings as on any other (and can target them with `policy: <name>`). A suppression of `kind: pinned-hash-mismatch` is allowed but defeats the pin; use it only with an `expires`.
- **`ignoreQueryParams`.** The identity URL already has ignored parameters removed, and `url` matchers are canonicalised the same way.

## Reports and `thirdsentry diff`

Every finding affected by a policy has a `policy` field and a line in its evidence, and its reason names the policy. The report (`report.json`, HTML) has a `policies` section listing **active** (matched scripts in this scan), **unused** (matched nothing: a typo or a leftover) and **expired** policies with the number of matched scripts, accepted updates and findings, plus which policy governs which script. `thirdsentry diff` prints the same: the section "Policy matches" shows the policy that matched each resource.

## Finding kinds and signals

| Kind | Severity | Meaning |
| --- | --- | --- |
| `policy-accepted-update` | info (raised by behaviour signals as described above) | A script governed by `path-versions` or `domain-only` changed |
| `pinned-hash-mismatch` | high | A pinned script does not match any allowed hash |

Signals: `pinned-hash-mismatch` (+55), `policy-accepted-update` (+0). A `policy-accepted-update` with new behaviour carries the usual `hash-changed-*` and `new-rule:*` signals.
