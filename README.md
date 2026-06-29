# SAML & OAuth 2.0 Auto Tester — Burp Suite Extension

A Burp Suite extension (Montoya API) that **automates the manual SAML and OAuth 2.0 / OIDC
test cases a pentester runs by hand**. Select requests in Proxy history, right-click
**“Send to SAML/OAuth Tester”**, and the extension auto-detects the protocol, runs the full
attack battery against each request, and lists every finding as **Vulnerable** or **Secure** —
with one click to push any attack request to **Repeater** for manual confirmation.

> ⚠️ **Authorized testing only.** Use this against systems you own or are explicitly
> permitted to test. The tool sends live, tampered authentication requests.

---

## How it works (the analyst workflow, automated)

1. **Select** one or many requests in **Proxy → HTTP history** (Ctrl/Shift-click for many).
2. **Right-click → “Send to SAML/OAuth Tester (N requests)”**.
3. For each request the extension:
   - **detects** whether it is SAML (`SAMLResponse`/`SAMLRequest`) or OAuth/OIDC
     (`response_type`, `client_id`, `redirect_uri`, `grant_type`, `code`, …);
   - **decodes** the message (SAML: Base64 for POST binding, raw-DEFLATE+Base64 for Redirect binding);
   - **applies each attack** (e.g. strips the signature), **re-encodes**, and **replays** it;
   - **judges the response** the way you would by eye — did the server grant a token/session
     (**Vulnerable**) or reject it with an error (**Secure**)?
4. Results stream into the **“SAML/OAuth Tester”** suite tab. Select any row to view the exact
   attack request/response, tick **“Show only Vulnerable”** to focus, and **“Send selected to
   Repeater”** to confirm manually.

Each finding carries the literal request that produced it, so verdicts are always verifiable —
the heuristics get you to the candidates fast, your eyes confirm the kill.

---

## Test cases

### SAML (run against a `SAMLResponse`) — 25 test cases
**Signature attacks**
- **Signature stripping** — remove all `<Signature>` blocks (SP requires no signature)
- **Empty SignatureValue** — blank the signature bytes (content not verified)
- **Certificate faking** — replace the embedded `X509Certificate` (SP trusts the in-message cert → attacker re-signs)
- **Signature algorithm downgrade** — force weak `rsa-sha1`

**XML Signature Wrapping (XSW1–XSW8)** — the 8 classic variants (Somorovsky et al. / SAML Raider). Each places a forged, admin-identity assertion in a different position relative to the original signed element:
- **XSW1/XSW2** target the **Response** signature (wrap / detached)
- **XSW3/XSW4** insert the evil assertion before / wrapping the signed assertion
- **XSW5/XSW6** borrow / hide the signature inside the evil assertion
- **XSW7** hides the evil assertion in `<Extensions>`; **XSW8** hides the original in a Signature `<Object>`

**Assertion & condition tampering** (all without re-signing)
- **NameID forge** — escalate identity to an admin account
- **Attribute/role escalation** — set a role attribute to `Administrator`
- **Issuer spoofing** — point `Issuer` at an untrusted IdP
- **Audience restriction bypass** — change `Audience`
- **Token recipient confusion** — change `Recipient`/`Destination`
- **Expiry tampering** — push `NotOnOrAfter` to 2099
- **InResponseTo removal** — SAML login CSRF / unsolicited response
- **XML comment injection in NameID** — canonicalization truncation

**Parser / processing attacks**
- **XXE injection** — `DOCTYPE`/entity in the assertion
- **XSLT injection** — malicious `<Transform>` stylesheet
- **Assertion replay** — submit the same assertion twice (single-use enforcement)

### OAuth 2.0 / OIDC — 20+ test cases
**Static checks** (missing protections, no request sent):
- **Missing `state`** (login CSRF / code injection)
- **Missing / weak PKCE `code_challenge`** (and `plain` method)
- **Missing `nonce`** on OIDC (`scope=openid`)
- **Implicit flow in use** (`response_type=token`/`id_token`)
- **Insecure `redirect_uri`** (`http://`)
- **Missing client authentication** on the token endpoint (no `client_secret`/`Authorization`)

**Active checks** (mutate + replay + judge):
- **`redirect_uri` hijack** — swap host to an attacker domain
- **`redirect_uri` suffix/subdomain bypass** — defeat naive prefix matching
- **`redirect_uri` path / `@`-userinfo bypass**
- **`redirect_uri` loopback/userinfo bypass**
- **`redirect_uri` parameter pollution** — duplicate param, server reads the wrong copy
- **Implicit downgrade** (`response_type=token`)
- **Hybrid flow downgrade** (`response_type=code id_token token`)
- **`client_id` confusion** — swap to an unknown client
- **Silent auth abuse** (`prompt=none`)
- **Scope escalation** — request `admin`/`offline_access`
- **Authorization-code replay** — send a `code` twice; single-use must fail the 2nd

**OIDC `id_token` / JWT attacks** (on `id_token`, `id_token_hint`, `assertion`)
- **`alg=none`** — strip algorithm + signature
- **Signature stripping** — keep header/payload, blank signature
- **Claim escalation** — forge `sub`/`email`/`role` without re-signing

---

## Build

No Maven/Gradle required — just a JDK.

```bat
build.bat
```

This compiles against `lib\montoya-api-2026.4.jar` and writes **`dist\saml-oauth-tester.jar`**.
(If your JDK isn’t at `C:\Program Files\Java\jdk-21`, edit the `JDK` line at the top of `build.bat`.)

Optional Gradle build is also provided (`gradle jar`).

## Load into Burp

**Extensions → Installed → Add** → Extension type **Java** → select `dist\saml-oauth-tester.jar`.
A new **“SAML/OAuth Tester”** tab appears, and the context-menu item is added to Proxy/Repeater/etc.

---

## How verdicts are decided (response-diff + negative control)

The verdict is reached the way an analyst reasons by hand: **tamper the request, then compare the
response to the legitimate baseline.** For an integrity test (strip signature, forge NameID,
`alg=none`, …) a properly-secured server *must* reject the manipulated message, so:

- **tampered request rejected** (4xx, error markers) → **Secure** — even if the error page echoes
  our payload back;
- **the redirect / response changes to a login/error page** → **Secure** (the server treated the
  forgery differently);
- **the response is *unchanged* vs the valid baseline** (same status, same `Location`, ~same body)
  → the server **accepted the forgery**. This is reported **Vulnerable** *only if* a **negative
  control** — a deliberately-invalid message sent first — **was rejected**, proving the endpoint
  actually validates. If even the bad control was accepted, the endpoint is ignoring the token, so
  the result is **Inconclusive** instead (no false "Vulnerable");
- **changed but not a clear rejection** → **Inconclusive**.

For OAuth redirect tests, the proof of an open redirect is the **`Location` header** actually
pointing at the attacker host — reflection in an error body never counts. Each finding shows the
**Original** and **Attack** request/response side by side and is gated by the same negative control.

The older absolute classifier is still used as a fallback when no baseline is available:

- **Rejection dominates.** Any **HTTP 4xx/5xx**, or a rejection marker in the body
  (`invalid signature`, `access denied`, `invalid_grant`, `redirect_uri_mismatch`, …) is reported
  **Secure** — *even if the error page echoes our injected value back*. (This removes the classic
  false positive where a `400 Bad Request` whose body repeats the bad `redirect_uri` was flagged
  Vulnerable.)
- **Open-redirect proof is the `Location` header, not the body.** A redirect test is only
  **Vulnerable** when the response's `Location` header actually points at the attacker host
  (authority or `@`-userinfo) — reflection inside an error body does **not** count.
- **Baseline-aware.** Each target's original, untampered response is captured first. If a tampered
  request produces an outcome **indistinguishable from that baseline** (same status, same redirect,
  no new session cookie), the verdict is **Inconclusive**, not Vulnerable — because tampering
  changed nothing observable. The **Original** and **Attack** request/response are shown side by
  side so you can make the final call.
- **Vulnerable (accepted):** a distinct success marker (`logout`, `dashboard`, `access_token`),
  a freshly granted session `Set-Cookie`, or a redirect to a non-login app resource that the
  baseline did **not** already produce.

Always confirm a Vulnerable finding in Repeater. Some checks have inherent caveats — e.g. SAML
assertions are often single-use, so replayed baselines can fail for benign reasons;
scope-escalation acceptance must be confirmed by inspecting the issued token’s scopes.

## New in this version

- **Proxy auto-highlight.** SAML and OAuth/OIDC requests are painted **blue** in Proxy history as
  they pass through (passive — never modifies traffic), with a note saying which protocol, so the
  requests worth testing jump out.
- **Original vs Attack panes.** Every finding shows the **Original** request/response and the
  **Attack** request/response side by side.
- **Separate SAML / OAuth.** Filter findings by **Category** (All / SAML / OAuth2.0), and force a
  battery with **“Send to SAML Tester”** / **“Send to OAuth Tester”** in addition to auto-detect.
- **SAML Decoder workbench** (SAML-Raider style). A **“SAML Decoder”** sub-tab and a
  **“Send SAML to Decoder”** context item: decode a `SAMLRequest`/`SAMLResponse` (POST or Redirect
  binding) to readable, pretty-printed XML, edit it by hand, then re-encode it for the original
  binding to paste into Repeater.
- **Inline decoder tab everywhere SAML appears.** A **“SAML (decoded)”** tab is added to Burp's
  request editor (Proxy / Repeater / Intruder) for any request carrying a SAML message — view and
  **edit the decoded XML in place**; edits are re-encoded on send. A test-case dropdown applies any
  mutation and **“Send mutated → Repeater”** / **“Send ALL cases → Repeater”** queue the whole
  battery for manual testing.
- **Inline OAuth tab.** An **“OAuth (test cases)”** tab decodes any JWT (`id_token`,
  `id_token_hint`, `assertion`, `access_token`) to readable JSON and offers the OAuth tampering
  battery → Repeater the same way.
- **Negative control.** Before judging, the tool sends a deliberately-invalid message; if the
  endpoint accepts even that, "accepted" results are downgraded to Inconclusive to avoid false
  positives.
- **"Changes (highlighted)" view.** Selecting a finding shows the **original values on the left and
  the attack values on the right, with every changed line highlighted** — decoded SAML XML for SAML
  findings, request parameters otherwise — so you can eyeball exactly what was mutated and compare
  it by hand before confirming.
- **Burp Collaborator OOB confirmation.** When Collaborator is available, blind issues are
  **confirmed out-of-band**: SAML **XXE** and **XSLT** point an external fetch at a Collaborator URL,
  and OAuth **redirect_uri / request_uri SSRF** do the same. A real interaction turns the verdict
  into a definitive **Vulnerable [OOB confirmed]**; if Collaborator is unavailable the tool falls
  back to in-band heuristics.
- **Separate SAML / OAuth context menu.** The combined "Send to SAML/OAuth Tester" item was removed —
  right-click offers **"Send to SAML Tester"** and **"Send to OAuth 2.0 Tester"** directly.

---

## Project layout

```
src/main/java/com/pentest/samloauth/
  SamlOAuthExtension.java        entry point + context menu
  core/   Detector, TestEngine, ResponseEvaluator, Params, TestResult
  saml/   SamlCodec, SamlTarget, SamlMutations, SamlTester
  oauth/  OAuthTester
  ui/     MainTab, FindingsTableModel
  model/  Finding, TargetType, TestStatus, Severity
src/main/resources/META-INF/services/burp.api.montoya.BurpExtension
test/SelfTest.java               standalone core tests (no Burp needed)
lib/montoya-api-2026.4.jar       compile-time API (provided by Burp at runtime)
build.bat / build.gradle         builds dist/saml-oauth-tester.jar
```
