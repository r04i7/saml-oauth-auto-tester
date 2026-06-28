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

## How verdicts are decided

The classifier mirrors a human judgement on the replayed response:

- **Secure (rejected):** HTTP 400/401/403/5xx, or body contains rejection markers
  (`invalid signature`, `access denied`, `invalid_grant`, `redirect_uri_mismatch`, …).
- **Vulnerable (accepted):** success markers (`logout`, `dashboard`, `access_token`),
  a session `Set-Cookie`, or a redirect to a non-login app resource — and, for redirect tests,
  the **attacker host reflected** in the `Location`/body.
- **Inconclusive:** couldn’t be classified — open the row and check in Repeater.

These are heuristics (the same signals you read manually). Always confirm a Vulnerable finding by
sending it to Repeater. Some checks have inherent caveats — e.g. SAML assertions are often
single-use, so re-played baselines can fail for benign reasons; scope-escalation acceptance must
be confirmed by inspecting the issued token’s scopes.

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
