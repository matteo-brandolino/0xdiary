---
layout: post
title: "The Scanner Flagged a Lead I Didn't Need, and a Lockout I Deliberately Caused"
date: 2026-10-21
categories: [web-security, walkthrough]
tags: [portswigger, mystery-lab, web-cache-poisoning, cookies, javascript, burp-suite, intruder, authentication, account-lockout, username-enumeration]
excerpt: "Two labs from the same roll: one where Burp's scanner handed me a scary-looking SQLi lead that wasn't the bug, and one where the only way to find a valid username was to lock the account on purpose and read the error that followed."
lang: en
page_id: cache-poisoning-account-lockout-enumeration
permalink: /posts/cache-poisoning-account-lockout-enumeration/
---

Usually you're trying to avoid getting an account locked. In the second lab here, locking it on purpose was the entire attack. And in the first one, Burp's own scanner handed me a finding that looked exactly like a SQL injection lead, pointed at an out-of-band domain and everything — and the right move was to not chase it, because the real bug was sitting in plain text two scrolls down in the same response.

Both labs came out of [Mystery Pool]({% post_url 2026-10-04-mystery-pool %}), pool now at five topics: web cache deception, cross-site scripting, DOM-based vulnerabilities, host header attacks, and — added this round — authentication.

## Setup

Lab one: no comment form, no search bar, nothing obviously injectable. Just a plain `GET /` with a `Cache-Control` header on the response, which is its own kind of hint. Lab two: a login form and nothing else, no visible rate limiting, no account lockout message on the first dozen tries.

## Lab one: web cache poisoning via an unkeyed cookie

### 1. A scanner finding that says less than it looks like

Running Burp's scanner against `GET /` turned up "Input returned in response (stored)," Information severity, Certain confidence: a cookie value was being copied into the page. On its own that's not a vulnerability — it's a precondition for one. Combined with a `Cache-Control` header on the same response, it's a specific shape: a value that influences the page, on a response that gets cached. That combination is the actual lead, not the finding's severity label.

### 2. A scary-looking payload that wasn't the bug

The scanner had also fired its own generic probes at that same cookie, including a blind, out-of-band SQLi/XXE payload built around `extractvalue()` and an external entity pointing at an `oastify.com` Collaborator domain. Seeing that in Burp's history is unsettling the first time — it looks exactly like a confirmed SQL injection lead, Collaborator address and all. But the pool for this roll didn't include SQL injection as a category, and the scanner fires every stock payload at every parameter regardless of what the lab actually wants. Chasing it down properly would have meant checking the Collaborator client for a hit; the faster, more relevant move was to stop treating the scanner's output as the investigation and go read the raw response myself.

### 3. The raw response, read properly

`view-source`, not the rendered DOM, is where the actual shape of the bug was sitting:

```html
<script>
    data = {"host":"0ae9...web-security-academy.net","path":"/","frontend":"prod-cache-01"}
</script>
```

```
Cache-Control: max-age=30
Age: 20
X-Cache: hit
```

The `host` field is just the domain from the request — server-controlled, boring, not the lead. The cookie sent on the request was `fehost`, and its value lands, unescaped, as the **last** property in that object: `frontend`. `X-Cache: hit` on top of it confirms the mechanism: this response wasn't generated fresh for this request, it was pulled from a cache shared across visitors, and that cache's key apparently doesn't include this cookie at all. Unkeyed input, into a cached response, reflected into a script. That's the whole bug in one sentence.

### 4. The first guess at a breakout was wrong, and that was fine

My first idea was to target the `host` field, assuming a clean object literal where closing the string and the object (`"};alert(...);//`) would work anywhere. It didn't fire — `host` isn't the last property, so closing it that way leaves the rest of the object (`,"path":"/","frontend":"prod-cache-01"}`) dangling as broken syntax. Looking again at where the cookie actually landed — `frontend`, the *last* key, right before the closing `}` — changed what kind of breakout was even needed.

### 5. The payload that fit the actual position

```
fehost=x"-alert(document.cookie)-"x
```

Substituted into the object:

```js
data = {"host":"0ae9...","path":"/","frontend":"x"-alert(document.cookie)-"x"}
```

Read as JavaScript, `"x"-alert(document.cookie)-"x"` is a single valid expression: subtraction coerces both string operands toward numbers, `alert()` runs as a side effect of being evaluated, and the whole thing resolves to `NaN` — which nobody cares about, because by then the alert has already fired. No semicolon, no object-closing brace needed, because the value sits right where the object naturally ends anyway.

### 6. Poisoning the shared cache, not just my own response

Getting the payload to render in my own `view-source` was necessary but not sufficient — the lab's objective is a victim who never sends this cookie at all. Repeating the same request with the malicious `fehost` cookie, checking the response each time, eventually showed the payload sitting in the cached copy that any plain request to `/` would now receive, `max-age=30` and all. Once that held, the lab's own victim simulation picked it up on a normal visit, cookie-free, and fired.

## Lab two: username enumeration via account locking

### 1. No lockout, no rate limiting, nothing obviously wrong

A handful of manual attempts against the login form produced the same generic "Invalid username or password" every time, no slowdown, no block. Read in isolation, that's indistinguishable from a form that's actually fine — the interesting behavior wasn't going to show up from a handful of tries. It needed volume.

### 2. Forcing the one signal that exists, on purpose

The idea here inverts the usual approach: instead of trying to avoid a lockout, trigger it deliberately, on every username, and see which one produces a *different* lockout response than the rest. Burp Intruder, Cluster bomb attack:

- Payload position 1: username, PortSwigger's candidate-usernames wordlist
- Payload position 2: password, a null payload generated 5 times per username — five near-simultaneous wrong-password attempts against the same account, enough to trip a per-account attempt threshold if one exists

### 3. One response breaks the pattern

Every username came back with the same generic invalid-credentials message, except one:

```
ec2-user → You have made too many incorrect login attempts
```

That message has nothing to do with whether any particular password was right. It fires because the account exists and just hit a failed-attempt threshold — a side channel that confirms a valid username without ever guessing its password. Every other candidate username got the generic message because there was no account behind it to lock in the first place.

### 4. The account I needed was now the one I'd just locked

Confirming the username meant the account was, at that exact moment, in whatever locked state the five rapid-fire failed attempts had put it in. Logging in with the right password immediately after would have failed anyway, for a reason that had nothing to do with the password being wrong — the response would look identical to a real failure, which is exactly the kind of ambiguity that wastes the next ten minutes if you don't notice it's there.

### 5. Waiting it out, then a Sniper attack that actually meant something

The lockout cleared after a wait, rather than being permanent. Once it had, a Sniper attack with `ec2-user` fixed and a password wordlist on the single payload position came back with every candidate giving the same error response except one: `mobilemail`, standing apart from the rest. A manual login with `ec2-user` / `mobilemail` — after waiting out the account's lock state once more, since the Sniper attack itself had re-triggered it — confirmed it. Lab solved.

## The pattern

Both labs turned on reading a signal for what it actually indicated, not what it resembled. The scanner's SQLi-shaped finding resembled a real lead and wasn't one, because the category it belonged to wasn't even in play — the shape of a payload is not evidence it's relevant to the objective in front of you. The account lockout message resembled a dead end (blocked, no useful information) and was actually the only useful information available, because what it revealed — "this account exists" — was true regardless of which password triggered it.

The generalizable version: a response that looks like a failure state (a block, an error, a generic rejection) still carries information about *why* it fired. Reading only the surface ("blocked" / "rejected") throws that away. Reading the specific wording, or the specific trigger condition, is what turns a dead end into a side channel.

## Exam and field

**Lab one — web cache poisoning via an unkeyed cookie**

| | Exam | Field |
|---|---|---|
| What to recognise | a scanner-flagged "input returned in response" finding on a response that also carries `Cache-Control`, plus an `X-Cache` header confirming hits | front-end caches (CDNs, reverse proxy caches) that key on URL and a fixed header set, while the origin app reflects a header, cookie, or query value the cache doesn't know about |
| Where the time goes | not chasing every scanner probe at face value — distinguishing a relevant lead from generic noise fired at every parameter; finding the exact position of the reflected value before picking a breakout | confirming cache scope (per-user, per-edge-node, or truly shared) before assuming a poisoned response reaches anyone beyond your own session |
| Common trap | assuming a scary-looking payload (OOB SQLi, XXE) is automatically the intended bug just because it's in the scan results | treating `Vary` or documented cache-key config as exhaustive — unkeyed inputs are unkeyed precisely because nobody listed them |
| Real limit | one shared cache, 30-second TTL, a lab-provided victim simulation | needs the response to actually be cacheable and shared, and the poisoned entry to survive long enough for a real victim to hit it before expiry or a legitimate re-fetch overwrites it |

Defence: make sure every input that can influence a response is included in the cache key, or isn't cached at all — and never let a cache-control decision be made without knowing exactly which inputs the origin actually uses.

**Lab two — username enumeration via account locking**

| | Exam | Field |
|---|---|---|
| What to recognise | a login form with no visible rate limiting on casual testing, where volume (not cleverness) is what surfaces the actual signal | account lockout policies implemented inconsistently — present for one flow (login) but silent about *why* it triggered, leaking account existence |
| Where the time goes | configuring Intruder correctly (cluster bomb, null payloads repeated per username) and noticing the account you just confirmed is now locked, before trying to use it | building or sourcing a realistic username list; real systems don't ship you `candidate-usernames.txt` |
| Common trap | reading "too many attempts" as purely a blocker and moving on, instead of as a side channel that just confirmed something | assuming any lockout message is equally safe; a message that differs based on account existence defeats the point of having generic errors elsewhere |
| Real limit | a single clearable lockout window, one valid account, a wordlist that happens to contain the password | depends on lockout duration, whether it's per-account or per-IP, and whether the generic message is actually generic everywhere else in the flow |

Defence: never let a lockout response differ, in wording or in trigger condition, based on whether the account exists — if the account doesn't exist, the response to five wrong passwords should look identical to the response to five wrong passwords against an account that does.

## What comes next

The cache poisoning lab worked because the response was reflected into a script context with no encoding at all — the open question is how this generalizes to partial encoding, where a value is HTML-escaped but not JS-escaped (or vice versa), and whether the same unkeyed-input hunting process still finds it as fast. On the lockout side, the open question is what happens when the lockout is IP-based instead of account-based: the enumeration trick still works, but the cleanup (waiting out a lock, or finding a reset condition) changes shape entirely.

## Takeaways

- A scanner finding's severity or payload sophistication isn't evidence of relevance — check it against what the lab (or the actual threat model) is even testing for before spending time on it.
- Find the exact position of a reflected value before picking a breakout string. The last property in an object literal needs a different payload than one in the middle, and guessing the wrong position wastes a cycle for nothing.
- `X-Cache: hit` is the one header that tells you whether you're looking at a shared cached response or a fresh one — check it before concluding a poisoning attempt worked or failed.
- A "blocked" or "too many attempts" response still carries information about why it fired. Read the specific wording, not just the fact that something failed.
- Deliberately triggering a failure state (a lockout, a rate limit) can be the attack itself when the failure's trigger condition depends on information you don't have yet, like account existence.

## Useful references

- [PortSwigger Web Security Academy: Web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning)
- [PortSwigger Web Security Academy: Authentication](https://portswigger.net/web-security/authentication)
- [Mystery Pool: a random lab from only the topics you choose]({% post_url 2026-10-04-mystery-pool %})

*All techniques shown were performed on an isolated lab environment (PortSwigger's Web Security Academy). Running these attacks against systems you don't own or have written authorization to test is illegal in most jurisdictions.*
