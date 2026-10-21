---
layout: post
title: "The Bug Wasn't in the Password Field, It Was in the Request Line"
date: 2026-10-21
categories: [web-security, walkthrough]
tags: [portswigger, mystery-lab, ssrf, request-smuggling, burp-suite, intruder, http]
excerpt: "I rolled a lab, saw a login form, and spent twenty minutes brute-forcing credentials that were never the point — the actual bug lived in how the request-line and the Host header can disagree about who you're talking to."
lang: en
page_id: ssrf-flawed-request-parsing-admin-delete
permalink: /posts/ssrf-flawed-request-parsing-admin-delete/
---

I saw a username and password field, so I attacked a username and password field. `wiener` / `peter`, invalid credentials, no lockout after a dozen tries — textbook broken brute-force protection, I thought, and I kept going. Twenty minutes in, nothing was moving, and nothing about the login form had changed. The form wasn't the bug. It wasn't even close to the bug. The actual vulnerability didn't care about anything I typed into it — it cared about a line of the HTTP request I hadn't touched at all.

This one came out of [Mystery Pool]({% post_url 2026-10-04-mystery-pool %}), pool expanded this time with authentication added to the usual set. PortSwigger rolled **SSRF via flawed request parsing**.

## Setup

A login form on the landing page, nothing else visibly interactive. No comment box, no profile field, no obvious injection point. Just credentials and a generic error.

## The session

### 1. Wrong category, wrong attack, twenty minutes gone

"Invalid username or password," no change in response time, no account lockout after repeated attempts, no different message for a valid username versus a nonexistent one. I read all of that as "broken brute-force protection" — the pool had authentication in it, so that's the box my head went into, and I stayed there testing usernames and watching for any signal that would tell me I had a real one. There wasn't one. The form was a dead end dressed up as a reasonable first guess, and I didn't check the actual lab description until I'd already burned the time.

### 2. The description says "request parsing," not "credentials"

The lab name is the whole hint, and I'd ignored it in favor of the first interactive element I saw. "Flawed request parsing" has nothing to do with what you type into a field — it's about how two different components of the stack read the *same request* and disagree on what it says.

### 3. The Host header is being checked for something — the 403 proves it

I switched to testing the request itself. A plain request to an internal-looking host got a flat `403 Forbidden`. That's not a parsing error, that's a decision — something is actively checking a value and actively refusing it. The question that matters here isn't "how do I get past the 403," it's "what field is this check actually reading, and is there another field carrying the same information that it *isn't* reading."

### 4. Absolute-form request line: making the two fields disagree

HTTP allows the request-line to carry a full absolute URL instead of just a path — the **absolute-form**, defined for proxies, which most servers still have to accept even though almost nothing sends it by hand. I rewrote the request directly in Burp's raw editor:

```
GET https://0aa600f903cec5b48082cc7600b0006b.web-security-academy.net HTTP/2
Host: <attacker-controlled Collaborator address>
```

The response flipped from `403 Forbidden` to `502 Bad Gateway`. That's the tell: the filter checked the Host header, saw the public domain in the request-line and let it through, but whatever actually opens the outbound connection downstream used the *Host header* instead — which pointed at an address under my control. `502` means the request left the building. I confirmed it wasn't a guess by pointing the Host header at a real Burp Collaborator domain and watching the interaction land in the Collaborator tab: a request had genuinely gone out to it.

### 5. Sweeping the internal range with Intruder

A working SSRF primitive with no known target yet is just a working primitive. I put the request in Intruder, set the payload position on the last octet of the Host header, and ran `192.168.0.$0$` across the full range:

```
GET https://0aa600f903cec5b48082cc7600b0006b.web-security-academy.net HTTP/2
Host: 192.168.0.112
```

Every other address in the sweep came back as a timeout or the normal public response. `.112` came back different:

```
HTTP/2 302 Found
Location: /admin
```

A redirect to `/admin` on an internal address the public site never redirects to is the sweep finding exactly what it's for: something listening there treats the request as already privileged, because from its point of view, it's arriving from inside the trusted network.

### 6. The admin panel, and a CSRF token taken from the right place

Loading `/admin` with the same `Host: 192.168.0.112` trick returned the real panel — user list, delete action, and a CSRF token sitting in that same page's form. I pulled the token from there, not from any earlier request, and used it immediately against the same host:

```
POST https://0aa600f903cec5b48082cc7600b0006b.web-security-academy.net/admin/delete HTTP/2
Host: 192.168.0.112
Cookie: session=...

csrf=pqV2wIFnTcwqODKVlyBUvKv6VjGWG7yK&username=carlos
```

`carlos` gone, lab solved. Nothing about the exploit touched a password, a username guess, or any application logic at all — it was two fields in a raw HTTP request, made to disagree with each other.

## The pattern

A filter and a routing engine were both reading "the request," and both assumed they were reading the same value, because in the overwhelmingly common case — a direct client request, origin-form request-line, no proxy in the picture — the request-line's implicit host and the `Host` header *are* the same information twice. Nobody writing the security filter thought to ask "what if they're not," because the absolute-form request-line is a feature almost nobody uses on purpose. The front-end checked the field everyone checks. The back-end's routing code, written for a different purpose (actually being a proxy), read the other one.

The generalizable version: whenever a security control reads field A and the real processing downstream reads field B, and A and B are *usually* redundant copies of the same information, that redundancy is exactly where to look for a way to make them disagree. The 403 told me a check existed. It took noticing that HTTP has more than one place to put "the host" to find the field that check wasn't looking at.

## Exam and field

| | Exam | Field |
|---|---|---|
| What to recognise | a hard `403` on a clearly host-based check, especially when the lab name itself says "parsing" rather than naming an attack class | a reverse proxy or gateway in front of an app server, where security filtering and request routing are implemented in different components (or different code paths of the same one) |
| Where the time goes | not chasing the first interactive element (a login form, a search box) when the lab's actual name points elsewhere; rewriting the request-line by hand in Burp's raw editor, since there's no UI control for it | finding that the target architecture even has this split in the first place — most modern setups don't expose it, but CDNs, legacy proxies, and homegrown gateways sometimes do |
| Common trap | assuming the only attack surface is a parameter value, and never touching the request-line or less common headers | treating a 403 as "this is closed" instead of "something is checking a value, and there might be another value carrying the same information" |
| Real limit | one internal admin endpoint, a known `/24` to sweep | depends entirely on what's reachable from the vulnerable component — internal APIs, cloud metadata endpoints, other internal services, all through the one field the filter wasn't reading |

Defence: have the component that enforces the security policy and the component that performs the actual outbound connection agree on exactly one source of truth for the destination host — ideally the same one, read the same way, in the same place — rather than letting a filter validate one field while routing logic trusts another.

## What comes next

The sweep across `192.168.0.0/24` worked because the lab handed me a small, known range to brute-force in minutes. The open question is the same one from last time: how far does this kind of primitive actually get you on a real internal network, where the ranges aren't a tidy `/24` and a redirect to `/admin` isn't going to announce itself the same way. That's reconnaissance, not exploitation, and it's the part I haven't practiced yet.

## Takeaways

- A lab's name is the first and most literal hint — "flawed request parsing" is a statement about *where* the bug lives, not a flavor description to skim past on the way to the first form you see.
- A hard `403` on a specific value means a check exists and is actively evaluating that value — the next question is whether another field in the same protocol carries the same information without being checked.
- HTTP's absolute-form request-line is a legitimate, spec-defined feature almost nobody writes by hand, which is exactly why it's a good place to look for parsing mismatches between front-end and back-end components.
- `403` → `502` on the same attack shape is a state transition worth reading literally: it means the request started reaching further than it did before, not that the attack failed differently.
- Grab CSRF tokens from the exact page you're about to submit against, not from an earlier request in the session — it's a small discipline that saves a confusing retry later.

## Useful references

- [PortSwigger Web Security Academy: Server-side request forgery (SSRF)](https://portswigger.net/web-security/ssrf)
- [RFC 9112 §3.2 — HTTP/1.1 request-target forms](https://www.rfc-editor.org/rfc/rfc9112#section-3.2)
- [PortSwigger Web Security Academy: HTTP request smuggling](https://portswigger.net/web-security/request-smuggling)
- [Mystery Pool: a random lab from only the topics you choose]({% post_url 2026-10-04-mystery-pool %})

*All techniques shown were performed on an isolated lab environment (PortSwigger's Web Security Academy). Running these attacks against systems you don't own or have written authorization to test is illegal in most jurisdictions.*
