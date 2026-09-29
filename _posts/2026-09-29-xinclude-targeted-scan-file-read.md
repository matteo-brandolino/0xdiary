---
layout: post
title: "XInclude and the parameter that wouldn't talk back"
date: 2026-09-29
categories: [web-security, walkthrough]
tags: [bscp, burp-suite, burp-scanner, xxe, xinclude, xml-injection, ssrf, portswigger]
excerpt: "Burp Scanner found an arbitrary file read on my first BSCP lab in seconds — then I spent twenty minutes reading /etc/passwd from the one parameter that would actually show it to me, and learning that 'external service interaction' and 'out-of-band resource load' are two different findings for a reason."
lang: en
page_id: xinclude-targeted-scan-file-read
permalink: /posts/xinclude-targeted-scan-file-read/
---

The response was three bytes long: `869`. A stock quantity. Not `root:x:0:0`, not an XML parse error, not even a complaint — just the number of items in some warehouse, sitting exactly where the contents of `/etc/passwd` were supposed to be. Thirty seconds earlier Burp Scanner had told me, with **Certain** confidence, that this precise request could read arbitrary files off the server. And here it was, calmly checking stock.

The gap between *the scanner found it* and *I can read the file* is the whole post.

## Setup: aiming the scanner, not owning it

This is my first real lab since buying Burp Suite Professional, and the first stop on the BSCP road. Every DVWA session so far I did on Community — no scanner at all — so half of this is me meeting Burp's audit engine for the first time.

The lab is **[Discovering vulnerabilities quickly with targeted scanning](https://portswigger.net/web-security/essential-skills/using-burp-scanner-during-manual-testing/lab-discovering-vulnerabilities-quickly-with-targeted-scanning)** (Practitioner). Read `/etc/passwd` within 10 minutes. The lab's own framing *is* the lesson: you can scan the whole site, but you won't have time. Use intuition to pick an endpoint that looks vulnerable, run a targeted scan on that single request, then exploit it by hand. The skill isn't having the scanner. It's aiming it.

## 1. Triage before scanning: which request even earns the scan

Walking the app with the proxy on, two requests took input from me:

| Endpoint | Method | Parameters |
|---|---|---|
| `/product` | GET | `productId=1` |
| `/product/stock` | POST | `productId=1` + `storeId=2` |

The goal is reading a file, so I want input whose value could end up *referencing a resource*. A product-lookup id smells like a database key. A stock check smells like "go fetch the availability for this store" — the shape of something that reads. I pointed the targeted scan at `/product/stock`: right-click the request → **Scan** → **Audit selected items** (not *Crawl and audit*). That "selected items" is the entire targeted part — one request, no crawl.

## 2. The scanner names the class, not the exploit

Seconds later, on `/product/stock`: **XML injection** (Medium, Certain) and **External service interaction (HTTP)** (High, Certain). The payload Burp had sent:

```xml
<cyn xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="http://<collaborator>.oastify.com/foo"/></cyn>
```

Two findings, one root cause: my input lands inside a **server-side XML document**, and the parser resolves an `XInclude` I injected. Burp proved it by making the server call out to Collaborator.

That is the vector. It is not the exploit. The lab wants a file on disk, not a callback — as the lab puts it, *"once Burp Scanner has identified an attack vector, you can use your own expertise to find a way to exploit it."*

## 3. Why XInclude, and not the XXE from the textbook

Textbook XXE: you control the whole document, you put a `<!DOCTYPE>` with an `<!ENTITY>` at the top, done. Here I control none of that. I own one parameter value that the server drops into the *middle* of an XML document it builds itself. There's no room for a `DOCTYPE` — I'm not at the start of anything.

That is precisely the situation `XInclude` exists for. An `<xi:include>` element can sit inside any data value; it doesn't need you to own the document, only to land a single element somewhere inside it. Recognizing *why* the technique is XInclude and not classic XXE is more of this lab than the payload is.

The lab hint says to look up the Academy topic on the identified class. The file-read form:

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
```

Two changes from the scanner's proof-of-concept: `file://` instead of `http://`, and `parse="text"`. That second one matters — `/etc/passwd` is not valid XML, and without `parse="text"` the parser tries to parse it *as* XML and dies with `Content is not allowed in prolog`.

## 4. The parameter that returned 869

I dropped the payload into `storeId`, URL-encoded the whole block (`Ctrl+U` on the selection — it's `application/x-www-form-urlencoded`, so `<`, `>`, `/`, `"` have to go), and sent it. Back came `869`. A normal stock number. No file, no error, nothing.

It wasn't the encoding — I decoded my own parameter back and it was clean. So I moved the *exact same payload* into `productId`, left `storeId=1`, and sent again:

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

Solved. And immediately something didn't add up. The scanner's own evidence request — the one it used to *prove* the bug — had the payload in `storeId`. I read the file out of `productId`. Both true at once. How?

## 5. "External service interaction" and "Out-of-band resource load" are two different findings

So I scanned again, this time aiming the insertion point at `productId` alone. Three findings came back, and the third one had never appeared on the `storeId` scan:

- **XML injection**
- **External service interaction (HTTP)**
- **Out-of-band resource load (HTTP)** ← new

Burp's own words on that third one:

> It is possible to induce the application to retrieve the contents of an arbitrary external URL **and return those contents in its own response**. […] The response from that request was then **included in the application's own response**.

There it is — two issue names I'd been reading as one thing:

| Finding | What Burp is actually claiming | Channel |
|---|---|---|
| **External service interaction** | the server *made* the request | blind |
| **Out-of-band resource load** | the server made the request *and handed me back what it fetched* | reflected |

`storeId` reaches the parser — the Collaborator hit proves the include fires. But its result is never returned to me, so a file read there is **blind**: I'd have seen a callback and never the file. `productId`'s value comes *back in the response body*, which is exactly why `/etc/passwd` showed up where `869` had been.

Burp had told me the difference. It had two different names for it, sitting one row apart in the Issues list. I read them both as "it did something with a URL" and moved on. This is the whole thing this blog is about: the tool told me exactly what was wrong, and I didn't read it right.

## The pattern underneath

The scanner is a vector-finder, not an exploiter — the lab says so in plain English. But the sharper version is this: the scanner also tells you *which kind* of vector, and the kinds are not interchangeable. A blind out-of-band interaction and an in-band reflected load are the difference between "there is a bug here" and "I can read your files from here." Same vulnerability, same endpoint, two parameters — and only one of them talks back.

My mistake was never really the wrong parameter. It was flattening two issue names into one fact. HTTP found the callback; the response body found the file. Separate channels. I'd collapsed them into a single "SSRF-ish thing" in my head and lost the one distinction that decided whether the exploit was in-band or blind.

## What comes next

`storeId` is still vulnerable — it's just a *blind* file read. Which opens the question this session didn't close: could I exfiltrate a file through `storeId` anyway, out-of-band, by having the server fetch a URL I control and reading the contents off my own listener? That's blind XXE over OOB, and it's the obvious next lab. The plan said interleave categories from day one; this is the thread that pulls me into the next one.

## Takeaways

- **Targeted scan, not full scan.** Triage by "what could reference a resource," aim at one request: right-click → Scan → *Audit selected items*. The intuition is the skill; the scanner is just the trigger.
- **The scanner finds the class; you find the exploit.** The lab means it literally — the PoC proves the vector, the file read is yours to build.
- **XInclude, not classic XXE, whenever you control only one value inside a document you don't own.** No `DOCTYPE` needed. Add `parse="text"` or the parser chokes on any non-XML file.
- **"External service interaction" is not "Out-of-band resource load."** One is blind, one is reflected. Read them as two separate facts — they decide whether you can read the file in-band or only prove the bug.
- **A stock check that "goes and fetches" is exactly the endpoint shape to suspect** when the goal is reading server-side resources.

## Useful references

- [PortSwigger — Lab: Discovering vulnerabilities quickly with targeted scanning](https://portswigger.net/web-security/essential-skills/using-burp-scanner-during-manual-testing/lab-discovering-vulnerabilities-quickly-with-targeted-scanning)
- [PortSwigger — XXE injection / XInclude attacks](https://portswigger.net/web-security/xxe)
- [PortSwigger — Using Burp Scanner during manual testing](https://portswigger.net/burp/documentation/desktop/testing-workflow/testing-using-burp-scanner)
- [siunam — Discovering vulnerabilities quickly with targeted scanning (write-up)](https://siunam321.github.io/ctf/portswigger-labs/Essential-Skills/essential-skills-1/)

---

*All techniques shown were performed on an isolated lab environment (PortSwigger's Web Security Academy). Running these attacks against systems you don't own or have written authorization to test is illegal in most jurisdictions.*
