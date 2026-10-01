---
layout: post
title: "Filtered for DOM, flagged as reflected XSS"
date: 2026-10-01
categories: [web-security, walkthrough]
tags: [bscp, burp-suite, dom-invader, burp-scanner, xss, dom-based, cookie-manipulation, portswigger]
excerpt: "I filtered the Mystery Lab down to DOM vulnerabilities, chased a 'last viewed product' cookie I was writing myself out of window.location — and then Burp Scanner called the whole thing plain reflected XSS, DOM Invader saw nothing at all, and I had to work out why the one tool built for DOM bugs was the blindest of the three."
lang: en
page_id: dom-cookie-manipulation-mystery-lab
permalink: /posts/dom-cookie-manipulation-mystery-lab/
---

`print()` had just fired. The little browser print dialog was sitting right there, undeniable proof that my injected `<script>` had run. So I opened the console to admire the damage, typed `document.cookie`, and found my payload lying in the cookie **fully percent-encoded** — `...&%27%3E%3Cscript%3Eprint()%3C/script%3E` — every angle bracket flattened into a `%3C`, every quote into a `%27`, about as inert-looking a string as you could ask for.

A payload that had just executed, stored in a form that couldn't possibly execute. Both true, at the same time, in the same tab.

The gap between those two facts is the post.

## Setup: a Mystery Lab, filtered on purpose

My [previous session](/posts/xinclude-targeted-scan-file-read/) was the first real lab with Burp Suite Professional. This is the second, and it's the first time I did what [the study plan](/posts/bscp-study-plan-interleaving/) kept nagging me to do: open the **Mystery Lab Challenge** and let it hand me something without a label.

Except I cheated slightly — I filtered the Mystery Lab down to **DOM-based vulnerabilities**, because I'd just spent a weekend building a study guide on them (taint-flow, sources and sinks, Burp Scanner vs. DOM Invader, the whole map). I wanted to practise *that* category. So I knew the broad family. I did not know the specific bug, the sink, or how to deliver it — which is where the actual lab lives.

The one piece of theory worth carrying in: DOM-based bugs are about a **source** (a value you influence — `location`, `document.cookie`, `postMessage`, …) flowing into a dangerous **sink** (`document.write`, `innerHTML`, an `href`, …). And crucially, that flow lives **in the browser, at runtime** — not in the HTTP traffic. Last time the whole story was in Burp's request/response panes. This time, I assumed, it'd be in the DOM.

Hold that assumption. It's wrong by the end.

## 1. The button that wasn't there a minute ago

I walked the app with the proxy on, clicking like a bored customer, not hunting for anything yet — just building the list of *where does my input go*. Nothing interesting on the product pages. Then I went back to the home page and there was a new link in the header, next to **Home**:

> Last viewed product

It hadn't been there when I first loaded the site. It appeared only after I'd viewed a product. Which means: **the app remembered something I did.** A piece of state that was empty on arrival and is now populated.

That's the whole triage move, and it has nothing to do with DOM yet. A thing that persists between page loads, client-side, can only live in a few places: a cookie, `localStorage`/`sessionStorage`, or the URL. So before asking "is this a bug," I asked "where does that memory live, and do I control it?"

DevTools → Application → Cookies. There it was:

```
lastViewedProduct = https://YOUR-LAB-ID.web-security-academy.net/product?productId=1
```

The remembered state is a **URL** — the address of the product I'd just viewed. If that URL gets stored and later read back to build the link, I've got both ends of a flow to chase.

## 2. The cookie is not the source

Here's the first thing I'd have gotten wrong a month ago: treating the cookie as the source. It isn't. I never typed a cookie. I *visited a page*. So something turned my visit into that cookie. View-source on the product page, and there it is at the bottom:

```html
<script>
    document.cookie = 'lastViewedProduct=' + window.location + '; SameSite=None; Secure'
</script>
```

The source is `window.location` — the URL I navigate to — laundered into a cookie. And the URL is mine to shape: I can append whatever I like after `productId=1`. The cookie just looks like the state; the real attacker-controlled input is the location, one step upstream.

(Park that `SameSite=None; Secure` for now. It looks like boilerplate. It's half the exploit.)

## 3. The sink, and the shape of the break-out

The write side was easy. Where does the cookie get *read back* and put into the page? I'd been looking on the home page for a second `<script>`. It wasn't a script — it was the link itself, reflected straight into an attribute:

```html
<a href='https://YOUR-LAB-ID.web-security-academy.net/product?productId=1'>Last viewed product</a>
```

That `href` value **is** the cookie. Raw. No encoding visible, no sanitisation. And I control it via the product URL. So the sink is an HTML attribute, single-quoted, and the question writes itself: *what if I put something in the URL that doesn't stay inside the quotes?*

Breaking out of an attribute is three moves, each closing one layer of the cage you're inside:

| Piece | Closes / opens | Why |
|---|---|---|
| `'` | closes the `href='…` value | until you close the quote, everything is just text in the attribute |
| `>` | closes the `<a …>` tag | until the tag is closed, you can't open a new one |
| `<script>print()</script>` | opens *your* tag | now you're in free HTML; the parser reads a real `<script>` |

Chain them: `'><script>print()</script>`. And `print()` isn't arbitrary — the lab's objective (base64'd into the page header, decoded) was literally *"deliver an attack that calls the `print()` function in the victim's browser."* `print()` is the minimal, harmless "arbitrary JS ran" proof.

So I visited:

```
/product?productId=1&'><script>print()</script>
```

reloaded, and `print()` fired. Felt great for about four seconds.

## 4. The encoding scare that cancelled itself out

Because then I checked the cookie, and my payload was sitting there percent-encoded — `%27%3E%3Cscript%3E…`. I'd been *sure* that would kill it: to an HTML parser, `%3Cscript%3E` is not a tag, it's six harmless characters. A payload stored like that shouldn't execute. But it had.

This took longer to understand than the break-out did, and the resolution is the nicest technical point of the session. There are **two opposite encoding steps, on two different layers**, and they cancel:

1. **The browser encodes on the way out.** `window.location` doesn't hand JavaScript back the raw characters I typed — it returns a *normalised, percent-encoded* URL. By the time `document.cookie = … + window.location` runs, `'` is already `%27`, `<` is `%3C`, `>` is `%3E`. So the cookie genuinely stores the encoded version. That's what the console shows.
2. **The server decodes on the way back in.** When the browser sends the cookie up in the `Cookie` header, it sends it encoded. But the server-side framework, parsing the cookie value, **URL-decodes it** — that's the standard convention for cookie values. So the application code sees `'><script>print()</script>` *decoded*, and reflects that into the HTML.

The payload makes a round-trip: encoded going out through the client, decoded coming back through the server. The two transforms annihilate each other, and the break-out survives.

I only nailed this by looking at the two ends separately — the stored cookie (`document.cookie` in the console: **encoded**) versus the reflected `href` in the response (**decoded**). If I'd trusted either one alone, I'd have told myself a wrong story: "it's encoded, it's dead" or "it's decoded, no problem here." It's the same lesson as [last time](/posts/xinclude-targeted-scan-file-read/), squared — **each layer transforms the data, and reading one layer tells you nothing certain about the next.**

## 5. Doing it again with Burp's tools — and the category falling apart

I'd solved it by hand. But the whole point of the Mystery Lab is to practise recognition *the proper way*, so I went back and reached the same place with Burp's audit tools — the static-then-dynamic method my study guide prescribes. This is where the lab stopped being what I thought it was.

**Burp Scanner.** Right-click the product request → Scan → *Audit selected items* (targeted, same as last post). The finding came back:

> **Cross-site scripting (reflected)** — Medium, Certain
> *The value of the `lastViewedProduct` cookie is copied into the value of a tag attribute… This input was echoed unmodified in the application's response.*

Not "DOM-based XSS." Not "DOM cookie manipulation." **Reflected XSS.** CWE-79. Burp has a separate issue type for DOM-based findings, and it didn't pick it — because it saw the payload **echoed in the HTTP response body**, which is the server's doing, not the DOM's. The "DOM-based" part of this lab lives *only* in the one line that writes the cookie (`document.cookie = window.location`). The exploitable XSS is old-school, server-side reflection — the input just happens to arrive in a cookie instead of a query string.

So I'd filtered the Mystery Lab for **DOM** vulnerabilities and landed on a bug whose exploitable half isn't in the DOM at all. The label was half a red herring. At an exam with no labels, that distinction is the entire game.

**DOM Invader.** This is the tool built *specifically* for DOM bugs — it injects a canary into sources and traces it dynamically to client-side sinks. I turned it on, enabled canary injection on sources and cookies, navigated, waited.

Nothing. No source, no sink, no flow.

My first reaction was "I'm driving it wrong." I wasn't. DOM Invader hooks **client-side sink functions** inside the browser. The reflection that produces this XSS happens **on the server**, in HTML generation. There is no client-side sink to hook — so there's nothing for DOM Invader to find. Its silence wasn't a failure; it was the single most informative result of the session: *the sink is not in the DOM.* The tool I'd have trusted most for a "DOM lab" was the one that correctly saw nothing.

## 6. "Are you sure?" — settling it in the response body

I'll be honest: I argued with myself about whether DOM Invader was just misconfigured. "DOM-based cookie manipulation" is *in the lab's name*; surely the DOM tool should see it. Theorising wasn't going to resolve it. The response body would.

Repeater. `GET /`, and I hand-set the cookie:

```
Cookie: lastViewedProduct=https://YOUR-LAB-ID.web-security-academy.net/product?productId=1&'><script>print()</script>
```

The response came back, and there in the raw body — not the rendered DOM, the actual bytes the server sent:

```html
<a href='https://YOUR-LAB-ID.web-security-academy.net/product?productId=1&'><script>print()</script>'>Last viewed product</a>
```

Server-side. Definitively. The script tag is in the response the server generated from the `Cookie` header. DOM Invader never had a chance, and it was right to stay quiet. The way to end a disagreement about which layer a bug lives in is to look at the response body, not to win the argument.

## 7. The lab wasn't the injection — it was the delivery

Popping `print()` in my own browser solved nothing. The objective said *the victim's* browser, via the exploit server. And the victim starts clean: no `lastViewedProduct` cookie, nothing malicious to reflect. Burp's own report spelled out the catch:

> *you will need to find a means of setting an arbitrary cookie value in the victim's browser… "cookie-forcing" conditions.*

So the real work is an ordering problem, done in someone else's browser:

1. make the victim **write** the malicious cookie (visit my poisoned product URL), then
2. make the victim **load** a page that reflects it (so `print()` runs).

A single link can't do it — on the first load the server still reflects the *old* clean cookie; mine is only written afterwards. You need a second load. An `<iframe>` orchestrates both:

```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/product?productId=1&'><script>print()</script>"
        onload="if(!window.x){window.x=1;this.src='https://YOUR-LAB-ID.web-security-academy.net/'}">
</iframe>
```

- **First load** (the `src`): the victim opens the poisoned product page → `document.cookie = window.location` plants the malicious cookie in *their* browser. `print()` does **not** fire yet (the server reflected their old cookie). This is the moment `SameSite=None; Secure` earns its place: without it the browser would drop the cookie inside a cross-site iframe, and the whole thing dies here.
- **`onload` fires** → I repoint the iframe at `/`.
- **Second load**: the victim requests `/` sending the *malicious* cookie now; the server reflects it into the `href`; the parser reads `<script>print()</script>` → **`print()` runs in the victim's browser.**
- **The `if(!window.x)` guard**: `onload` fires again after the redirect, so without a sentinel I'd loop forever. It means "redirect exactly once."

Paste that into the exploit server body, **Store**, **View exploit** to test it on myself, then **Deliver exploit to victim**. Lab solved — and the thing that solved it was the choreography, not the payload.

## The pattern underneath

Three tools looked at this bug and gave three different answers, and all three were correct — because each was looking at a different layer:

| Tool | Layer it sees | Verdict here |
|---|---|---|
| Burp Scanner | request → **server** response | found it: reflected XSS, Certain |
| Repeater | raw **server** response body | confirmed it: server-side |
| DOM Invader | **client** DOM sinks | saw nothing — correctly |

The bug I'd filtered for as "DOM" was exploitable at the server. The DOM tool went dark, and if I'd trusted it alone I'd have concluded "nothing here" while staring at a Certain XSS. **A tool only tells you the truth if you know which layer it's looking at** — and the category label (DOM) pointed at the layer where the bug *wasn't*.

And underneath the write side, the thing that generalises past this one lab: **a cookie is attacker-influenceable input, not trusted data.** This app reflects its own cookie as if it had authored it — but the client writes that cookie, from `window.location`, which I control. Compare the two reads:

```javascript
// Vulnerable: cookie value trusted straight into HTML
element.innerHTML = '<a href="' + lastViewedProduct + '">Last viewed product</a>';

// Safer: encode on output, and validate it's actually a same-origin URL
const a = document.createElement('a');
a.textContent = 'Last viewed product';
a.href = new URL(lastViewedProduct, location.origin).href; // throws on garbage; href is assigned, not parsed as HTML
```

The fix isn't "sanitise the cookie." It's "stop treating a cookie as if you wrote it."

## What comes next

The open thread is the encoding round-trip. Here the client encoded and the server decoded and it cancelled — but that's a property of *this* server's cookie parsing. The next question is where that symmetry breaks: a sink that doesn't decode, a source the browser *doesn't* normalise (`location.hash` is read far more literally than `location.href`), a framework that double-decodes. Each of those turns "the encoding cancelled out" into "the encoding is now the bug." That's the next few labs — and it's exactly the kind of thread a Mystery Lab is supposed to pull.

## Takeaways

- **Don't assume the category points at the layer.** I filtered for DOM and the exploitable bug was server-side reflected XSS. At an unlabeled exam, "where does this actually live" is the whole skill.
- **A quiet tool is still telling you something.** DOM Invader found nothing because there was no client-side sink — that *is* the finding. Know which layer each tool watches.
- **Read both ends before believing an encoding story.** The cookie was stored encoded and reflected decoded; only looking at both told the truth (client encodes out, server decodes in).
- **A cookie is attacker input.** It's written client-side from `window.location` here — treat anything that reflects its "own" cookie as reflecting untrusted data.
- **The injection is rarely the hard part — the delivery is.** Cookie-forcing in the victim's browser (two loads, an iframe, `SameSite=None`) was the actual lab. "It works for me" isn't solved.

## Useful references

- [PortSwigger — Lab: DOM-based cookie manipulation](https://portswigger.net/web-security/dom-based/cookie-manipulation/lab-dom-cookie-manipulation)
- [PortSwigger — DOM-based cookie manipulation](https://portswigger.net/web-security/dom-based/cookie-manipulation)
- [PortSwigger — DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader)
- [PortSwigger — Reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected)

---

*All techniques shown were performed on an isolated lab environment (PortSwigger's Web Security Academy). Running these attacks against systems you don't own or have written authorization to test is illegal in most jurisdictions.*
