---
layout: post
title: "A substring is not a scheme: DOM XSS via web messages and a javascript: URL"
date: 2026-10-12
categories: [web-security, walkthrough]
tags: [portswigger, dom-based, xss, postmessage, dom-invader, burp-suite, javascript-url]
excerpt: "DOM Invader found nothing, so I enabled automated messages, pasted the wrong source into my own notes, and only then understood why 'the URL contains https' is not the same as 'the URL starts with https'."
lang: en
page_id: dom-xss-web-messages-javascript-url
permalink: /posts/dom-xss-web-messages-javascript-url/
---

I opened DOM Invader, reloaded the lab's home page, expecting the postMessage panel to light up the way it always does in the walkthroughs. Messages: 0. DOM: 0. For a tool that's supposed to find this stuff for me, zero is a strange way to start.

The lab is PortSwigger's "DOM XSS using web messages and a JavaScript URL." I went in wanting to use DOM Invader properly this time, not just read the solution and type it in. That plan survived about four minutes.

## Setup: the tool that watches, but only what passes

DOM Invader (version 2.0.12 in my case) hooks `window.addEventListener('message', ...)` and other known sinks across the page, then waits for traffic to flow through them. The home page loaded, the listener was presumably sitting there somewhere in the JavaScript, and the Messages panel stayed empty. Canary set, postmessage interception on, canary injection on — all green in the settings panel. Still nothing.

## 1. Zero messages doesn't mean zero listener

The fix turned out to be a toggle I'd skipped: **Generate automated messages**. DOM Invader doesn't just eavesdrop — it can manufacture its own postMessage traffic and send it to every `message` listener it finds, specifically to provoke a reaction without waiting for real cross-window traffic. I'd assumed "intercept" meant "actively test." It means "watch." Turning that toggle on is what actually tests.

Once it was on and I reloaded, three messages showed up, two flagged with a red exclamation mark. Each one had a `Data` field that looked like this:

```
https://0a16005b...web-security-academy.net/sa9je6lj0-/%3C%3E'"
```

That string is not a URL to visit. It's the *value DOM Invader assigned to `e.data`* when it called `postMessage()` on the page — built to look URL-shaped (because some sinks reject anything that doesn't parse as a URL), carrying a canary (`sa9je6lj`, the random token from settings) so DOM Invader can recognise its own probe later, and padded with classic XSS probe characters (`<>'"`) to see if they survive unescaped once they hit a sink. The rows with the appended `http:` or `https:` were doing something more specific, which I didn't understand until later: testing a particular bad-validation pattern DOM Invader already knows is common.

## 2. The stack trace that wasn't the page's code

I wanted to see exactly where that data landed, so I clicked through to the stack trace. The DOM Invader panel told me to check the Console instead of showing it inline — fine. I went looking, grabbed what looked like source, and pasted it into my notes to go find the sink.

It was DOM Invader's own extension code. Several thousand lines of it, obfuscated, variable names like `_0x43c43e`. Not one line of the lab's JavaScript.

This is the kind of mistake that costs more time than it should, because the output *looks* like source code, and your brain pattern-matches "this is probably what I asked for" before checking whose source it actually is. The fix was mechanical once I stopped assuming: open Sources, find the tree node for the lab's own domain (not the extension's), and read the inline `<script>` on the home page directly. No stack trace needed at all — the listener was sitting right there in the page HTML.

## 3. The check that counts substrings, not schemes

The real listener:

```javascript
window.addEventListener('message', function(e) {
    var url = e.data;
    if (url.indexOf('http:') > -1 || url.indexOf('https:') > -1) {
        location.href = url;
    }
}, false);
```

`indexOf('http:') > -1` asks one question: does the string `http:` appear *anywhere* in this value. It does not ask whether the value *starts with* `http:`, which is the question a scheme check actually needs to answer. A string can satisfy "contains `http:`" while starting with something else entirely — like `javascript:`.

That's also what DOM Invader's `http:`/`https:`-suffixed probes were testing for, in hindsight: it already knows `indexOf`/`includes` substring checks are a common, broken way developers try to validate URL schemes, so it appends the literal string to its payloads to see if a sink accepts them anyway.

## 4. The payload, and what `location.href = "javascript:..."` actually does

```
javascript:alert(document.domain)//http://a
```

I had to walk back my own mental model here, because my first instinct was wrong: I assumed `location.href` would somehow end up holding the result of calling `alert()`. It doesn't. `location.href` gets assigned the literal string above — all of it, unexecuted. What happens next is a quirk of how browsers treat the `javascript:` scheme: when a navigation target's scheme is `javascript:`, the browser doesn't navigate anywhere. It runs everything after the colon as JavaScript, in place, in the current page's context. `//http://a` becomes a JS comment the moment that execution happens, so the only thing that actually runs is `alert(document.domain)`. The trailing `http://a` only exists to make `indexOf('http:')` return a real position — it's not part of the attack, it's the key that unlocks the broken lock.

## 5. A postMessage payload is not a page you visit

One more thing I had backwards before it clicked: that URL-shaped probe string from DOM Invader's Messages panel — I asked whether *navigating to it* would trigger the listener. It won't. `addEventListener('message', ...)` reacts to `message` events, full stop, and those only fire from a `postMessage()` call, never from typing something into the address bar or loading a page. The probe string only ever existed as the `data` argument of a `postMessage()` call DOM Invader made for itself:

```javascript
window.postMessage("https://...sa9je6lj0-/%3C%3E'\":https:", "*")
```

The exploit server payload does the equivalent, deliberately:

```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/" onload="this.contentWindow.postMessage('javascript:alert(document.domain)//http://a','*')">
```

`onload` matters here for the same reason it mattered in the last postMessage lab I solved: the listener only exists once the lab's page has finished loading. Send the message before that, and it goes nowhere.

## The pattern underneath

Two different gaps did the work here, and they're easy to conflate if you only remember "weak validation." The first is a check written against the wrong question — "does this string contain X" instead of "does this string start with X" — which is a substring-vs-anchor bug that shows up well beyond URL schemes (query strings, cookie values, header checks all get this wrong the same way). The second is a browser behaviour that turns any string assignable to `location.href` (or `.src`, or similar sinks) into an execution primitive, as long as its scheme is `javascript:`. Neither gap alone is the vulnerability. Together, they are.

## Exam and field

| | Exam | Field |
|---|---|---|
| What to recognise | a `postMessage` handler that validates a URL with `indexOf`/`includes` instead of anchoring the check | the same loose check on redirect targets, iframe sources, or "safe URL" allowlists anywhere in a codebase, not just in postMessage handlers |
| Where the time goes | reading the exact validation logic, not guessing a payload | figuring out which sinks in the app actually consume attacker-reachable URLs |
| Typical trap | assuming `indexOf('http') > -1` behaves like `startsWith('http')` | assuming a substring check anywhere near a URL is "probably fine" because it mentions the right scheme |
| Real limit | one JS call, one iframe, done | the victim still has to load a page that triggers the `postMessage`; if the vulnerable page can't be framed, the trick moves to `window.open` plus the same payload |

On the exam, this is fast once you've actually read the condition instead of skimming it — `indexOf` and `startsWith` look interchangeable if you're pattern-matching instead of reading.

In the field, the same `indexOf('http')`-style check turns up anywhere a developer tried to validate "is this a safe URL" with a one-liner instead of a proper parser. `new URL(input).protocol === 'https:'` closes this specific hole; a plain substring test never does, no matter how many schemes it lists.

The fix for this exact listener is two changes, not one: check `e.origin` against an explicit allowlist before touching `e.data` at all, and replace the substring check with something that actually inspects the scheme — `new URL(url).protocol` compared against `'http:'`/`'https:'`, or at minimum `url.startsWith('http://')`.

## What comes next

The obfuscated-extension detour taught me something unrelated to the lab but worth keeping: when DOM Invader tells you to check the console, check the console *scoped to the right origin*, and when you're reading what looks like source, confirm whose source it is before you start reasoning about it. That's a cheap check that would have saved the whole detour.

The next postMessage lab I pick from [Mystery Pool]({% post_url 2026-10-04-mystery-pool %}) is the one with `JSON.parse(e.data)` guarding the message shape instead of a raw string — I've already seen that pattern once, [in the previous postMessage lab]({% post_url 2026-10-05-dom-xss-postmessage-mystery-lab %}), and I want to see if an origin check changes how fast DOM Invader's automated probes find the sink.

## Takeaways

- `indexOf`/`includes` checks on a URL answer "does this string contain X," never "does this string start with X" — they're not interchangeable, and a `javascript:` URL can satisfy the first while failing the second.
- DOM Invader's "Generate automated messages" setting is what actually provokes `message` listeners into reacting; without it, an empty Messages panel just means no real traffic happened yet.
- A `location.href = "javascript:..."` assignment never executes anything by itself — the browser's handling of the `javascript:` scheme is what turns the assignment into code execution.
- A postMessage probe string is data passed to `postMessage()`, not a URL to visit; only an actual `postMessage()` call triggers a `message` listener.
- When a tool shows you "the source," check whose source — extension internals and target-page code can look identical at a glance, especially both minified.

## Useful references

- [PortSwigger: DOM XSS using web messages and a JavaScript URL](https://portswigger.net/web-security/dom-based/open-redirection/lab-dom-xss-using-web-messages-and-a-javascript-url)
- [PortSwigger: DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader)
- [PortSwigger: Controlling the web message source](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source)
- [MDN: Window.postMessage()](https://developer.mozilla.org/docs/Web/API/Window/postMessage)
- [MDN: javascript: URLs](https://developer.mozilla.org/docs/Web/URI/Schemes/javascript)

---

*All techniques shown were performed on an isolated lab environment (PortSwigger's Web Security Academy). Running these attacks against systems you don't own or have written authorization to test is illegal in most jurisdictions.*
