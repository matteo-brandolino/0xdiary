---
layout: post
title: "Quick, Then Not Quick At All: Two Mystery Labs in One Sitting"
date: 2026-10-08
categories: [web-security, walkthrough]
tags: [portswigger, mystery-lab, dom-based, xss, postmessage, eval, javascript, burp-suite]
excerpt: "I rolled two mystery labs back to back: the first one was solved before I'd finished writing down the payload, and the second one needed a minus sign to turn a closed JavaScript string back into code I could run."
lang: en
page_id: two-mystery-labs-postmessage-eval
permalink: /posts/two-mystery-labs-postmessage-eval/
---

The first lab took less time to solve than it took to write the payload down. The second one needed a minus sign to work, and once I understood why, I still couldn't explain it to myself in under four steps. Both came out of the same two-topic pool, rolled back to back in the same sitting, and that gap between them is the whole post.

The labs came from [Mystery Pool]({% post_url 2026-10-04-mystery-pool %}), the tool I built to roll a lab from only the topics you choose. Pool set to DOM-based and XSS, same as every other mystery session. PortSwigger still picks the actual lab. I just get to narrow the odds.

## Setup

No Burp scan on the first lab, no DOM Invader either — there was nothing to scan. The second one had an actual search box, so this time the scanner got to do something.

## Lab one: a listener that checks nothing at all

No login box, no comment field. Just a page with an ad slot sitting empty, waiting for content from somewhere else — which, as it turns out, is exactly the kind of place a real site hands control to someone else's script.

### 1. Straight to Sources, no detour

There was nothing to type into, so there was nothing for a scanner to put a payload in either. I went directly to the page's own JavaScript. One file, one listener:

```javascript
window.addEventListener('message', function(e) {
    document.getElementById('ads').innerHTML = e.data;
});
```

That's the entire check. No `e.origin`, no shape validation, no `try/catch` pretending to be careful. `e.data` goes into `innerHTML` as-is. Reading this took less time than deciding whether to run DOM Invader first.

### 2. Testing from the console before building anything

Before touching the exploit server, I tested the sink from the lab's own console:

```javascript
window.postMessage('<img src=x onerror=alert(document.domain)>', '*')
```

The alert fired immediately. `alert(document.domain)` instead of `alert(1)` on purpose — it confirms the code is running in the lab's own origin, not in some isolated context that just happens to also pop a box.

### 3. The `<script>` tag I already knew not to use

I knew from a previous lab not to bother with `<script>alert(1)</script>` here, but knowing the rule and understanding it are different things, and I wanted the second one. The answer is a parser detail, not a filter: when a string is assigned to `innerHTML`, the browser runs it through *fragment parsing*, a separate algorithm from the one parsing the rest of the document. That algorithm builds a real `<script>` node — you can see it in the DOM — but flags it internally as already executed, so the engine skips it when the fragment is attached to the live tree. It isn't sanitization. It's a parser rule, built for exactly this case.

It's also not a universal rule about `innerHTML`. `document.write()` uses the real document parser, the one still reading the rest of the page, and a script written through it runs. Same payload, different sink, opposite outcome. And none of this touches attributes like `onerror` or `onload` — those aren't script elements, they're handlers evaluated when their event actually fires, no matter how the element reached the DOM. That's the whole reason the `<img>` payload above works and a `<script>` tag wouldn't.

### 4. Delivery, and done

Objective: `print()`. The exploit server body:

```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')"></iframe>
```

`onload`, because the listener only exists once the lab's page has finished loading. `'*'` as the target origin, because the sender decides nothing about who should receive the message — the receiver is supposed to check that, and here it doesn't. Store, deliver, solved. Faster than lab two's setup section.

## Lab two: Burp said certain, and that wasn't the whole story

This one was a small blog: a list of posts with titles, summaries and header images, and a search box above the list. A search box is an input field, which meant Burp's scanner finally had something to chew on.

### 1. A scan, and a report that argued with itself

The active scan came back with a reflected XSS finding on `/search-results`, confidence **Certain**, severity **Information**. Those two words sitting next to each other are the whole lesson of this moment: Confidence is Burp's certainty that what it found is real — here, that the `search` parameter comes back in the response completely unmodified, canary and all. Severity is a separate claim about how exploitable that fact actually is. Burp was certain the symptom was real and, in the same report, unwilling to call it dangerous — and it said exactly why, in the one paragraph of boilerplate I almost skimmed past:

> *The response does not state that the content type is HTML. [...] No modern browser will interpret the response as HTML. However, the issue might be indirectly exploitable if a client-side script processes the response and embeds it into an HTML context.*

### 2. Checking what the scanner already told me

The response:

```
HTTP/2 200 OK
Content-Type: application/json; charset=utf-8

{"results":[],"searchTerm":"livic<script>alert(1)</script>pv1hc"}
```

`application/json`. Navigating straight to that URL with a payload in the query string does nothing — the browser reads the declared content type and shows the body as data, never as markup. The reflection was real. It just wasn't, by itself, an attack.

### 3. The line that looked guilty and wasn't

The client-side code that calls this endpoint:

```javascript
function search(path) {
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            eval('var searchResultsObj = ' + this.responseText);
            displaySearchResults(searchResultsObj);
        }
    };
    xhr.open("GET", path + window.location.search);
    xhr.send();

    function displaySearchResults(searchResultsObj) {
        var searchTerm = searchResultsObj.searchTerm
        var h1 = document.createElement("h1");
        h1.innerText = searchResults.length + " search results for '" + searchTerm + "'";
        // ...
    }
}
```

For a second the suspect looked obvious: `h1.innerText = ... + searchTerm`. It isn't. `innerText` never parses markup — there's no HTML context to escape into, so there's nothing to break. The real sink sits two lines above `displaySearchResults`, before `searchTerm` even exists as a variable: the entire raw response body gets handed to `eval()`. Not `JSON.parse`, which would have turned that same text into inert data. `eval()`, which turns it into instructions.

### 4. One quote, correctly escaped

First probe: `search=test"`. Response:

```json
{"results":[],"searchTerm":"test\""}
```

The quote comes back as `\"`. The server escapes double quotes before embedding them. For a minute that looked like the end of it — if the one character that closes a string is guarded, there's no way to leave the string early, and I nearly moved on to a different lab.

### 5. "It's escaped" was the wrong read

It wasn't the end of it, because the escaping function only does one thing: it looks for `"` and puts a `\` in front of it. It says nothing about `\` itself. I tested that directly — `search=\`, a single backslash, nothing else:

```
Content-Length: 31

{"results":[],"searchTerm":"\"}
```

Thirty-one bytes, exactly the template plus one untouched backslash — I counted them to be sure, because at that point I didn't trust my own reading of the response anymore. My backslash passes straight through. And a backslash of mine, sitting right before the `"` the server is about to escape, changes what that escape means: `\` (mine) + `\"` (the server's insertion) reads inside `eval()` as `\\` — one literal backslash, escape fully consumed — followed by a `"` that's no longer protected by anything. It closes the string early. The server's own escaping becomes the thing that breaks its own escaping.

### 6. Building the payload, one piece that does nothing at a time

Full payload: `\"-alert(1)}//`. I built it in four pieces, and three of the four produce nothing at all on their own — not a partial alert, not a half-broken page, just silence, because `eval()` has to parse the entire string before it executes a single character of it. A syntax error anywhere kills the whole thing, not just the part after the error.

**Piece 1 — break the string:** `\"` → inside `eval()`, the string closes after consuming one literal backslash, leaving a bare `"}` dangling with nothing to close it. `SyntaxError: Unterminated string literal`. Nothing runs.

**Piece 2 — add the real code:** `\"-alert(1)` → the string still closes early, `-alert(1)` reads as a valid continuation of the value expression, but the template's own trailing `"}` is still sitting there unmatched. Still a `SyntaxError`. `alert(1)` is sitting right there in the code, syntactically correct, and it still never runs.

**Piece 3 — close the object:** `\"-alert(1)}` → the object literal now closes cleanly. But the template adds its own `"}` right after mine, and that leftover quote starts a string with nothing to end it. `SyntaxError`, again.

**Piece 4 — comment out the rest:** `\"-alert(1)}//` → everything after `//` on that line — the stray quote, the stray brace, the trailing semicolon the template adds — disappears into a comment. The whole thing finally parses, and `alert(1)` runs.

### 7. Why the minus sign is load-bearing

After the string closes early, the value for `searchTerm` isn't finished — a property value is a single expression, and a closed string sitting next to a bare `alert(1)` with nothing between them isn't one expression, it's two fragments with no connector. The `-` glues them into one: `"\\" - alert(1)` is a subtraction, and to compute a subtraction JavaScript has to evaluate both sides — which means calling `alert(1)` whether the resulting number means anything or not (it doesn't; it's `NaN`). Almost any binary operator would have done the same job. A comma wouldn't: inside an object literal, a comma after a value means "start a new property," and `alert(1)` on its own isn't a `"key": value` pair, so that path just trades one syntax error for another.

Tested directly in the search bar, with the lab's own JavaScript doing the eval: the alert fired, and the lab was solved — no exploit server needed this time, because the source of the bug is the page's own URL, not a message from another origin.

## What the two labs have in common

Neither bug was about whether the input reached the page — it always did, in both labs, immediately. The question that mattered was what context it landed in, and what that context is actually willing to treat as code.

`innerHTML` draws that line one specific way: it'll run an `onerror` handler without blinking, and it will not run a `<script>` tag, by a parser rule that exists for that one purpose. `eval()` draws no line at all — it has exactly one gate, and the gate is "does the whole string parse as valid syntax," nothing about where that syntax came from or what it does once it runs. Knowing the sink means knowing exactly where its particular boundary sits. Assuming every sink draws the line in the same place is how a correct payload for one bug does absolutely nothing against the other.

## Exam and field

**Lab one — postMessage into innerHTML**

| | Exam | Field |
|---|---|---|
| What to recognise | a `message` listener assigning `e.data` straight into `innerHTML`, no `e.origin` check anywhere | third-party widgets, ad slots, embeds — anything that takes content from a window it doesn't control |
| Where the time goes | delivery: `onload` timing, the `'*'` target, an event-handler payload instead of a `<script>` tag | finding what the logged-in user's session can actually do once the script runs |
| Common trap | reaching for `<script>alert(1)</script>` out of habit and getting nothing, with no error to explain why | assuming framing protections (`X-Frame-Options`) also stop `postMessage`; they don't, it's a separate mechanism |
| Real limit | a single scripted objective | a victim has to load a page you control; if the target blocks framing, `window.open` keeps the same message call working |

Defence: check `e.origin` against an explicit allow-list before touching `e.data` at all, and never assign message content straight to `innerHTML` — render it as text, not markup.

**Lab two — search parameter into eval()**

| | Exam | Field |
|---|---|---|
| What to recognise | client-side code calling `eval()` (or `new Function()`) on a server response, instead of `JSON.parse` | hand-rolled JSONP-style endpoints and old API clients that predate `JSON.parse` being ubiquitous |
| Where the time goes | finding the one character the escaping function forgot, and keeping the rest of the file syntactically valid afterward | the payload is trivial once you have a working breakout; the escaping gap is the actual puzzle |
| Common trap | trusting "Confidence: Certain" as proof of exploitability and skipping the severity line underneath it | treating a scanner's silence on an endpoint as proof it's safe, when the scanner never saw the client-side consumer at all |
| Real limit | depends entirely on which characters the target app happens to escape; a different app, a different gap | if the escaping function also guards backslashes, this exact path closes — the bug would need a different breakout character or a different sink entirely |

Defence: never build executable JavaScript by concatenating untrusted strings — not with `eval`, not with `new Function`, not with `setTimeout("string")`. `JSON.parse` exists precisely so that "parse the data" and "run the code" can never be the same operation by accident.

## What comes next

The second lab's whole exploit rode on one specific gap: the escaping function handled `"` and forgot `\`. That's a narrow, almost accidental hole — `JSON.stringify` wouldn't have made it, because it escapes both correctly by design. The next useful test isn't this lab again; it's finding one where the escaping is actually complete, and seeing whether the breakout has to move to a different character, or whether `eval()`-as-a-sink stops being exploitable at all once the string handling is done properly. I don't know the answer yet, and I'd rather find out than guess.

## Takeaways

- A sink's rules are specific to that sink. `innerHTML` won't run a `<script>` tag but will run an `onerror` attribute; `eval()` won't stop either one, it only checks that the whole string parses.
- Burp's Confidence and Severity answer two different questions — "is this real" and "does it matter" — and a report can answer yes to the first and no to the second in the same paragraph.
- `eval()` doesn't give partial credit. A payload that's three pieces out of four correct produces a silent syntax error, not a partial result, because the whole string has to parse before any of it runs.
- An escaping function that handles one special character correctly can still ignore the character that lets you neutralize that very escaping — test the narrowest input you can before testing the full exploit.

## Useful references

- [PortSwigger Web Security Academy: DOM-based vulnerabilities](https://portswigger.net/web-security/dom-based)
- [PortSwigger Web Security Academy: Cross-site scripting](https://portswigger.net/web-security/cross-site-scripting)
- [MDN: Window.postMessage()](https://developer.mozilla.org/docs/Web/API/Window/postMessage)
- [MDN: Element.innerHTML](https://developer.mozilla.org/docs/Web/API/Element/innerHTML)
- [MDN: eval()](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/eval)
- [A message from nowhere: DOM XSS through postMessage]({% post_url 2026-10-05-dom-xss-postmessage-mystery-lab %}) — the previous postMessage lab, which at least pretended to validate the message shape

*All techniques shown were performed on an isolated lab environment (PortSwigger's Web Security Academy). Running these attacks against systems you don't own or have written authorization to test is illegal in most jurisdictions.*
