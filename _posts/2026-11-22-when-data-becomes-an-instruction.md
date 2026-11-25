---
layout: post
title: "When Data Becomes an Instruction: Five Rolls Into Step Three"
date: 2026-11-22
categories: [web-security, walkthrough]
tags: [portswigger, bscp, insecure-deserialization, ssti, ssrf, path-traversal, prototype-pollution, rce, mystery-lab, burp-suite]
excerpt: "First five rolls of the exfiltration step, and the reflex from step two — become the admin — was the wrong verb entirely. Every door opened on the same hinge: some engine under the app treating my input as an instruction the app only meant to store, validate, or display."
lang: en
page_id: when-data-becomes-an-instruction
permalink: /posts/when-data-becomes-an-instruction/
---

I flipped the admin boolean in the serialized cookie — `b:0` to `b:1`, the move three posts of step two had wired into my fingers — and the server did nothing. Logged me straight back in as plain wiener. For a second that felt like a broken lab. It wasn't. Step three doesn't care who you are. The reflex I'd spent a month building — *become the admin* — was the wrong verb entirely. The cookie wasn't a thing to edit. It was a thing to **run**.

That's the shift this whole post is about. The [last three posts]({% post_url 2026-11-19-the-wheel-starts-repeating %}) were step two — privilege escalation, every road ending at someone else's account. This is step three — exfiltration, and the goal on every lab is the same blunt sentence: *read the content of `/home/carlos/secret`*, delete a file, run a command. Not *who are you*, but *what can you make the machine do*. I spun my [Mystery Pool]({% post_url 2026-10-04-mystery-pool %}) five times through the exfiltration card, and every single roll turned on the same hinge: some engine beneath the app — a deserializer, a template compiler, an HTTP client, a file-open syscall, a Node process spawner — treating my input as an **instruction** the application only ever meant to store, validate, or display. Step two was about lying to the app about who you are. Step three is about talking past the app, to the machine underneath it.

## The setup

Same tool, Exfiltration card ticked, Practitioner level. The pool had all eight topics checked — SSRF, XXE, SSTI, path traversal, insecure deserialization, file upload, server-side prototype pollution (RCE), OS command injection. I rolled five of them before calling it; the three I never drew (XXE, file upload, OS command injection) are the end of this post.

As usual several came up as **direct topics**, spoiling their title on load — I'd still rather roll broadly than keep every title hidden. One thing changed from the step-two sessions and it's worth naming up front: the winning move was almost never *more payload*. It was reading one component's source or one error message closely enough to see where it disagreed with the component next to it. Identification carried every roll. Exploitation was the easy half.

Tooling: Burp with the scanner on single insertion points, Repeater, Decoder (which earned its keep this time), the Server-Side Prototype Pollution Scanner extension; `php -r` for building serialized objects; and a lot of staring at source code.

## The session

### Roll 1 — The class I was never supposed to build (PHP object injection)

A serialized PHP object in the session cookie — Burp's scanner flags it the moment it decodes the base64 and sees `O:4:"User":...`. My first move was the step-two reflex: decode it, flip the admin flag, re-encode, send. Nothing. And *nothing* is the correct answer, because the value I wanted was never in the object's **data**. It was in the object's **class**.

`unserialize()` doesn't just rebuild your fields. It reads `O:14:"CustomTemplate"` and instantiates *whatever class you name*, with no whitelist, and then — when that object is destroyed at the end of the request — PHP runs its `__destruct()` automatically. So the exploit isn't editing a `User`. It's injecting a different class entirely, one that happens to do something dangerous when it dies. I found it by reading the source of a `CustomTemplate` class leaked under `/libs`:

```php
function __destruct() {
    // Carlos thought this would be a good idea
    if (file_exists($this->lock_file_path)) {
        unlink($this->lock_file_path);
    }
}
```

`unlink()` on a path that's an *attribute of the object* — i.e. a value I control. So I replaced the `User` object in the cookie with a hand-built `CustomTemplate` pointed at the target:

```php
O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}
```

base64 into the cookie, send, and PHP's garbage collector deletes the file for me. **The rabbit hole is the private-property mangling**: `lock_file_path` is declared `private`, which normally serializes as `\0CustomTemplate\0lock_file_path` with null bytes and a different length — and if you know that, you can burn ten minutes building the mangled version this lab doesn't need. The clean name works here. Don't count bytes by hand either; declare the property `public` in a stub class and let PHP do it:

```bash
php -r 'class CustomTemplate { public $lock_file_path="/home/carlos/morale.txt"; } echo base64_encode(serialize(new CustomTemplate()));'
```

The exam sentence: in deserialization the exploit is not the data you send, it's the **class you make the server instantiate**. Hunt a magic method (`__destruct`, `__wakeup`, `__toString`) that reaches a sink through a controllable attribute. The cookie is just the delivery. Stage 3, non-interactive.

### Roll 2 — The display name that ran (SSTI, code context)

A blog comment feature let me set the author display name, and that name came back **rendered** in the published comment. Input that lands inside a template instead of a query is the whole smell of server-side template injection — and it's a step-three favourite because a template engine with filesystem or OS access is one short step from RCE.

The identification nuance is the part I'm proud of. I didn't fire a bare `{% raw %}{{7*7}}{% endraw %}`; I sent `{% raw %}user.first_name}}{{7*7{% endraw %}`. The reason: my input was already *inside* an expression (`{% raw %}{{ user.first_name }}{% endraw %}`), so I had to **close that context** with `}}` before opening my own. The page printed `49` — breakout confirmed. To fingerprint the engine I'd normally run `{% raw %}{{7*'7'}}{% endraw %}` (Python engines repeat the string → `7777777`; Twig coerces → `49`), but the exploit shape gave it away: this was **Tornado**. Breaking out and importing a module:

```
{% raw %}user.name}}{% import os %}{{os.system('rm /home/carlos/morale.txt')}}{% endraw %}
```

Close the original expression, `{% raw %}{% import os %}{% endraw %}` pulls the module into the template namespace, `{% raw %}{{os.system(...)}}{% endraw %}` executes. That's the step-three payoff stated plainly: the lab asked me to delete `morale.txt`, but once `os.system` is in your hand, `cat /home/carlos/secret` is the identical gesture. **A template engine that evaluates your string isn't an XSS risk — it's a shell.** The only trap is context: miscount the delimiters you're nested inside (`}}` vs `%}`) and your payload renders as text. Stage 3, non-interactive.

### Roll 3 — Count the decodes (SSRF, blacklist filter)

A `stockApi` parameter took a full URL and the server fetched it — textbook SSRF, confirmed twice over: manually (the param swallows any URL) and by Burp's scanner lighting up *Out-of-band resource load* when I pointed it at Collaborator. The server is my proxy now; anything *it* can reach — localhost, the internal network, cloud metadata — I can reach, from its trusted position.

Pointing it at `http://localhost/admin` and `http://127.1/admin` both returned `400 "External stock check blocked for security reasons"`. Not a reachability error — a **blacklist** on the string. The blocked token turned out to be `admin`, and this is where the roll earned its lesson. URL-encoding the `a` once — `%61dmin` — *still got blocked*. The fix was to encode it **twice**: `%2561dmin`. Here's the mechanism, and it's the exact shape that recurs all session:

> The filter URL-decodes the string once *before* it checks the blacklist. So `%61dmin` decodes to `admin` and gets caught. `%2561dmin` decodes once to `%61dmin` — not the word `admin`, so it passes — and *then* the server's HTTP client decodes it a second time, to `admin`, and makes the request.

It isn't "obfuscate the letter." It's "**add one more decode layer than the filter performs**." The filter and the executor disagree about how many times to decode the string, and you live in the gap. Burp Decoder builds it for you — Encode as URL, twice — and don't be alarmed when it hands back `%25%36%31` instead of `%2561`; it encodes every character, but after two decodes both resolve to the same byte. Final: `stockApi=http://127.1/%2561dmin`, then `/%2561dmin/delete?username=carlos`. Stage 3, non-interactive.

### Roll 4 — Two readers, one string (path traversal, null-byte bypass)

The app was almost bare: no account area, no forms, just `GET /image?filename=54.jpg` serving files by name. When the attack surface is one parameter, that parameter is the surface — and the scanner confirmed path traversal, handing me the exact payload:

```
GET /image?filename=../../../../../../etc/passwd%0054.jpg
```

That `%00` before `54.jpg` is the whole lab — *File path traversal, validation of file extension with null-byte bypass* — and it's roll 3's lesson wearing different clothes:

- The **extension check** (application code, in a memory-safe language) reads the entire string, sees it ends in `.jpg`, and approves it.
- The **`open()` syscall** (C underneath) treats `%00` as a string terminator, stops reading there, and opens `/home`... `/etc/passwd`, ignoring everything after the null.

Two readers, one string, two different ideas of where it ends. The validator reads to the `.jpg`; the kernel reads to the `\0`. `root:x:0:0:` came back in the response. Same hinge as the double-decode: a check and an executor that parse your input under different rules. Stage 3, non-interactive.

### Roll 5 — The config I smuggled into a process (RCE via server-side prototype pollution)

The finale, and the clearest statement of the step-two-to-step-three jump. This was the *same source* as a [step-two roll]({% post_url 2026-11-17-five-rolls-into-step-two %}) — an Express app merging my JSON into a server object via `POST /my-account/change-address` — but there the prize was flipping `isAdmin`. Here it was a shell.

First, confirm the pollution with a reversible probe. Express reads its `json spaces` option off the prototype, so poisoning it reformats every JSON response:

```json
"__proto__": { "json spaces": 10 }
```

The reply came back indented by ten spaces — `Object.prototype` is now mine. Flipping `isAdmin` is the step-two endpoint; the step-three gadget is **`execArgv`**, the array of flags Node passes to a forked child process. Pollute it with an `--eval`:

```json
"__proto__": {
  "execArgv": ["--eval=require('child_process').execSync('rm /home/carlos/morale.txt')"]
}
```

Pollution alone is inert — it does nothing until something calls `child_process.fork()`, at which point the new Node process inherits my `execArgv` and runs my code at startup. I triggered that by **running the maintenance jobs from the admin panel**, which spawns the subprocess. Command executed, file deleted. The chain in four beats worth memorising: **source** (unsafe JSON merge) → **confirm** (`json spaces` indentation) → **gadget** (`execArgv` read by `fork`) → **trigger** (the admin job that forks). The app thought it was saving my address. Node read process configuration out of the same poisoned object graph. Stage 3 — and "interactive" only in that *I* had to trigger the fork; no victim required.

## The pattern

Five rolls, one mechanism under all of them: **I got an engine beneath the application to treat my input as an instruction the application only meant to store, validate, or display.** A cookie field became a class constructor. A display name became a shell command. A URL parameter became a request from inside the network. A filename became a read of `/etc/passwd`. An address form became process configuration. In every case the app was handling what it thought was inert data, and a layer below it — `unserialize`, the template compiler, the HTTP client, `open()`, `fork()` — read that same data as a command.

The sharpest, most portable version of this is the bypass in rolls 3 and 4: **the component that validates and the component that executes parse your string under different rules.** The filter decodes once; the HTTP client decodes twice. The extension check reads to the `.jpg`; the kernel reads to the `\0`. Every blacklist bypass I'll ever write is some version of this — find the two readers, find where they disagree, and put your payload in the gap. You don't defeat the filter by being clever about the word. You defeat it by knowing the filter and the executor aren't the same reader.

And the step-two reflex had to die. Three times this session I reached for *become the admin* — flipping the serialized boolean, eyeing `isAdmin` in the Express response — and three times it was the wrong verb. Step three isn't a lie about identity. It's a message to the machine, routed around the app that was supposed to be in the way.

## Exam and field

**In the exam**, all five are Stage 3 — data exfiltration — and the goal is never an account, it's a file read or a command. Four of the five are **non-interactive**: you deserialize, you template-inject, you SSRF, you traverse, entirely by your own requests, no victim in the loop — the profile you want under the clock. The prototype-pollution RCE is the only one with a trigger, and even that trigger is *you* (running the admin job), not a simulated victim. The identification tells are the whole game: `O:` or a base64 that decodes to a class name means deserialization, so go read source for a magic method; input that comes back *rendered* means SSTI, so break the template context and fingerprint the engine; a parameter that takes a URL means SSRF, so pivot it to `localhost` and the `169.254.169.254` metadata endpoint; a lone `filename=` on a bare app means path traversal; and a JSON merge on a Node app means prototype pollution — confirm with `json spaces`, escalate with `execArgv`. When a filter blocks you, don't reach for a bigger payload — ask how many times each side decodes.

**In the field**, these are the bugs that end incident reports. Deserialization and SSTI and the prototype-pollution gadget are straight RCE; SSRF is the pivot that turns a web bug into an internal-network foothold and the canonical cloud-metadata credential theft; path traversal reads whatever the web user can. The single defensive discipline behind all five: **never let a value cross from the layer that stores it into a layer that executes it without re-validating it in the executor's own terms.** An extension check in Python doesn't protect a C `open()`. A blacklist that decodes once doesn't protect a client that decodes twice. A JSON merge doesn't know it's writing a process's launch flags. The data-to-instruction boundary is where you audit, because it's where the readers stop agreeing.

## What comes next

Three exfiltration topics never came up and they're the obvious next rolls: **XXE** (external entities pulling files or hitting Collaborator — SSRF's XML-shaped cousin), **file upload** (web shells, and the content-type and extension filters built to stop them), and **OS command injection** (the most direct data-to-instruction bug there is — your string lands straight in a shell). Deserialization alone has far more coats than the one I drew: Java with `ysoserial`, PHAR deployment, pre-built `phpggc` gadget chains against library code rather than a convenient `CustomTemplate`. Step three is wide, and I've opened five doors into it. The wheel keeps turning toward the filesystem.

## Takeaways

- Step three changes the verb. Stop trying to *become the admin* — the serialized boolean flip and the `isAdmin` edit are step-two reflexes. Step three asks what you can make the machine **run**, and the answer is usually a file read or a command.
- In deserialization the payload is the **class**, not the data. `unserialize()` builds whatever class you name and fires its `__destruct`; read source for a magic method that reaches a sink, and let `php -r 'serialize(...)'` count the bytes.
- Blacklist bypasses are a decode-counting problem. `%61` gets caught because the filter decodes once; `%2561` passes because it decodes to `%61` first and the executor decodes the second time. Add one layer more than the filter performs.
- A null byte is the same bug as double-encoding: the validator reads your string to `.jpg`, the C `open()` reads it to `\0`. Find the two readers and the rule they disagree on.
- Prototype pollution scales from `isAdmin` to RCE through the gadget: `json spaces` to confirm, `execArgv` + `--eval` to execute, and a `fork()` you trigger yourself to fire it.

## Useful references

- [PortSwigger: Arbitrary object injection in PHP](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-arbitrary-object-injection-in-php)
- [PortSwigger: Basic server-side template injection (code context)](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-code-context)
- [PortSwigger: SSRF with blacklist-based input filter](https://portswigger.net/web-security/ssrf/lab-ssrf-with-blacklist-filter)
- [PortSwigger: File path traversal, validation of file extension with null byte bypass](https://portswigger.net/web-security/file-path-traversal/lab-validate-file-extension-null-byte-bypass)
- [PortSwigger: Remote code execution via server-side prototype pollution](https://portswigger.net/web-security/prototype-pollution/server-side/lab-remote-code-execution-via-server-side-prototype-pollution)
- [PortSwigger: Insecure deserialization](https://portswigger.net/web-security/deserialization) · [Server-side template injection](https://portswigger.net/web-security/server-side-template-injection) · [SSRF](https://portswigger.net/web-security/ssrf)
- [Server-Side Prototype Pollution Scanner (Burp extension)](https://portswigger.net/bappstore/c1d4bd60626d4178a54d36ee802cf7e8) · [Burp Decoder](https://portswigger.net/burp/documentation/desktop/tools/decoder)
- [botesjuan — Burp Suite Certified Practitioner Exam Study](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study)
- [Mystery Pool — the tool these rolls came from]({% post_url 2026-10-04-mystery-pool %})

*All techniques shown were performed on an isolated lab environment (PortSwigger's Web Security Academy). Running these attacks against systems you don't own or have written authorization to test is illegal in most jurisdictions.*
