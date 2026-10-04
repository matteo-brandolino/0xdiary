---
layout: post
title: "Mystery Pool: a random lab from only the topics you choose"
date: 2026-10-04
categories: [web-security, tools]
tags: [portswigger, mystery-lab, javascript, samesite, cookies, github-pages]
excerpt: "Mystery Lab gives you one topic or all twenty, so I built a small static page that rolls a lab from a pool you pick, and found out how little a page on another site is allowed to know about you."
lang: en
page_id: mystery-pool
permalink: /posts/mystery-pool/
---

Mystery Lab gives you two choices: one topic, or all twenty. I had just finished the DOM-based and XSS labs, and what I wanted was a random lab from exactly those two topics, and nothing else. The button has no field for that. So I built the field myself.

## What Mystery Pool is

Mystery Pool is a static page: no backend, no account, no tracking. You tick the topics you want to practise, pick a level, and press Roll. A new tab opens on a lab picked at random from those topics. PortSwigger still chooses the lab itself. The page only chooses the category.

It exists for one case: you know some topics well enough to want random practice inside them, without rolling the whole catalogue. Everything it doesn't do is deliberate.

The link it opens is the same one the official button builds, so you need to be logged in to PortSwigger in the same browser. The browser supplies your session. The page never sees it.

The result is at [matteo-brandolino.github.io/mystery-pool](https://matteo-brandolino.github.io/mystery-pool/), and the code is in [the repo](https://github.com/matteo-brandolino/mystery-pool).

## How it works

There are four parts, and each one copies a rule from PortSwigger's own widget:

1. **Topic data.** A file with the twenty categories and the levels each one exists at. I copied it from the widget's HTML, and the README has the command to refresh it.
2. **Eligibility.** A category can be rolled at a level only if that level appears in its list. "Any" removes the constraint. If no topic in your pool exists at the chosen level, the button is disabled and the page says why.
3. **The roll.** It picks uniformly among the eligible categories and builds the launch URL by string concatenation:

   ```js
   const launchUrl = (categoryId, level) =>
     PS_ORIGIN + '/academy/labs/launchMystery?categoryId=' + categoryId +
     '&level=' + level + '&referrer=' + REFERRER;
   ```

   It isn't built with `URLSearchParams`, because the original doesn't encode the referrer, and the slashes have to stay literal to produce the same request.
4. **Sharing.** The pool and the level live in the URL hash, so a pool can be bookmarked or sent to someone. Opening a shared link selects the pool. It never rolls by itself, because a link should not drop you into a lab.

## What it can't do

- **It rolls a topic, not a lab.** PortSwigger picks the lab inside the category, so the same lab can come up twice, and the page can't avoid it.
- **The odds aren't even across labs.** The roll is uniform across topics. A category with three labs is as likely as one with twelve.
- **It doesn't know what you've completed.** The session cookie is `HttpOnly` and belongs to another site, so the page can't read it.
- **It can't hide the topic from the address bar.** The launch URL contains `categoryId`, so the new tab shows it for as long as the launch is pending.

That last point is the one I spent the most time on, and it shaped the whole build.

## Moments from the build

### 1. The button only takes one value

The page doesn't contain the button. It contains an empty placeholder, which a script fills by posting to `/api/widgets`. The script that comes back builds the link from two single `<select>` elements, using `selectedOptions[0].value`. One value from one select. The client has no concept of a list, so the missing option isn't a server rule. It's absent from the code. Reading the handler took five minutes. Probing the server would not have answered the question.

### 2. Anonymous probes can't see past the login

I sent three requests without being logged in: `categoryId=2`, `categoryId=2,3` and `categoryId=-1`. All three got the same `302` to `/users?returnurl=...`. The authentication check runs before the parameters are bound, so from outside I learned nothing about how the server parses `2,3`. The test that answers it needs a logged-in session, and I haven't run it.

### 3. The cookie decides what the page can know

The session cookie is `HttpOnly`, `Secure`, `SameSite=Lax`, scoped to `.portswigger.net`, with a twelve-hour max-age. That combination sets the boundary of the tool:

- A plain link to the launch URL is a top-level navigation, so the browser attaches the session. The link works.
- A `fetch` to the same URL is cross-origin, has no CORS headers, and `Lax` doesn't send cookies on that kind of request. It doesn't work.

So the page can produce the link, but it can't know whether you're logged in, and it can't know which labs you've finished. That's why the `onlyCompleted` flag is never sent. The page has no way to know what it would mean.

### 4. My first version printed the answer

The first version showed the generated URL under the button, next to the category name. Looking at it on screen, the problem was obvious. The URL says `categoryId=11`, and in a mystery lab that's exactly what you don't want to read before you start. I removed the URL and the category from the page. The name sits behind a collapsed "Reveal the topic" toggle, for after you've finished.

### 5. The final address is out of reach too

After the launch redirects, the lab lives on another origin. I checked whether the endpoint sends CORS headers, so the page could read where the redirect ends: the preflight returns 404 and there are no `Access-Control-*` headers. Reading `location` on a window from another origin throws. The page can't show you the lab's address. Only the tab can, and the tab is what you're looking at.

### 6. Two bugs in my own checks

Parts of the verification I wrote were broken in ways that made it look either fine or wrong.

- My dead-code check built a regex inside shell single quotes, where `\\b` became a literal backslash. Every function was flagged as dead. The fix was one escape, and finding it took longer than the bug deserved.
- Another check failed because its selector regex didn't match `.spoiler`. The failing check was wrong, not the page.
- The level list was sorted with `.sort()`, which compares strings. Levels 0, 1 and 2 hide the bug. A two-digit id wouldn't.

A checker is code too, and it needs a test of its own.

### 7. The waiting room I removed

The page was supposed to open the lab and keep you looking somewhere else while it generated. I built a waiting room in a second window, which would switch you to the lab after a button press or ten seconds.

The browser blocked the second window and asked for permission. When it was blocked, the lab tab stayed in front, showing `about:blank` for a few seconds while the launch request was still pending, and then the lab's address. That blank period is the part I liked, and I kept it. The category never reached the address bar in that run, but that's a timing effect, not a protection. Logged out, the redirect goes to `/users?returnurl=...categoryid=...`, and that address does show the category.

Making the waiting room reliable would have needed to know when the lab tab had finished loading, and that tab is cross-origin. I removed it.

### 8. Presets, cut

The first version saved named pools in `localStorage`. I cut them: the hash already carries the pool and the level, and a second storage layer was more to explain than it saved. Saved presets were the feature that needed the most caveats, and the least was gained by them.

## What the pattern is

A missing option in a UI is often a missing option in the client code, and reading the handler is faster than probing the server. The URL is the API: once you know the parameters, you can build any URL the UI could have built.

The browser decides what a second page can see, and the answer is mostly nothing. The session cookie travels only with top-level navigations. So a static page can send you to a lab, but it can't see your session, the labs you've completed, or the final address. Anything that has to stay secret and reach a tab will sit in that tab's address bar.

For this tool, the mystery is kept by whoever looks away from the address bar. The site can't do it for you.

## What comes next

- The logged-in test for `categoryId=2,3`. Anonymous probes can't answer it, and the answer decides whether a multi-topic roll could ever be done on the server side.
- Weighting the roll by the number of labs per category. That needs data I don't have yet.
- A bookmarklet would be able to read the final URL, because it would run on PortSwigger's own page. I left it out on purpose. It would depend on their markup, and a static companion shouldn't.

## Takeaways

- If a UI can't express an option, check the client code before assuming the server blocks it.
- An anonymous probe can't test anything that sits behind an authentication check.
- `SameSite=Lax` decides what a link can carry: enough to send you to a page, never enough for that page to know who you are.
- A tool for practice should keep the mystery out of its own UI. Whatever has to reach a tab will be visible there.

## Useful references

- [Mystery Pool repository on GitHub](https://github.com/matteo-brandolino/mystery-pool)
- [PortSwigger Web Security Academy: Mystery Lab Challenge](https://portswigger.net/web-security/mystery-lab-challenge)
- [MDN: Window.open()](https://developer.mozilla.org/docs/Web/API/Window/open)
- [MDN: Set-Cookie, the SameSite attribute](https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie#samesitesamesite-value)
- [MDN: Cross-Origin Resource Sharing (CORS)](https://developer.mozilla.org/docs/Web/HTTP/CORS)

*All techniques shown were performed on an isolated lab environment (PortSwigger's Web Security Academy). Running these attacks against systems you don't own or have written authorization to test is illegal in most jurisdictions.*
