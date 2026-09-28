---
layout: post
title: "My BSCP study plan was training the wrong skill"
date: 2026-09-28
categories: [web-security, concept]
tags: [bscp, burp-suite, portswigger, study-plan, interleaving, spaced-repetition]
excerpt: "I wrote a study plan that would make me great at solving labs once I knew the category — and the exam never tells you the category."
lang: en
page_id: bscp-study-plan-interleaving
permalink: /posts/bscp-study-plan-interleaving/
---

I had a study plan. Eighteen vulnerability categories mapped across three exam stages, a repo cloned, a checklist ready to tick. It felt like the responsible thing to do before touching a single lab.

Then I went looking into how people actually build diagnostic intuition — the kind of skill where you have to recognize what's wrong before you're allowed to fix it, which is precisely what medicine, debugging, and penetration testing have in common — and had to admit my plan was quietly optimizing for the wrong exam. Not the real one. The one where someone tells you "this is XSS" before you start.

The Burp Suite Certified Practitioner exam does not do that.

## Setup: what I'm actually preparing for

BSCP is PortSwigger's hands-on practical certification. Three stages — Foothold, Privilege Escalation, Data Exfiltration — six hours, real labs, and no category label anywhere. You get an application and a clock. Figuring out what's actually wrong with it *is* the exam, not a preamble to it.

I'm using [botesjuan's BSCP study repo](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study) as the backbone: a category checklist mapped onto the three stages, plus Python verification scripts I'm under strict instructions from myself not to open until after I've tried a lab manually — using them first would mean the lab never actually counted as attempted. No exam date booked yet. That's deliberate: I'd rather commit to a date once the plan has survived contact with actual labs, not before.

What follows is version 2 of that plan. Version 1 lasted about as long as it took to think seriously about how expert diagnosticians — radiologists, debuggers, pentesters — actually build that kind of intuition. At which point it turned out to be wrong in four specific ways.

## 1. Blocking by category trains the wrong reflex

The v1 instinct was obvious: finish all the XSS material, then move to SQL injection, then CSRF, working stage by stage until Foothold was "done" before starting Privilege Escalation.

It's a comfortable way to study. It's also backwards. If every lab you attempt already comes labeled — "this is the XSS session" — you never practice the part that's actually hard: looking at an unlabeled application and forming a hypothesis about what's wrong with it. Category blocking trains "solve XSS once told it's XSS." The exam tests "recognize XSS was the answer all along."

Fix: mix categories from day one, even in week one. Use the Mystery Lab Challenge — which randomizes the category — as early as possible, before the review phase is even finished. It'll feel less mastered than blocking does. That's the point; it's measuring the actual skill instead of a proxy for it.

## 2. Phases are a scheduling illusion

v1 had three clean phases: study everything, then practice everything, then simulate the exam. Each category's material got touched once and left alone until the next phase happened to circle back to it.

Except nothing "happens to circle back" on its own. Once I move from an SQLi week to an XSS week, SQLi just stops. No plan to revisit it means no revisiting happens, and whatever got built in week 2 quietly erodes by week 5.

Fix: spacing is explicit now, not incidental. Every category gets revisited every 4–10 days, tracked in a table with a "next review" date that has to actually get filled in. Closer to 4 days while a category is still shaky (hint level 3–4), stretching toward 10 once it's stable. A plan that doesn't force the revisit date onto paper doesn't survive contact with week 3.

## 3. A hint scale without a cost isn't a hint scale

v1 had the right shape — four hint levels, from "no help" to "full solution" — but no friction attached to climbing it. Which meant climbing it was free, and free things get used the moment a lab feels uncomfortable.

Fix: every level now has a time-box before you're allowed to go up (20–30 minutes at level 1, 10–15 more before level 2, another 10 before level 3), and — the part that actually matters — before moving up a level you have to write one line: what you tried, where you got stuck, and whether you think you could have gotten there with more time or you were genuinely missing information. That sentence is where the learning happens. The payload that follows it is just execution.

## 4. Not every category matures at the same speed

v1 assumed a single finish line: once the material is "done," it's done everywhere. But some categories are going to click after two attempts and some after six, and treating them identically means either under-practicing the hard ones or wasting cycles re-drilling the ones already solid.

Fix: fading is per category. Two consecutive Level-1 (no-hint) solves and a category graduates from active practice to spaced maintenance review — 10–14 days instead of 4–10. Access Control might get there in a week. Deserialization probably won't, and that's data, not failure.

## The pattern underneath all four

Every one of these fixes points at the same thing: the exam is a recognition task wearing an exploitation-skill costume. Nobody fails BSCP because they can't write a working UNION payload. They fail it because they spend forty minutes convinced a login form is vulnerable to SQLi, when the actual bug three requests later is a CSRF token that was never validated. Blocking, monolithic phases, a free hint ladder, and uniform pacing all optimize for "can execute the technique." None of them touch "can tell which technique applies before anyone says so."

## What comes next

This week is Phase 0 — no labs, just enough per-category signal ("what clues make me suspect this before the app confirms it") to stop guessing blind. Then Phase 1 starts: interleaved practice, spaced reviews, the hint ladder with its new cost attached. The categories where the gap between "I could execute it" and "I recognized it first" turns out to be largest are presumably where the next few posts come from.

## Takeaways

- Blocking practice by category is comfortable and trains the wrong skill — the exam never announces the category, so neither should your practice.
- Spacing has to be scheduled explicitly, as a date on a table, not assumed to happen because you'll "get back to it."
- A hint scale only teaches you something if climbing it costs a time-box and forces a one-line self-explanation before you go up.
- Different categories mature at different speeds — track it per category, not as one global "am I ready" flag.
- The real skill BSCP tests is recognition under uncertainty, not execution once the answer is already labeled.

## Useful references

- [botesjuan — Burp Suite Certified Practitioner Exam Study](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [bscp.guide](https://bscp.guide)
- Micah van Deusen's blog post mapping BSCP categories to exam stages — the one to check when a lab feels impossible
