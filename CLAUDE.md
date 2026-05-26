# 0xdiary — Claude working instructions

## What this project is

A personal blog documenting a hands-on journey through web security: DVWA, HackTheBox, CTFs, bug bounty concepts, tool exploration. Posts are written in English. The author is learning in public — honestly, with mistakes included.

## Voice and tone

**Companion on the journey, not a lecturer.**
The reader is assumed to be in a similar position: curious, learning, and also occasionally defeated by a typo. The narrator is never above the struggle. "We" and "you" appear naturally — not as rhetorical devices, but because the author genuinely means "you probably did this too."

**Irony: open and direct.**
When something stupid happened, say it. Name it clearly. Use it as the entry point for the technical point. The humor comes from honesty, not from downplaying the mistake. The classic pattern:

> Yes, I spent 40 minutes debugging a typo. This is fine. This is what hacking feels like 90% of the time, and anyone who tells you otherwise is lying.

Do not soften this with hedges like "perhaps" or "in retrospect." Say it plainly.

**Emotions are narrative, not decoration.**
The frustration of not understanding something, the AHA moment when it clicks, the genuine (slightly embarrassing) satisfaction when an attack works — these are part of the story, not asides. Name them explicitly when they're real:

> And then it worked. Five users dumped on screen. I actually said 'yes' out loud to an empty room. That's the feeling I'm chasing.

Do not manufacture emotions. Only include them when they actually happened and serve the point.

**Tone calibration:**
- Dry wit: yes
- Sarcasm toward the reader: never
- Sarcasm toward the author's own past mistakes: always welcome
- Motivational language ("you can do it!"): no
- Condescension ("as you surely know"): no

---

## Post structure

Posts are technical diaries, not tutorials. The difference: a tutorial tells you the right way to do something; a diary tells you what actually happened, including the detours, and extracts the lesson from the detour.

**Preferred structure:**
1. A short, punchy opening that names the core tension (expected X, got Y, that gap is the post)
2. Setup — environment, tool, context — kept brief, just enough to orient
3. The actual session: numbered mistakes or moments, each with what happened, why it happened, and the concrete lesson
4. A synthesis section — what pattern emerged, what this generalizes to
5. A "what comes next" paragraph — where the thread leads
6. Takeaways as a short bulleted list (3–5 items max)
7. Useful references section
8. Disclaimer (mandatory — see below)

**The opening paragraph sets the tone for everything.** It should not summarize the post. It should put the reader inside the moment of confusion or failure. Start in the middle, not at the beginning.

---

## Technical writing rules

- Code always in fenced code blocks with the correct language tag
- Commands shown exactly as typed, including flags
- Tables for comparison data (e.g., SQL comment syntax across dialects)
- When explaining a concept, go from "what the tool expected" to "what actually happened" to "why" — in that order
- Never assume the reader knows something that wasn't just explained; never explain something obvious
- HTTP and SQL are always treated as separate layers that can each fail independently — make this explicit when relevant
- DB dialect differences (MySQL vs PostgreSQL vs MariaDB) should always be flagged when they affect payload behavior

---

## Things that make a post good here

- A mistake that took longer to debug than the actual attack
- A moment where the error message told you exactly what was wrong but you didn't read it right
- A comparison between a vulnerable and a safe implementation (not just "use prepared statements" — show the code)
- Explicit naming of the *pattern* being exploited, not just the specific instance
- Ending with what's unresolved — the next question the session opened

## Things to avoid

- Clean walkthroughs where everything works on the first try — they're less useful and less true
- "As we can see" — show, don't announce
- Padding: long background sections that delay getting to the actual content
- Generic advice without grounding in the specific session ("always sanitize inputs" means nothing without the context)
- Clickbait titles or manufactured urgency

---

## Mandatory disclaimer

Every post that demonstrates an offensive technique must end with this (or equivalent):

```
*All techniques shown were performed on an isolated lab environment. Running these attacks against systems you don't own or have written authorization to test is illegal in most jurisdictions.*
```

---

## Language

English. Consistent American or British, but not mixed. Technical terms stay in their original form (SQL injection, not "SQL iniezione"). Tool names are exact (Burp Suite, not "burp", not "BurpSuite").

---

## Frontmatter format

```yaml
---
layout: post
title: "..."
date: YYYY-MM-DD
categories: [web-security, walkthrough]   # or: [web-security, concept], [web-security, tools]
tags: [specific, tags, here]
excerpt: "One honest sentence about what this post is actually about."
---
```

The excerpt should be the kind of sentence you'd say to a colleague: "I spent two hours trying to understand why my UNION payload kept breaking, turns out I had the column count wrong and the error message was telling me the whole time."
