---
layout: post
title: "How I stopped collecting write-ups and started building a knowledge base"
date: 2026-06-02
categories: [tools, methodology]
tags: [ai, notebooklm, claude, study-system, portswigger, methodology]
excerpt: "I had five write-ups sitting in a folder and no idea what to do with them besides publish them. The answer turned out to involve two AI tools doing completely different jobs."
---

Five sessions in, I had a folder of write-ups and a vague sense that I was doing the right thing. I was documenting the mistakes, extracting the lessons, publishing them. Solid habit.

Then I tried to remember exactly which lab had introduced me to the inverted boolean oracle on MariaDB — the one where `CASE WHEN 1/0` returns NULL instead of crashing, so your oracle runs backwards from what you expected. I knew I'd written about it. I couldn't find it in under a minute. I could have searched the files, but that's not the point. The point is: five sessions of hard-won knowledge, and I couldn't query it.

A write-up published but not queryable is just a public diary. Useful for the reader who finds it, not particularly useful to me three months from now.

That's the problem I was actually trying to solve when I started looking at study tooling.

## What I wanted vs what I built

The instinct was to throw everything at Claude and be done with it. Claude knows SQLi. I can ask it things. Why add complexity?

Because Claude is stateless across sessions. It doesn't remember that last week I confused error-based with blind, or that I keep forgetting to check the HTTP layer before blaming the SQL payload, or that MariaDB's comment syntax has tripped me up twice now. Every session starts cold. That's fine for explaining concepts — it's not fine for building on a week of sessions where I've accumulated specific gaps and specific patterns.

What I needed wasn't a smarter tutor. I needed memory.

The answer was **NotebookLM** connected to Claude via MCP — which means Claude can create notebooks, add sources to them, and query them directly. The setup is one command:

```bash
claude mcp add --scope user notebooklm notebooklm-mcp
```

Then restart, authenticate with Google, and the tools are there. The authentication part is worth flagging: `notebooklm-mcp` uses Playwright under the hood to drive a browser login. If you haven't used Playwright before, it'll ask you to install the browsers first:

```bash
playwright install chromium
python3 -m notebooklm login
```

After that it works. The session persists for weeks.

## Two notebooks, not one

First instinct: one notebook per topic. SQLi, XSS, SSRF — each with its own notebook containing everything I knew about that topic.

Wrong instinct.

The better structure is by *type of content*, not by topic:

**Theory notebook** — sources are the official PortSwigger articles. Static, authoritative, not mine. I query this when I need to understand a concept before a session, or generate flashcards before sitting down with Burp.

**Lab notebook** — sources are my write-ups, added as text after each session. Dynamic, personal, growing. I query this when I want to know what I actually encountered in practice.

The reason to separate them: when you mix theory and personal experience in one notebook, queries return confused answers. "How does EXTRACTVALUE work?" gets you a blend of textbook explanation and fragments of my specific DVWA session that don't quite fit together. Separated, the theory notebook gives you the clean mechanism; the lab notebook tells you that MariaDB truncates EXTRACTVALUE output at 31 characters and here's the exact payload I used to recover the last byte.

Different questions, different notebooks.

## The lab notebook is the one that matters

The theory notebook is someone else's content. The PortSwigger articles are excellent — I didn't write them, I just ingested them.

The lab notebook is mine. It knows that I consistently confirm injection in the wrong SQL context first. It knows I've been bitten by the HTTP/SQL layer confusion twice (a correct payload that never reached the database because the URL encoding was wrong). It knows that the first time the credential dump worked I said something out loud to an empty room that I'm not going to repeat here.

That's the content you can't get from a textbook. And it's the content that's most useful to me specifically, because it maps exactly to where my gaps are.

Six months from now I can ask: *"in which labs did I use hex encoding to bypass quote-based filters, and what was the context?"* The notebook will answer with my own examples. Not generic examples — mine, with the specific error messages and the specific moment the bypass clicked.

A write-up without the notebook is just a public record. The notebook without the write-ups is just someone else's reference. Together they're a queryable record of your own experience.

## The write-up habit is the connective tissue

This only works if you actually write up each session. Which sounds obvious until you finish a lab at 11pm, you're tired, the attack worked, and the last thing you want to do is document it.

The argument for doing it anyway: the specific details that make a write-up worth querying — the exact error message that looked like something else, the five minutes you spent blaming the wrong layer, the precise moment the oracle flipped — those are the first things to go. Not the technique. The texture.

Write it the same day, while the texture is still there. Then add it to the lab notebook. Two minutes of work that compounds across every future session.

## What comes next

The workflow I've landed on:

1. Query the theory notebook for a summary before a session
2. Generate flashcards, spend twenty minutes on them
3. Do the lab by hand — no solutions, no shortcuts
4. If stuck, reason with Claude — not "give me the payload" but "why isn't this working"
5. Write the session up that evening
6. Add the write-up to the lab notebook
7. Periodically generate a quiz from the lab notebook and see what's actually stuck

Step 4 is where the two tools work together in the most concrete way. Claude doesn't know my lab history, but it knows the technique. I know my lab history but I'm stuck on the specific instance. The gap between those two things is usually where the understanding lives.

The open question is whether this scales beyond SQLi. The next topic is authentication vulnerabilities, which involves a lot more state — session tokens, cookie flags, OAuth flows — and I'm not sure yet whether one theory notebook per topic stays manageable or turns into a maintenance problem. That's a question for next month.

---

*The notebooklm-mcp project lives at [github.com/teng-lin/notebooklm-py](https://github.com/teng-lin/notebooklm-py). All labs mentioned were performed in isolated environments on local machines.*
