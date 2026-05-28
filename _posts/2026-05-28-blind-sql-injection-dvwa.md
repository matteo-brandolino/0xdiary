---
layout: post
title: "Blind SQL Injection on DVWA: when the database stops talking to you"
date: 2026-05-28
categories: [web-security, walkthrough]
tags: [sqli, blind-sqli, dvwa, boolean-based, burp-suite, mariadb]
excerpt: "I tried UNION SELECT on the blind module and got nothing back. Then I spent twenty minutes asking the database yes/no questions one character at a time, and that's when I understood why sqlmap exists."
---

The previous session ended with a credential dump — five users, five MD5 hashes, the whole table. Clean, visible, satisfying. I moved to the Blind SQL Injection module expecting more of the same, typed `' UNION SELECT user,password FROM users-- +`, and got this:

```
User ID exists in the database.
```

That's it. No names, no hashes, no output. Just a single line confirming that yes, a record exists. I tried again with a different payload. Same line. I tried `OR 1=1`. Same line. The database was running my queries — the injection was working — but the application had stopped reflecting anything back to me. All that data, somewhere in there, and the page was just nodding.

This is Blind SQLi. The database still talks to your queries. It just doesn't talk to you.

## The setup

Same DVWA container, security level Low, different module: **SQL Injection (Blind)**. The vulnerable parameter is still `id` in a GET request, but the response has been stripped down to two states: *"User ID exists in the database"* or *"User ID is MISSING from the database."* That's your entire information channel.

To confirm that UNION really is useless here, I tried:

```
?id=1'+UNION+SELECT+user,password+FROM+users--+
```

Response: `User ID exists in the database.`

The injection ran. The data was there. The application just didn't care to show it. UNION is dead. You need a different approach.

## Building the oracle

With no data in the output, the only thing you can read is **behavior**. The application has two states — exists / missing — and that maps directly to true / false. That's your oracle.

First, verify it works:

```
?id=1'+AND+1=1--+    → 200, "User ID exists"     → TRUE
?id=1'+AND+1=2--+    → 404, "User ID is MISSING"  → FALSE
```

The 404 on the false case was momentarily confusing — a 404 is supposed to mean "page not found", not "your SQL condition evaluated to false." But looking at the response body, the page was there and fully rendered. DVWA deliberately returns 404 as the HTTP status for the "missing" state. It's a choice in the PHP code, not a server error. In a real target the two states might both be 200 with different text, or a redirect, or a timing difference. What matters is that they're consistently distinguishable.

Two different HTTP status codes is actually the cleaner case. The oracle is working.

## Confirming a specific user exists

Before going after the password, I tested a more targeted query — confirming that a specific user exists in the table without knowing their numeric ID:

```
?id=1'+AND+(SELECT+'a'+FROM+users+WHERE+user='admin')='a'--+
```

Logic: if the subquery returns `'a'` (which it does when `user='admin'` exists), the condition is true and the page returns 200. If the user doesn't exist the subquery returns nothing and the condition fails.

Response: 200. Admin exists. Obvious in hindsight, but the mechanism matters — this is how you confirm table and column names blind when you don't already know them. You'd run the same query structure against `information_schema`, one character at a time, to enumerate everything from scratch. It's slow. We'll get there.

## Finding the password length

The first useful extraction: how long is admin's password? Binary search on `LENGTH()`:

```
?id=1'+AND+LENGTH((SELECT+password+FROM+users+WHERE+user='admin'))>20--+   → 200
?id=1'+AND+LENGTH((SELECT+password+FROM+users+WHERE+user='admin'))>31--+   → 200
?id=1'+AND+LENGTH((SELECT+password+FROM+users+WHERE+user='admin'))>32--+   → 404
```

Length is exactly **32 characters**. Which is the length of an MD5 hash, which we already knew from the UNION session — but now we derived it blind, with no direct output, just by watching the page say yes or no.

## Extracting the first character

Now the slow part. `SUBSTRING(password, 1, 1)` returns the first character of the password. I need to figure out what that character is by asking yes/no questions about it.

Binary search on the ASCII value:

```
SUBSTRING(password,1,1)>'m'  → 404  (it's 'm' or before)
SUBSTRING(password,1,1)>'f'  → 404  (it's 'f' or before)
SUBSTRING(password,1,1)>'3'  → 200  (it's after '3')
SUBSTRING(password,1,1)>'9'  → 404  (it's '9' or before — so between '4' and '9')
SUBSTRING(password,1,1)>'6'  → 404  (between '4' and '6')
SUBSTRING(password,1,1)>'5'  → 404  (it's '5' or before)
SUBSTRING(password,1,1)='5'  → 200  ✓
```

Seven requests for one character. The first character is **`5`**.

I already knew the full hash from the previous session — `5f4dcc3b5aa765d61d8327deb882cf99`. So yes, it starts with `5`. But extracting that single character blind, through seven yes/no questions, makes the whole thing tangible in a way that reading about it doesn't.

Then I did the math: 32 characters, ~7 requests each, that's roughly 220 requests to extract one password. By hand. One payload at a time.

## Automating with Burp Intruder

At this point doing it manually stops making sense. Burp Suite's **Intruder** tab is built for exactly this — take a request, mark one position as variable, cycle through a payload list, read the results.

Setup:
1. Intercept the working request with the proxy
2. Send to Intruder
3. Mark the character being tested as the payload position — in `='§5§'`, the `5` becomes the variable
4. Payload list: the 16 hex characters (`0123456789abcdef`) since MD5 hashes only use those
5. Add a **Grep - Match** on `User ID exists in the database` — Burp adds a column with a tick for every hit

Launch, read the column, find the one tick. That's your character. Change `SUBSTRING(password,1,1)` to `SUBSTRING(password,2,1)`, repeat.

Still 32 runs. Still tedious. But each run is automated — 16 requests fired in seconds instead of 7 requests typed by hand. The grep column makes the result obvious at a glance.

## The pattern, and why tools exist

Boolean-based blind SQLi has a fixed structure that doesn't change much across targets:

1. Find two distinguishable states (the oracle)
2. Confirm the oracle is stable and injectable
3. Extract metadata: database name, table names, column names — all via `information_schema`, character by character
4. Extract the actual data: one character at a time with `SUBSTRING()`

The mechanism isn't complicated. It's just mechanical and repetitive to a degree that breaks the human doing it. After one character extracted by hand, you understand the technique. After 32, you understand `sqlmap`.

`sqlmap` does all of this automatically — oracle detection, length probing, binary search, character extraction, parallelized requests. It's not magic, it's the same queries we ran, in a loop, with a sensible search strategy. Using it without understanding what it's doing under the hood makes you dependent on a tool you can't debug when it fails. Using it *after* understanding makes you fast.

## What comes next

The next step is running `sqlmap` against the same module and watching it do in thirty seconds what took us an entire session by hand. Then: the Medium and High levels of DVWA, where the application adds filters and the payloads need to adapt.

## Takeaways

- **UNION is useless without reflection.** If the application doesn't show query output, you need a different information channel. Behavior is that channel.
- **The oracle is everything.** Two stable, distinguishable states are all you need. The cleaner the oracle, the faster the extraction.
- **Binary search matters.** A naive approach tests every character sequentially — 128 requests per character. Binary search cuts that to 7. At 32 characters the difference is ~4000 requests vs ~220.
- **Burp Intruder bridges manual and automated.** It's faster than typing payloads by hand and slower than sqlmap — but it forces you to understand each step before automating it completely.
- **You do it by hand once.** Not because it's efficient, but because you need to feel how slow it is. That's what makes you understand why sqlmap is a tool and not a shortcut.

## Useful references

- [PortSwigger — Blind SQL Injection](https://portswigger.net/web-security/sql-injection/blind)
- [PortSwigger — Boolean-based blind SQLi](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses)
- [PayloadsAllTheThings — Blind SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#blind-sql-injection)

---

*All techniques shown were performed on an isolated lab environment running in Docker on my local machine. Running these attacks against systems you don't own or have written authorization to test is illegal in most jurisdictions.*
