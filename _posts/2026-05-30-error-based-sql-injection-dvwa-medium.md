---
layout: post
title: "Error-based SQL Injection on DVWA Medium: when the cookie lies to you"
date: 2026-05-30
categories: [web-security, walkthrough]
tags: [sqli, error-based, dvwa, mariadb, burp-suite, hex-encoding]
excerpt: "I thought I was testing Medium level for ten minutes. I was still on Low. A duplicate cookie was the culprit, and once I fixed it, I found out that mysqli_real_escape_string() on an unquoted integer is basically decorative."
---

*This is Part 2 of the error-based injection session. [Part 1]({% post_url 2026-05-30-error-based-sql-injection-dvwa-low %}) covered the technique on DVWA Low — EXTRACTVALUE, the 31-character limit, and CASE WHEN on MariaDB. This part picks up from the cliffhanger: I thought I had switched to Medium, but the cookie had other plans.*

---

Switching DVWA from Low to Medium should be straightforward: DVWA Security → set Medium → save. Except for ten minutes nothing worked the way I expected — the form still looked like Low's text field, the security level in the page footer said `low`, and the payload that had just worked perfectly was still working perfectly.

Which was the problem.

## The cookie that kept lying to me

The culprit was in the cookie header:

```
Cookie: security=low; PHPSESSID=...; security=medium
```

Two `security` values. The browser was sending the old `security=low` cookie alongside the new `security=medium` one, and the server was picking up the first. Burp was intercepting requests that looked like Medium but were still executing as Low. The payload worked because I was testing the wrong thing entirely.

Fix: clear all DVWA cookies, log in fresh, set Medium, start a new intercept. After that the footer correctly showed `Security Level: medium` and the form had changed to a `<select>` dropdown with values 1–5.

Ten minutes lost to a duplicate cookie. This is fine.

## The dropdown is not a defense

Medium replaces the text input with a `<select>` element offering only values 1 through 5. The intention is to limit what the user can submit. The problem: the `<select>` is enforced only in the browser. The server accepts whatever the POST body contains.

In Burp Repeater, you change `id=1` to `id=anything` regardless of what the dropdown offers. Client-side input restrictions are not a security control. They are a suggestion.

## Discovering injection without seeing the source code

On Medium you don't know in advance whether the input uses quotes or not. The approach: probe both contexts and read the behavior.

**`id=1'` via POST:**

```
You have an error in your SQL syntax... near '\''
```

The error shows `\'` — the quote was escaped by `mysqli_real_escape_string()`. String-based injection with quotes: blocked.

**`id=1 AND 1=1--+` via POST:** user visible.

**`id=1 AND 1=2--+` via POST:** page empty.

Two different behaviors from `1=1` and `1=2`. Injection confirmed in integer context — no quotes needed.

You can deduce the context without seeing the source: if `intval()` had been applied, `1 AND 1=1` would have been truncated to `1` and both conditions would have returned the same result. They didn't — so the input reached the SQL parser intact and unquoted.

## Why `mysqli_real_escape_string()` fails here

The Medium source code does this:

```php
$id = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $_POST['id']);
$query = "SELECT first_name, last_name FROM users WHERE user_id = $id;";
```

`$id` is not inside quotes in the query. `mysqli_real_escape_string()` escapes characters that are dangerous inside a quoted string — but there is no quoted string. The input lands directly in the SQL as a bare integer. Escaping quotes on an unquoted integer is like putting a lock on a door with no walls.

## Error-based on Medium — and the hex bypass

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

## Conditional rendering with hex

The boolean oracle from the blind session works here too, adapted for integer context and hex encoding:

```
id=1 AND SUBSTRING((SELECT password FROM users WHERE user=0x61646d696e),1,1)=0x35--+&Submit=Submit
```

- `0x61646d696e` = `admin`
- `0x35` = `5`

Response: user visible. First character confirmed `5`. Page shown vs page empty is the oracle — same blind boolean concept, but routed through a context where quotes are blocked and hex is the workaround.

## Takeaways

- **`mysqli_real_escape_string()` on an unquoted integer is useless.** No string context, nothing to escape. The defense is applied in the wrong place.
- **Hex encoding bypasses quote-based filters.** `0x61646d696e` is `admin` without a single quote in sight. When string literals are blocked, hex literals work.
- **Client-side input restrictions are not security controls.** A `<select>` dropdown stops a casual user. Burp ignores it completely.
- **Cookie conflicts can silently break your test environment.** Check what security level the server is actually receiving, not what you think you set. The footer doesn't lie — the cookie might.

## Useful references

- [PortSwigger — SQL injection with conditional errors](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors)
- [PayloadsAllTheThings — Error-based injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#error-based-injection)
- [MariaDB — EXTRACTVALUE](https://mariadb.com/kb/en/extractvalue/)

---

*All techniques shown were performed on an isolated lab environment running in Docker on my local machine. Running these attacks against systems you don't own or have written authorization to test is illegal in most jurisdictions.*
