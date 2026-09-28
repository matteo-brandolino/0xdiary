---
layout: post
title: "I miei primi passi con la SQL Injection su DVWA: cosa ho rotto e cosa ho imparato"
date: 2026-05-18
categories: [web-security, walkthrough]
tags: [sqli, dvwa, mariadb, http, owasp]
excerpt: "Un resoconto onesto del primo modulo SQLi di DVWA — inclusi i due errori stupidi su cui ho perso più tempo che sull'attacco vero e proprio."
lang: it
page_id: sql-injection-dvwa-first-steps
permalink: /posts/sql-injection-dvwa-primi-passi/
---

La SQL Injection è uno di quegli attacchi che leggi un centinaio di volte e pensi di aver capito. Poi avvii una macchina vulnerabile, lanci il classico `' OR 1=1--` e ti ritrovi con un bellissimo **400 Bad Request**. È lì che capisci che teoria e pratica sono due animali diversi.

Questo post è il diario della mia prima sessione seria su **DVWA** (Damn Vulnerable Web Application), un'applicazione web deliberatamente vulnerabile costruita per l'addestramento alla sicurezza. Non è un tutorial patinato: è il resoconto dei tre o quattro errori veri che ho fatto e di cosa ognuno mi ha insegnato. L'ho scritto per fissarmi in testa le lezioni, e perché penso che questo tipo di resoconto sia più utile — sia per chi legge sia per chiunque stia valutando il mio lavoro — di un walkthrough pulito dove tutto funziona al primo tentativo.

## Il setup

DVWA gira in Docker con una riga:

```bash
docker run --rm -it -p 80:80 vulnerables/web-dvwa
```

Login di default `admin / password`, poi **Setup/Reset DB**, poi **DVWA Security → Low**. Iniziamo dal modulo **SQL Injection**, che presenta un form con un singolo campo "User ID".

Il codice server-side vulnerabile, al livello Low di DVWA, è essenzialmente:

```php
$id = $_REQUEST['id'];
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
```

Concatenazione diretta dell'input utente nella stringa SQL. Nessun escaping, nessun prepared statement. Il punto di partenza canonico.

## Errore #1: `1'--` e l'apice orfano

Primo tentativo, dritto dal manuale:

```
?id=1'--&Submit=Submit
```

Risposta del server:

```
You have an error in your SQL syntax; check the manual that corresponds to
your MariaDB server version for the right syntax to use near ''' at line 1
```

Mi aspettavo un bypass. Ho ottenuto un errore di sintassi. Cos'è successo?

La query costruita è:

```sql
SELECT first_name, last_name FROM users WHERE user_id = '1'--';
```

In **MariaDB/MySQL**, il commento `--` richiede **uno spazio (o tab/newline) dopo i due trattini** per essere riconosciuto come commento. Senza lo spazio, `--` è solo testo, e l'apice di chiusura (`'`) del mio payload originale resta lì spaiato alla fine. Da qui l'errore.

Questa è una di quelle differenze tra dialetti SQL che i tutorial raramente evidenziano: PostgreSQL accetta `--` senza spazio finale, MariaDB no. Sapere quale DB c'è sotto il target conta.

**Lezione:** i payload generici esistono, ma il DBMS ha le sue regole lessicali. Vale la pena memorizzare le tre forme di commento supportate da MySQL/MariaDB:

| Sintassi | Note |
|--------|-------|
| `-- ` (con spazio finale) | Richiede spazio dopo i trattini |
| `#` | Commento di riga, non richiede spazio finale |
| `/* ... */` | Commento inline, utile per l'evasione dei WAF |

## Errore #2: il 400 Bad Request

Lezione imparata, sistemo il payload aggiungendo lo spazio:

```
?id=1'-- &Submit=Submit
```

Nuova sorpresa: **HTTP 400 Bad Request**. Il server questa volta non mi dà nemmeno un errore SQL — rifiuta direttamente la richiesta.

Guardo la request line:

```
GET /vulnerabilities/sqli/?id=1'-- &Submit=Submit HTTP/1.1
```

C'è uno spazio letterale dentro l'URL. In HTTP, la request line ha tre campi separati da spazi: metodo, target, versione del protocollo. Apache vede tre spazi invece di due, non riesce a capire dove finisce il target e inizia la versione — request line malformata, 400.

Avevo dimenticato che **gli spazi negli URL vanno percent-encoded**: `%20`, oppure `+` nella query string. Lavorando direttamente nella barra degli indirizzi del browser, questa codifica non avviene sempre automaticamente — dipende dal browser e dal contesto.

Tre alternative che funzionano:

```
?id=1'--%20&Submit=Submit     # encoding esplicito
?id=1'--+&Submit=Submit        # + decodificato come spazio nella query string
?id=1'%23&Submit=Submit        # # come commento, nessuno spazio necessario
```

**Lezione:** il payload SQL e il trasporto HTTP sono due livelli distinti. Un payload sintatticamente perfetto potrebbe non arrivare mai al DB se rompi il protocollo di trasporto lungo la strada. È il momento in cui capisci che ti serve uno strumento come **Burp Suite** o **curl**, dove puoi controllare la richiesta byte per byte senza che il browser riscriva le cose sotto i tuoi piedi.

Con curl:

```bash
curl "http://localhost/vulnerabilities/sqli/?id=1'--+&Submit=Submit" \
  -b "PHPSESSID=...; security=low"
```

## Il primo bypass funzionante

Una volta risolti entrambi i problemi, ho provato il payload canonico:

```
?id='+OR+1=1--+
```

E finalmente: tutti e cinque gli utenti di DVWA riversati sulla pagina (admin, gordonb, 1337, pablo, smithy). Soddisfazione genuina.

Come funziona, nel dettaglio. La query costruita è:

```sql
SELECT first_name, last_name FROM users WHERE user_id = '1' OR 1=1-- ';
```

Succedono tre cose insieme:

1. **L'apice rompe il contesto stringa.** Lo sviluppatore si aspettava che il mio input restasse dentro gli apici singoli, ma io chiudo quegli apici in anticipo. Da quel punto in poi, quello che scrivo viene interpretato come codice SQL, non come dato. *Questo è il cuore di ogni injection*: passare dal contesto "dato" al contesto "codice".

2. **`OR 1=1` riscrive la logica del WHERE.** In logica booleana, `A OR B` è vero se almeno un lato è vero. `1=1` è una tautologia — vera per ogni riga. Quindi `user_id = '1' OR 1=1` è vero per ogni riga della tabella, e il `WHERE` smette di filtrare. La `SELECT` restituisce l'intera tabella.

3. **`-- ` neutralizza la coda.** Dopo il mio input, il codice originale aveva ancora `'` e `;` in attesa. Il commento di riga li manda al macero così non rompono la sintassi.

Questa triade — **rompi il contesto, inietta logica, neutralizza la coda** — è il pattern generale di quasi ogni SQLi. Ciò che cambia da caso a caso è il contesto che devi rompere: stringa tra apici singoli, stringa tra apici doppi, intero senza apici, dentro un `LIKE`, dentro `IN()`, dentro `ORDER BY`. Ognuno richiede la sua apertura e chiusura.

## Cosa rende DVWA Low così vulnerabile e cosa rende Impossible sicuro

Vale la pena confrontare il codice sorgente tra i vari livelli di difficoltà — è lì che impari il lato difensivo.

**Low** — concatenazione diretta, nessuna difesa:

```php
$id = $_REQUEST['id'];
$query = "SELECT ... WHERE user_id = '$id';";
```

**Medium** — `mysqli_real_escape_string`, ma il campo è un intero senza apici, e POST invece di GET (che è solo security through obscurity):

```php
$id = mysqli_real_escape_string($conn, $_POST['id']);
$query = "SELECT ... WHERE user_id = $id;";  // nessun apice → l'escape è inutile
```

L'escape degli apici non fa nulla qui perché non ci sono apici da chiudere. Inietti direttamente con `1 OR 1=1-- `.

**Impossible** — prepared statement con parametri tipizzati:

```php
$id = $_GET['id'];
$data = $db->prepare('SELECT ... WHERE user_id = (:id) LIMIT 1;');
$data->bindParam(':id', $id, PDO::PARAM_INT);
$data->execute();
```

L'input non viene mai concatenato nella stringa SQL. Il driver lo invia al DB come parametro separato, e il DB sa già che è un dato, non codice. Non c'è apice da chiudere, nessun contesto da rompere. È strutturalmente non sfruttabile — non per qualche filtro intelligente, ma perché dato e codice non si incontrano mai.

Questa è la lezione difensiva più importante: **non si previene la SQL injection con filtri o blacklist, la si previene separando codice e dati.** Tutto il resto (escaping, sanitizzazione, WAF) è mitigazione di riserva.

## Takeaways dalla prima sessione

Ho passato più tempo a debuggare due errori "stupidi" — lo spazio di commento mancante e lo spazio non codificato nell'URL — che a eseguire davvero l'attacco. Il che è probabilmente la parte più realistica dell'esperienza: nel pentesting vero, la maggior parte del tempo non si spende a inventare exploit creativi, si spende a capire perché qualcosa non funziona come dovrebbe.

Tre takeaway concreti:

- **Conoscere il DBMS sottostante conta.** Stesso "SQL", dialetti diversi, sintassi dei commenti diversa, funzioni built-in diverse. `database()`, `version()`, `@@hostname` non si chiamano allo stesso modo ovunque.
- **HTTP è un livello che può tradirti.** Browser, URL encoding, parser del server: tutte cose che possono distruggere un payload corretto prima che arrivi all'applicazione. Imparare a usare Burp/curl presto ripaga subito.
- **Ogni SQLi è una variazione dello stesso pattern.** Rompi il contesto, inietta logica, neutralizza la coda. Capire il contesto sintattico in cui atterra il tuo input è il vero esercizio mentale.

Il prossimo passo è usare la query iniettata per **leggere davvero i dati** — non solo bypassare un filtro. È lì che entra in gioco `UNION SELECT`, ed è dove la sessione diventa genuinamente interessante. Ne parlo nel prossimo post.

## Riferimenti utili

- [DVWA — repository ufficiale](https://github.com/digininja/DVWA)
- [PortSwigger Web Security Academy — SQL Injection](https://portswigger.net/web-security/sql-injection) (gratuito, ottimo)
- [OWASP — SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [MariaDB — Comment Syntax](https://mariadb.com/kb/en/comment-syntax/)

---

*Tutte le tecniche mostrate sono state eseguite in un ambiente di laboratorio isolato via Docker sul mio computer locale. Attaccare sistemi che non possiedi o per cui non hai un'autorizzazione scritta è illegale nella maggior parte delle giurisdizioni.*
