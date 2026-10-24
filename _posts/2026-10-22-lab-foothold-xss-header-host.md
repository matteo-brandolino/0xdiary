---
layout: post
title: "Quattro Lab, Una Sola Domanda: Cosa Può Diventare Questo Input?"
date: 2026-10-22
categories: [web-security, walkthrough]
tags: [portswigger, dom-xss, reflected-xss, host-header, password-reset-poisoning, document-write, param-miner, burp-suite]
excerpt: "Param Miner ha girato per undici minuti, mandato 1.232 richieste, ed è tornato con zero findings su un header che era effettivamente avvelenabile — perché l'unico posto dove rompeva qualcosa era un'email che lo strumento non ha mai guardato."
lang: it
page_id: foothold-xss-host-header-labs
permalink: /posts/lab-foothold-xss-header-host/
---

`Completed request with key ... 1 of 1 in 681 seconds with 1232 requests, 0 candidates and 0 findings`. Undici minuti, oltre mille richieste, e il verdetto di Param Miner era: niente da segnalare. Ci avrei anche creduto, se non sapessi già che quell'header funzionava — semplicemente non avevo guardato nell'unico posto dove contava davvero. Quello scarto tra "lo strumento non ha trovato niente" e "il bug è reale" è il filo che attraversa tutti e quattro i lab di questa sessione.

## Setup

Quattro lab di PortSwigger, rollati uno dopo l'altro, tutti sotto lo stesso ombrello: ottenere un foothold come utente, lo step prima di trovarsi dentro qualcosa di privilegiato. Sono partito puntando vagamente su DOM XSS, auth, attacchi all'header Host e cache poisoning, lasciando che ogni lab mi dicesse all'arrivo quale di queste categorie si applicasse davvero — nessun form di login significava niente auth, nessun `Cache-Control` sulla pagina iniziale significava niente cache poisoning. Quello che restava, lab dopo lab, si è rivelato più interessante delle etichette di categoria.

## La sessione

### 1. Un listener postMessage che si fida di tutto quello che riceve

DOM Invader l'ha segnalato subito: un listener `message` senza nessun controllo su `e.origin`, che fa il parsing di qualsiasi JSON arrivi e fa uno switch su un campo `type`. Un case, `load-channel`, prende un `url` direttamente dal messaggio e lo assegna a `src` di un iframe — nessuna validazione sullo scheme.

```js
case "load-channel":
    ACMEplayer.element.src = d.url;
    break;
```

Consegnato via exploit server:

```html
<iframe src="https://TARGET-LAB/" onload="this.contentWindow.postMessage(JSON.stringify({type: 'load-channel', url: 'javascript:alert(document.domain)'}), '*')"></iframe>
```

Questo pattern esatto — dati non attendibili da postMessage che finiscono in un sink che non controlla lo scheme che gli viene passato — l'ho già raccontato per intero in un [post precedente]({% post_url 2026-10-12-xss-dom-messaggi-web-url-javascript %}), quindi qui non rifaccio tutta la sessione. Stesso bug, stessa correzione (controllare `e.origin`, validare lo scheme dell'URL prima che tocchi `src`), lab risolto in un paio di minuti questa volta, perché sapevo già cosa cercare.

### 2. Lo scanner lo trova, ma la logica di escaping è la vera lezione

Una barra di ricerca, scansionata con Burp Scanner, ha restituito un finding di reflected XSS. Il contesto riflesso era rivelatore:

```js
var searchTerms = 'zzz\'<>';
```

Quel `\'` conta più di `<>`. Il server fa l'HTML-encoding (o lascia passare) le parentesi angolari, ma fa attivamente l'escape dell'apice singolo — sostituisce ogni `'` che trova con `\'`. L'errore è in quello che *non* viene fatto l'escape: il carattere backslash stesso.

Il payload che ha effettivamente risolto il lab, decodificato dalla richiesta che ha funzionato:

```
zzz'<>40186\';alert(1)//500
```

Ripercorrendo cosa fa il server con questo input: scansiona l'input per i caratteri `'` e mette un `\` davanti a ciascuno che trova. Il mio input contiene già un `\` proprio davanti a un `'`. Il server non riconosce quel backslash come niente di speciale — reagisce solo agli apici — quindi aggiunge il suo escape davanti all'apice che ho mandato, ottenendo:

```
zzz'<>40186\\';alert(1)//500
```

Incollato nel template (`var searchTerms = '...';`), il parser JS legge `\\` come un singolo backslash con escape (consuma entrambi i caratteri come un'unica unità), il che significa che l'apice immediatamente dopo non è più "protetto" da niente — chiude davvero la stringa. Tutto quello che segue viene parsato come JavaScript vivo: `;alert(1)` fa partire il popup, e `//` commenta qualsiasi cosa il `';` di chiusura del template avrebbe altrimenti contribuito, quindi non resta nessuna sintassi orfana su cui inciampare.

La parte su cui vale la pena fermarsi: l'escaping delle quote non è la *validazione* delle quote. Se il carattere di escape stesso non è nella blocklist, un attaccante che manda una sua copia decide lui quale apice nella stringa finale è quello "vero".

### 3. Un finding CSRF che non era il bug, e uno scanner che non poteva vedere quello reale

Questo lab aveva un flusso `forgot-password` e la parola "middleware" nel nome — da prendere alla lettera. Una scansione dell'endpoint ha fatto emergere un finding informativo di CSRF (endpoint non autenticato, sessione identificata solo dal cookie, da manuale). Interessante, ma con severity "Information" per un motivo: non era il bug vero, solo un effetto collaterale del fatto che l'endpoint non richiede auth in partenza.

L'angolo reale era quale header si fida il backend quando costruisce l'URL assoluto per il link di reset. In un'architettura con un reverse proxy davanti all'app, il proxy spesso preserva l'host originale del client in `X-Forwarded-Host` mentre riscrive `Host` per il suo instradamento interno — quindi il backend, se deve costruire un link per un'email, può fidarsi specificamente di `X-Forwarded-Host` perché assume che il proxy l'abbia già validato. Non l'ha fatto; l'ha solo inoltrato.

Ho puntato "Guess headers" di Param Miner sulla richiesta per scoprire esattamente quale header legge il backend, e ho ottenuto il risultato che ha aperto questo post: `0 candidates and 0 findings`, dopo 1.232 richieste in undici minuti. Ecco perché non è davvero una contraddizione: Param Miner lavora facendo il diff della risposta HTTP contro un baseline. Se un header cambia qualcosa dentro la risposta, compare come candidato. Ma l'effetto di un `X-Forwarded-Host` avvelenato qui non è affatto nella risposta alla richiesta `forgot-password` — la pagina di conferma è identica a prescindere da cosa mandi. L'effetto finisce nell'**email** di reset password, un canale che lo strumento non tocca mai. Zero differenze osservabili nella risposta significa zero findings, che il bug sia lì o no.

Controllare direttamente il client email del lab ha chiuso la questione: mandando la richiesta per `carlos` con `X-Forwarded-Host` puntato al mio exploit server, il mio dominio è finito dritto nel suo link di reset. Ho recuperato il suo token dal log di accesso dell'exploit server, preso la struttura di una richiesta `reset-password` legittima (quella generata per il mio account `wiener`, quindi conoscevo la forma esatta), sostituito il token di Carlos a quello mio, e resettata la sua password. Account takeover, senza indovinare password, senza XSS — solo un header di cui il backend si fidava più di quanto dovesse.

### 4. Stesso sink, regole di escaping completamente diverse rispetto al lab 2

Una pagina e-commerce con una funzione "check stock" per ogni prodotto — esca plausibile da SSRF — ma il bug vero era nel selettore del negozio accanto:

```js
var store = (new URLSearchParams(window.location.search)).get('storeId');
document.write('<option selected>'+store+'</option>');
```

`document.write` di nuovo, stessa funzione del modello mentale del lab 2 — ma un contesto completamente diverso, e quella differenza è tutto il punto. Nel lab 2, l'equivalente di `store` finiva dentro un literal di stringa JS, quindi l'escaping che contava era sulle quote. Qui, `store` finisce come contenuto HTML grezzo tra due tag, con zero encoding applicato. Non c'è nessuna quota da neutralizzare, nessun attributo da cui uscire — è già seduto in un punto dove qualsiasi tag gli passi viene parsato come tag.

```
?storeId=<script>alert(document.domain)</script>
```

Funziona nello specifico perché `document.write` viene chiamato mentre il browser sta ancora parsando il documento originale. Uno `<script>` iniettato così finisce nello stream di parsing live e viene eseguito come se fosse sempre stato parte del codice sorgente della pagina — a differenza, per esempio, di assegnare la stessa stringa a `innerHTML`, dove un tag `<script>` iniettato è inerte per design. Stessa funzione sink della categoria mentale del lab 2 ("HTML costruito per concatenazione di stringhe"), stesso segnale d'allarme generale, ma il bypass non ha niente in comune: il lab 2 richiedeva un backslash per sconfiggere un escape; questo non richiedeva niente, perché non c'era nessun escaping da sconfiggere.

## Il pattern

Quattro lab, quattro meccanismi completamente diversi, e sotto tutti una sola domanda: *in che contesto finisce questo input, e chi lo legge in quel contesto lo impone davvero, o lo assume soltanto?* Un messaggio cross-window assumeva che qualsiasi mittente fosse legittimo. Una routine di escaping delle quote assumeva che un attaccante non si sarebbe portato il suo backslash. Un flusso di password reset assumeva che un header inoltrato fosse pre-validato perché qualcosa a monte sembrava dovesse averlo fatto. Una concatenazione di stringhe dentro `document.write` assumeva che nessuno si sarebbe accorto che non c'era nessun encoding.

| Lab | Dove finisce l'input | Cosa si è rotto |
|---|---|---|
| 1 — postMessage | un'assegnazione a `iframe.src` | nessun controllo sull'origin, nessuna validazione dello scheme |
| 2 — ricerca | un literal di stringa JS | le quote erano escapate, il backslash no |
| 3 — forgot-password | un URL email costruito dal server | header fidato senza riverificarlo |
| 4 — selettore negozio | HTML grezzo via `document.write` | nessun encoding applicato |

L'altra metà del pattern riguarda gli strumenti, non il codice: Param Miner e Burp Scanner fanno entrambi il loro lavoro osservando la risposta HTTP per un cambiamento. È una tecnica corretta e utile per una fetta enorme di bug — e non dice assolutamente nulla su un bug il cui unico effetto osservabile vive altrove, come un'email in uscita. "Lo scanner non ha trovato niente" è un'affermazione sul canale che lo scanner guardava, non un'affermazione sull'applicazione.

## Exam e field

| | Exam | Field |
|---|---|---|
| Cosa riconoscere | sink `document.write`/concatenazione di stringhe nel view-source, e nomi di header come `X-Forwarded-Host` vicino a qualsiasi cosa che mandi un'email con un link | gli stessi sink compaiono in filtri prodotto legacy, selettori di negozio/locale, e qualsiasi flusso "forgot password" dietro un reverse proxy o una CDN |
| Dove va il tempo | leggere l'*esatta* logica di escaping dall'output riflesso (quale carattere è escapato, quale no) invece di tirare a caso un payload generico; capire che uno scan automatico con 0 findings non significa che il bug di header-trust non esista | confermare se l'app costruisce davvero URL assoluti da un header controllato dal client — la maggior parte dei framework moderni usa di default un base URL hardcoded, quindi questo bug è meno comune di quanto il lab lasci pensare, ma devastante quando presente |
| Trappola comune | tirare un payload standard `'-alert(1)-'` contro ogni filtro di escaping delle quote e arrendersi quando non scatta, invece di controllare cosa colpisce davvero la routine di escape | fidarsi del "nessun finding" di uno scanner automatico su qualsiasi cosa il cui effetto non si rifletta nella risposta HTTP — email, log, effetti collaterali asincroni, webhook |
| Limite reale | ogni lab offre un punto di riflessione visibile o una casella email di test su cui confermare | la vittima deve comunque ricevere e cliccare l'email di reset password, o caricare una pagina che faccia partire il postMessage — niente di tutto questo è un attacco "senza interazione" |

Note di difesa, una per lab: validare `event.origin` prima di fidarsi di qualsiasi cosa arrivi da `postMessage`, e non far mai toccare a un sink come `src` i dati del messaggio senza controllarne lo scheme; usare encoding context-aware (un escape JSON-safe, non una blocklist di quote) ogni volta che un input utente finisce dentro un literal di stringa JS; non costruire mai URL assoluti per email o redirect da un header fornito dal client — usare invece un base URL configurato server-side; e fare l'encoding dell'output allo stesso modo a prescindere che vada dentro un attributo, una stringa, o markup HTML grezzo, perché "è solo `document.write`" non è un confine di sicurezza.

## Cosa viene dopo

Il lab 3 è quello che voglio spingere più avanti: l'exploit ha funzionato perché il client email del lab mi rendeva visibile direttamente il link avvelenato. Su un target reale non avrei quella vista — lavorerei sui log dell'exploit server e su congetture su cosa renderizzi davvero il template dell'email. Quello è lo scarto tra "posso avvelenare questo header" e "posso esfiltrare in modo affidabile un token da qualcuno che clicca un link che non vedo mai consegnato", e non è qualcosa che un lab così contenuto testi davvero.

## Takeaways

- L'escaping delle quote non è la validazione delle quote — se il carattere di escape stesso non viene neutralizzato, un attaccante può fornire la sua copia e decidere quale apice nell'output chiude davvero la stringa.
- Lo stesso sink (`document.write`, `innerHTML`, qualsiasi cosa) può richiedere un bypass completamente diverso a seconda che il tuo input finisca dentro una stringa JS, un attributo HTML, o markup grezzo — non portare un payload da un contesto all'altro senza riverificare dove finisce davvero.
- Uno strumento di header-bruteforcing che segnala zero findings significa solo zero differenze nella *risposta HTTP* — non dice niente su effetti che emergono altrove, come un'email, una riga di log, o un webhook downstream.
- `X-Forwarded-Host` (e simili) esistono per un uso legittimo da proxy, ed è esattamente per questo che i backend a volte si fidano di loro più di quanto si fidino del `Host` rivolto al client — controlla quale dei due alimenta davvero una decisione rilevante per la sicurezza.
- Un finding informativo di uno scanner (come un CSRF flag secco su un endpoint non autenticato) merita un'occhiata e poi si va avanti — non è automaticamente il bug che il lab sta testando.

## Riferimenti utili

- [PortSwigger Web Security Academy: Cross-site scripting](https://portswigger.net/web-security/cross-site-scripting)
- [PortSwigger Web Security Academy: DOM-based vulnerabilities](https://portswigger.net/web-security/dom-based)
- [PortSwigger Web Security Academy: HTTP Host header attacks](https://portswigger.net/web-security/host-header)
- [Param Miner su GitHub](https://github.com/PortSwigger/param-miner)
- [DOM XSS via messaggi web e un URL JavaScript]({% post_url 2026-10-12-xss-dom-messaggi-web-url-javascript %})

*Tutte le tecniche mostrate sono state eseguite in un ambiente di laboratorio isolato (PortSwigger Web Security Academy). Attaccare sistemi che non possiedi o per cui non hai un'autorizzazione scritta è illegale nella maggior parte delle giurisdizioni.*
