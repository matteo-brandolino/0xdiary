---
layout: post
title: "Filtrato per DOM, segnalato come reflected XSS"
date: 2026-10-01
categories: [web-security, walkthrough]
tags: [bscp, burp-suite, dom-invader, burp-scanner, xss, dom-based, cookie-manipulation, portswigger]
excerpt: "Ho filtrato la Mystery Lab sulle DOM vulnerabilities, ho inseguito un cookie 'last viewed product' che mi scrivevo da solo a partire da window.location — e poi Burp Scanner ha chiamato tutto reflected XSS, DOM Invader non ha visto niente, e ho dovuto capire perché l'unico strumento fatto apposta per i bug DOM fosse il più cieco dei tre."
lang: it
page_id: dom-cookie-manipulation-mystery-lab
permalink: /posts/manipolazione-cookie-dom-mystery-lab/
---

`print()` era appena partito. La finestrella di stampa del browser stava lì, prova innegabile che il mio `<script>` iniettato aveva girato. Così apro la console per ammirare i danni, scrivo `document.cookie`, e trovo il mio payload nel cookie **completamente percent-encoded** — `...&%27%3E%3Cscript%3Eprint()%3C/script%3E` — ogni parentesi angolare schiacciata in un `%3C`, ogni apice in un `%27`, la stringa più inerte che tu possa immaginare.

Un payload che era appena stato eseguito, salvato in una forma che non poteva in alcun modo eseguire. Entrambe vere, nello stesso momento, nella stessa scheda.

Lo scarto tra questi due fatti è tutto il post.

## Setup: una Mystery Lab, filtrata di proposito

La [sessione precedente](/posts/xinclude-scansione-mirata-lettura-file/) era il primo lab vero con Burp Suite Professional. Questo è il secondo, ed è la prima volta che faccio quello che [il piano di studio](/posts/piano-di-studio-bscp-interleaving/) continuava a ripetermi di fare: aprire la **Mystery Lab Challenge** e farmi dare qualcosa senza etichetta.

Solo che ho barato un po' — ho filtrato la Mystery Lab sulle **DOM-based vulnerabilities**, perché avevo appena passato un weekend a costruirci sopra una guida di studio (taint-flow, source e sink, Burp Scanner contro DOM Invader, tutta la mappa). Volevo allenare *quella* categoria. Quindi conoscevo la famiglia generale. Non conoscevo il bug specifico, il sink, né come consegnarlo — che è dove il lab vive davvero.

L'unico pezzo di teoria che vale la pena portarsi dentro: i bug DOM-based sono un **source** (un valore che influenzi — `location`, `document.cookie`, `postMessage`, …) che scorre fino a un **sink** pericoloso (`document.write`, `innerHTML`, un `href`, …). E soprattutto: quel flusso vive **nel browser, a runtime** — non nel traffico HTTP. L'ultima volta tutta la storia era nei pannelli request/response di Burp. Questa volta, davo per scontato, sarebbe stata nel DOM.

Tieni a mente questa assunzione. Alla fine è sbagliata.

## 1. Il bottone che un minuto prima non c'era

Ho camminato l'app con il proxy acceso, cliccando come un cliente annoiato, senza ancora cercare niente — solo costruendo la lista di *dove finisce il mio input*. Niente di interessante nelle pagine prodotto. Poi torno sulla home e nell'header c'è un link nuovo, accanto a **Home**:

> Last viewed product

Non c'era quando avevo caricato il sito la prima volta. È comparso solo dopo che avevo visto un prodotto. Il che significa: **l'app ha ricordato qualcosa che ho fatto.** Un pezzo di stato che all'arrivo era vuoto e ora è pieno.

È tutta qui la mossa di triage, e con il DOM non c'entra ancora niente. Una cosa che sopravvive tra un caricamento e l'altro, lato client, può stare solo in pochi posti: un cookie, `localStorage`/`sessionStorage`, o l'URL. Quindi prima di chiedermi "è un bug?", mi sono chiesto "dove vive quella memoria, e la controllo io?".

DevTools → Application → Cookies. Eccolo:

```
lastViewedProduct = https://YOUR-LAB-ID.web-security-academy.net/product?productId=1
```

Lo stato ricordato è un **URL** — l'indirizzo del prodotto che avevo appena visto. Se quell'URL viene salvato e poi riletto per costruire il link, ho entrambi i capi di un flusso da inseguire.

## 2. Il cookie non è il source

Ecco la prima cosa che un mese fa avrei sbagliato: trattare il cookie come source. Non lo è. Non ho mai digitato un cookie. Ho *visitato una pagina*. Quindi qualcosa ha trasformato la mia visita in quel cookie. View-source sulla pagina prodotto, ed eccolo in fondo:

```html
<script>
    document.cookie = 'lastViewedProduct=' + window.location + '; SameSite=None; Secure'
</script>
```

Il source è `window.location` — l'URL su cui navigo — lavato dentro un cookie. E l'URL è mio da modellare: posso appendere quello che voglio dopo `productId=1`. Il cookie sembra lo stato; il vero input controllato dall'attaccante è la location, un passo più a monte.

(Parcheggia quel `SameSite=None; Secure` per ora. Sembra boilerplate. È metà dell'exploit.)

## 3. Il sink, e la forma del break-out

Il lato write era facile. Dove viene *riletto* il cookie e rimesso nella pagina? Avevo cercato sulla home un secondo `<script>`. Non era uno script — era il link stesso, riflesso dritto in un attributo:

```html
<a href='https://YOUR-LAB-ID.web-security-academy.net/product?productId=1'>Last viewed product</a>
```

Quel valore di `href` **è** il cookie. Grezzo. Nessun encoding visibile, nessuna sanitizzazione. E lo controllo tramite l'URL del prodotto. Quindi il sink è un attributo HTML, con apici singoli, e la domanda si scrive da sola: *e se metto nell'URL qualcosa che non resta dentro gli apici?*

Rompere fuori da un attributo sono tre mosse, ognuna che chiude un livello della gabbia in cui sei:

| Pezzo | Chiude / apre | Perché |
|---|---|---|
| `'` | chiude il valore `href='…` | finché non chiudi l'apice, tutto è testo dell'attributo |
| `>` | chiude il tag `<a …>` | finché il tag è aperto, non puoi aprirne un altro |
| `<script>print()</script>` | apre il *tuo* tag | ora sei nell'HTML libero; il parser legge un `<script>` vero |

Incatenali: `'><script>print()</script>`. E `print()` non è casuale — l'obiettivo del lab (in base64 nell'header della pagina, decodificato) diceva letteralmente *"deliver an attack that calls the `print()` function in the victim's browser".* `print()` è la prova minima e innocua che "è girato JS arbitrario".

Quindi ho visitato:

```
/product?productId=1&'><script>print()</script>
```

ricaricato, e `print()` è partito. Bella soddisfazione, per circa quattro secondi.

## 4. Lo spavento dell'encoding che si è annullato da solo

Perché poi ho controllato il cookie, e il payload stava lì percent-encoded — `%27%3E%3Cscript%3E…`. Ero *sicuro* che l'avrebbe ammazzato: per un parser HTML, `%3Cscript%3E` non è un tag, sono sei caratteri innocui. Un payload salvato così non dovrebbe eseguire. E invece aveva eseguito.

Capirlo mi ha preso più tempo del break-out, e la soluzione è il punto tecnico più bello della sessione. Ci sono **due step di encoding opposti, su due layer diversi**, e si annullano:

1. **Il browser codifica in uscita.** `window.location` non restituisce a JavaScript i caratteri grezzi che ho digitato — restituisce un URL *normalizzato e percent-encoded*. Quando gira `document.cookie = … + window.location`, l'apice è già `%27`, il `<` è `%3C`, il `>` è `%3E`. Quindi il cookie salva davvero la versione codificata. È ciò che mostra la console.
2. **Il server decodifica in entrata.** Quando il browser rimanda il cookie nell'header `Cookie`, lo manda codificato. Ma il framework lato server, parsando il valore del cookie, lo **URL-decodifica** — è la convenzione standard per i valori dei cookie. Quindi il codice applicativo rivede `'><script>print()</script>` *decodificato*, e riflette quello nell'HTML.

Il payload fa un round-trip: codificato all'andata attraverso il client, decodificato al ritorno attraverso il server. Le due trasformazioni si annullano a vicenda, e il break-out sopravvive.

Ci sono arrivato solo guardando i due capi separatamente — il cookie salvato (`document.cookie` in console: **encoded**) contro l'`href` riflesso nella response (**decoded**). Se mi fossi fidato di uno solo, mi sarei raccontato una storia sbagliata: "è encoded, è morto" oppure "è decoded, qui non c'è niente". È la stessa lezione dell'[ultima volta](/posts/xinclude-scansione-mirata-lettura-file/), al quadrato — **ogni layer trasforma il dato, e leggere un layer solo non ti dice niente di certo sul prossimo.**

## 5. Rifarlo con gli strumenti di Burp — e la categoria che si sgretola

L'avevo risolto a mano. Ma tutto il senso della Mystery Lab è allenare il riconoscimento *nel modo giusto*, quindi sono tornato indietro e sono arrivato allo stesso punto con gli strumenti di audit di Burp — il metodo statico-poi-dinamico che la mia guida prescrive. È qui che il lab ha smesso di essere quello che pensavo.

**Burp Scanner.** Tasto destro sulla richiesta del prodotto → Scan → *Audit selected items* (targeted, come nel post scorso). Il finding è tornato così:

> **Cross-site scripting (reflected)** — Medium, Certain
> *The value of the `lastViewedProduct` cookie is copied into the value of a tag attribute… This input was echoed unmodified in the application's response.*

Non "DOM-based XSS". Non "DOM cookie manipulation". **Reflected XSS.** CWE-79. Burp ha un issue type separato per i finding DOM-based, e non l'ha scelto — perché ha visto il payload **riflesso nel body della response HTTP**, che è roba del server, non del DOM. La parte "DOM-based" di questo lab vive *solo* nell'unica riga che scrive il cookie (`document.cookie = window.location`). L'XSS sfruttabile è vecchia scuola, riflessione server-side — l'input arriva semplicemente in un cookie invece che in una query string.

Quindi avevo filtrato la Mystery Lab sulle vulnerabilità **DOM** e ero finito su un bug la cui metà sfruttabile nel DOM non c'è proprio. L'etichetta era mezzo depistaggio. A un esame senza etichette, questa distinzione è tutto il gioco.

**DOM Invader.** Questo è lo strumento fatto *apposta* per i bug DOM — inietta un canary nelle source e lo traccia dinamicamente fino ai sink client-side. L'ho acceso, abilitato l'iniezione del canary su source e cookie, navigato, aspettato.

Niente. Nessun source, nessun sink, nessun flusso.

La prima reazione è stata "lo sto usando male". Non era così. DOM Invader aggancia **funzioni sink lato client** dentro il browser. La riflessione che produce questa XSS avviene **sul server**, nella generazione dell'HTML. Non c'è nessun sink client-side da agganciare — quindi non c'è niente che DOM Invader possa trovare. Il suo silenzio non era un fallimento: era il risultato più informativo della sessione: *il sink non è nel DOM.* Lo strumento di cui mi sarei fidato di più per un "lab DOM" era quello che, correttamente, non vedeva niente.

## 6. "Sei sicuro?" — chiuderla nel body della response

Sarò onesto: ci ho litigato, con me stesso, sul fatto che DOM Invader fosse solo mal configurato. "DOM-based cookie manipulation" è *nel nome del lab*; sicuramente lo strumento DOM dovrebbe vederla. Teorizzare non l'avrebbe risolto. Il body della response sì.

Repeater. `GET /`, e setto a mano il cookie:

```
Cookie: lastViewedProduct=https://YOUR-LAB-ID.web-security-academy.net/product?productId=1&'><script>print()</script>
```

La response torna, e lì nel body grezzo — non il DOM renderizzato, i byte veri che il server ha mandato:

```html
<a href='https://YOUR-LAB-ID.web-security-academy.net/product?productId=1&'><script>print()</script>'>Last viewed product</a>
```

Server-side. In modo definitivo. Il tag `<script>` è nella response che il server ha generato dall'header `Cookie`. DOM Invader non aveva alcuna possibilità, e ha fatto bene a restare zitto. Il modo per chiudere un disaccordo su quale layer vive un bug è guardare il body della response, non vincere la discussione.

## 7. Il lab non era l'iniezione — era la consegna

Far partire `print()` nel mio browser non risolveva niente. L'obiettivo diceva il browser *della vittima*, via exploit server. E la vittima parte pulita: nessun cookie `lastViewedProduct`, niente di malevolo da riflettere. Il referto di Burp aveva messo nero su bianco il problema:

> *you will need to find a means of setting an arbitrary cookie value in the victim's browser… "cookie-forcing" conditions.*

Quindi il lavoro vero è un problema di ordine, fatto nel browser di qualcun altro:

1. far **scrivere** alla vittima il cookie malevolo (visitare la mia URL prodotto avvelenata), poi
2. farle **caricare** una pagina che lo riflette (così `print()` parte).

Un singolo link non basta — al primo caricamento il server riflette ancora il cookie *vecchio* e pulito; il mio viene scritto solo dopo. Serve un secondo caricamento. Un `<iframe>` orchestra entrambi:

```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/product?productId=1&'><script>print()</script>"
        onload="if(!window.x){window.x=1;this.src='https://YOUR-LAB-ID.web-security-academy.net/'}">
</iframe>
```

- **Primo load** (la `src`): la vittima apre la pagina prodotto avvelenata → `document.cookie = window.location` pianta il cookie malevolo nel *suo* browser. `print()` **non** parte ancora (il server ha riflesso il suo cookie vecchio). È il momento in cui `SameSite=None; Secure` si guadagna il posto: senza, il browser scarterebbe il cookie dentro un iframe cross-site, e tutto morirebbe qui.
- **`onload` scatta** → ripunto l'iframe su `/`.
- **Secondo load**: la vittima richiede `/` mandando ora il cookie *malevolo*; il server lo riflette nell'`href`; il parser legge `<script>print()</script>` → **`print()` gira nel browser della vittima.**
- **Il guard `if(!window.x)`**: `onload` riscatta dopo il redirect, quindi senza una sentinella entrerei in loop all'infinito. Significa "fai il redirect esattamente una volta".

Incollato nel body dell'exploit server, **Store**, **View exploit** per testarlo su di me, poi **Deliver exploit to victim**. Lab risolto — e a risolverlo è stata la coreografia, non il payload.

## Il pattern di fondo

Tre strumenti hanno guardato questo bug e hanno dato tre risposte diverse, e tutte e tre giuste — perché ognuno guardava un layer diverso:

| Strumento | Layer che vede | Verdetto qui |
|---|---|---|
| Burp Scanner | request → response del **server** | l'ha trovata: reflected XSS, Certain |
| Repeater | body grezzo della response del **server** | l'ha confermata: server-side |
| DOM Invader | sink del **DOM** (client) | non ha visto niente — correttamente |

Il bug che avevo filtrato come "DOM" era sfruttabile sul server. Lo strumento DOM è rimasto al buio, e se mi fossi fidato di lui soltanto avrei concluso "qui non c'è niente" davanti a una XSS Certain. **Uno strumento ti dice la verità solo se sai quale layer sta guardando** — e l'etichetta della categoria (DOM) puntava al layer dove il bug *non era*.

E sotto il lato write, la cosa che generalizza oltre questo singolo lab: **un cookie è input influenzabile dall'attaccante, non un dato fidato.** Questa app riflette il proprio cookie come se l'avesse scritto lei — ma il cookie lo scrive il client, da `window.location`, che controllo io. Confronta le due letture:

```javascript
// Vulnerabile: valore del cookie fidato dritto nell'HTML
element.innerHTML = '<a href="' + lastViewedProduct + '">Last viewed product</a>';

// Più sicuro: encoding in output, e verifica che sia davvero un URL same-origin
const a = document.createElement('a');
a.textContent = 'Last viewed product';
a.href = new URL(lastViewedProduct, location.origin).href; // lancia su spazzatura; href assegnato, non parsato come HTML
```

Il fix non è "sanitizza il cookie". È "smetti di trattare un cookie come se l'avessi scritto tu".

## Dove porta

Il filo aperto è il round-trip dell'encoding. Qui il client codificava e il server decodificava e si annullavano — ma è una proprietà del cookie parsing di *questo* server. La prossima domanda è dove quella simmetria si rompe: un sink che non decodifica, un source che il browser *non* normalizza (`location.hash` viene letto molto più letteralmente di `location.href`), un framework che decodifica due volte. Ognuno di questi trasforma "l'encoding si è annullato" in "l'encoding adesso è il bug". Sono i prossimi lab — ed è esattamente il tipo di filo che una Mystery Lab dovrebbe tirare.

## Takeaway

- **Non dare per scontato che la categoria punti al layer.** Ho filtrato per DOM e il bug sfruttabile era reflected XSS server-side. A un esame senza etichette, "dove vive davvero" è tutta la skill.
- **Uno strumento silenzioso ti sta comunque dicendo qualcosa.** DOM Invader non ha trovato niente perché non c'era un sink client-side — e *quello* è il finding. Sappi quale layer guarda ciascuno strumento.
- **Leggi entrambi i capi prima di credere a una storia sull'encoding.** Il cookie era salvato encoded e riflesso decoded; solo guardandoli entrambi è venuta fuori la verità (il client codifica in uscita, il server decodifica in entrata).
- **Un cookie è input dell'attaccante.** Qui è scritto lato client da `window.location` — tratta qualunque cosa rifletta il proprio cookie come se riflettesse dati non fidati.
- **L'iniezione è raramente la parte difficile — la consegna sì.** Il cookie-forcing nel browser della vittima (due load, un iframe, `SameSite=None`) era il lab vero. "A me funziona" non è "risolto".

## Riferimenti utili

- [PortSwigger — Lab: DOM-based cookie manipulation](https://portswigger.net/web-security/dom-based/cookie-manipulation/lab-dom-cookie-manipulation)
- [PortSwigger — DOM-based cookie manipulation](https://portswigger.net/web-security/dom-based/cookie-manipulation)
- [PortSwigger — DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader)
- [PortSwigger — Reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected)

---

*Tutte le tecniche mostrate sono state eseguite in un ambiente di laboratorio isolato (il Web Security Academy di PortSwigger). Attaccare sistemi che non possiedi o per cui non hai un'autorizzazione scritta è illegale nella maggior parte delle giurisdizioni.*
