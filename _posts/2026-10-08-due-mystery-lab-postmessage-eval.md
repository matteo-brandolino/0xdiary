---
layout: post
title: "Veloce, poi per niente veloce: due Mystery Lab nella stessa sessione"
date: 2026-10-08
categories: [web-security, walkthrough]
tags: [portswigger, mystery-lab, dom-based, xss, postmessage, eval, javascript, burp-suite]
excerpt: "Ho tirato due mystery lab uno dietro l'altro: il primo era risolto prima ancora che finissi di scrivere il payload, il secondo mi ha richiesto un segno meno per trasformare una stringa JavaScript chiusa in codice che potessi davvero eseguire."
lang: it
page_id: two-mystery-labs-postmessage-eval
permalink: /posts/two-mystery-labs-postmessage-eval/
---

Il primo lab ci ha messo meno tempo a essere risolto di quanto me ne sia servito per scrivere il payload. Il secondo aveva bisogno di un segno meno per funzionare, e anche dopo aver capito perché, non riuscivo a spiegarmelo in meno di quattro passaggi. Entrambi vengono dallo stesso pool a due topic, tirati uno dietro l'altro nella stessa sessione, e quel distacco tra i due è tutto il post.

I lab arrivano da [Mystery Pool]({% post_url 2026-10-04-mystery-pool-strumento %}), lo strumento che ho costruito per tirare un lab solo dai topic che scelgo io. Pool impostato su DOM-based e XSS, come in ogni sessione mystery. PortSwigger continua a scegliere il lab vero e proprio. Io restringo solo le probabilità.

## Setup

Niente scan di Burp sul primo lab, niente DOM Invader: non c'era nulla da scansionare. Il secondo aveva invece una vera casella di ricerca, quindi stavolta lo scanner ha avuto qualcosa da masticare.

## Primo lab: un listener che non controlla proprio nulla

Nessuna login, nessun campo per i commenti. Solo una pagina con uno spazio pubblicitario vuoto, in attesa di contenuto da qualche altra parte — che è esattamente il tipo di posto in cui un sito reale cede il controllo allo script di qualcun altro.

### 1. Dritto alle Sources, senza deviazioni

Non c'era niente in cui scrivere, quindi non c'era nemmeno niente in cui uno scanner potesse infilare un payload. Sono andato dritto al JavaScript della pagina. Un file, un listener:

```javascript
window.addEventListener('message', function(e) {
    document.getElementById('ads').innerHTML = e.data;
});
```

Questo è l'intero controllo. Nessun `e.origin`, nessuna validazione della forma del messaggio, nessun `try/catch` che faccia finta di essere prudente. `e.data` finisce in `innerHTML` com'è. Leggere questo codice ha richiesto meno tempo di quanto ne serva per decidere se aprire prima DOM Invader.

### 2. Testare dalla console prima di costruire qualsiasi cosa

Prima di toccare l'exploit server, ho testato il sink direttamente dalla console del lab:

```javascript
window.postMessage('<img src=x onerror=alert(document.domain)>', '*')
```

L'alert è partito subito. `alert(document.domain)` invece di `alert(1)` apposta — confermava che il codice girava davvero nell'origine del lab, non in un contesto isolato che fa comparire un popup per caso.

### 3. Il tag `<script>` che sapevo già di non dover usare

Sapevo già, da un lab precedente, di non provare `<script>alert(1)</script>` qui — ma conoscere la regola e capirla sono due cose diverse, e volevo la seconda. La risposta è un dettaglio del parser, non un filtro: quando assegni una stringa a `innerHTML`, il browser la fa passare per il *fragment parsing*, un algoritmo separato da quello che sta leggendo il resto del documento. Quell'algoritmo costruisce un nodo `<script>` reale — lo vedi nel DOM — ma lo marca internamente come già eseguito, così il motore lo salta quando il frammento viene agganciato all'albero live. Non è sanitizzazione. È una regola del parser, pensata apposta per questo caso.

E non è nemmeno una regola universale su `innerHTML`. `document.write()` usa il parser vero del documento, quello che sta ancora leggendo il resto della pagina, e uno script scritto tramite quello gira eccome. Stesso payload, sink diverso, risultato opposto. E niente di tutto questo tocca attributi come `onerror` o `onload` — non sono elementi script, sono handler valutati quando il loro evento scatta davvero, indipendentemente da come l'elemento sia finito nel DOM. È esattamente per questo che il payload con `<img>` qui sopra funziona e un tag `<script>` no.

### 4. Consegna, e fatto

Obiettivo: `print()`. Il body dell'exploit server:

```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')"></iframe>
```

`onload`, perché il listener esiste solo dopo che la pagina del lab ha finito di caricare. `'*'` come target origin, perché chi manda il messaggio non decide nulla su chi dovrebbe riceverlo — quel controllo spetta a chi lo riceve, e qui non c'è. Store, deliver, risolto. Più veloce della sezione di setup del secondo lab.

## Secondo lab: Burp ha detto "certain", e non era tutta la storia

Questo era un piccolo blog: una lista di post con titoli, riassunti e immagini di copertina, e una casella di ricerca sopra la lista. Una casella di ricerca è un campo di input, il che significa che finalmente lo scanner di Burp aveva qualcosa da masticare.

### 1. Uno scan, e un report che si contraddiceva da solo

Lo scan attivo è tornato con un finding di reflected XSS su `/search-results`, confidence **Certain**, severity **Information**. Queste due parole messe una vicino all'altra sono tutta la lezione di questo momento: Confidence è quanto Burp è sicuro che quello che ha trovato sia reale — qui, che il parametro `search` torni nella risposta completamente inalterato, canary incluso. Severity è un'affermazione separata su quanto quel fatto sia davvero exploitable. Burp era certo che il sintomo fosse reale e, nello stesso report, non voleva chiamarlo pericoloso — e diceva esattamente perché, in quel paragrafo di boilerplate che ho quasi letto senza leggerlo:

> *The response does not state that the content type is HTML. [...] No modern browser will interpret the response as HTML. However, the issue might be indirectly exploitable if a client-side script processes the response and embeds it into an HTML context.*

### 2. Verificare quello che lo scanner mi aveva già detto

La risposta:

```
HTTP/2 200 OK
Content-Type: application/json; charset=utf-8

{"results":[],"searchTerm":"livic<script>alert(1)</script>pv1hc"}
```

`application/json`. Navigare direttamente su quell'URL con un payload nella query string non fa nulla — il browser legge il content type dichiarato e mostra il body come dato, mai come markup. La riflessione era reale. Da sola, però, non era un attacco.

### 3. La riga che sembrava colpevole e non lo era

Il codice client-side che chiama questo endpoint:

```javascript
function search(path) {
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            eval('var searchResultsObj = ' + this.responseText);
            displaySearchResults(searchResultsObj);
        }
    };
    xhr.open("GET", path + window.location.search);
    xhr.send();

    function displaySearchResults(searchResultsObj) {
        var searchTerm = searchResultsObj.searchTerm
        var h1 = document.createElement("h1");
        h1.innerText = searchResults.length + " search results for '" + searchTerm + "'";
        // ...
    }
}
```

Per un secondo il sospetto sembrava ovvio: `h1.innerText = ... + searchTerm`. Non lo è. `innerText` non parserà mai del markup — non c'è nessun contesto HTML in cui sfuggire, quindi non c'è nulla da rompere. Il sink vero sta due righe sopra `displaySearchResults`, prima ancora che `searchTerm` esista come variabile: l'intero body grezzo della risposta viene passato a `eval()`. Non `JSON.parse`, che avrebbe trasformato quello stesso testo in dato inerte. `eval()`, che lo trasforma in istruzioni.

### 4. Una virgoletta, scappata correttamente

Prima prova: `search=test"`. Risposta:

```json
{"results":[],"searchTerm":"test\""}
```

La virgoletta torna come `\"`. Il server fa l'escape delle virgolette prima di incollarle nella risposta. Per un minuto sembrava la fine della storia — se l'unico carattere che chiude una stringa è protetto, non c'è modo di uscirne prima del previsto, e stavo quasi per passare a un altro lab.

### 5. "È scappato" era la lettura sbagliata

Non era la fine della storia, perché la funzione di escaping fa esattamente una cosa: cerca `"` e ci mette un `\` davanti. Non dice nulla sul `\` in sé. L'ho testato direttamente — `search=\`, un singolo backslash, nient'altro:

```
Content-Length: 31

{"results":[],"searchTerm":"\"}
```

Trentuno byte, esattamente il template più un backslash intoccato — li ho contati per esserne sicuro, perché a quel punto non mi fidavo più della mia stessa lettura della risposta. Il mio backslash passa dritto. E un backslash mio, piazzato proprio prima della `"` che il server sta per scappare, cambia il significato di quell'escape: `\` (il mio) + `\"` (l'inserimento del server) si legge dentro `eval()` come `\\` — un solo backslash letterale, escape completamente consumato — seguito da una `"` che non è più protetta da nulla. Chiude la stringa in anticipo. L'escaping del server diventa lo strumento che rompe il suo stesso escaping.

### 6. Costruire il payload, un pezzo che non fa nulla alla volta

Payload completo: `\"-alert(1)}//`. L'ho costruito in quattro pezzi, e tre su quattro non producono nulla da soli — non un alert parziale, non una pagina mezza rotta, solo silenzio, perché `eval()` deve parsare l'intera stringa prima di eseguirne anche un solo carattere. Un errore di sintassi in un punto qualsiasi uccide tutto, non solo la parte dopo l'errore.

**Pezzo 1 — rompere la stringa:** `\"` → dentro `eval()`, la stringa si chiude dopo aver consumato un backslash letterale, lasciando un `"}` sciolto senza nulla che lo chiuda. `SyntaxError: Unterminated string literal`. Niente parte.

**Pezzo 2 — aggiungere il codice vero:** `\"-alert(1)` → la stringa si chiude ancora in anticipo, `-alert(1)` si legge come continuazione valida dell'espressione, ma il `"}` finale del template è ancora lì, spaiato. Ancora `SyntaxError`. `alert(1)` è scritto lì, sintatticamente corretto, e non viene ancora eseguito.

**Pezzo 3 — chiudere l'oggetto:** `\"-alert(1)}` → l'oggetto letterale ora si chiude correttamente. Ma il template aggiunge il suo `"}` subito dopo il mio, e quella virgoletta avanzata apre una stringa senza niente che la chiuda. `SyntaxError`, di nuovo.

**Pezzo 4 — commentare il resto:** `\"-alert(1)}//` → tutto quello che segue `//` su quella riga — la virgoletta di troppo, la graffa di troppo, il punto e virgola finale del template — scompare in un commento. Finalmente tutto parsa, e `alert(1)` viene eseguito.

### 7. Perché il segno meno è load-bearing

Dopo che la stringa si chiude in anticipo, il valore di `searchTerm` non è ancora finito — un valore di proprietà è una singola espressione, e una stringa chiusa accanto a un `alert(1)` sciolto senza nulla in mezzo non è un'espressione, sono due frammenti senza connettore. Il `-` li incolla in una sola cosa: `"\\" - alert(1)` è una sottrazione, e per calcolarla JavaScript deve valutare entrambi i lati — il che significa chiamare `alert(1)`, a prescindere da cosa significhi il numero risultante (non significa nulla; è `NaN`). Quasi ogni operatore binario avrebbe fatto lo stesso lavoro. Una virgola no: dentro un oggetto letterale, una virgola dopo un valore dice "qui inizia una nuova proprietà", e `alert(1)` da solo non è una coppia `"chiave": valore` — quella strada scambia solo un errore di sintassi con un altro.

Testato direttamente nella barra di ricerca, con il JavaScript del lab stesso a fare l'eval: l'alert è partito, e il lab si è segnato come risolto — nessun exploit server necessario stavolta, perché la fonte del bug è l'URL della pagina stessa, non un messaggio da un'altra origine.

## Cosa hanno in comune i due lab

Nessuno dei due bug riguardava il fatto che l'input arrivasse alla pagina — arrivava sempre, in entrambi i lab, immediatamente. La domanda che contava era in che contesto finiva, e cosa quel contesto è davvero disposto a trattare come codice.

`innerHTML` traccia quel confine in un modo specifico: eseguirà senza battere ciglio un handler `onerror`, e non eseguirà un tag `<script>`, per una regola del parser pensata esattamente per quello. `eval()` non traccia nessun confine — ha un solo cancello, ed è "l'intera stringa parsa come sintassi valida", senza nulla sul da dove venga quella sintassi o cosa faccia una volta eseguita. Conoscere il sink vuol dire conoscere esattamente dove sta il suo confine particolare. Assumere che ogni sink tracci il confine nello stesso punto è il modo in cui un payload corretto per un bug non fa assolutamente nulla contro l'altro.

## Exam e field

**Primo lab — postMessage in innerHTML**

| | Exam | Field |
|---|---|---|
| Cosa riconoscere | un listener `message` che assegna `e.data` direttamente a `innerHTML`, senza nessun controllo su `e.origin` | widget di terze parti, spazi pubblicitari, embed — qualunque cosa prenda contenuto da una finestra che non controlli |
| Dove va il tempo | la consegna: il timing di `onload`, il target `'*'`, un payload con event handler invece di un tag `<script>` | capire cosa può fare davvero la sessione dell'utente loggato una volta eseguito lo script |
| Trappola comune | provare `<script>alert(1)</script>` per abitudine e non ottenere nulla, senza nessun errore a spiegare perché | assumere che le protezioni sul framing (`X-Frame-Options`) blocchino anche `postMessage`; non lo fanno, è un meccanismo separato |
| Limite reale | un singolo obiettivo scriptato | la vittima deve caricare una pagina che controlli tu; se il target blocca il framing, `window.open` mantiene funzionante la stessa chiamata al messaggio |

Difesa: controllare `e.origin` contro una lista esplicita di origini permesse prima di toccare `e.data`, e non assegnare mai il contenuto di un messaggio direttamente a `innerHTML` — renderlo come testo, non come markup.

**Secondo lab — parametro di ricerca in eval()**

| | Exam | Field |
|---|---|---|
| Cosa riconoscere | codice client-side che chiama `eval()` (o `new Function()`) su una risposta del server, invece di `JSON.parse` | endpoint in stile JSONP fatti a mano e vecchi client API precedenti alla diffusione di `JSON.parse` |
| Dove va il tempo | trovare l'unico carattere che la funzione di escaping ha dimenticato, e mantenere il resto del file sintatticamente valido dopo | il payload è banale una volta che hai un breakout funzionante; il buco nell'escaping è il vero rompicapo |
| Trappola comune | fidarsi di "Confidence: Certain" come prova di exploitability e saltare la riga di severity sotto | trattare il silenzio di uno scanner su un endpoint come prova che sia sicuro, quando lo scanner non ha mai visto chi consuma quella risposta lato client |
| Limite reale | dipende interamente da quali caratteri l'app target sceglie di scappare; un'app diversa, un buco diverso | se la funzione di escaping protegge anche i backslash, questa strada esatta si chiude — il bug avrebbe bisogno di un carattere di breakout diverso o di un sink completamente diverso |

Difesa: non costruire mai JavaScript eseguibile concatenando stringhe non fidate — non con `eval`, non con `new Function`, non con `setTimeout("stringa")`. `JSON.parse` esiste proprio perché "parsare il dato" e "eseguire il codice" non possano mai diventare la stessa operazione per errore.

## Cosa viene dopo

L'intero exploit del secondo lab si appoggiava su un buco specifico: la funzione di escaping gestiva `"` e si dimenticava `\`. È un buco stretto, quasi accidentale — `JSON.stringify` non lo avrebbe lasciato, perché scappa entrambi correttamente per progettazione. Il prossimo test utile non è questo lab di nuovo; è trovarne uno dove l'escaping è davvero completo, e vedere se il breakout deve spostarsi su un carattere diverso, o se `eval()` come sink smette del tutto di essere exploitable una volta che la gestione delle stringhe è fatta a modo. Non conosco ancora la risposta, e preferisco scoprirla piuttosto che indovinarla.

## Takeaways

- Le regole di un sink sono specifiche di quel sink. `innerHTML` non eseguirà un tag `<script>` ma eseguirà un attributo `onerror`; `eval()` non blocca né l'uno né l'altro, controlla solo che l'intera stringa parsi.
- Confidence e Severity di Burp rispondono a due domande diverse — "è reale" e "importa" — e un report può rispondere sì alla prima e no alla seconda nello stesso paragrafo.
- `eval()` non dà credito parziale. Un payload corretto per tre pezzi su quattro produce un errore di sintassi silenzioso, non un risultato parziale, perché l'intera stringa deve parsare prima che una sola parte venga eseguita.
- Una funzione di escaping che gestisce correttamente un carattere speciale può comunque ignorare il carattere che permette di neutralizzare quello stesso escaping — testa l'input più piccolo possibile prima di testare l'exploit completo.

## Risorse utili

- [PortSwigger Web Security Academy: DOM-based vulnerabilities](https://portswigger.net/web-security/dom-based)
- [PortSwigger Web Security Academy: Cross-site scripting](https://portswigger.net/web-security/cross-site-scripting)
- [MDN: Window.postMessage()](https://developer.mozilla.org/docs/Web/API/Window/postMessage)
- [MDN: Element.innerHTML](https://developer.mozilla.org/docs/Web/API/Element/innerHTML)
- [MDN: eval()](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/eval)
- [Un messaggio dal nulla: DOM XSS tramite postMessage]({% post_url 2026-10-05-xss-dom-postmessage-mystery-lab %}) — il precedente lab su postMessage, che almeno faceva finta di validare la forma del messaggio

*Tutte le tecniche mostrate sono state eseguite in un ambiente di laboratorio isolato (PortSwigger's Web Security Academy). Attaccare sistemi che non possiedi o per cui non hai un'autorizzazione scritta è illegale nella maggior parte delle giurisdizioni.*
