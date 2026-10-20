---
layout: post
title: "Un Header che Chiama Casa, e un XSS che Stavo Inseguendo per Sbaglio"
date: 2026-10-20
categories: [web-security, walkthrough]
tags: [portswigger, mystery-lab, host-header, ssrf, dom-based, xss, postmessage, burp-suite, intruder]
excerpt: "Ho trovato due bug veri e riproducibili nello stesso form dei commenti. Solo uno dei due era la vulnerabilità vera del lab, e ho perso venti minuti sull'altro perché avevo spento l'unico strumento che me lo avrebbe detto subito."
lang: it
page_id: host-header-network-pivot-red-herring-xss
permalink: /posts/un-header-che-chiama-casa-e-un-xss-inseguito-per-sbaglio/
---

Un 504 Gateway Timeout che dice "connecting to localhost" non è un errore. È il server che ti dice, per sbaglio, esattamente cosa fa con un header che controlli tu. Ci ho creduto subito. Venti minuti dopo, in un lab completamente diverso, avevo un payload XSS vero, non escapato, seduto nel DOM, che si rifiutava di partire — e ho passato la maggior parte di quel tempo convinto che il payload fosse sbagliato, quando il bug vero stava da un'altra parte, dove non stavo nemmeno guardando.

Entrambi i lab sono usciti da [Mystery Pool]({% post_url 2026-10-04-mystery-pool-strumento %}), pool impostato su quattro topic questa volta: web cache deception, cross-site scripting, vulnerabilità DOM-based, host header attack. PortSwigger ha scelto un lab per ogni lancio, come sempre. Io ho solo ristretto da quali quattro ceste potesse uscire.

## Setup

Il primo lab aveva una pagina di login e nient'altro su cui cliccare, quindi la scan è partita su una semplice `GET /`. Il secondo era un "Mystery challenge" — nessun indizio visibile sul topic, solo un blog con i commenti, e DOM Invader per capire cosa stava davvero ascoltando.

## Lab uno: un header che si è rivelato un indirizzo di rete

### 1. Scansione del login, e una richiesta verso un host completamente diverso

La scan su `GET /` ha restituito un finding che non avevo chiesto, su una richiesta diversa: **External service interaction (HTTP)**, severity High, confidence Certain, su `POST /login`. Lo scanner aveva sostituito l'header `Host` in un replay del login con un indirizzo Burp Collaborator, e il server era andato a fare una richiesta HTTP in uscita verso quell'indirizzo. Confermato, non ipotizzato — Collaborator non segnala un forse.

Quel singolo finding dice più di quanto sembri a una prima lettura: l'applicazione — o qualcosa davanti a lei — prende l'header `Host` e lo usa per aprire una connessione di rete reale, non solo per leggerlo di nuovo in un template.

### 2. Testare la teoria apposta: `Host: localhost`

Un finding dello scanner si guadagna una verifica manuale prima di guadagnarsi una frase in un post. Ho mandato `GET /my-account` con `Host: localhost` e ho ottenuto:

```
HTTP/2 504 Gateway Timeout
Content-Length: 149

<html><head><title>Server Error: Gateway Timeout</title></head><body><h1>Server Error: Gateway Timeout (3) connecting to localhost</h1></body></html>
```

Quel messaggio di errore fa il lavoro dello scanner gratis. Non dice "invalid host" o "bad request" — dice *connecting to localhost*, al presente, come se stesse componendo un numero di telefono che gli ho passato io. Il front-end non sta validando l'header `Host` contro una lista di nomi noti. Lo usa per scegliere una destinazione e poi prova a raggiungerla. `localhost` dall'interno della loro infrastruttura non ha semplicemente nulla in ascolto sulla porta attesa, quindi resta appeso finché non rinuncia.

### 3. Localhost è un vicolo cieco. La rete interna no.

`Host: localhost` ha dimostrato il meccanismo e non ha risolto niente — non c'è nessun pannello admin in esecuzione sul loopback del proxy stesso. Ma se l'header viene letto come "quale macchina devo chiamare", la prossima mossa ovvia non è un singolo tentativo, è una scansione. Ho messo la richiesta in Intruder, impostato la posizione del payload sull'ultimo ottetto, e lanciato `192.168.0.$0$` da 0 a 255.

Un risultato ha rotto lo schema:

```
GET / HTTP/2
Host: 192.168.0.74
```

```
HTTP/2 302 Found
Location: /admin
```

Ogni altro indirizzo nel range andava in timeout oppure tornava il sito pubblico. `.74` reindirizzava dritto a `/admin` — qualcosa su quell'indirizzo interno tratta la richiesta come già autorizzata, cosa che la versione pubblica della stessa app chiaramente non fa.

### 4. Seguire il redirect, e chiudere il lab

`GET /admin` con `Host: 192.168.0.74` caricava il pannello vero: una lista utenti, un'azione delete per riga, e un token CSRF seduto nel form proprio su quella pagina. L'ho preso da lì — non dalla pagina di login, non riusato da una richiesta precedente, direttamente dalla pagina contro cui stavo per inviare, perché un token stantio di un contesto diverso è esattamente il genere di cosa che fallisce in silenzio e ti brucia i dieci minuti successivi.

```
POST /admin/delete HTTP/2
Host: 192.168.0.74
Cookie: session=...

csrf=68J2lfcefhrO1CB1zGZnYkFbbwFWcafO&username=carlos
```

`carlos` eliminato, lab risolto. L'intero attacco non ha mai toccato una sola riga di logica applicativa — è stato un valore di header, puntato prima su un vicolo cieco diagnostico, poi sull'indirizzo interno giusto.

## Lab due: un XSS che funzionava, e non era comunque il bug

### 1. Un form di commenti che mette "website" dentro un `href`

Nessuno scanner necessario per questo — il pannello Elements è bastato. Ogni nome autore di un commento è un link, e l'`href` del link viene direttamente dal campo "website" del form commenti:

```html
<a id="author" href="https://foo.com">matteo</a>
```

### 2. Due livelli di validazione, e solo uno che conta davvero

Un semplice `"><b>test</b>` non è arrivato alla pagina come mi aspettavo — c'è una validazione lato client sul campo (vuole qualcosa a forma di URL prima ancora di inviarlo), e mandare la richiesta grezza via Repeater ha mostrato che il server controlla la stessa cosa in modo indipendente. Nessuno dei due livelli è una preferenza stilistica; il secondo è quello che conta, visto che il controllo lato client deve essere vero solo nel momento in cui il browser decide di inviare, non nel momento in cui il server decide di salvare.

### 3. Un payload che comincia giusto e finisce sbagliato, apposta

Il controllo lato server si è rivelato interessato solo all'inizio del valore. Ho mandato, via Repeater:

```
https://foo" onmouseover=alert(1)
```

e il commento è tornato con questo nel DOM:

```html
<a id="author" href="https://foo.com" onmouseover="alert(1)">matteo</a>
```

Virgoletta non escapata, `href` chiuso, un attributo nuovo di zecca seduto proprio accanto. Il controllo del formato passava perché il valore inizia con `https://`; niente a valle ricontrollava o ri-encodava quello che veniva dopo. Un vero XSS da attribute injection, funzionante, confermato nel DOM.

### 4. Passare il mouse, niente che succede, e venti minuti a guardare la cosa sbagliata

Ho mosso il mouse sopra il link. Nessun alert. La mia prima lettura è stata che il payload stesso fosse rotto — forse l'encoding era diverso da quello mostrato dall'ispettore DOM, forse il browser stava trattando la virgoletta come testo letterale nonostante tutto. Ho testato quell'ipotesi direttamente, scrivendo `&quot;` a mano nel campo website invece di una `"` letterale, il che prevedibilmente ha solo prodotto un commento con `&quot;` come testo inerte nel valore dell'`href` — un vicolo cieco che almeno escludeva una teoria, ma non spiegava il fallimento originale, perché non stava mai testando il fallimento originale. Stavo debuggando un payload che si era già dimostrato corretto nel DOM, convinto che la soluzione dovesse stare in quello stesso punto.

### 5. La causa vera era uno strumento che avevo spento

DOM Invader era spento dall'inizio della sessione. Una volta riacceso e ricaricata la pagina, ha segnalato qualcosa che non avevo mai guardato: un listener `message`, da nessuna parte vicino al form commenti, che faceva questo:

```javascript
window.addEventListener('message', function(e) {
    var url = e.data;
    if (url.indexOf('http:') > -1 || url.indexOf('https:') > -1) {
        location.href = url;
    }
});
```

L'XSS via `onmouseover` era reale. Non era mai stato, però, il percorso previsto dal lab — il sink vero stava seduto in un file diverso da tutto il tempo, e l'unico motivo per cui non l'avevo visto è che lo strumento costruito apposta per far emergere esattamente questo tipo di listener era spento, e io avevo riempito il silenzio risultante con una teoria sul mio stesso payload invece di andare a cercare quello che DOM Invader mi avrebbe consegnato direttamente.

### 6. Un controllo che conferma la presenza, non la forma

`url.indexOf('http:') > -1` risponde a una sola domanda: questa sottostringa compare da qualche parte nella stringa? Non dice niente su dove, su cosa la circonda, o se il resto del valore è sicuro da passare a `location.href`. Uno schema e un marcatore di commento entrano entrambi in quei vincoli:

```
javascript:print()//http:
```

`indexOf('http:')` lo trova, alla fine, dentro quello che JavaScript legge come un commento una volta che l'espressione inizia a eseguire. Il controllo passa. `location.href` riceve una stringa che inizia con `javascript:`, verso cui il browser non naviga — la esegue.

### 7. Delivery

```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/" onload="this.contentWindow.postMessage('javascript:print()//http:', '*')"></iframe>
```

`onload`, perché il listener esiste solo una volta che la pagina si è caricata. `'*'` come target origin, perché il ricevente — correttamente, ai fini di questo lab — non controlla nemmeno chi ha mandato il messaggio. Store, deliver, `print()` parte, lab risolto. L'attribute injection è rimasta esattamente dov'era: reale, riproducibile, e mai la cosa che veniva effettivamente valutata.

## Cosa hanno in comune i due lab

Nessuno dei due bug stava in un punto difficile da raggiungere — l'header `Host` e il campo "website" erano entrambi lì, entrambi banalmente modificabili, entrambi riflessi indietro quasi immediatamente. Quello che ha richiesto tempo in entrambi i lab è stato capire cosa si fidasse davvero il lato ricevente, contro cosa sembrava solo controllare.

L'header `Host` sembrava metadato e si è rivelato una destinazione di rete letterale — il 504 lo diceva apertamente, dovevo solo credere al messaggio di errore invece di presumere fosse rumore. Il controllo `indexOf('http:')` sembrava validazione di un URL e si è rivelato un controllo di presenza senza opinioni sulla struttura. E l'XSS in mezzo a questi due momenti è stato un promemoria che trovare *un* exploit funzionante sulla pagina non è la stessa cosa che trovare *il* bug che il lab vuole risolto — l'attribute injection è partita esattamente come progettata e non aveva comunque niente a che fare con l'obiettivo vero, un errore che è costato tempo reale solo perché lo strumento che avrebbe mostrato il sink vero immediatamente era lì, spento.

## Esame e campo

**Lab uno — pivot di rete via Host header verso un admin interno**

| | Esame | Campo |
|---|---|---|
| Cosa riconoscere | una richiesta in uscita inspiegata su un endpoint scansionato, o un 504/500 il cui messaggio nomina una destinazione che hai appena fornito tu | hosting condiviso, routing del reverse proxy per nome, pannelli admin raggiungibili solo da range IP interni "fidati" |
| Dove va il tempo | la scansione con Intruder su un range interno, una volta che `localhost` dimostra il meccanismo ma non apre niente | capire quali range interni esistano affatto; il lab ti consegna `192.168.0.0/24`, le reti vere no |
| Trappola comune | fermarsi al finding di Collaborator e non testare manualmente `Host: localhost`, perdendo il messaggio di errore che spiega l'intero meccanismo | assumere che un confine di fiducia a livello di rete (IP interno = fidato) equivalga a un controllo di identità; non è così, ed è esattamente il gap che lo SSRF sfrutta |
| Limite reale | un'eliminazione scriptata, IP interno fisso | dipende interamente da cosa è raggiungibile dal server vulnerabile — endpoint di metadata cloud, API interne, altri tenant, tutto attraverso lo stesso singolo header |

Difesa: validare l'header `Host` contro una allow-list esplicita prima di usarlo per il routing, e non far mai dipendere il controllo di accesso a livello applicativo da quale segmento di rete sembra originare una richiesta.

**Lab due — open redirect DOM-based trasformato in XSS via postMessage**

| | Esame | Campo |
|---|---|---|
| Cosa riconoscere | un listener `message` che assegna `e.data` (o una sua versione controllata con substring) a `location.href` o `window.location` | endpoint di "open redirect" e allow-list di redirect implementate come controllo di substring o regex invece di un vero parsing dell'URL |
| Dove va il tempo | non inseguire un XSS funzionante ma irrilevante trovato altrove sulla stessa pagina, e lanciare DOM Invader prima di fidarsi della propria lettura della pagina | il bypass con `javascript:` è banale una volta trovato il sink; il lavoro vero è accorgersi che il listener esiste affatto su una pagina senza alcun trigger visibile per esso |
| Trappola comune | scambiare un bug reale e riproducibile per l'obiettivo del lab solo perché parte in modo affidabile | fidarsi di controlli stile `indexOf`/`includes` sui target di redirect perché "sembrano" validazione in una code review |
| Limite reale | serve che una vittima carichi una pagina che controlli tu, come ogni attacco basato su postMessage | se l'app controlla anche `e.origin`, o fa il parsing del valore con il costruttore `URL()` invece di un match di substring, questo esatto bypass si chiude |

Difesa: non validare mai un URL controllando se una substring compare al suo interno — fare il parsing con `new URL()` e controllare i campi reali `protocol` e `host`, e controllare sempre `e.origin` prima di fidarsi del contenuto di un messaggio.

## Cosa viene dopo

Il pivot via Host header ha funzionato perché il range interno era piccolo e il lab mi ha consegnato implicitamente i suoi confini — `192.168.0.0/24` è il genere di cosa che si brute-forza in minuti. Una rete interna vera non arriva con quel regalo. La domanda aperta che mi porto dietro per la prossima sessione non riguarda il payload, riguarda la ricognizione: quanto della topologia interna di un target si può effettivamente mappare attraverso un header capace di SSRF prima che la scansione stessa diventi il collo di bottiglia, e come dovrebbe essere fatto il rate limiting di un difensore per rendere quella scansione costosa invece che gratuita.

## Takeaways

- Un messaggio di errore che nomina una destinazione ("connecting to X") ti sta dicendo come un valore viene usato davvero, non solo come viene mostrato — leggilo alla lettera prima di presumere che sia rumore.
- `indexOf()` / `includes()` su un valore a forma di URL controlla la presenza, non la forma. Non ti dirà mai se la stringa *è* un URL sicuro, solo se una sottostringa dall'aria sicura compare da qualche parte al suo interno.
- Un exploit funzionante non è la prova di aver trovato il bug previsto dal lab. Verificalo contro l'obiettivo dichiarato prima di costruirci sopra il resto del tuo tempo.
- Non debuggare un payload che si è già dimostrato corretto nel DOM. Se non parte, il fallimento è più probabilmente a valle (uno strumento spento, un sink completamente diverso) che nella stringa che hai già verificato.
- Prendi i token (CSRF o altro) freschi dalla pagina contro cui stai per inviare — un token riusato da un contesto diverso è un fallimento silenzioso pronto a mangiarti i prossimi dieci minuti.

## Riferimenti utili

- [PortSwigger Web Security Academy: HTTP Host header attacks](https://portswigger.net/web-security/host-header)
- [PortSwigger Web Security Academy: Server-side request forgery (SSRF)](https://portswigger.net/web-security/ssrf)
- [PortSwigger Web Security Academy: DOM-based vulnerabilities](https://portswigger.net/web-security/dom-based)
- [PortSwigger Web Security Academy: Cross-site scripting](https://portswigger.net/web-security/cross-site-scripting)
- [MDN: Window.postMessage()](https://developer.mozilla.org/docs/Web/API/Window/postMessage)
- [MDN: URL()](https://developer.mozilla.org/docs/Web/API/URL/URL)
- [Mystery Pool: uno strumento per pescare un lab casuale solo dai topic che scegli]({% post_url 2026-10-04-mystery-pool-strumento %})

*Tutte le tecniche mostrate sono state eseguite in un ambiente di laboratorio isolato (PortSwigger Web Security Academy). Attaccare sistemi che non possiedi o per cui non hai un'autorizzazione scritta è illegale nella maggior parte delle giurisdizioni.*
