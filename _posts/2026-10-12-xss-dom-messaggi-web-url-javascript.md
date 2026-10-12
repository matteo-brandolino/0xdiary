---
layout: post
title: "Una substring non è uno schema: XSS DOM tramite messaggi web e un URL javascript:"
date: 2026-10-12
categories: [web-security, walkthrough]
tags: [portswigger, dom-based, xss, postmessage, dom-invader, burp-suite, javascript-url]
excerpt: "DOM Invader non trovava niente, così ho attivato i messaggi automatici, ho incollato per sbaglio il codice sorgente sbagliato nei miei appunti, e solo dopo ho capito perché 'l'URL contiene https' non è la stessa cosa di 'l'URL inizia con https'."
lang: it
page_id: dom-xss-web-messages-javascript-url
permalink: /posts/xss-dom-messaggi-web-url-javascript/
---

Ho aperto DOM Invader, ricaricato la home page del lab, aspettandomi che il pannello postMessage si illuminasse come succede sempre nei walkthrough. Messages: 0. DOM: 0. Per uno strumento che dovrebbe trovare queste cose al posto mio, zero è un modo strano di iniziare.

Il lab è "DOM XSS using web messages and a JavaScript URL" di PortSwigger. Volevo usare DOM Invader sul serio, questa volta, non limitarmi a leggere la soluzione e digitarla. Il piano è sopravvissuto circa quattro minuti.

## Setup: lo strumento che osserva, ma solo quello che passa

DOM Invader (versione 2.0.12 nel mio caso) aggancia `window.addEventListener('message', ...)` e altri sink noti su tutta la pagina, poi aspetta che ci passi del traffico. La home si è caricata, il listener presumibilmente era lì da qualche parte nel JavaScript, e il pannello Messages è rimasto vuoto. Canary impostato, intercettazione postmessage attiva, iniezione canary attiva — tutto verde nel pannello delle impostazioni. Ancora niente.

## 1. Zero messaggi non vuol dire zero listener

La soluzione si è rivelata un'opzione che avevo saltato: **Generate automated messages**. DOM Invader non si limita ad ascoltare — può fabbricarsi da solo del traffico postMessage e mandarlo a ogni listener `message` che trova, apposta per provocare una reazione senza aspettare traffico reale tra finestre diverse. Avevo dato per scontato che "intercettazione" volesse dire "test attivo". Vuol dire "osservazione". Quel toggle acceso è ciò che testa davvero.

Una volta attivato e ricaricata la pagina, sono comparsi tre messaggi, due segnalati con un punto esclamativo rosso. Ognuno aveva un campo `Data` simile a questo:

```
https://0a16005b...web-security-academy.net/sa9je6lj0-/%3C%3E'"
```

Quella stringa non è un URL da visitare. È il *valore che DOM Invader ha assegnato a `e.data`* quando ha chiamato `postMessage()` sulla pagina — costruito per sembrare un URL (perché alcuni sink rifiutano qualsiasi cosa non venga interpretata come tale), con dentro un canary (`sa9je6lj`, il token casuale delle impostazioni) per far sì che DOM Invader riconosca in seguito il proprio probe, e imbottito di caratteri classici per il probing XSS (`<>'"`) per vedere se sopravvivono senza essere escapati una volta arrivati a un sink. Le righe con `http:` o `https:` aggiunto in coda facevano qualcosa di più specifico, cosa che ho capito solo dopo: testare un pattern di validazione sbagliata che DOM Invader sa già essere comune.

## 2. Lo stack trace che non era il codice della pagina

Volevo vedere esattamente dove finiva quel dato, quindi ho cliccato per vedere lo stack trace. Il pannello di DOM Invader mi ha detto di controllare la Console invece di mostrarmelo inline — va bene. Sono andato a cercare, ho preso quello che sembrava essere il sorgente, e l'ho incollato nei miei appunti per andare a trovare il sink.

Era il codice interno dell'estensione DOM Invader stessa. Qualche migliaio di righe, offuscate, nomi di variabili tipo `_0x43c43e`. Nemmeno una riga del JavaScript del lab.

È il tipo di errore che costa più tempo di quanto dovrebbe, perché l'output *sembra* codice sorgente, e il cervello fa pattern-matching su "probabilmente è quello che ho chiesto" prima ancora di controllare di chi sia davvero il codice. La correzione è stata meccanica una volta smesso di dare per scontato: aprire Sources, trovare il nodo dell'albero per il dominio del lab stesso (non quello dell'estensione), e leggere direttamente lo `<script>` inline nella home page. Nessuno stack trace necessario — il listener era lì, nell'HTML della pagina.

## 3. Il controllo che conta le substring, non gli schemi

Il listener vero:

```javascript
window.addEventListener('message', function(e) {
    var url = e.data;
    if (url.indexOf('http:') > -1 || url.indexOf('https:') > -1) {
        location.href = url;
    }
}, false);
```

`indexOf('http:') > -1` fa una sola domanda: la stringa `http:` compare *da qualche parte* in questo valore. Non chiede se il valore *inizia con* `http:`, che è la domanda a cui un controllo sullo schema dovrebbe davvero rispondere. Una stringa può soddisfare "contiene `http:`" pur iniziando con qualcos'altro di completamente diverso — come `javascript:`.

È anche quello che i probe di DOM Invader con `http:`/`https:` in coda stavano testando, col senno di poi: lo strumento sa già che i controlli di substring con `indexOf`/`includes` sono un modo comune e rotto in cui gli sviluppatori provano a validare gli schemi degli URL, quindi appende quella stringa letterale ai suoi payload per vedere se un sink la accetta comunque.

## 4. Il payload, e cosa fa davvero `location.href = "javascript:..."`

```
javascript:alert(document.domain)//http://a
```

Qui ho dovuto correggere il mio stesso modello mentale, perché il primo istinto era sbagliato: davo per scontato che `location.href` finisse in qualche modo per contenere il risultato della chiamata ad `alert()`. Non è così. A `location.href` viene assegnata la stringa letterale qui sopra — tutta intera, non eseguita. Quello che succede dopo è una particolarità di come i browser trattano lo schema `javascript:`: quando lo schema della destinazione di una navigazione è `javascript:`, il browser non naviga da nessuna parte. Esegue tutto quello che viene dopo i due punti come JavaScript, sul posto, nel contesto della pagina corrente. `//http://a` diventa un commento JS nel momento in cui quell'esecuzione avviene, quindi l'unica cosa che gira davvero è `alert(document.domain)`. Il `http://a` finale esiste solo per far sì che `indexOf('http:')` restituisca una posizione valida — non fa parte dell'attacco, è la chiave che apre la serratura rotta.

## 5. Un payload postMessage non è una pagina da visitare

Un'altra cosa che avevo capita al contrario prima che scattasse: quella stringa a forma di URL dal pannello Messages di DOM Invader — ho chiesto se *navigarci sopra* avrebbe fatto scattare il listener. Non succede. `addEventListener('message', ...)` reagisce a eventi `message`, punto, e questi scattano solo da una chiamata a `postMessage()`, mai digitando qualcosa nella barra degli indirizzi o caricando una pagina. La stringa di probe è esistita solo come argomento `data` di una chiamata `postMessage()` che DOM Invader ha fatto per conto proprio:

```javascript
window.postMessage("https://...sa9je6lj0-/%3C%3E'\":https:", "*")
```

Il payload per l'exploit server fa l'equivalente, deliberatamente:

```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/" onload="this.contentWindow.postMessage('javascript:alert(document.domain)//http://a','*')">
```

`onload` conta qui per lo stesso motivo per cui contava nell'ultimo lab postMessage che avevo risolto: il listener esiste solo una volta che la pagina del lab ha finito di caricarsi. Mandare il messaggio prima, e non arriva da nessuna parte.

## Il pattern sotto

Qui hanno lavorato due buchi diversi, ed è facile confonderli se si ricorda solo "validazione debole". Il primo è un controllo scritto sulla domanda sbagliata — "questa stringa contiene X" invece di "questa stringa inizia con X" — un bug substring-vs-anchor che compare ben oltre gli schemi degli URL (querystring, valori di cookie, controlli su header soffrono dello stesso errore). Il secondo è un comportamento del browser che trasforma qualsiasi stringa assegnabile a `location.href` (o `.src`, o sink simili) in un primitivo di esecuzione, purché il suo schema sia `javascript:`. Nessuno dei due buchi da solo è la vulnerabilità. Insieme, lo sono.

## Esame e campo

| | Esame | Campo |
|---|---|---|
| Cosa riconoscere | un handler `postMessage` che valida un URL con `indexOf`/`includes` invece di ancorare il controllo | lo stesso controllo lasco su redirect target, src di iframe, o allowlist di "URL sicuri" ovunque in un codebase, non solo negli handler postMessage |
| Dove va il tempo | leggere la logica di validazione esatta, non indovinare un payload | capire quali sink nell'app consumano davvero URL raggiungibili dall'attaccante |
| Trappola tipica | dare per scontato che `indexOf('http') > -1` si comporti come `startsWith('http')` | dare per scontato che un controllo substring vicino a un URL sia "probabilmente a posto" solo perché nomina lo schema giusto |
| Limite reale | una chiamata JS, un iframe, fatto | la vittima deve comunque caricare una pagina che inneschi il `postMessage`; se la pagina vulnerabile non può essere messa in un frame, il trucco si sposta su `window.open` con lo stesso payload |

All'esame, questo è veloce una volta che hai davvero letto la condizione invece di scorrerla — `indexOf` e `startsWith` sembrano intercambiabili se fai pattern-matching invece di leggere.

Sul campo, lo stesso tipo di controllo `indexOf('http')` salta fuori ovunque uno sviluppatore abbia provato a validare "è un URL sicuro" con una riga sola invece che con un parser vero. `new URL(input).protocol === 'https:'` chiude esattamente questo buco; un test substring semplice non lo fa mai, per quanti schemi elenchi.

La fix per questo listener specifico è fatta di due modifiche, non una: controllare `e.origin` contro una allowlist esplicita prima ancora di toccare `e.data`, e sostituire il controllo substring con qualcosa che ispezioni davvero lo schema — `new URL(url).protocol` confrontato con `'http:'`/`'https:'`, o come minimo `url.startsWith('http://')`.

## Cosa viene dopo

La deviazione sul codice offuscato dell'estensione mi ha insegnato qualcosa che non c'entra col lab ma vale la pena tenere: quando DOM Invader dice di controllare la console, controllare la console *con lo scope sul dominio giusto*, e quando stai leggendo qualcosa che sembra codice sorgente, conferma di chi è il sorgente prima di iniziare a ragionarci sopra. È un controllo economico che mi avrebbe risparmiato tutta la deviazione.

Il prossimo lab postMessage che pesco da [Mystery Pool]({% post_url 2026-10-04-mystery-pool-strumento %}) è quello con `JSON.parse(e.data)` a guardia della forma del messaggio invece di una stringa grezza — ho già visto quel pattern una volta, [nel lab postMessage precedente]({% post_url 2026-10-05-xss-dom-postmessage-mystery-lab %}), e voglio vedere se un controllo sull'origine cambia quanto velocemente i probe automatici di DOM Invader trovano il sink.

## Takeaways

- I controlli `indexOf`/`includes` su un URL rispondono a "questa stringa contiene X", mai a "questa stringa inizia con X" — non sono intercambiabili, e un URL `javascript:` può soddisfare il primo fallendo il secondo.
- L'opzione "Generate automated messages" di DOM Invader è ciò che fa davvero reagire i listener `message`; senza, un pannello Messages vuoto vuol dire solo che non è ancora passato traffico reale.
- Un'assegnazione `location.href = "javascript:..."` non esegue mai nulla da sola — è il modo in cui il browser gestisce lo schema `javascript:` a trasformare l'assegnazione in esecuzione di codice.
- Una stringa di probe postMessage è un dato passato a `postMessage()`, non un URL da visitare; solo una vera chiamata `postMessage()` fa scattare un listener `message`.
- Quando uno strumento ti mostra "il sorgente", controlla di chi è — il codice interno di un'estensione e il codice della pagina target possono sembrare identici a prima vista, specialmente se entrambi minificati.

## Riferimenti utili

- [PortSwigger: DOM XSS using web messages and a JavaScript URL](https://portswigger.net/web-security/dom-based/open-redirection/lab-dom-xss-using-web-messages-and-a-javascript-url)
- [PortSwigger: DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader)
- [PortSwigger: Controlling the web message source](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source)
- [MDN: Window.postMessage()](https://developer.mozilla.org/docs/Web/API/Window/postMessage)
- [MDN: schema javascript:](https://developer.mozilla.org/docs/Web/URI/Schemes/javascript)

---

*Tutte le tecniche mostrate sono state eseguite in un ambiente di laboratorio isolato (Web Security Academy di PortSwigger). Attaccare sistemi che non possiedi o per cui non hai un'autorizzazione scritta è illegale nella maggior parte delle giurisdizioni.*
