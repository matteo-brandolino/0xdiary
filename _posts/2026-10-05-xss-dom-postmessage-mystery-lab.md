---
layout: post
title: "Un messaggio da nessuna parte: XSS DOM tramite postMessage"
date: 2026-10-05
categories: [web-security, walkthrough]
tags: [portswigger, mystery-lab, dom-based, xss, postmessage, dom-invader, burp-suite]
excerpt: "La pagina non aveva né barra di ricerca né commenti, quindi sono andato a cercare nel JavaScript. Ho trovato un listener che si fidava di ogni mittente, e per un po' ho inseguito un messaggio che DOM Invader si era inventato da solo."
lang: it
page_id: dom-xss-postmessage-mystery-lab
permalink: /posts/xss-dom-postmessage-mystery-lab/
---

Non c'era nulla in cui scrivere. Nessuna barra di ricerca, nessun form per i commenti, nessun parametro che vedessi cambiare qualcosa nella pagina. Il lab era una delle due categorie che avevo messo nel mio pool, DOM o XSS, e la pagina non mi dava niente su cui inserire un canary. Quindi ho fissato un negozio vuoto e ho pensato: se non c'è un posto dove scrivere, l'input deve essere da qualche parte dove io non posso scrivere.

Il lab è uscito da [Mystery Pool]({% post_url 2026-10-04-mystery-pool-strumento %}), lo strumento che ho costruito per estrarre un lab solo dagli argomenti che scegli. Avevo scelto DOM e XSS, e PortSwigger non ti dice quale dei due ti è capitato. È proprio questo il senso di un mystery lab.

## Setup: un negozio senza input

Il lab si chiama "Mystery challenge" ed è un piccolo negozio online che vende carta da regalo all'uncinetto. Avevo Burp Suite attivo, l'estensione DOM Invader (versione 2.0.11) in Chrome, e il browser puntato sul proxy di Burp. Niente di furbo per ora: volevo sapere da dove arrivavano i dati della pagina prima di decidere che tipo di bug stavo guardando.

## 1. Una pagina vuota è comunque un indizio

Se una pagina non ha input visibili, quello che legge arriva da un posto che l'utente non vede: l'hash dell'URL, un parametro che nessun form espone, `window.name`, oppure un messaggio da un'altra finestra. Questo restringeva la ricerca, ma non la chiudeva. Una XSS riflessa ha bisogno che il server rimandi indietro qualcosa, e io non trovavo nulla che il server potesse rimandare. La scommessa è andata sul JavaScript, e DOM Invader era lo strumento per verificarla.

## 2. Zero non è un verdetto

La prima schermata di DOM Invader mostrava due contatori a zero: DOM 0 e Messages 0. Il canary era `zgrucnap`, e un avviso in fondo diceva che venivano mostrati solo i sink interessanti, con tutte le sorgenti nascoste. Zero sink non vuol dire che la pagina è sicura. Vuol dire che il canary non ha mai raggiunto un sink. La domanda successiva era se il canary fosse mai stato mandato da qualche parte, quindi ho attivato l'intercettazione dei postMessage e ho ricaricato.

## 3. Un messaggio da un host che non esiste

Dopo il ricaricamento, Messages mostrava un risultato. La sua origine era `https://0a4e…web-security-academy.net.fakeweb-security-academy.net`. Non è un'origine reale, e per un attimo sembrava una prova: qualcosa nella pagina stava mandando messaggi da un host che non le apparteneva.

Ho controllato le impostazioni. Lo spoofing dell'origine dei postMessage era acceso, e lo era anche "Generate automated messages". DOM Invader aveva creato quel messaggio da solo, come test, e l'origine falsa era opera sua. Ho spento entrambe le opzioni e ricaricato. Messages era vuoto. Da solo, il sito non mandava niente.

La lezione riguarda il traffico che stai leggendo. Un test generato dallo strumento e un messaggio inviato dalla pagina nella lista sembrano uguali. L'origine era l'unico indizio, e l'ho visto solo perché sono tornato alle impostazioni. Da quel momento ho spento le funzioni di test prima di leggere qualsiasi messaggio.

## 4. Il listener appartiene a una pagina sola

Una lista Messages vuota voleva dire che la pagina aspettava qualcosa dall'esterno. Quindi sono andato a cercare il listener. Nello history HTTP di Burp, la risposta a `GET /` contiene uno script inline con `window.addEventListener('message', ...)`. La stessa stringa non compare nella risposta della pagina prodotto.

Un listener appartiene alla pagina che lo registra, non a tutto il sito. La home e la pagina prodotto non eseguono lo stesso script, e una ricerca che ne controlla solo una può raccontarti la storia sbagliata.

## 5. Lo scanner non aveva niente da dire

La scansione Burp su `GET /` è tornata vuota, e a pensarci bene era prevedibile. La richiesta non ha parametri in cui lo scanner possa inserire payload. Il dato di questo bug non viaggia mai in una richiesta HTTP: arriva come messaggio da un'altra finestra e viene gestito nel browser. Un report vuoto qui non vuol dire che la pagina è pulita. Vuol dire che lo scanner non aveva un percorso verso il sink.

## 6. Quattro righe che decidono tutto

Questa è la parte del listener che conta:

```javascript
window.addEventListener('message', function(e) {
    ...
    d = JSON.parse(e.data);      // controlla la forma del messaggio
    switch(d.type) {
        case "load-channel":
            ACMEplayer.element.src = d.url;   // il sink
            break;
    ...
```

Il `try/catch` attorno a `JSON.parse` e lo `switch` su `d.type` sembrano entrambi una validazione, e tutti e due controllano la forma del messaggio. Nessuno controlla chi l'ha mandato. In tutta la funzione non compare nessun `e.origin`. Poi `d.url` finisce direttamente in `iframe.src`. Un iframe il cui `src` è un URL `javascript:` esegue quel codice con l'origine della pagina che ha impostato il `src`, e qui quella pagina è il lab, perché è stato il suo listener a impostarlo.

## 7. L'obiettivo, e il payload

L'obiettivo era `print()`. L'ho letto cliccando "Reveal objective" nella pagina del lab, perché nient'altro nella pagina mi avrebbe detto cosa voleva il lab. A quel punto il payload doveva fare due cose: mandare un messaggio `load-channel` al listener, e mettere un URL `javascript:` nel campo che il listener legge.

Il body dell'exploit server:

```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/" onload="this.contentWindow.postMessage(JSON.stringify({type:'load-channel',url:'javascript:print()'}),'*')"></iframe>
```

Ogni dettaglio c'è per un motivo:

- **`onload`.** Il listener esiste solo dopo che la home del lab è caricata. Un messaggio inviato prima non arriva da nessuna parte.
- **`JSON.stringify`.** Il listener chiama `JSON.parse(e.data)`. Un oggetto farebbe fallire il parsing e arriverebbe al `return`, senza che succeda niente.
- **`'*'` come origine di destinazione.** Permette al messaggio di raggiungere una finestra di un'origine diversa. È previsto dal design. Chi deve controllare chi sta mandando il messaggio è il ricevente.

Ho salvato l'exploit, l'ho consegnato alla vittima, e il lab è passato a risolto.

## Il pattern sotto

Un controllo sulla forma di un messaggio non è un controllo sul mittente. Il `try/catch` e lo `switch` facevano sembrare il listener accurato, e lo era, ma sulla cosa sbagliata. Il formato del messaggio era l'unica cosa che validava.

I contatori a zero e la lista Messages vuota erano entrambi veri, e non mi dicevano niente finché non ho saputo quale traffico manda la pagina stessa. Uno strumento che ti mostra il traffico è utile solo quanto sai distinguere il traffico tuo da quello degli altri.

## Esame e campo

| | Esame | Campo |
|---|---|---|
| Cosa riconoscere | un listener `message` senza controllo di `e.origin`, che alimenta un sink | lo stesso pattern in widget, player video, chat embed e iframe di terze parti |
| Dove va il tempo | la delivery: `onload`, forma del JSON, schema `javascript:` | capire cosa può fare l'utente loggato sul sito bersaglio |
| Trappola tipica | un payload perfetto inviato prima che il listener esista | pensare che la vittima debba visitare un link, quando una pagina di cui si fida può ospitare l'iframe |
| Limite reale | un solo obiettivo, qui `print()` | la vittima deve visitare la pagina dell'attaccante; se il sito blocca il framing, l'attaccante può usare `window.open` e mantenere lo stesso messaggio |

All'esame il payload è la parte facile. Il bug sta nella delivery, e un `onload` messo nel posto sbagliato fa sembrare rotto un exploit che funziona.

Sul campo, lo stesso listener dà a un attaccante del codice che gira come utente loggato sul sito bersaglio. Un cookie `HttpOnly` non si può leggere dallo script, ma le richieste fatte da quell'origine lo portano comunque con sé. I token CSRF nel DOM sono leggibili. Tutto quello che l'utente può fare su quel sito, lo script può farlo a sua volta.

La difesa è un controllo solo: confrontare `e.origin` con una lista di origini attese prima di toccare `e.data`. La seconda regola è non passare mai un valore arrivato da un messaggio a `iframe.src`, o accettare solo URL `https:` da una lista di host.

## Cosa viene dopo

L'origine falsa generata da DOM Invader, `…net.fakeweb-security-academy.net`, ha esattamente la forma che accetta un controllo sull'origine fatto male. Un controllo che chiede se l'origine *finisce con* `web-security-academy.net` la lascerebbe passare, perché nessuno richiede il punto prima del dominio. Questo lab non aveva nessun controllo, quindi non ho potuto provarlo. È la prossima cosa da verificare su un lab che ne ha uno, ed è la stessa domanda del [lab dei cookie]({% post_url 2026-10-01-manipolazione-cookie-dom-mystery-lab %}): cosa crede la pagina sulla provenienza dei suoi dati?

## Takeaways

- Un listener senza controllo sull'origine accetta input da qualsiasi pagina di internet.
- Una lista Messages vuota vuol dire che la pagina non manda niente da sola. Non vuol dire che non le arrivi niente.
- Un controllo sul formato del messaggio non è un controllo sul mittente.
- Gli scanner testano ciò che viaggia nelle richieste HTTP. Un `postMessage` non ci viaggia mai, quindi un report vuoto dello scanner non dice nulla sulla pagina.

## Riferimenti utili

- [PortSwigger: Controlling the web message source](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source)
- [PortSwigger: DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader)
- [MDN: Window.postMessage()](https://developer.mozilla.org/docs/Web/API/Window/postMessage)
- [MDN: evento message](https://developer.mozilla.org/docs/Web/API/Window/message_event)

---

*Tutte le tecniche mostrate sono state eseguite in un ambiente di laboratorio isolato (Web Security Academy di PortSwigger). Attaccare sistemi che non possiedi o per cui non hai un'autorizzazione scritta è illegale nella maggior parte delle giurisdizioni.*
