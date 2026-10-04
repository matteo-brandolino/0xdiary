---
layout: post
title: "Mystery Pool: un lab casuale solo tra gli argomenti che scegli"
date: 2026-10-04
categories: [web-security, tools]
tags: [portswigger, mystery-lab, javascript, samesite, cookie, github-pages]
excerpt: "Mystery Lab offre un argomento oppure tutti e venti, così ho costruito una piccola pagina statica che sorteggia un lab solo tra quelli che scegli, e ho scoperto quanto poco può sapere di te una pagina su un altro sito."
lang: it
page_id: mystery-pool
permalink: /posts/mystery-pool/
---

Mystery Lab ti dà due scelte: un argomento, oppure tutti e venti. Avevo appena finito i lab su DOM-based e XSS, e quello che volevo era un lab casuale tra esattamente questi due argomenti, e nient'altro. Il bottone non ha un campo per questo. Così me lo sono costruito.

## Che cos'è Mystery Pool

Mystery Pool è una pagina statica: niente backend, niente account, niente tracciamento. Spunti gli argomenti che vuoi allenare, scegli il livello e premi Roll. Si apre una nuova tab su un lab estratto a caso tra quegli argomenti. Il lab lo sceglie ancora PortSwigger. La pagina sceglie solo la categoria.

Serve a un caso preciso: conosci alcuni argomenti abbastanza bene da voler fare pratica casuale dentro di essi, senza estrarre dall'intero catalogo. Tutto quello che non fa è una scelta deliberata.

Il link che apre è lo stesso che costruisce il bottone ufficiale, quindi devi essere loggato su PortSwigger nello stesso browser. È il browser a portare la sessione. La pagina non la vede mai.

Il risultato è su [matteo-brandolino.github.io/mystery-pool](https://matteo-brandolino.github.io/mystery-pool/), e il codice è [nella repo](https://github.com/matteo-brandolino/mystery-pool).

## Come funziona

Ci sono quattro parti, e ognuna copia una regola del widget di PortSwigger:

1. **Dati degli argomenti.** Un file con le venti categorie e i livelli in cui ciascuna esiste. L'ho copiato dall'HTML del widget, e il README ha il comando per aggiornarlo.
2. **Eleggibilità.** Una categoria può essere estratta a un certo livello solo se quel livello compare nella sua lista. "Any" toglie il vincolo. Se nessun argomento del pool esiste al livello scelto, il bottone si disabilita e la pagina dice perché.
3. **Il sorteggio.** Sceglie in modo uniforme tra le categorie eleggibili e costruisce l'URL di lancio per concatenazione di stringhe:

   ```js
   const launchUrl = (categoryId, level) =>
     PS_ORIGIN + '/academy/labs/launchMystery?categoryId=' + categoryId +
     '&level=' + level + '&referrer=' + REFERRER;
   ```

   Non uso `URLSearchParams`, perché l'originale non codifica il referrer, e gli slash devono restare letterali per produrre la stessa richiesta.
4. **Condivisione.** Pool e livello stanno nell'hash dell'URL, quindi un pool si può salvare nei preferiti o mandare a qualcuno. Aprendo un link condiviso il pool si seleziona, e non si tira da solo: un link non dovrebbe farti finire in un lab.

## Cosa non può fare

- **Estrae un argomento, non un lab.** Il lab dentro la categoria lo sceglie PortSwigger, quindi lo stesso lab può ricapitare, e la pagina non può evitarlo.
- **Le probabilità non sono uguali tra i lab.** Il sorteggio è uniforme tra argomenti. Una categoria con tre lab pesa quanto una con dodici.
- **Non sa cosa hai già completato.** Il cookie di sessione è `HttpOnly` e appartiene a un altro sito, quindi la pagina non può leggerlo.
- **Non può nascondere l'argomento nella barra degli indirizzi.** L'URL di lancio contiene `categoryId`, quindi la nuova tab lo mostra finché il lancio è in sospeso.

Quest'ultimo punto è quello su cui ho passato più tempo, e ha dato forma a tutto il resto.

## Momenti della costruzione

### 1. Il bottone accetta un solo valore

La pagina non contiene il bottone. Contiene un segnaposto vuoto, che uno script riempie inviandolo a `/api/widgets`. Lo script che torna costruisce il link da due `<select>` singoli, con `selectedOptions[0].value`. Un valore da un select. Il client non ha il concetto di lista, quindi l'opzione mancante non è una regola del server. È semplicemente assente dal codice. Leggere il gestore ci ha messo cinque minuti. Sondare il server non avrebbe risposto alla domanda.

### 2. Le richieste anonime non vedono oltre il login

Ho mandato tre richieste senza essere loggato: `categoryId=2`, `categoryId=2,3` e `categoryId=-1`. Tutte e tre hanno ricevuto lo stesso `302` verso `/users?returnurl=...`. Il controllo di autenticazione viene prima del binding dei parametri, quindi da fuori non ho imparato nulla su come il server interpreta `2,3`. Il test che risponde richiede una sessione loggata, e non l'ho ancora fatto.

### 3. Il cookie decide cosa può sapere la pagina

Il cookie di sessione è `HttpOnly`, `Secure`, `SameSite=Lax`, legato a `.portswigger.net`, con una durata di dodici ore. Questa combinazione fissa il confine dello strumento:

- Un link semplice verso l'URL di lancio è una navigazione top-level, quindi il browser allega la sessione. Il link funziona.
- Una `fetch` verso lo stesso URL è cross-origin, non ha header CORS, e `Lax` non invia i cookie su quel tipo di richiesta. Non funziona.

Quindi la pagina può produrre il link, ma non può sapere se sei loggato, né quali lab hai completato. Per questo il flag `onlyCompleted` non viene mai inviato: la pagina non avrebbe modo di sapere cosa significherebbe.

### 4. La mia prima versione stampava la risposta

La prima versione mostrava l'URL generato sotto il bottone, accanto al nome della categoria. Guardandola a schermo, il problema era evidente. L'URL dice `categoryId=11`, e in un mystery lab è esattamente quello che non vuoi leggere prima di iniziare. Ho tolto l'URL e la categoria dalla pagina. Il nome sta dietro un toggle chiuso "Reveal the topic", per quando hai finito.

### 5. Anche l'indirizzo finale è fuori portata

Dopo il redirect di lancio, il lab vive su un'altra origin. Ho controllato se l'endpoint manda header CORS, così la pagina potrebbe leggere dove finisce il redirect: il preflight risponde 404 e non ci sono header `Access-Control-*`. Leggere `location` da una finestra di un'altra origin lancia un errore. La pagina non può mostrarti l'indirizzo del lab. Solo la tab può, ed è la tab che stai guardando.

### 6. Due bug nei miei controlli

Parte della verifica che avevo scritto era rotta in modi che la facevano sembrare o giusta o sbagliata.

- Il mio controllo del codice morto costruiva una regex dentro apici singoli della shell, quindi `\\b` diventava un backslash letterale. Ogni funzione risultava morta. La correzione era un solo escape, e trovarlo ha richiesto più di quanto meritasse il bug.
- Un altro controllo falliva perché la sua regex del selettore non matchava `.spoiler`. A sbagliare era il controllo, non la pagina.
- La lista dei livelli era ordinata con `.sort()`, che confronta come stringhe. I livelli 0, 1 e 2 nascondono il bug. Un id a due cifre no.

Un controllo è codice come gli altri, e va testato a sua volta.

### 7. La sala d'attesa che ho tolto

La pagina doveva aprire il lab e tenerti lontano dalla tab mentre si generava. Ho costruito una sala d'attesa in una seconda finestra, che ti avrebbe portato sul lab dopo un click o dopo dieci secondi.

Il browser ha bloccato la seconda finestra e ha chiesto il permesso. Quando è stata bloccata, la tab del lab è rimasta in primo piano, con `about:blank` per qualche secondo mentre la richiesta di lancio era ancora in sospeso, e poi l'indirizzo del lab. Quel periodo vuoto è la parte che mi piaceva, e l'ho tenuta. La categoria in quella prova non è mai arrivata nella barra, ma è un effetto dei tempi, non una protezione. Da non loggato, il redirect va a `/users?returnurl=...categoryid=...`, e quell'indirizzo la categoria la mostra.

Rendere la sala affidabile avrebbe richiesto di sapere quando la tab del lab ha finito di caricare, e quella tab è cross-origin. L'ho tolta.

### 8. I preset, tagliati

La prima versione salvava pool con nome in `localStorage`. Li ho tagliati: l'hash contiene già pool e livello, e un secondo livello di storage era più da spiegare di quanto facesse guadagnare. I preset erano la funzione che richiedeva più avvertenze, e quella che aggiungeva meno.

## Che schema è questo

Un'opzione che manca nella UI spesso manca nel codice client, e leggere il gestore è più veloce che sondare il server. L'URL è l'API: una volta conosciuti i parametri, puoi costruire qualunque URL la UI avrebbe potuto costruire.

Il browser decide cosa può vedere una seconda pagina, e la risposta è quasi niente. Il cookie di sessione viaggia solo con le navigazioni top-level. Quindi una pagina statica può mandarti a un lab, ma non può vedere la tua sessione, i lab che hai completato o l'indirizzo finale. Tutto ciò che deve restare segreto e arrivare in una tab finisce nella barra degli indirizzi di quella tab.

Per questo strumento, il mistero lo mantiene chi distoglie lo sguardo dalla barra. Il sito non può farlo al posto tuo.

## Cosa viene dopo

- Il test loggato per `categoryId=2,3`. Le richieste anonime non possono rispondere, e la risposta decide se un sorteggio su più argomenti si potrebbe mai fare lato server.
- Pesare il sorteggio sul numero di lab per categoria. Servono dati che non ho ancora.
- Un bookmarklet potrebbe leggere l'URL finale, perché girerebbe sulla pagina di PortSwigger stessa. L'ho escluso di proposito. Dipenderebbe dal loro markup, e un companion statico non dovrebbe farlo.

## Takeaways

- Se una UI non sa esprimere un'opzione, controlla il codice client prima di dare la colpa al server.
- Una richiesta anonima non può testare nulla che stia dietro un controllo di autenticazione.
- `SameSite=Lax` decide cosa può portare un link: abbastanza per mandarti a una pagina, mai abbastanza perché quella pagina sappia chi sei.
- Uno strumento per la pratica deve tenere il mistero fuori dalla propria UI. Tutto ciò che deve arrivare in una tab ci sarà visibile.

## Riferimenti utili

- [Repository di Mystery Pool su GitHub](https://github.com/matteo-brandolino/mystery-pool)
- [PortSwigger Web Security Academy: Mystery Lab Challenge](https://portswigger.net/web-security/mystery-lab-challenge)
- [MDN: Window.open()](https://developer.mozilla.org/docs/Web/API/Window/open)
- [MDN: Set-Cookie, l'attributo SameSite](https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie#samesitesamesite-value)
- [MDN: Cross-Origin Resource Sharing (CORS)](https://developer.mozilla.org/docs/Web/HTTP/CORS)

*Tutte le tecniche mostrate sono state eseguite in un ambiente di laboratorio isolato (Web Security Academy di PortSwigger). Attaccare sistemi che non possiedi o per cui non hai un'autorizzazione scritta è illegale nella maggior parte delle giurisdizioni.*
