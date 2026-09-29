---
layout: post
title: "XInclude e il parametro che non voleva rispondere"
date: 2026-09-29
categories: [web-security, walkthrough]
tags: [bscp, burp-suite, burp-scanner, xxe, xinclude, xml-injection, ssrf, portswigger]
excerpt: "Burp Scanner ha trovato una lettura di file arbitrari nel mio primo lab BSCP in pochi secondi — poi ho passato venti minuti a leggere /etc/passwd dall'unico parametro che me lo mostrava davvero, scoprendo che 'external service interaction' e 'out-of-band resource load' sono due finding diversi per un motivo preciso."
lang: it
page_id: xinclude-targeted-scan-file-read
permalink: /posts/xinclude-scansione-mirata-lettura-file/
---

La response era lunga tre byte: `869`. Una quantità di magazzino. Non `root:x:0:0`, non un errore di parsing XML, nemmeno una lamentela — solo il numero di pezzi disponibili in qualche magazzino, piazzato esattamente dove sarebbe dovuto comparire il contenuto di `/etc/passwd`. Trenta secondi prima Burp Scanner mi aveva detto, con confidence **Certain**, che quella precisa richiesta poteva leggere file arbitrari dal server. E lì stava, a controllare tranquillo la disponibilità a magazzino.

Lo scarto tra *lo scanner l'ha trovato* e *io riesco a leggere il file* è tutto il post.

## Setup: puntare lo scanner, non possederlo

È il mio primo lab vero da quando ho comprato Burp Suite Professional, e la prima tappa verso il BSCP. Tutte le sessioni DVWA fin qui le ho fatte con la Community — nessuno scanner — quindi metà di questo pezzo sono io che incontro il motore di audit di Burp per la prima volta.

Il lab è **[Discovering vulnerabilities quickly with targeted scanning](https://portswigger.net/web-security/essential-skills/using-burp-scanner-during-manual-testing/lab-discovering-vulnerabilities-quickly-with-targeted-scanning)** (Practitioner). Leggere `/etc/passwd` entro 10 minuti. Il modo in cui il lab si presenta *è già* la lezione: puoi scansionare tutto il sito, ma non ti resterà tempo. Usa l'intuito per scegliere un endpoint che sembra vulnerabile, lancia un targeted scan su quella singola richiesta, poi sfruttala a mano. La skill non è *avere* lo scanner. È puntarlo.

## 1. Triage prima della scansione: quale richiesta si merita lo scan

Camminando l'app col proxy acceso, due richieste prendevano input mio:

| Endpoint | Metodo | Parametri |
|---|---|---|
| `/product` | GET | `productId=1` |
| `/product/stock` | POST | `productId=1` + `storeId=2` |

L'obiettivo è leggere un file, quindi voglio input il cui valore potrebbe finire per *riferirsi a una risorsa*. Un id di lookup prodotto sa di chiave di database. Un controllo di stock sa di "vai a recuperare la disponibilità per questo negozio" — la forma di qualcosa che *legge*. Ho puntato il targeted scan su `/product/stock`: tasto destro sulla richiesta → **Scan** → **Audit selected items** (non *Crawl and audit*). Quel "selected items" è tutta la parte "targeted" — una richiesta, nessun crawl.

## 2. Lo scanner nomina la classe, non l'exploit

Dopo pochi secondi, su `/product/stock`: **XML injection** (Medium, Certain) e **External service interaction (HTTP)** (High, Certain). Il payload che Burp aveva mandato:

```xml
<cyn xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="http://<collaborator>.oastify.com/foo"/></cyn>
```

Due finding, una sola causa radice: il mio input finisce dentro un **documento XML lato server**, e il parser risolve un `XInclude` che ho iniettato. Burp l'ha dimostrato facendo chiamare il server verso Collaborator.

Quello è il vettore. Non è l'exploit. Il lab vuole un file su disco, non una callback — come dice il lab stesso, *"once Burp Scanner has identified an attack vector, you can use your own expertise to find a way to exploit it."*

## 3. Perché XInclude, e non l'XXE da manuale

XXE da manuale: controlli tutto il documento, metti un `<!DOCTYPE>` con una `<!ENTITY>` in cima, fatto. Qui non controllo niente di tutto ciò. Possiedo un solo valore di parametro che il server infila nel *mezzo* di un documento XML che costruisce lui. Non c'è spazio per un `DOCTYPE` — non sono all'inizio di niente.

È esattamente la situazione per cui `XInclude` esiste. Un elemento `<xi:include>` può stare dentro qualsiasi valore; non gli serve che tu possieda il documento, solo che tu piazzi un singolo elemento da qualche parte al suo interno. Riconoscere *perché* la tecnica è XInclude e non l'XXE classico è più di questo lab del payload stesso.

L'hint del lab dice di cercare il topic Academy sulla classe identificata. La forma per la lettura di file:

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
```

Due modifiche rispetto al proof-of-concept dello scanner: `file://` al posto di `http://`, e `parse="text"`. La seconda è cruciale — `/etc/passwd` non è XML valido, e senza `parse="text"` il parser prova a interpretarlo *come* XML e muore con `Content is not allowed in prolog`.

## 4. Il parametro che ha risposto 869

Ho messo il payload dentro `storeId`, ho URL-encodato tutto il blocco (`Ctrl+U` sulla selezione — è `application/x-www-form-urlencoded`, quindi `<`, `>`, `/`, `"` vanno codificati) e l'ho mandato. È tornato `869`. Un numero di stock normale. Niente file, niente errore, niente.

Non era l'encoding — ho ridecodificato il mio parametro ed era pulito. Così ho spostato lo *stesso identico payload* dentro `productId`, lasciando `storeId=1`, e ho rimandato:

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

Risolto. E subito qualcosa non tornava. La request di evidenza dello scanner — quella che aveva usato per *dimostrare* il bug — aveva il payload in `storeId`. Io il file l'ho letto da `productId`. Vere entrambe, contemporaneamente. Come?

## 5. "External service interaction" e "Out-of-band resource load" sono due finding diversi

Allora ho riscansionato, stavolta puntando l'insertion point solo su `productId`. Sono tornati tre finding, e il terzo non era mai comparso nello scan di `storeId`:

- **XML injection**
- **External service interaction (HTTP)**
- **Out-of-band resource load (HTTP)** ← nuovo

Le parole di Burp su quel terzo:

> It is possible to induce the application to retrieve the contents of an arbitrary external URL **and return those contents in its own response**. […] The response from that request was then **included in the application's own response**.

Eccolo — due nomi di issue che stavo leggendo come una cosa sola:

| Finding | Cosa Burp sta davvero affermando | Canale |
|---|---|---|
| **External service interaction** | il server *ha fatto* la richiesta | cieco |
| **Out-of-band resource load** | il server ha fatto la richiesta *e mi ha restituito ciò che ha recuperato* | riflesso |

`storeId` raggiunge il parser — il colpo su Collaborator prova che l'include scatta. Ma il suo risultato non mi viene mai restituito, quindi lì la lettura di file è **cieca**: avrei visto una callback e mai il file. Il valore di `productId` invece torna *dentro il body della response*, ed è esattamente per questo che `/etc/passwd` è comparso dove prima c'era `869`.

Burp me l'aveva detto, la differenza. Aveva due nomi diversi, a una riga di distanza nella lista degli Issues. Li ho letti entrambi come "ha fatto qualcosa con una URL" e sono andato avanti. È tutto qui il senso di questo blog: lo strumento mi diceva esattamente cosa c'era, e io l'ho letto male.

## Il pattern sotto

Lo scanner è un trova-vettori, non un exploiter — il lab lo dice in inglese chiaro. Ma la versione più affilata è questa: lo scanner ti dice anche *che tipo* di vettore, e i tipi non sono intercambiabili. Un'interazione out-of-band cieca e un load riflesso in banda sono la differenza tra "qui c'è un bug" e "da qui ti leggo i file". Stessa vulnerabilità, stesso endpoint, due parametri — e solo uno dei due risponde.

Il mio errore non è mai stato davvero il parametro sbagliato. È stato appiattire due nomi di issue in un fatto solo. HTTP ha trovato la callback; il body della response ha trovato il file. Canali separati. Li avevo collassati in un'unica "cosa tipo SSRF" nella mia testa, perdendo l'unica distinzione che decideva se l'exploit fosse in banda o cieco.

## Cosa viene dopo

`storeId` è comunque vulnerabile — è solo una lettura di file *cieca*. Il che apre la domanda che questa sessione non ha chiuso: potrei esfiltrare un file attraverso `storeId` lo stesso, out-of-band, facendo recuperare al server una URL che controllo io e leggendo il contenuto dal mio listener? È blind XXE over OOB, ed è il lab successivo ovvio. Il piano diceva di interleavare le categorie dal primo giorno; questo è il filo che mi tira dentro la prossima.

## Takeaways

- **Targeted scan, non full scan.** Fai triage per "cosa potrebbe riferirsi a una risorsa", punta a una richiesta: tasto destro → Scan → *Audit selected items*. L'intuito è la skill; lo scanner è solo il grilletto.
- **Lo scanner trova la classe, tu trovi l'exploit.** Il lab lo intende alla lettera — il PoC prova il vettore, la lettura del file la costruisci tu.
- **XInclude, non XXE classico, ogni volta che controlli un solo valore dentro un documento che non possiedi.** Nessun `DOCTYPE` necessario. Aggiungi `parse="text"` o il parser si strozza su qualsiasi file non-XML.
- **"External service interaction" non è "Out-of-band resource load".** Una è cieca, l'altra è riflessa. Leggile come due fatti separati — decidono se puoi leggere il file in banda o solo provare il bug.
- **Un controllo di stock che "va a recuperare" è esattamente la forma di endpoint da sospettare** quando l'obiettivo è leggere risorse lato server.

## Riferimenti utili

- [PortSwigger — Lab: Discovering vulnerabilities quickly with targeted scanning](https://portswigger.net/web-security/essential-skills/using-burp-scanner-during-manual-testing/lab-discovering-vulnerabilities-quickly-with-targeted-scanning)
- [PortSwigger — XXE injection / XInclude attacks](https://portswigger.net/web-security/xxe)
- [PortSwigger — Using Burp Scanner during manual testing](https://portswigger.net/burp/documentation/desktop/testing-workflow/testing-using-burp-scanner)
- [siunam — Discovering vulnerabilities quickly with targeted scanning (write-up)](https://siunam321.github.io/ctf/portswigger-labs/Essential-Skills/essential-skills-1/)

---

*Tutte le tecniche mostrate sono state eseguite in un ambiente di laboratorio isolato (la Web Security Academy di PortSwigger). Attaccare sistemi che non possiedi o per cui non hai un'autorizzazione scritta è illegale nella maggior parte delle giurisdizioni.*
