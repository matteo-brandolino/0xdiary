---
layout: post
title: "Primo roll dello step due: il token CSRF che proteggeva la cosa sbagliata"
date: 2026-11-16
categories: [web-security, walkthrough]
tags: [portswigger, bscp, csrf, crlf-injection, response-header-injection, account-takeover, mystery-lab, burp-suite]
excerpt: "Prima volta che giro il mio Mystery Pool sullo step di escalation: il form di cambio email urlava CSRF, il token reggeva davvero, e lo scanner continuava a puntare la barra di ricerca — che poi era l'altra metà dello stesso attacco."
lang: it
page_id: csrf-token-tied-to-non-session-cookie
permalink: /posts/csrf-token-tied-to-non-session-cookie/
---

Lo scanner puntava il posto sbagliato e mi ci è voluto un minuto per ammettere che non lo fosse. Avevo fatto login, visto il form di cambio email, catalogato come CSRF prima di toccare qualunque cosa — il riflesso che vuoi avere all'esame — e poi lo scan era tornato con la sua unica bandiera rossa piantata non sul form ma sulla *barra di ricerca*: HTTP response header injection. Per un attimo è sembrata una deviazione, un secondo bug slegato da smaltire più tardi. Non lo era. La barra di ricerca era il motivo per cui il CSRF era sfruttabile. Il token sul form era vero e reggeva; la via d'ingresso era smettere di attaccare il token e cominciare ad attaccare la cosa a cui era legato.

Era la prima volta che puntavo il mio [Mystery Pool]({% post_url 2026-10-04-mystery-pool-strumento %}) sul **secondo** step del BSCP — privilege escalation — invece del cluster di foothold che stavo macinando. Fase diversa, testa diversa: lo step uno è "esegui qualcosa in un browser", lo step due è "diventa l'admin o rubagli i dati". La ruota ha aperto l'account proprio con questo.

## Il setup

Dall'ultima volta che ho scritto del tool, era cresciuto abbastanza da rendere piacevole puntarlo sullo step due. Gli ultimi commit, per cronaca:

- i topic ora sono **raggruppati per fase d'esame** — Foothold, Escalation, Exfiltration — ognuno la sua card con un toggle "seleziona tutto", così "tirami lo step due" sono tre click, non venti checkbox;
- la logica del roll è passata in un **modulo senza DOM con i test** (`assets/roll.js`), così la scelta casuale è testata a unità invece che impastata nella pagina;
- ho aggiunto i **topic diretti** che il Mystery Lab non copre — OS command injection, Clickjacking, WebSockets, GraphQL, API testing, race conditions, NoSQL, Web LLM, cache deception e prototype pollution divisa in client-side e server-side — generati direttamente dalla pagina all-labs. L'endpoint del Mystery Lab per quelli risponde *"nessun lab"*, quindi il tool ne pesca uno da solo e lo apre per via diretta;
- la prototype pollution server-side sta in Escalation accanto al topic client-side, e il suo unico lab che finisce in RCE è diventato un topic a sé, in Exfiltration.

Ho spuntato la card Escalation e ho tirato. Un dettaglio onesto dallo schermo: **Access control era in grigio, disattivata**. Nel widget del Mystery Lab quella categoria esiste solo a livello Apprentice, e io avevo il filtro su Practitioner, quindi il tool si è giustamente rifiutato di far finta di avere un lab da darmi. Meglio così — preferisco vedere un'opzione morta disabilitata che tirare e sbattere contro un "nessun lab corrisponde alla tua richiesta".

Strumenti per la sessione: Burp, lo scanner puntato sui singoli input invece che su un crawl largo, Repeater per tutto il resto.

## La sessione

### 1. Il candidato ovvio che non era il punto

Login come `wiener:peter`, e la prima cosa sulla pagina account è un bottone per aggiornare l'email. Nello step due, un form che cambia lo stato dell'account è un candidato CSRF prima ancora di aver letto un byte — quindi la testa è andata lì.

Poi ho intercettato il submit, e la lettura ovvia è crollata:

```http
POST /my-account/change-email HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: csrfKey=ItjPUfoR1KO73IXiV8KmYfpzzLWAtLBU; session=g9NrFqqwnOp8oV2DneR2u8OweUSaHnVL; LastSearchTerm=test
...
email=test1%40gmail.com&csrf=WnX9ZKcGmOFmd2p8y4lhW8YtB1fmejT6
```

C'è un token `csrf` nel body, e non è decorativo — toglilo o storpialo e il server rifiuta la richiesta. Il CSRF ingenuo ("ometti il token e vedi se passa") muore qui. Il form *ha* una difesa e la difesa *funziona*. Se la storia finisse qui il lab sarebbe non sfruttabile, il che è un forte indizio che la storia non finisce qui.

### 2. Lo scanner punta la barra di ricerca

Ho lanciato lo scanner e la sua unica finding ad alta severità l'ha messa dove non stavo guardando: **HTTP response header injection** sul parametro di ricerca. Il probe nella richiesta rendeva il meccanismo lampante:

```http
GET /?search=00eei%0d%0a3hpxk HTTP/2
```

`00eei` e `3hpxk` sono solo i marker random dello scanner attorno al punto d'iniezione. Il payload in mezzo è `%0d%0a` — un **CRLF**. Lo scanner mi stava dicendo che quei due byte tornavano *grezzi* in un header della risposta, spezzandolo. Il mio primo istinto è stato archiviarlo come bug separato per dopo. Istinto sbagliato, e accorgersi del perché è tutto il lab.

Riguarda i cookie sulla richiesta di cambio email: `LastSearchTerm=test`. **La barra di ricerca scrive un cookie.** La cosa che lo scanner segnalava — CRLF grezzo riflesso dentro un header `Set-Cookie` — è una primitiva per scrivere cookie *arbitrari* nel browser della vittima. Tieni il pensiero.

### 3. Il clic: il token è legato a un cookie, non alla sessione

Torniamo al token. Perché un token CSRF valga qualcosa, deve essere ancorato a qualcosa che l'attaccante non controlla — di norma **la sessione**. Il server ricorda "la sessione `g9Nr...` ha il token `WnX9...`" e li controlla insieme. L'attaccante non conosce né l'una né l'altro, quindi non può forgiare una coppia valida.

Questo token non è legato alla sessione. È legato a quel **secondo cookie**, `csrfKey`. La regola di validazione è solo:

> il `csrf` nel body deve fare coppia con il `csrfKey` nel cookie.

La sessione non entra mai nel controllo. Lo confermi in dieci secondi, ed è lo step di identificazione che conta sotto pressione d'esame: prendi la coppia `csrfKey` + `csrf` di un account e rigiochi il cambio email su una sessione *diversa* — passa lo stesso. Oppure togli del tutto il cookie `session` e lascia `csrfKey` + `csrf`: il controllo CSRF passa comunque. Il token non sa niente di chi sei; sa solo di `csrfKey`.

È il momento in cui ha fatto clic, e ribalta l'intero attacco. Il senso di un token CSRF è che l'attaccante non può procurarsi una coppia valida *per la vittima*. Ma io il mio account ce l'ho, quindi ho la **mia** coppia valida — `csrfKey=ItjP...` / `csrf=WnX9...`. Non devo indovinare il token della vittima. Devo far sì che la vittima **usi la mia coppia**. E metà della mia coppia vive in un cookie — un cookie che ho appena scoperto di poter scrivere, tramite la barra di ricerca.

Due difese mancanti, ognuna innocua da sola, letali insieme: il token ancorato a un cookie scrivibile, e un cookie scrivibile dall'esterno.

### 4. La primitiva: CRLF nella search per piantare il mio `csrfKey`

Teniamo separati i due layer, perché falliscono in modo indipendente.

**Layer HTTP.** La funzione di ricerca prende `?search=...` e lo rimanda in un header che ricorda l'ultima ricerca:

```http
Set-Cookie: LastSearchTerm=test
```

Un header HTTP finisce con `\r\n`. L'app scrive il mio valore in quell'header senza togliere i caratteri di controllo, quindi se mando un `\r\n` (`%0d%0a`) il browser considera finita la riga e legge quello che segue come un *header nuovo, tutto mio*:

```http
GET /?search=test%0d%0aSet-Cookie:%20csrfKey%3dItjPUfoR1KO73IXiV8KmYfpzzLWAtLBU%3b%20SameSite%3dNone HTTP/2
```

che produce:

```http
Set-Cookie: LastSearchTerm=test
Set-Cookie: csrfKey=ItjPUfoR1KO73IXiV8KmYfpzzLWAtLBU; SameSite=None   ← iniettato
```

Il browser onora entrambe le righe `Set-Cookie`, quindi `csrfKey` nel browser della vittima diventa il *mio* valore. Il `SameSite=None` conta: quel cookie dovrà poi viaggiare su un POST cross-site, e senza `None` il browser non lo allegherebbe.

**Layer logica.** Perché posso far visitare quella URL alla vittima? Perché **la ricerca non ha protezione CSRF propria** — è una semplice GET senza token, quindi posso innescarla dal browser della vittima con un nudo `<img src="...">`. Se anche la ricerca avesse voluto un token, non potrei forzarla e la catena morirebbe qui. Una difesa (il token) rende `csrfKey` l'anello debole; l'altro buco (la ricerca, non protetta e vulnerabile a CRLF) è come raggiungo quell'anello.

### 5. L'ordine: l'immagine fa da sequenziatore

Ora ho due azioni da far compiere alla vittima, in ordine stretto:

1. GET alla search → pianta `csrfKey=ItjP...` (il mio).
2. POST a change-email con `csrf=WnX9...` → fa coppia col key appena piantato → eseguito.

Invertile e il POST parte mentre la vittima ha ancora il *suo* vecchio `csrfKey`, il mio token non combacia, rifiutato. Quindi l'exploit server deve garantire "prima il cookie, poi il form". Il payload che lo fa:

```html
<html>
  <body>
    <script>history.pushState('', '', '/')</script>
    <form action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="attacker@YOUR-EXPLOIT-SERVER.exploit-server.net" />
      <input type="hidden" name="csrf" value="WnX9ZKcGmOFmd2p8y4lhW8YtB1fmejT6" />
      <input type="submit" value="Submit request" />
    </form>
    <img src="https://YOUR-LAB-ID.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrfKey=ItjPUfoR1KO73IXiV8KmYfpzzLWAtLBU%3b%20SameSite=None"
         onerror="document.forms[0].submit()">
  </body>
</html>
```

L'`<img>` fa partire la GET della ricerca. La risposta è HTML, non un'immagine, quindi il caricamento **fallisce** — e un caricamento fallito è esattamente il punto in cui il `Set-Cookie` è già stato incassato dal browser. `onerror` scatta *allora*, e solo allora chiama `document.forms[0].submit()`. L'immagine non è decorazione, è il **sequenziatore**: trasforma "spero che la GET arrivi prima" in "il POST non può partire finché la GET non è tornata".

Il `history.pushState('', '', '/')` in cima riscrive l'URL dell'exploit server così il `Referer` del POST sembra pulito — assicurazione gratis se il server controlla anche il Referer, innocua se non lo fa.

Consegna alla vittima, l'email si ribalta sulla mia, e da un'email cambiata un reset password è il passo successivo di prammatica. Account takeover.

## Il pattern

Nomina il pattern, non l'istanza: **un token CSRF è forte solo quanto la cosa a cui è ancorato.** Il token in sé andava bene — imprevedibile, validato, impossibile da indovinare. Era legato all'ancora sbagliata. Ancorarlo a `csrfKey` invece che alla sessione vuol dire far poggiare la difesa su "l'attaccante non può settare questo cookie", e nel momento in cui un endpoint *diverso* lascia che un attaccante setti cookie nel browser della vittima, il token non difende nulla. Non rompi il token. Sostituisci l'ancora e porti il tuo token abbinato.

La seconda lezione, più generale, è quella che per poco non sbagliavo: **lo scanner nomina sintomi su input isolati; incatenare tocca a te.** Ha segnalato "header injection sulla search" e "un form che sa di CSRF" come due finding, su due pagine, in due severità diverse. Sono un attacco solo. L'header injection è inutile da sola (chi se ne importa che posso settare i miei cookie nel mio browser) e il token CSRF è inattaccabile da solo. L'exploit esiste solo nella cucitura tra i due, e niente nell'elenco degli issue te la disegna.

Tieni separati i layer HTTP e logica mentre ragioni, perché falliscono per motivi diversi: il CRLF è un fallimento di parsing HTTP (byte di controllo scritti in un header), la debolezza del token è un fallimento di logica applicativa (ancora sbagliata), e la consegna funziona per un comportamento del browser (cookie allegati in automatico, `SameSite` permettendo). Tre layer, tre errori indipendenti, una catena.

## Esame e campo

**All'esame**, siamo in pieno Stage 2 — privilege escalation via account takeover. I tell per riconoscerlo in fretta sono concreti: un campo nascosto `csrf` *più un cookie `csrfKey` separato* è il segnale — due cookie, uno fa identità e l'altro ancora il token. Conferma in pochi secondi rigiocando la coppia del token sotto una sessione diversa; se valida ancora, il token non è legato alla sessione e vai a caccia di una primitiva per settare cookie. Quella primitiva di solito è un CRLF/response-header injection in un posto noioso — una barra di ricerca, un selettore di lingua, qualunque cosa rimandi l'input in `Set-Cookie`. Profilo di interazione: alla vittima basta *aprire* la tua pagina sull'exploit server; niente click, niente digitazione. I rabbit hole che costano minuti qui: trattare l'header injection sulla search come un bug separato da riprendere dopo (è la chiave del lab), e sbagliare l'**ordine** dell'exploit — fai partire il form prima che il cookie atterri e fallisce in silenzio con un payload all'apparenza valido.

**Sul campo**, la forma si ripresenta ben oltre questo lab: qualunque token, nonce o valore anti-CSRF vale quanto il suo binding. Legalo alla sessione e a stato lato server; mai a un cookie che il client — o un bug — può sovrascrivere. E il bug abilitante, CRLF in un header di risposta, è quello silenzioso: da solo è una curiosità a bassa severità, ma è una primitiva di cookie injection e cache poisoning che alza la severità di qualunque cosa gli incateni. Togli il `\r\n` da tutto ciò che raggiunge un header, e la catena perde il primo anello.

## Cosa viene dopo

Questo era il roll uno dello step due, e ha già disegnato la mappa del resto della fase: l'escalation è soprattutto *account takeover per qualche altra strada* — CSRF qui, ma accanto nel pool stanno falle di password reset, JWT, OAuth e prototype pollution, tutte puntate allo stesso premio da angoli diversi. Il filo aperto è la testa stessa dello step due: nello step di foothold ero contento di piazzare un `alert(1)`; qui la condizione di vittoria è l'account di qualcun altro, e ogni lab è una risposta diversa a "come divento te". La ruota gira ancora.

## Takeaways

- Un token CSRF è forte solo quanto la sua ancora: legato a un cookie invece che alla sessione, non difende nulla una volta che esiste una primitiva per settare cookie — non rompi il token, sostituisci l'ancora e porti la tua coppia abbinata.
- Conferma la debolezza in pochi secondi: rigioca la coppia `csrfKey` + `csrf` di un account sotto una sessione diversa; se il cambio passa ancora, il token non è legato alla sessione.
- Il CRLF injection (`%0d%0a`) in un `Set-Cookie` riflesso è una primitiva per scrivere cookie — bassa severità da sola, letale come primo anello di una catena.
- L'ordine conta negli exploit multi-step: usa `<img ... onerror="form.submit()">` così il cookie è piantato *prima* che il form parta; invertito, fallisce in silenzio.
- Lo scanner segnala sintomi su input isolati; la catena sta a te vederla. "Header injection sulla search" e "un form CSRF" erano un attacco solo, archiviato come due finding.

## Riferimenti utili

- [PortSwigger Web Security Academy: CSRF](https://portswigger.net/web-security/csrf)
- [PortSwigger: CSRF where token is tied to non-session cookie](https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-tied-to-non-session-cookie)
- [OWASP: CRLF injection](https://owasp.org/www-community/vulnerabilities/CRLF_Injection)
- [PortSwigger: SameSite cookies](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions)
- [botesjuan — Burp Suite Certified Practitioner Exam Study](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study)
- [Mystery Pool — il tool da cui è uscito questo roll]({% post_url 2026-10-04-mystery-pool-strumento %})

*Tutte le tecniche mostrate sono state eseguite in un ambiente di laboratorio isolato (la Web Security Academy di PortSwigger). Attaccare sistemi che non possiedi o per cui non hai un'autorizzazione scritta è illegale nella maggior parte delle giurisdizioni.*
