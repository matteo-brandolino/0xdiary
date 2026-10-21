---
layout: post
title: "Il Bug Non Era nel Campo Password, Era nella Request Line"
date: 2026-10-21
categories: [web-security, walkthrough]
tags: [portswigger, mystery-lab, ssrf, request-smuggling, burp-suite, intruder, http]
excerpt: "Ho rollato un lab, visto una form di login, e perso venti minuti a bruteforzare credenziali che non erano affatto il punto — il vero bug stava in come la request-line e il Host header possono non essere d'accordo su chi stai davvero contattando."
lang: it
page_id: ssrf-flawed-request-parsing-admin-delete
permalink: /posts/ssrf-flawed-request-parsing-admin-delete/
---

Ho visto un campo username e password, e ho attaccato un campo username e password. `wiener` / `peter`, credenziali non valide, nessun blocco dopo una decina di tentativi — classico broken brute-force protection, ho pensato, e ho continuato. Venti minuti dopo, niente si muoveva, e niente nella form di login era cambiato. La form non era il bug. Non le era nemmeno vicina. La vulnerabilità vera non aveva alcun interesse per quello che scrivevo dentro — le interessava una riga della richiesta HTTP che non avevo nemmeno toccato.

Questo lab viene da [Mystery Pool]({% post_url 2026-10-04-mystery-pool-strumento %}), pool ampliato questa volta con authentication aggiunta al solito gruppo. PortSwigger ha rollato **SSRF via flawed request parsing**.

## Setup

Una form di login nella landing page, nient'altro di visibilmente interattivo. Nessun campo commenti, nessun profilo utente, nessun punto di injection ovvio. Solo credenziali e un errore generico.

## La sessione

### 1. Categoria sbagliata, attacco sbagliato, venti minuti persi

"Invalid username or password," nessuna differenza nel tempo di risposta, nessun blocco account dopo tentativi ripetuti, nessun messaggio diverso tra un username valido e uno inesistente. Ho letto tutto questo come "broken brute-force protection" — il pool conteneva authentication, quindi la mia testa è finita lì dentro, e ci sono rimasto a testare username cercando un qualsiasi segnale che mi dicesse di averne trovato uno vero. Non c'era. La form era un vicolo cieco travestito da primo tentativo ragionevole, e non ho controllato la descrizione reale del lab finché non avevo già bruciato quel tempo.

### 2. La descrizione dice "request parsing," non "credenziali"

Il nome del lab è l'indizio intero, e l'avevo ignorato a favore del primo elemento interattivo che avevo visto. "Flawed request parsing" non ha niente a che fare con quello che scrivi in un campo — riguarda come due componenti diversi dello stack leggono la *stessa richiesta* e non si accordano su cosa dica.

### 3. Il Host header viene controllato per qualcosa — il 403 lo dimostra

Sono passato a testare la richiesta in sé. Una richiesta semplice verso un host che sembrava interno ha ricevuto un secco `403 Forbidden`. Non è un errore di parsing, è una decisione — qualcosa controlla attivamente un valore e lo rifiuta attivamente. La domanda giusta qui non è "come supero il 403," è "quale campo sta davvero leggendo questo controllo, e c'è un altro campo che porta la stessa informazione che *non* viene letto."

### 4. Request-line in absolute-form: far disaccordare i due campi

HTTP permette alla request-line di portare un URL assoluto completo invece del solo path — l'**absolute-form**, definita per i proxy, che la maggior parte dei server deve ancora accettare anche se quasi nessuno la scrive a mano. Ho riscritto la richiesta direttamente nell'editor raw di Burp:

```
GET https://0aa600f903cec5b48082cc7600b0006b.web-security-academy.net HTTP/2
Host: <indirizzo Collaborator controllato dall'attaccante>
```

La risposta è passata da `403 Forbidden` a `502 Bad Gateway`. Questo è l'indizio: il filtro ha controllato il Host header, ha visto il dominio pubblico nella request-line e ha lasciato passare, ma qualunque cosa apra davvero la connessione in uscita più a valle ha usato invece il *Host header* — che puntava a un indirizzo sotto il mio controllo. `502` significa che la richiesta è davvero partita. Ho confermato che non fosse una supposizione puntando il Host header verso un vero dominio Burp Collaborator e vedendo l'interazione arrivare nella tab di Collaborator: una richiesta era davvero uscita verso di esso.

### 5. Sweep sulla rete interna con Intruder

Un primitivo SSRF funzionante senza un bersaglio noto è solo un primitivo funzionante. Ho messo la richiesta in Intruder, impostato la posizione del payload sull'ultimo ottetto del Host header, e lanciato `192.168.0.$0$` su tutto il range:

```
GET https://0aa600f903cec5b48082cc7600b0006b.web-security-academy.net HTTP/2
Host: 192.168.0.112
```

Ogni altro indirizzo nello sweep è tornato con un timeout o la normale risposta pubblica. `.112` è tornato diverso:

```
HTTP/2 302 Found
Location: /admin
```

Un redirect verso `/admin` su un indirizzo interno che il sito pubblico non reindirizza mai è esattamente ciò per cui esiste lo sweep: qualcosa in ascolto lì tratta la richiesta come già privilegiata, perché dal suo punto di vista arriva da dentro la rete di fiducia.

### 6. Il pannello admin, e un token CSRF preso dal posto giusto

Caricare `/admin` con lo stesso trucco `Host: 192.168.0.112` ha restituito il pannello vero — lista utenti, azione delete, e un token CSRF nella form di quella stessa pagina. Ho preso il token da lì, non da una richiesta precedente, e l'ho usato subito contro lo stesso host:

```
POST https://0aa600f903cec5b48082cc7600b0006b.web-security-academy.net/admin/delete HTTP/2
Host: 192.168.0.112
Cookie: session=...

csrf=pqV2wIFnTcwqODKVlyBUvKv6VjGWG7yK&username=carlos
```

`carlos` eliminato, lab risolto. Niente nell'exploit ha toccato una password, un tentativo di username, o qualunque logica applicativa — erano due campi in una richiesta HTTP raw, messi in disaccordo tra loro.

## Il pattern

Un filtro e un motore di routing stavano entrambi leggendo "la richiesta," ed entrambi presumevano di leggere lo stesso valore, perché nel caso schiacciante più comune — una richiesta diretta del client, request-line in origin-form, nessun proxy di mezzo — l'host implicito nella request-line e il Host header *sono* la stessa informazione scritta due volte. A nessuno, scrivendo il filtro di sicurezza, è venuto in mente di chiedersi "e se non lo fossero," perché la request-line in absolute-form è una feature che quasi nessuno usa di proposito. Il front-end ha controllato il campo che controlla chiunque. Il codice di routing del back-end, scritto per un altro scopo (essere davvero un proxy), leggeva l'altro.

La versione generalizzabile: ogni volta che un controllo di sicurezza legge il campo A e l'elaborazione reale a valle legge il campo B, e A e B sono *di solito* copie ridondanti della stessa informazione, quella ridondanza è esattamente il punto dove cercare un modo per farli disaccordare. Il 403 mi ha detto che un controllo esisteva. È bastato notare che HTTP ha più di un posto dove scrivere "l'host" per trovare il campo che quel controllo non stava guardando.

## Exam e field

| | Exam | Field |
|---|---|---|
| Cosa riconoscere | un `403` netto su un controllo chiaramente basato sull'host, specialmente quando il nome del lab stesso dice "parsing" invece di nominare una classe di attacco | un reverse proxy o gateway davanti a un server applicativo, dove il filtro di sicurezza e il routing della richiesta sono implementati in componenti diversi (o percorsi di codice diversi dello stesso componente) |
| Dove va il tempo | non inseguire il primo elemento interattivo (una form di login, una barra di ricerca) quando il nome stesso del lab punta altrove; riscrivere la request-line a mano nell'editor raw di Burp, perché non c'è un controllo UI per farlo | scoprire che l'architettura del bersaglio ha davvero questa separazione — la maggior parte dei setup moderni non la esponde, ma CDN, proxy legacy e gateway fatti in casa a volte sì |
| Trappola comune | assumere che l'unica superficie d'attacco sia il valore di un parametro, senza mai toccare la request-line o header meno comuni | trattare un 403 come "questo è chiuso" invece di "qualcosa sta controllando un valore, e potrebbe esistere un altro valore che porta la stessa informazione" |
| Limite reale | un singolo endpoint admin interno, un `/24` noto da fare sweep | dipende interamente da cosa è raggiungibile dal componente vulnerabile — API interne, endpoint di metadata cloud, altri servizi interni, tutto attraverso l'unico campo che il filtro non stava leggendo |

Difesa: fai in modo che il componente che applica la policy di sicurezza e il componente che esegue davvero la connessione in uscita siano d'accordo su un'unica fonte di verità per l'host di destinazione — idealmente la stessa, letta nello stesso modo, nello stesso punto — invece di lasciare che un filtro validi un campo mentre la logica di routing si fida di un altro.

## Cosa viene dopo

Lo sweep su `192.168.0.0/24` ha funzionato perché il lab mi ha dato un range piccolo e noto da bruteforzare in pochi minuti. La domanda aperta è la stessa dell'ultima volta: quanto lontano porta davvero questo tipo di primitivo su una rete interna reale, dove i range non sono un `/24` ordinato e un redirect verso `/admin` non si annuncia nello stesso modo. Quella è reconnaissance, non exploitation, ed è la parte che non ho ancora praticato.

## Takeaways

- Il nome di un lab è l'indizio più letterale e immediato — "flawed request parsing" è un'affermazione su *dove* vive il bug, non una descrizione di sapore da scorrere in fretta verso la prima form che vedi.
- Un `403` netto su un valore specifico significa che un controllo esiste e lo sta valutando attivamente — la domanda successiva è se un altro campo dello stesso protocollo porta la stessa informazione senza essere controllato.
- La request-line in absolute-form di HTTP è una feature legittima, definita dallo standard, che quasi nessuno scrive a mano — ed è esattamente per questo un buon posto dove cercare disallineamenti di parsing tra front-end e back-end.
- `403` → `502` sulla stessa forma di attacco è una transizione di stato da leggere alla lettera: significa che la richiesta ha iniziato ad arrivare più lontano di prima, non che l'attacco è fallito in un modo diverso.
- Prendi i token CSRF dalla pagina esatta contro cui stai per fare submit, non da una richiesta precedente nella sessione — è una piccola disciplina che evita un retry confuso più avanti.

## Link utili

- [PortSwigger Web Security Academy: Server-side request forgery (SSRF)](https://portswigger.net/web-security/ssrf)
- [RFC 9112 §3.2 — HTTP/1.1 request-target forms](https://www.rfc-editor.org/rfc/rfc9112#section-3.2)
- [PortSwigger Web Security Academy: HTTP request smuggling](https://portswigger.net/web-security/request-smuggling)
- [Mystery Pool: a random lab from only the topics you choose]({% post_url 2026-10-04-mystery-pool-strumento %})

*Tutte le tecniche mostrate sono state eseguite in un ambiente di laboratorio isolato (PortSwigger Web Security Academy). Attaccare sistemi che non possiedi o per cui non hai un'autorizzazione scritta è illegale nella maggior parte delle giurisdizioni.*
