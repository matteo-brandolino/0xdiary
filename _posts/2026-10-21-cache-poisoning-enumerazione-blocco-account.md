---
layout: post
title: "Lo Scanner Ha Segnalato una Pista Inutile, e un Blocco Che Ho Causato Apposta"
date: 2026-10-21
categories: [web-security, walkthrough]
tags: [portswigger, mystery-lab, web-cache-poisoning, cookies, javascript, burp-suite, intruder, authentication, account-lockout, username-enumeration]
excerpt: "Due lab dallo stesso roll: uno in cui lo scanner di Burp mi ha dato una pista che sembrava una SQL injection e non lo era, e uno in cui il solo modo per trovare uno username valido era bloccare l'account apposta e leggere l'errore che ne seguiva."
lang: it
page_id: cache-poisoning-account-lockout-enumeration
permalink: /posts/cache-poisoning-account-lockout-enumeration/
---

Di solito cerchi di evitare che un account venga bloccato. Nel secondo lab di oggi, bloccarlo apposta era l'intero attacco. E nel primo, lo scanner di Burp mi ha dato una segnalazione che sembrava esattamente una SQL injection, tanto di domain out-of-band — e la mossa giusta era non inseguirla, perché il bug vero stava a schermo piatto due righe più in basso nella stessa risposta.

Entrambi i lab vengono da [Mystery Pool]({% post_url 2026-10-04-mystery-pool-strumento %}), pool ora a cinque topic: web cache deception, cross-site scripting, vulnerabilità DOM-based, host header attacks, e — aggiunta questa volta — authentication.

## Setup

Lab uno: nessuna form di commenti, nessuna barra di ricerca, niente di ovviamente iniettabile. Solo una semplice `GET /` con un header `Cache-Control` nella risposta, che è già di per sé un indizio. Lab due: una form di login e nient'altro, nessun rate limiting visibile, nessun messaggio di blocco account dopo una decina di tentativi.

## Lab uno: web cache poisoning via unkeyed cookie

### 1. Una segnalazione dello scanner che dice meno di quanto sembri

Lo scan di Burp su `GET /` ha trovato "Input returned in response (stored)," severità Informational, confidenza Certain: il valore di un cookie veniva copiato nella pagina. Da sola non è una vulnerabilità — è una precondizione per diventarlo. Combinata con un header `Cache-Control` sulla stessa risposta, diventa una forma specifica: un valore che influenza la pagina, su una risposta che viene cache-ata. È quella combinazione la vera pista, non l'etichetta di severità della segnalazione.

### 2. Un payload spaventoso che non era il bug

Lo scanner aveva anche lanciato i suoi probe generici su quello stesso cookie, incluso un payload blind, out-of-band, basato su `extractvalue()` e un'entità esterna che puntava a un domain Collaborator `oastify.com`. Vederlo nella history di Burp la prima volta mette a disagio — sembra esattamente una SQL injection confermata, domain Collaborator e tutto. Ma il pool di questo roll non includeva SQL injection come categoria, e lo scanner spara ogni payload standard su ogni parametro a prescindere da cosa chieda davvero il lab. Inseguirla fino in fondo avrebbe richiesto controllare il client Collaborator per un'interazione; la mossa più rapida e pertinente era smettere di trattare l'output dello scanner come l'indagine e andare a leggere io stesso la risposta grezza.

### 3. La risposta grezza, letta per bene

`view-source`, non il DOM renderizzato, è dove stava la vera forma del bug:

```html
<script>
    data = {"host":"0ae9...web-security-academy.net","path":"/","frontend":"prod-cache-01"}
</script>
```

```
Cache-Control: max-age=30
Age: 20
X-Cache: hit
```

Il campo `host` è solo il dominio della richiesta — gestito dal server, innocuo, non è la pista. Il cookie mandato con la richiesta era `fehost`, e il suo valore finisce, senza escaping, come **ultima** proprietà di quell'oggetto: `frontend`. `X-Cache: hit` sopra tutto questo confirma il meccanismo: questa risposta non è stata generata fresca per questa richiesta, è stata presa da una cache condivisa tra visitatori, e la chiave di quella cache a quanto pare non include affatto questo cookie. Input non keyed, in una risposta cache-ata, riflesso in uno script. Questo è l'intero bug in una frase.

### 4. Il primo tentativo di breakout era sbagliato, e andava bene così

La mia prima idea era puntare al campo `host`, assumendo un oggetto letterale pulito dove chiudere la stringa e l'oggetto (`"};alert(...);//`) avrebbe funzionato ovunque. Non ha sparato — `host` non è l'ultima proprietà, quindi chiuderla così lascia il resto dell'oggetto (`,"path":"/","frontend":"prod-cache-01"}`) sintatticamente rotto. Guardando di nuovo dove il cookie finiva davvero — `frontend`, l'**ultima** chiave, subito prima della `}` di chiusura — cambia completamente quale tipo di breakout serve.

### 5. Il payload che calzava con la posizione reale

```
fehost=x"-alert(document.cookie)-"x
```

Sostituito nell'oggetto:

```js
data = {"host":"0ae9...","path":"/","frontend":"x"-alert(document.cookie)-"x"}
```

Letto come JavaScript, `"x"-alert(document.cookie)-"x"` è una singola espressione valida: la sottrazione forza entrambi gli operandi stringa verso una coercizione numerica, `alert()` viene eseguita come effetto collaterale della valutazione, e tutto il resto si risolve a `NaN` — che non interessa a nessuno, perché a quel punto l'alert è già scattato. Nessun punto e virgola, nessuna parentesi di chiusura necessaria, perché il valore sta esattamente dove l'oggetto finisce comunque.

### 6. Avvelenare la cache condivisa, non solo la mia risposta

Far renderizzare il payload nel mio stesso `view-source` era necessario ma non sufficiente — l'obiettivo del lab è una vittima che non manda mai questo cookie. Ripetendo la stessa richiesta con il cookie `fehost` malevolo, controllando la risposta ogni volta, alla fine il payload è apparso nella copia cache-ata che qualunque richiesta semplice a `/` avrebbe ora ricevuto, `max-age=30` e tutto. Una volta confermato, la simulazione della vittima integrata nel lab lo ha ricevuto in una visita normale, senza cookie, e ha eseguito.

## Lab due: username enumeration via account locking

### 1. Nessun blocco, nessun rate limiting, niente di evidentemente sbagliato

Una manciata di tentativi manuali contro la form di login ha prodotto sempre lo stesso generico "Invalid username or password," nessun rallentamento, nessun blocco. Letto isolatamente, è indistinguibile da una form che funziona davvero bene — il comportamento interessante non sarebbe emerso da una manciata di tentativi. Serviva volume.

### 2. Forzare apposta l'unico segnale che esiste

L'idea qui inverte l'approccio solito: invece di evitare un blocco, scatenarlo di proposito, su ogni username, e vedere quale produce una risposta di blocco *diversa* dagli altri. Burp Intruder, attacco Cluster bomb:

- Posizione payload 1: username, wordlist di username candidati di PortSwigger
- Posizione payload 2: password, un payload nullo generato 5 volte per username — cinque tentativi con password errata quasi simultanei contro lo stesso account, abbastanza da far scattare una soglia di blocco per account, se ne esiste una

### 3. Una risposta rompe lo schema

Ogni username è tornato con lo stesso messaggio generico di credenziali non valide, tranne uno:

```
ec2-user → You have made too many incorrect login attempts
```

Quel messaggio non ha niente a che fare con se una particolare password fosse corretta. Scatta perché l'account esiste ed ha appena superato una soglia di tentativi falliti — un canale laterale che conferma uno username valido senza mai indovinarne la password. Ogni altro username candidato ha ricevuto il messaggio generico perché non c'era nessun account dietro da bloccare, in primo luogo.

### 4. L'account che mi serviva era proprio quello che avevo appena bloccato

Confermare lo username significava che l'account era, in quel preciso momento, nello stato di blocco in cui i cinque tentativi falliti rapidi lo avevano messo. Fare login con la password giusta immediatamente dopo sarebbe comunque fallito, per un motivo che non aveva niente a che fare con la password sbagliata — la risposta sarebbe sembrata identica a un vero fallimento, esattamente il tipo di ambiguità che spreca i prossimi dieci minuti se non te ne accorgi.

### 5. Aspettare che passasse, poi un attacco Sniper che significava davvero qualcosa

Il blocco si è esaurito dopo un'attesa, invece di essere permanente. Una volta passato, un attacco Sniper con `ec2-user` fisso e una wordlist di password sull'unica posizione payload è tornato con ogni candidato che dava la stessa risposta di errore tranne uno: `mobilemail`, distinto dal resto. Un login manuale con `ec2-user` / `mobilemail` — dopo aver aspettato di nuovo che passasse il blocco dell'account, dato che l'attacco Sniper stesso l'aveva fatto scattare di nuovo — l'ha confermato. Lab risolto.

## Il pattern

Entrambi i lab si sono risolti leggendo un segnale per quello che indicava davvero, non per quello a cui somigliava. La segnalazione dello scanner a forma di SQLi somigliava a una pista vera e non lo era, perché la categoria a cui apparteneva non era nemmeno in gioco — la forma di un payload non è prova della sua pertinenza con l'obiettivo che hai davanti. Il messaggio di blocco account somigliava a un vicolo cieco (bloccato, nessuna informazione utile) ed era invece l'unica informazione utile disponibile, perché quello che rivelava — "questo account esiste" — era vero indipendentemente da quale password l'avesse fatto scattare.

La versione generalizzabile: una risposta che somiglia a uno stato di fallimento (un blocco, un errore, un rifiuto generico) porta comunque informazione sul *perché* è scattata. Leggere solo la superficie ("bloccato" / "rifiutato") la butta via. Leggere il testo specifico, o la condizione specifica che l'ha fatta scattare, è quello che trasforma un vicolo cieco in un canale laterale.

## Exam e field

**Lab uno — web cache poisoning via unkeyed cookie**

| | Exam | Field |
|---|---|---|
| Cosa riconoscere | una segnalazione "input returned in response" dello scanner su una risposta che porta anche `Cache-Control`, più un header `X-Cache` che confirma gli hit | cache front-end (CDN, cache di reverse proxy) che fanno chiave su URL e un set fisso di header, mentre l'app di origine riflette un header, cookie o valore che la cache non conosce |
| Dove va il tempo | non inseguire ogni probe dello scanner per quello che sembra — distinguere una pista pertinente dal rumore generico sparato su ogni parametro; trovare la posizione esatta del valore riflesso prima di scegliere un breakout | confermare lo scope della cache (per-utente, per-nodo edge, o davvero condivisa) prima di assumere che una risposta avvelenata raggiunga qualcuno oltre la propria sessione |
| Trappola comune | assumere che un payload spaventoso (SQLi OOB, XXE) sia automaticamente il bug voluto solo perché è nei risultati dello scan | trattare `Vary` o la configurazione documentata della cache key come esaustiva — gli input non keyed sono tali esattamente perché nessuno li ha elencati |
| Limite reale | una cache condivisa, TTL di 30 secondi, una simulazione di vittima fornita dal lab | serve che la risposta sia davvero cacheable e condivisa, e che la voce avvelenata sopravviva abbastanza a lungo perché una vittima vera la colpisca prima della scadenza o che un refetch legittimo la sovrascriva |

Difesa: assicurati che ogni input capace di influenzare una risposta sia incluso nella cache key, oppure che non venga cache-ato affatto — e non lasciare mai che una decisione di cache-control venga presa senza sapere esattamente quali input usa davvero l'origine.

**Lab due — username enumeration via account locking**

| | Exam | Field |
|---|---|---|
| Cosa riconoscere | una form di login senza rate limiting visibile ai test casuali, dove è il volume (non l'astuzia) a far emergere il segnale vero | policy di account lockout implementate in modo incoerente — presenti per un flusso (login) ma silenziose sul *perché* sono scattate, facendo leakare l'esistenza dell'account |
| Dove va il tempo | configurare Intruder correttamente (cluster bomb, payload nulli ripetuti per username) e notare che l'account appena confermato è ora bloccato, prima di provare a usarlo | costruire o procurarsi una lista di username realistica; i sistemi reali non ti regalano `candidate-usernames.txt` |
| Trappola comune | leggere "too many attempts" solo come un ostacolo e andare avanti, invece che come un canale laterale che ha appena confermato qualcosa | assumere che qualsiasi messaggio di blocco sia ugualmente sicuro; un messaggio che cambia in base all'esistenza dell'account vanifica lo scopo di avere errori generici altrove |
| Limite reale | una singola finestra di blocco che si esaurisce, un account valido, una wordlist che per fortuna contiene la password | dipende dalla durata del blocco, se è per-account o per-IP, e se il messaggio generico è davvero generico ovunque altro nel flusso |

Difesa: non lasciare mai che una risposta di blocco differisca, nel testo o nella condizione che la fa scattare, in base al fatto che l'account esista — se l'account non esiste, la risposta a cinque password sbagliate dovrebbe essere identica alla risposta a cinque password sbagliate contro un account che esiste davvero.

## Cosa viene dopo

Il lab di cache poisoning ha funzionato perché la risposta era riflessa in un contesto script senza alcun encoding — la domanda aperta è come questo si generalizza a un encoding parziale, dove un valore è HTML-escaped ma non JS-escaped (o viceversa), e se lo stesso processo di caccia agli input non keyed lo trova altrettanto in fretta. Sul lato del lockout, la domanda aperta è cosa succede quando il blocco è per-IP invece che per-account: il trucco di enumerazione funziona ancora, ma il "pulire dopo" (aspettare un blocco, o trovare una condizione di reset) cambia forma del tutto.

## Takeaways

- La severità di una segnalazione dello scanner, o la sofisticazione del suo payload, non è prova di pertinenza — controllala contro quello che il lab (o il modello di minaccia reale) sta davvero testando prima di spenderci tempo.
- Trova la posizione esatta di un valore riflesso prima di scegliere una stringa di breakout. L'ultima proprietà di un oggetto letterale richiede un payload diverso da una in mezzo, e indovinare la posizione sbagliata spreca un ciclo per niente.
- `X-Cache: hit` è l'unico header che ti dice se stai guardando una risposta cache-ata condivisa o una fresca — controllalo prima di concludere che un tentativo di poisoning ha funzionato o è fallito.
- Una risposta "bloccato" o "too many attempts" porta comunque informazione sul perché è scattata. Leggi il testo specifico, non solo il fatto che qualcosa è fallito.
- Scatenare deliberatamente uno stato di fallimento (un blocco, un rate limit) può essere l'attacco stesso quando la condizione che lo fa scattare dipende da un'informazione che non hai ancora, come l'esistenza di un account.

## Link utili

- [PortSwigger Web Security Academy: Web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning)
- [PortSwigger Web Security Academy: Authentication](https://portswigger.net/web-security/authentication)
- [Mystery Pool: a random lab from only the topics you choose]({% post_url 2026-10-04-mystery-pool-strumento %})

*Tutte le tecniche mostrate sono state eseguite in un ambiente di laboratorio isolato (PortSwigger Web Security Academy). Attaccare sistemi che non possiedi o per cui non hai un'autorizzazione scritta è illegale nella maggior parte delle giurisdizioni.*
