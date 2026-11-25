---
layout: post
title: "Quando il dato diventa un'istruzione: cinque roll nello step tre"
date: 2026-11-22
categories: [web-security, walkthrough]
tags: [portswigger, bscp, insecure-deserialization, ssti, ssrf, path-traversal, prototype-pollution, rce, mystery-lab, burp-suite]
excerpt: "Primi cinque roll dello step di exfiltration, e il riflesso dello step due — diventa admin — era il verbo sbagliato. Ogni porta si è aperta sullo stesso cardine: un motore sotto l'app che tratta il mio input come un'istruzione che l'app voleva solo salvare, validare o mostrare."
lang: it
page_id: when-data-becomes-an-instruction
permalink: /posts/when-data-becomes-an-instruction/
---

Ho flippato il booleano admin nel cookie serializzato — `b:0` a `b:1`, la mossa che tre post di step due mi avevano cablato nelle dita — e il server non ha fatto nulla. Mi ha riloggato come il solito wiener. Per un attimo è sembrato un lab rotto. Non lo era. Allo step tre non importa *chi* sei. Il riflesso che mi ero costruito in un mese — *diventa admin* — era il verbo completamente sbagliato. Il cookie non era una cosa da modificare. Era una cosa da **eseguire**.

È tutto qui lo spostamento di cui parla questo post. Gli [ultimi tre post]({% post_url 2026-11-19-la-ruota-inizia-a-ripetersi %}) erano step due — privilege escalation, ogni strada che finiva nell'account di qualcun altro. Questo è step tre — exfiltration, e l'obiettivo di ogni lab è la stessa frase secca: *leggi il contenuto di `/home/carlos/secret`*, cancella un file, esegui un comando. Non *chi sei*, ma *cosa riesci a far fare alla macchina*. Ho girato la mia [Mystery Pool]({% post_url 2026-10-04-mystery-pool-strumento %}) cinque volte sulla card exfiltration, e ogni singolo roll ha girato sullo stesso cardine: un motore sotto l'app — un deserializzatore, un compilatore di template, un client HTTP, una syscall di apertura file, uno spawner di processi Node — che tratta il mio input come un'**istruzione** che l'applicazione voleva solo salvare, validare o mostrare. Lo step due era mentire all'app su chi sei. Lo step tre è parlare oltre l'app, alla macchina che ci sta sotto.

## Il setup

Stesso strumento, card Exfiltration spuntata, livello Practitioner. Nel pool tutti e otto i topic selezionati — SSRF, XXE, SSTI, path traversal, insecure deserialization, file upload, server-side prototype pollution (RCE), OS command injection. Ne ho girati cinque prima di fermarmi; i tre che non ho mai pescato (XXE, file upload, OS command injection) sono la fine di questo post.

Come al solito diversi sono usciti come **direct topic**, col titolo spoilerato al caricamento — preferisco comunque girare largo piuttosto che tenere nascosto ogni titolo. Una cosa è cambiata rispetto alle sessioni di step due, e vale la pena dirla subito: la mossa vincente non è quasi mai stata *più payload*. È stata leggere la sorgente di un componente, o un messaggio d'errore, abbastanza da vedere dove *non concordava* con il componente accanto. L'identificazione ha portato a casa ogni roll. L'exploitation era la metà facile.

Strumenti: Burp con lo scanner sui singoli insertion point, Repeater, Decoder (che stavolta si è guadagnato lo stipendio), l'estensione Server-Side Prototype Pollution Scanner; `php -r` per costruire oggetti serializzati; e tanto fissare il codice sorgente.

## La sessione

### Roll 1 — La classe che non dovevo mai costruire (PHP object injection)

Un oggetto PHP serializzato nel cookie di sessione — lo scanner di Burp lo segnala appena decodifica il base64 e vede `O:4:"User":...`. La mia prima mossa è stata il riflesso da step due: decodifica, flippa il flag admin, ri-encoda, invia. Niente. E *niente* è la risposta giusta, perché il valore che volevo non era mai stato nei **dati** dell'oggetto. Era nella sua **classe**.

`unserialize()` non ricostruisce solo i tuoi campi. Legge `O:14:"CustomTemplate"` e istanzia *qualunque classe tu nomini*, senza whitelist, e poi — quando quell'oggetto viene distrutto a fine richiesta — PHP esegue il suo `__destruct()` da solo. Quindi l'exploit non è modificare uno `User`. È iniettare una classe diversa, una che fa qualcosa di pericoloso quando muore. L'ho trovata leggendo la sorgente di una classe `CustomTemplate` trapelata sotto `/libs`:

```php
function __destruct() {
    // Carlos thought this would be a good idea
    if (file_exists($this->lock_file_path)) {
        unlink($this->lock_file_path);
    }
}
```

`unlink()` su un path che è un *attributo dell'oggetto* — cioè un valore che controllo io. Così ho sostituito l'oggetto `User` nel cookie con un `CustomTemplate` costruito a mano e puntato al bersaglio:

```php
O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}
```

base64 nel cookie, invio, e il garbage collector di PHP mi cancella il file. **Il vicolo cieco è il mangling delle proprietà private**: `lock_file_path` è dichiarata `private`, e normalmente si serializza come `\0CustomTemplate\0lock_file_path` con i null byte e una lunghezza diversa — e se conosci questa cosa, puoi bruciare dieci minuti a costruire la versione manglata che a questo lab non serve. Il nome pulito funziona. E non contare i byte a mano: dichiara la proprietà `public` in una classe-stub e lascia fare a PHP:

```bash
php -r 'class CustomTemplate { public $lock_file_path="/home/carlos/morale.txt"; } echo base64_encode(serialize(new CustomTemplate()));'
```

La frase da esame: nella deserialization l'exploit non è nei dati che mandi, è nella **classe che fai istanziare al server**. Caccia un magic method (`__destruct`, `__wakeup`, `__toString`) che raggiunge un sink tramite un attributo controllabile. Il cookie è solo il veicolo. Stage 3, non interattivo.

### Roll 2 — Il nome visualizzato che si è messo a eseguire (SSTI, code context)

Una funzione di commento al blog mi faceva impostare il nome dell'autore, e quel nome tornava **renderizzato** nel commento pubblicato. Input che finisce dentro un template invece che in una query è tutto il profumo della server-side template injection — ed è un pezzo forte dello step tre perché un template engine con accesso al filesystem o all'OS è a un passo dall'RCE.

La sottigliezza di identificazione è la parte di cui vado fiero. Non ho sparato un `{% raw %}{{7*7}}{% endraw %}` nudo; ho mandato `{% raw %}user.first_name}}{{7*7{% endraw %}`. Il motivo: il mio input era già *dentro* un'espressione (`{% raw %}{{ user.first_name }}{% endraw %}`), quindi dovevo **chiudere quel contesto** con `}}` prima di aprire il mio. La pagina ha stampato `49` — breakout confermato. Per il fingerprint del motore di solito lancio `{% raw %}{{7*'7'}}{% endraw %}` (i motori Python ripetono la stringa → `7777777`; Twig coercizza → `49`), ma la forma dell'exploit l'ha tradito: era **Tornado**. Breakout e import di un modulo:

```
{% raw %}user.name}}{% import os %}{{os.system('rm /home/carlos/morale.txt')}}{% endraw %}
```

Chiudi l'espressione originale, `{% raw %}{% import os %}{% endraw %}` porta il modulo nel namespace del template, `{% raw %}{{os.system(...)}}{% endraw %}` esegue. È il payoff dello step tre detto chiaro: il lab mi chiedeva di cancellare `morale.txt`, ma una volta che hai `os.system` in mano, `cat /home/carlos/secret` è il gesto identico. **Un template engine che valuta la tua stringa non è un rischio XSS — è una shell.** L'unica trappola è il contesto: sbaglia a contare i delimitatori in cui sei annidato (`}}` o `%}`) e il payload viene renderizzato come testo. Stage 3, non interattivo.

### Roll 3 — Conta i decode (SSRF, blacklist filter)

Un parametro `stockApi` prendeva un URL intero e il server lo fetchava — SSRF da manuale, confermata due volte: manualmente (il parametro ingoia qualunque URL) e dallo scanner di Burp che accende *Out-of-band resource load* quando lo punto a Collaborator. Il server adesso è il mio proxy; qualunque cosa raggiunga *lui* — localhost, la rete interna, i metadata cloud — la raggiungo io, dalla sua posizione di fiducia.

Puntandolo a `http://localhost/admin` e `http://127.1/admin` entrambi tornavano `400 "External stock check blocked for security reasons"`. Non un errore di raggiungibilità — una **blacklist** sulla stringa. Il token bloccato era `admin`, ed è qui che il roll si è guadagnato la lezione. URL-encodare la `a` una volta — `%61dmin` — *veniva comunque bloccato*. La soluzione era encodarla **due** volte: `%2561dmin`. Ecco il meccanismo, ed è la forma esatta che ritorna tutta la sessione:

> Il filtro URL-decodifica la stringa una volta *prima* di controllare la blacklist. Quindi `%61dmin` diventa `admin` e viene beccato. `%2561dmin` si decodifica una volta in `%61dmin` — non la parola `admin`, quindi passa — e *poi* il client HTTP del server la decodifica una seconda volta, in `admin`, e fa la richiesta.

Non è "offusca la lettera". È "**aggiungi uno strato di decodifica in più di quanti ne fa il filtro**". Il filtro e l'esecutore non concordano su quante volte decodificare la stringa, e tu vivi nel buco in mezzo. Burp Decoder te lo costruisce — Encode as URL, due volte — e non allarmarti se ti restituisce `%25%36%31` invece di `%2561`; encoda ogni carattere, ma dopo due decode entrambi tornano allo stesso byte. Finale: `stockApi=http://127.1/%2561dmin`, poi `/%2561dmin/delete?username=carlos`. Stage 3, non interattivo.

### Roll 4 — Due lettori, una stringa (path traversal, null-byte bypass)

L'app era quasi spoglia: niente area account, niente form, solo `GET /image?filename=54.jpg` che serve file per nome. Quando la superficie d'attacco è un parametro solo, quel parametro *è* la superficie — e lo scanner ha confermato path traversal, passandomi il payload esatto:

```
GET /image?filename=../../../../../../etc/passwd%0054.jpg
```

Quel `%00` prima di `54.jpg` è tutto il lab — *File path traversal, validation of file extension with null byte bypass* — ed è la lezione del roll 3 vestita in modo diverso:

- Il **controllo dell'estensione** (codice applicativo, in un linguaggio memory-safe) legge la stringa intera, vede che finisce in `.jpg`, e la approva.
- La **syscall `open()`** (C sottostante) tratta `%00` come terminatore di stringa, smette di leggere lì, e apre `/etc/passwd`, ignorando tutto ciò che viene dopo il null.

Due lettori, una stringa, due idee diverse di dove finisca. Il validatore legge fino al `.jpg`; il kernel legge fino al `\0`. `root:x:0:0:` è tornato nella risposta. Stesso cardine del double-decode: un controllo e un esecutore che parsano il tuo input con regole diverse. Stage 3, non interattivo.

### Roll 5 — La config che ho infilato in un processo (RCE via server-side prototype pollution)

Il finale, e la dichiarazione più chiara del salto da step due a step tre. Questa era la *stessa source* di un [roll dello step due]({% post_url 2026-11-17-cinque-roll-nello-step-due %}) — un'app Express che fa il merge del mio JSON in un oggetto server via `POST /my-account/change-address` — ma lì il premio era flippare `isAdmin`. Qui era una shell.

Prima, conferma la pollution con un probe reversibile. Express legge l'opzione `json spaces` dal prototipo, quindi inquinarla riformatta ogni risposta JSON:

```json
"__proto__": { "json spaces": 10 }
```

La risposta è tornata indentata di dieci spazi — `Object.prototype` è mio. Flippare `isAdmin` è il capolinea dello step due; il gadget dello step tre è **`execArgv`**, l'array di flag che Node passa a un processo figlio forkato. Inquinalo con un `--eval`:

```json
"__proto__": {
  "execArgv": ["--eval=require('child_process').execSync('rm /home/carlos/morale.txt')"]
}
```

La pollution da sola è inerte — non fa nulla finché qualcosa non chiama `child_process.fork()`, momento in cui il nuovo processo Node eredita il mio `execArgv` ed esegue il mio codice all'avvio. L'ho innescato **facendo partire i job di manutenzione dall'admin panel**, che spawna il sottoprocesso. Comando eseguito, file cancellato. La catena in quattro battute da memorizzare: **source** (merge JSON non sicuro) → **conferma** (indentazione `json spaces`) → **gadget** (`execArgv` letto da `fork`) → **trigger** (il job admin che forka). L'app credeva di salvare il mio indirizzo. Node ha letto la configurazione di processo dallo stesso object graph avvelenato. Stage 3 — e "interattivo" solo nel senso che *io* dovevo innescare il fork; nessuna vittima richiesta.

## Il pattern

Cinque roll, un meccanismo sotto tutti: **ho fatto sì che un motore sotto l'applicazione trattasse il mio input come un'istruzione che l'applicazione voleva solo salvare, validare o mostrare.** Un campo del cookie è diventato un costruttore di classe. Un nome visualizzato è diventato un comando shell. Un parametro URL è diventato una richiesta dall'interno della rete. Un filename è diventato una lettura di `/etc/passwd`. Un form indirizzo è diventato configurazione di processo. In ogni caso l'app gestiva quello che credeva dato inerte, e un livello sotto di lei — `unserialize`, il compilatore di template, il client HTTP, `open()`, `fork()` — leggeva quello stesso dato come un comando.

La versione più netta e più trasportabile di tutto questo è il bypass dei roll 3 e 4: **il componente che valida e il componente che esegue parsano la tua stringa con regole diverse.** Il filtro decodifica una volta; il client HTTP due. Il controllo estensione legge fino al `.jpg`; il kernel fino al `\0`. Ogni bypass di blacklist che scriverò mai è una variante di questo — trova i due lettori, trova dove non concordano, e metti il payload nel buco. Non batti il filtro essendo furbo sulla parola. Lo batti sapendo che il filtro e l'esecutore non sono lo stesso lettore.

E il riflesso dello step due doveva morire. Tre volte in questa sessione ho allungato la mano verso *diventa admin* — flippando il booleano serializzato, puntando `isAdmin` nella risposta Express — e tre volte era il verbo sbagliato. Lo step tre non è una bugia sull'identità. È un messaggio alla macchina, instradato attorno all'app che avrebbe dovuto starci in mezzo.

## Esame e campo

**All'esame**, tutti e cinque sono Stage 3 — data exfiltration — e il goal non è mai un account, è una lettura di file o un comando. Quattro dei cinque sono **non interattivi**: deserializzi, template-injecti, fai SSRF, traversi, interamente con le tue richieste, nessuna vittima nel giro — il profilo che vuoi sotto il cronometro. L'RCE da prototype pollution è l'unico con un trigger, e anche quel trigger sei *tu* (che lanci il job admin), non una vittima simulata. I tell di identificazione sono tutto il gioco: `O:` o un base64 che decodifica in un nome di classe = deserialization, quindi vai a leggere la sorgente per un magic method; input che torna *renderizzato* = SSTI, quindi rompi il contesto del template e fai il fingerprint del motore; un parametro che prende un URL = SSRF, quindi puntalo a `localhost` e all'endpoint metadata `169.254.169.254`; un solo `filename=` su un'app spoglia = path traversal; e un merge JSON su un'app Node = prototype pollution — conferma con `json spaces`, escala con `execArgv`. Quando un filtro ti blocca, non allungare la mano verso un payload più grande — chiediti quante volte ogni lato decodifica.

**Sul campo**, sono i bug che chiudono gli incident report. Deserialization, SSTI e il gadget da prototype pollution sono RCE diretta; l'SSRF è il pivot che trasforma un bug web in un foothold sulla rete interna e nel furto canonico delle credenziali dai metadata cloud; la path traversal legge qualunque cosa l'utente web possa leggere. L'unica disciplina difensiva dietro tutti e cinque: **non lasciare mai che un valore passi dal livello che lo salva a un livello che lo esegue senza ri-validarlo nei termini dell'esecutore.** Un controllo di estensione in Python non protegge una `open()` in C. Una blacklist che decodifica una volta non protegge un client che decodifica due volte. Un merge JSON non sa di star scrivendo le flag di lancio di un processo. Il confine dato-istruzione è dove fai l'audit, perché è dove i lettori smettono di concordare.

## Cosa viene dopo

Tre topic di exfiltration non sono mai usciti e sono i prossimi roll ovvi: **XXE** (entità esterne che tirano file o colpiscono Collaborator — il cugino in forma XML dell'SSRF), **file upload** (web shell, e i filtri su content-type ed estensione costruiti per fermarle), e **OS command injection** (il bug dato-istruzione più diretto che esista — la tua stringa finisce dritta in una shell). La sola deserialization ha molti più vestiti di quello che ho pescato: Java con `ysoserial`, deployment PHAR, gadget chain pre-costruite con `phpggc` contro codice di libreria invece di un comodo `CustomTemplate`. Lo step tre è largo, e ne ho aperte cinque porte. La ruota continua a girare verso il filesystem.

## Takeaway

- Lo step tre cambia il verbo. Smetti di provare a *diventare admin* — il flip del booleano serializzato e la modifica di `isAdmin` sono riflessi da step due. Lo step tre chiede cosa riesci a far **eseguire** alla macchina, e la risposta è di solito una lettura di file o un comando.
- Nella deserialization il payload è la **classe**, non il dato. `unserialize()` costruisce qualunque classe nomini e lancia il suo `__destruct`; leggi la sorgente per un magic method che raggiunge un sink, e lascia contare i byte a `php -r 'serialize(...)'`.
- I bypass di blacklist sono un problema di conteggio dei decode. `%61` viene beccato perché il filtro decodifica una volta; `%2561` passa perché prima diventa `%61` e l'esecutore decodifica la seconda volta. Aggiungi uno strato più di quanti ne fa il filtro.
- Un null byte è lo stesso bug del double-encoding: il validatore legge la tua stringa fino al `.jpg`, la `open()` in C la legge fino al `\0`. Trova i due lettori e la regola su cui non concordano.
- La prototype pollution scala da `isAdmin` a RCE tramite il gadget: `json spaces` per confermare, `execArgv` + `--eval` per eseguire, e un `fork()` che inneschi tu stesso per farlo partire.

## Riferimenti utili

- [PortSwigger: Arbitrary object injection in PHP](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-arbitrary-object-injection-in-php)
- [PortSwigger: Basic server-side template injection (code context)](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-code-context)
- [PortSwigger: SSRF with blacklist-based input filter](https://portswigger.net/web-security/ssrf/lab-ssrf-with-blacklist-filter)
- [PortSwigger: File path traversal, validation of file extension with null byte bypass](https://portswigger.net/web-security/file-path-traversal/lab-validate-file-extension-null-byte-bypass)
- [PortSwigger: Remote code execution via server-side prototype pollution](https://portswigger.net/web-security/prototype-pollution/server-side/lab-remote-code-execution-via-server-side-prototype-pollution)
- [PortSwigger: Insecure deserialization](https://portswigger.net/web-security/deserialization) · [Server-side template injection](https://portswigger.net/web-security/server-side-template-injection) · [SSRF](https://portswigger.net/web-security/ssrf)
- [Server-Side Prototype Pollution Scanner (estensione Burp)](https://portswigger.net/bappstore/c1d4bd60626d4178a54d36ee802cf7e8) · [Burp Decoder](https://portswigger.net/burp/documentation/desktop/tools/decoder)
- [botesjuan — Burp Suite Certified Practitioner Exam Study](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study)
- [Mystery Pool — lo strumento da cui arrivano questi roll]({% post_url 2026-10-04-mystery-pool-strumento %})

*Tutte le tecniche mostrate sono state eseguite in un ambiente di laboratorio isolato (la Web Security Academy di PortSwigger). Attaccare sistemi che non possiedi o per cui non hai un'autorizzazione scritta è illegale nella maggior parte delle giurisdizioni.*
