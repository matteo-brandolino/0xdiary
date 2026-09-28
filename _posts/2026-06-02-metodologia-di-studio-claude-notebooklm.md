---
layout: post
title: "Come ho smesso di accumulare write-up e ho iniziato a costruire una knowledge base"
date: 2026-06-02
categories: [tools, methodology]
tags: [ai, notebooklm, claude, study-system, portswigger, methodology]
excerpt: "Avevo cinque write-up fermi in una cartella e nessuna idea su cosa farne oltre a pubblicarli. La risposta si è rivelata coinvolgere due strumenti AI che fanno lavori completamente diversi."
lang: it
page_id: study-methodology-claude-notebooklm
permalink: /posts/metodologia-di-studio-claude-notebooklm/
---

Cinque sessioni dopo, avevo una cartella piena di write-up e la vaga sensazione di star facendo la cosa giusta. Documentavo gli errori, estraevo le lezioni, li pubblicavo. Buona abitudine.

Poi ho provato a ricordare esattamente quale lab mi avesse introdotto all'oracolo booleano invertito su MariaDB — quello dove `CASE WHEN 1/0` restituisce NULL invece di andare in crash, per cui il tuo oracolo funziona al contrario di quanto ti aspettavi. Sapevo di averne scritto. Non riuscivo a trovarlo in meno di un minuto. Avrei potuto cercare tra i file, ma non è questo il punto. Il punto è: cinque sessioni di conoscenza guadagnata con fatica, e non riuscivo a interrogarla.

Un write-up pubblicato ma non interrogabile è solo un diario pubblico. Utile per chi lo trova, non particolarmente utile a me stesso tra tre mesi.

Questo è il problema che stavo davvero cercando di risolvere quando ho iniziato a guardare gli strumenti di studio.

## Cosa volevo contro cosa ho costruito

L'istinto era buttare tutto dentro Claude e considerarla chiusa. Claude conosce la SQLi. Posso chiedergli cose. Perché aggiungere complessità?

Perché Claude è stateless tra una sessione e l'altra. Non ricorda che la settimana scorsa ho confuso error-based con blind, o che continuo a dimenticarmi di controllare il livello HTTP prima di dare la colpa al payload SQL, o che la sintassi dei commenti di MariaDB mi ha già fatto inciampare due volte. Ogni sessione riparte da zero. Va bene per spiegare concetti — non va bene per costruire su una settimana di sessioni in cui ho accumulato lacune specifiche e pattern specifici.

Quello che mi serviva non era un tutor più intelligente. Mi serviva una memoria.

La risposta è stata **NotebookLM** collegato a Claude via MCP — il che significa che Claude può creare notebook, aggiungerci sorgenti, e interrogarli direttamente. Il setup è un comando:

```bash
claude mcp add --scope user notebooklm notebooklm-mcp
```

Poi riavvia, autentica con Google, e gli strumenti sono lì. La parte dell'autenticazione merita una segnalazione: `notebooklm-mcp` usa Playwright sotto il cofano per guidare un login via browser. Se non hai mai usato Playwright prima, ti chiederà di installare prima i browser:

```bash
playwright install chromium
python3 -m notebooklm login
```

Dopodiché funziona. La sessione dura settimane.

## Due notebook, non uno

Primo istinto: un notebook per argomento. SQLi, XSS, SSRF — ognuno con il proprio notebook contenente tutto quello che sapevo su quel tema.

Istinto sbagliato.

La struttura migliore è per *tipo di contenuto*, non per argomento:

**Notebook di teoria** — le sorgenti sono gli articoli ufficiali di PortSwigger. Statico, autorevole, non mio. Lo interrogo quando ho bisogno di capire un concetto prima di una sessione, o per generare flashcard prima di sedermi con Burp.

**Notebook dei lab** — le sorgenti sono i miei write-up, aggiunti come testo dopo ogni sessione. Dinamico, personale, in crescita. Lo interrogo quando voglio sapere cosa ho effettivamente incontrato in pratica.

Il motivo per separarli: quando mescoli teoria ed esperienza personale in un unico notebook, le query restituiscono risposte confuse. "Come funziona EXTRACTVALUE?" ti dà una miscela di spiegazione da manuale e frammenti della mia specifica sessione DVWA che non si incastrano del tutto. Separati, il notebook di teoria ti dà il meccanismo pulito; il notebook dei lab ti dice che MariaDB tronca l'output di EXTRACTVALUE a 31 caratteri ed ecco il payload esatto che ho usato per recuperare l'ultimo byte.

Domande diverse, notebook diversi.

## Il notebook dei lab è quello che conta

Il notebook di teoria è contenuto di qualcun altro. Gli articoli di PortSwigger sono eccellenti — non li ho scritti io, li ho solo ingeriti.

Il notebook dei lab è mio. Sa che confermo costantemente l'injection nel contesto SQL sbagliato per primo. Sa che sono stato fregato due volte dalla confusione tra livello HTTP e SQL (un payload corretto che non ha mai raggiunto il database perché l'URL encoding era sbagliato). Sa che la prima volta che il dump delle credenziali ha funzionato ho detto qualcosa ad alta voce a una stanza vuota che non ripeterò qui.

Questo è il contenuto che non puoi ottenere da un manuale. Ed è il contenuto più utile a me specificamente, perché mappa esattamente dove sono le mie lacune.

Tra sei mesi potrò chiedere: *"in quali lab ho usato l'encoding esadecimale per bypassare filtri basati sugli apici, e in che contesto?"* Il notebook risponderà con i miei stessi esempi. Non esempi generici — miei, con i messaggi di errore specifici e il momento esatto in cui il bypass ha fatto click.

Un write-up senza il notebook è solo un registro pubblico. Il notebook senza i write-up è solo il riferimento di qualcun altro. Insieme sono un registro interrogabile della tua stessa esperienza.

## L'abitudine di scrivere il write-up è il tessuto connettivo

Questo funziona solo se scrivi davvero ogni sessione. Il che sembra ovvio finché non finisci un lab alle 11 di sera, sei stanco, l'attacco ha funzionato, e l'ultima cosa che vuoi fare è documentarlo.

L'argomento per farlo comunque: i dettagli specifici che rendono un write-up degno di essere interrogato — il messaggio di errore esatto che sembrava qualcos'altro, i cinque minuti passati a dare la colpa al livello sbagliato, il momento preciso in cui l'oracolo si è capovolto — sono le prime cose a sparire. Non la tecnica. La consistenza.

Scrivilo lo stesso giorno, finché la consistenza è ancora lì. Poi aggiungilo al notebook dei lab. Due minuti di lavoro che si accumulano attraverso ogni sessione futura.

## Cosa viene dopo

Il workflow a cui sono arrivato:

1. Interrogo il notebook di teoria per un riassunto prima di una sessione
2. Genero flashcard, ci passo venti minuti
3. Faccio il lab a mano — niente soluzioni, niente scorciatoie
4. Se sono bloccato, ragiono con Claude — non "dammi il payload" ma "perché questo non funziona"
5. Scrivo la sessione quella sera
6. Aggiungo il write-up al notebook dei lab
7. Periodicamente genero un quiz dal notebook dei lab e vedo cosa è rimasto davvero

Il passo 4 è dove i due strumenti lavorano insieme nel modo più concreto. Claude non conosce la mia storia nei lab, ma conosce la tecnica. Io conosco la mia storia nei lab ma sono bloccato sull'istanza specifica. Il divario tra queste due cose è di solito dove vive la comprensione.

La domanda aperta è se questo scala oltre la SQLi. Il prossimo argomento sono le vulnerabilità di autenticazione, che coinvolgono molto più stato — token di sessione, flag dei cookie, flussi OAuth — e non sono ancora sicuro se un notebook di teoria per argomento resti gestibile o diventi un problema di manutenzione. È una domanda per il mese prossimo.

---

*Il progetto notebooklm-mcp vive su [github.com/teng-lin/notebooklm-py](https://github.com/teng-lin/notebooklm-py). Tutti i lab menzionati sono stati eseguiti in ambienti isolati su macchine locali.*
