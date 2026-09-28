---
layout: post
title: "Il mio piano di studio BSCP stava allenando la skill sbagliata"
date: 2026-09-28
categories: [web-security, concept]
tags: [bscp, burp-suite, portswigger, study-plan, interleaving, spaced-repetition]
excerpt: "Ho scritto un piano di studio che mi avrebbe reso bravissimo a risolvere i lab una volta saputa la categoria — e l'esame non ti dice mai la categoria."
lang: it
page_id: bscp-study-plan-interleaving
permalink: /posts/piano-di-studio-bscp-interleaving/
---

Avevo un piano di studio. Diciotto categorie di vulnerabilità mappate su tre stage dell'esame, un repo clonato, una checklist pronta da spuntare. Sembrava la cosa responsabile da fare prima ancora di toccare un solo lab.

Poi mi sono messo a studiare seriamente come si costruisce davvero l'intuizione diagnostica — quel tipo di competenza in cui devi riconoscere cosa non va prima ancora di poterlo sistemare, esattamente ciò che accomuna medicina, debugging e penetration testing — e ho dovuto ammettere che il mio piano stava silenziosamente ottimizzando per l'esame sbagliato. Non quello vero. Quello in cui qualcuno ti dice "questo è XSS" prima che tu cominci.

L'esame Burp Suite Certified Practitioner non funziona così.

## Setup: per cosa mi sto davvero preparando

BSCP è la certificazione pratica di PortSwigger. Tre stage — Foothold, Privilege Escalation, Data Exfiltration — sei ore, lab veri, e nessuna etichetta di categoria da nessuna parte. Ti danno un'applicazione e un cronometro. Capire cosa c'è davvero che non va *è* l'esame, non un preambolo.

Uso il [repo di studio BSCP di botesjuan](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study) come ossatura: una checklist di categorie mappate sui tre stage, più degli script Python di verifica che mi sono vietato da solo di aprire finché non ho provato un lab a mano — usarli prima significherebbe che quel lab non è mai stato davvero tentato. Nessuna data d'esame prenotata ancora. È voluto: preferisco impegnarmi su una data una volta che il piano avrà superato il contatto con i lab veri, non prima.

Quello che segue è la versione 2 di quel piano. La versione 1 è durata il tempo di riflettere seriamente su come i diagnosti esperti — radiologi, debugger, pentester — costruiscano davvero quel tipo di intuizione. A quel punto si è rivelata sbagliata in quattro modi specifici.

## 1. Bloccare per categoria allena il riflesso sbagliato

L'istinto della v1 era ovvio: finire tutto il materiale sull'XSS, poi passare alla SQL injection, poi al CSRF, procedendo stage per stage finché il Foothold non fosse "finito" prima di iniziare la Privilege Escalation.

È un modo comodo di studiare. Ma è anche al contrario. Se ogni lab che affronti arriva già etichettato — "questa è la sessione XSS" — non ti eserciti mai nella parte davvero difficile: guardare un'applicazione senza etichette e formulare un'ipotesi su cosa non va. Bloccare per categoria allena "risolvi l'XSS una volta che ti dicono che è XSS". L'esame testa "riconosci che la risposta era XSS fin dall'inizio".

Soluzione: mescolare le categorie fin dal primo giorno, anche nella prima settimana. Usare il Mystery Lab Challenge — che randomizza la categoria — il prima possibile, anche prima che la fase di ripasso sia finita. Sembrerà meno padroneggiato di quanto ci si sentirebbe bloccando per categoria. Ed è proprio il punto: sta misurando la skill vera, non un suo surrogato.

## 2. Le fasi sono un'illusione di pianificazione

La v1 aveva tre fasi pulite: studiare tutto, poi esercitarsi su tutto, poi simulare l'esame. Il materiale di ogni categoria veniva toccato una volta e poi lasciato lì finché la fase successiva non ci fosse casualmente tornata sopra.

Solo che niente "ci torna casualmente sopra" da solo. Appena passo dalla settimana di SQLi a quella di XSS, la SQLi semplicemente si ferma. Nessun piano per rivederla significa che nessuna revisione avviene, e quello che ho costruito nella settimana 2 si erode silenziosamente entro la settimana 5.

Soluzione: la spaziatura ora è esplicita, non incidentale. Ogni categoria viene rivista ogni 4-10 giorni, tracciata in una tabella con una data di "prossima revisione" che devo davvero compilare. Più vicino ai 4 giorni finché una categoria è ancora instabile (livello di aiuto 3-4), più vicino ai 10 una volta stabile. Un piano che non forza la data di revisione su carta non sopravvive al contatto con la settimana 3.

## 3. Una scala di aiuti senza un costo non è una scala di aiuti

La v1 aveva l'impostazione giusta — quattro livelli di aiuto, da "nessun aiuto" a "soluzione completa" — ma nessun attrito nel salirla. Il che significava che salirla era gratis, e le cose gratis si usano nel momento stesso in cui un lab comincia a risultare scomodo.

Soluzione: ogni livello ora ha un time-box prima di poter salire (20-30 minuti al livello 1, altri 10-15 prima del livello 2, altri 10 prima del livello 3), e — la parte che conta davvero — prima di salire di livello devo scrivere una riga: cosa ho provato, dove mi sono bloccato, e se secondo me ci sarei arrivato con più tempo o mi mancava davvero un'informazione. È quella frase il momento in cui si impara. Il payload che segue è solo esecuzione.

## 4. Non tutte le categorie maturano alla stessa velocità

La v1 assumeva un unico traguardo: una volta che il materiale è "finito", è finito ovunque. Ma alcune categorie si sbloccano dopo due tentativi e altre dopo sei, e trattarle allo stesso modo significa o sotto-allenare quelle difficili o sprecare cicli a riesercitarsi su quelle già solide.

Soluzione: il fading è per categoria. Due soluzioni consecutive a Livello 1 (senza aiuto) e una categoria passa dalla pratica attiva alla revisione di mantenimento spaziata — 10-14 giorni invece di 4-10. Access Control potrebbe arrivarci in una settimana. Deserialization probabilmente no, ed è un dato, non un fallimento.

## Il pattern sotto tutti e quattro

Ognuna di queste correzioni punta alla stessa cosa: l'esame è un compito di riconoscimento travestito da skill di sfruttamento. Nessuno fallisce il BSCP perché non sa scrivere un payload UNION funzionante. Lo fallisce perché passa quaranta minuti convinto che un form di login sia vulnerabile a SQLi, quando il vero bug tre richieste dopo è un token CSRF mai validato. Bloccare per categoria, fasi monolitiche, una scala di aiuti gratuita e un ritmo uniforme ottimizzano tutti per "so eseguire la tecnica". Nessuno di loro tocca "so dire quale tecnica si applica prima che qualcuno me lo dica".

## Cosa viene dopo

Questa settimana è la Fase 0 — nessun lab, solo abbastanza segnale per categoria ("quali indizi mi fanno sospettare questa vulnerabilità prima che l'app me lo confermi") per smettere di tirare a indovinare alla cieca. Poi parte la Fase 1: pratica interleaved, revisioni spaziate, la scala di aiuti con il suo nuovo costo. Le categorie dove il divario tra "sapevo eseguirla" e "l'ho riconosciuta per prima" risulta più ampio sono presumibilmente da dove arriveranno i prossimi post.

## Takeaways

- Bloccare la pratica per categoria è comodo e allena la skill sbagliata — l'esame non annuncia mai la categoria, quindi non dovrebbe farlo nemmeno la pratica.
- La spaziatura va programmata esplicitamente, come una data su una tabella, non data per scontata perché "poi ci torno".
- Una scala di aiuti insegna qualcosa solo se salirla costa un time-box e obbliga a un'autospiegazione di una riga prima di salire.
- Categorie diverse maturano a velocità diverse — va tracciato per categoria, non come un unico flag globale "sono pronto".
- La skill vera che il BSCP testa è il riconoscimento sotto incertezza, non l'esecuzione una volta che la risposta è già etichettata.

## Riferimenti utili

- [botesjuan — Burp Suite Certified Practitioner Exam Study](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [bscp.guide](https://bscp.guide)
- Il post sul blog di Micah van Deusen che mappa le categorie BSCP sugli stage d'esame — quello da controllare quando un lab sembra impossibile
