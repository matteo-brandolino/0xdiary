---
layout: post
title: "I miei notebook non si parlano tra loro: un'idea di RAG che prima o poi voglio costruire"
date: 2026-06-03
categories: [projects]
tags: [rag, notebooklm, llm, regolo-ai, llamaindex, chromadb, fastapi, nextjs, ai]
excerpt: "Ho notebook NotebookLM che non sanno nulla l'uno dell'altro. Invece di accettarlo come un dato di fatto, ho iniziato a progettare una soluzione."
lang: it
page_id: federated-rag-notebooklm
permalink: /posts/rag-federato-notebooklm/
---

Al momento ho due notebook NotebookLM per il mio percorso nella PortSwigger Academy: uno con la teoria sulla SQL injection, uno con le sessioni di lab. Man mano che procedo nel curriculum, ce ne saranno altri — uno per argomento, probabilmente, forse uno per livello di difficoltà. La struttura ha senso finché sei dentro di essa.

Il problema emerge quando provi a ragionare attraverso di essa.

Se chiedo al notebook di teoria qualcosa che è venuto fuori solo durante un lab, non lo sa. Se voglio collegare un concetto che ho esercitato in pratica con la sua spiegazione teorica, devo aprire entrambi, rileggere, e ricostruire il collegamento a mano. Il che vanifica gran parte del motivo per cui ho costruito il sistema in primo luogo.

Non è colpa di NotebookLM. Ogni notebook è un ambiente isolato per design — è ciò che li rende buoni per lo studio mirato. Ma gli ambienti isolati non scalano bene quando la conoscenza che stai accumulando dovrebbe essere connessa.

Quindi ho iniziato a pensare a come sarebbe fatta davvero una soluzione.

## L'approccio ovvio — e perché non basta

La prima idea è il fan-out: per ogni domanda, chiedi la stessa cosa a tutti i notebook e sintetizza le risposte. Semplice, veloce, richiede quasi nessuna infrastruttura nuova. Potrei costruirlo in un pomeriggio.

Ma non è davvero RAG. Ogni notebook risponde nel suo contesto, senza vedere gli altri. La sintesi avviene dopo il retrieval, su testo pre-filtrato. Quello che perdi è la capacità di ragionare *attraverso* le fonti simultaneamente — un modello che riceve tre risposte finite può provare a cucirle insieme, ma non può notare che il frammento A da un notebook e il frammento B da un altro stanno descrivendo la stessa tecnica da angolazioni diverse, perché non li vede mai affiancati.

L'approccio giusto è estrarre le sorgenti da tutti i notebook in un unico vector store e interrogarlo con un solo motore. Il modello riceve i pezzi più rilevanti da ovunque, nella stessa finestra di contesto, e ragiona direttamente su quelli.

## Lo stack

**Vector store: ChromaDB**

Embedded, nessun server richiesto, gira in locale. Per un progetto personale a questa scala, un vector database gestito è overhead superfluo. ChromaDB fa tutto il necessario in una sola dipendenza.

**Framework RAG: LlamaIndex**

Più controllo sulla pipeline rispetto a LangChain — voglio calibrare come i chunk vengono recuperati e passati al modello, non solo chiamare una chain ad alto livello e sperare che i default vadano bene.

**Backend: FastAPI + Next.js**

Scelta standard. FastAPI per il layer API, Next.js con shadcn/ui per un frontend che non sembri una demo.

**Ingestion: NotebookLM MCP**

Questa è la parte non banale. NotebookLM non ha un'API pubblica, quindi estrarre le sorgenti richiede passare attraverso il layer MCP. Non è "apri file, leggi testo" — c'è idraulica vera di mezzo, e capirla è probabilmente il problema ingegneristico più interessante dell'intero progetto.

## Perché Regolo.ai

Potrei usare OpenAI per gli embedding e la generazione. È la scelta ovvia, quella a cui ogni tutorial ricade di default.

Ho scelto [Regolo.ai](https://regolo.ai) invece perché il progetto mi piace davvero e voglio sostenerlo. È un provider italiano che ospita modelli open source, e avere una buona alternativa europea alle solite API americane conta. Hanno esattamente ciò di cui una pipeline RAG ha bisogno — embedding, reranking e generazione tutti disponibili — e la loro API è compatibile con OpenAI, quindi l'integrazione è diretta.

## I modelli

**Embedding — `Qwen3-Embedding-8B`**

La qualità del retrieval è la parte che conta di più in un sistema RAG. Se i chunk che recuperi sono sbagliati, il modello parte da spazzatura per quanto sia capace. Un modello di embedding dedicato dello stesso provider mantiene pulito lo stack.

**Reranker — `Qwen3-Reranker-4B`**

Il passo che la maggior parte dei tutorial RAG salta. Il retrieval per similarità vettoriale è veloce ma spuntato — trova chunk "vicini" alla query nello spazio degli embedding, non necessariamente i più utili per rispondere alla domanda. Il reranker prende i primi k candidati e li riordina in base alla rilevanza semantica reale rispetto alla query. Meno rumore, contesto migliore, risposte migliori. Vale il passo in più.

**Generazione — `gemma-4-31B`**

Finestra di contesto da 256K e tool use nativo. Il supporto per i tool è ciò che lo rende interessante: invece di una pipeline statica che recupera sempre allo stesso modo, posso costruire un agente che decide dinamicamente come cercare — se interrogare una volta, raffinare, o attingere da fonti diverse in base a cosa trova.

## Il quadro completo

```
Notebook NotebookLM → ingestion via MCP → ChromaDB
                                               ↓
          query → LlamaIndex → Qwen3-Reranker → gemma-4-31B → risposta
```

Un solo motore di query su tutti i notebook. Teoria e lab nello stesso indice. Ogni nuovo notebook che creo man mano che procedo nella PortSwigger finisce nello stesso store — nessun riferimento incrociato manuale.

## Quando lo costruirò davvero

Nessuna scadenza. È un'idea a cui penso da qualche giorno, e scriverla è parte del decidere se valga la pena investirci tempo. La forma sembra giusta — il problema è reale, lo stack ha senso, e il layer di ingestion è genuinamente interessante da capire.

Quando inizierò, partirò dalla pipeline di ingestion, perché è l'incognita. Il resto è variazione su cose che ho già fatto. Estrarre sorgenti da NotebookLM in un formato pulito e strutturato è il problema nuovo.

E quando lo costruirò, scriverò di cosa è successo davvero. Che quasi sicuramente non coinciderà con quello che ho appena descritto.

## Takeaways

- I notebook NotebookLM sono isolati per design — buono per la profondità, limitante per l'ampiezza
- L'aggregazione fan-out e il RAG vero sono cose diverse; la differenza è dove avviene la sintesi
- Una pipeline RAG completa ha tre stadi: embedding, reranking, generazione — il passo di reranking è quello che la maggior parte salta ed è quello che conta di più per la qualità
- Il problema ingegneristico interessante qui non è il RAG in sé, è l'ingestion da uno strumento che non ha API pubblica
