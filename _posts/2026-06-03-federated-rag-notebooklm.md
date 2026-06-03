---
layout: post
title: "My notebooks don't talk to each other: a RAG idea I plan to build eventually"
date: 2026-06-03
categories: [projects]
tags: [rag, notebooklm, llm, regolo-ai, llamaindex, chromadb, fastapi, nextjs, ai]
excerpt: "I have NotebookLM notebooks that know nothing about each other. Instead of accepting this as a fact of life, I started designing a fix."
---

Right now I have two NotebookLM notebooks for my PortSwigger Academy journey: one with SQL injection theory, one with lab sessions. As I keep working through the curriculum, there will be more — one per topic, probably, maybe one per difficulty tier. The structure makes sense while you're inside it.

The problem shows up when you try to reason across it.

If I ask the theory notebook something that only came up during a lab, it doesn't know. If I want to connect a concept I drilled in practice with its theoretical explanation, I have to open both, re-read, and reconstruct the link manually. Which defeats a big part of why I built the system in the first place.

This isn't NotebookLM's fault. Each notebook is an isolated environment by design — it's what makes them good for focused study. But isolated environments don't scale well when the knowledge you're accumulating is supposed to be connected.

So I started thinking about what a fix would actually look like.

## The obvious approach — and why it falls short

The first idea is fan-out: for any question, ask all notebooks the same thing and synthesize the answers. Simple, fast, requires almost no new infrastructure. I could build it in an afternoon.

But it's not really RAG. Each notebook answers in its own context, without seeing the others. The synthesis happens after retrieval, on pre-filtered text. What you lose is the ability to reason *across* sources simultaneously — a model receiving three finished answers can try to stitch them together, but it can't notice that chunk A from one notebook and chunk B from another are describing the same technique from different angles, because it never sees them side by side.

The right approach is to pull sources from all notebooks into a single vector store and query it with one engine. The model gets the most relevant pieces from everywhere, in the same context window, and reasons on those directly.

## The stack

**Vector store: ChromaDB**

Embedded, no server required, runs locally. For a personal project at this scale, a managed vector database is unnecessary overhead. ChromaDB does everything needed in a single dependency.

**RAG framework: LlamaIndex**

More control over the pipeline than LangChain — I want to tune how chunks are retrieved and passed to the model, not just call a high-level chain and hope the defaults are reasonable.

**Backend: FastAPI + Next.js**

Standard choice. FastAPI for the API layer, Next.js with shadcn/ui for a frontend that doesn't look like a demo.

**Ingestion: NotebookLM MCP**

This is the non-trivial part. NotebookLM doesn't have a public API, so extracting sources requires going through the MCP layer. It's not `open file, read text` — there's actual plumbing involved, and figuring that out is probably the most interesting engineering problem in the whole project.

## Why Regolo.ai

I could use OpenAI for embeddings and generation. It's the obvious choice, the one every tutorial defaults to.

I'm going with [Regolo.ai](https://regolo.ai) instead because I genuinely like the project and want to support it. It's an Italian provider hosting open source models, and having a good European alternative to the usual American APIs matters. They have exactly what a RAG pipeline needs — embeddings, reranking, and generation all available — and their API is OpenAI-compatible, so the integration is straightforward.

## The models

**Embedding — `Qwen3-Embedding-8B`**

Retrieval quality is the part that matters most in a RAG system. If the chunks you retrieve are wrong, the model starts from garbage no matter how capable it is. A dedicated embedding model from the same provider keeps the stack clean.

**Reranker — `Qwen3-Reranker-4B`**

The step most RAG tutorials skip. Vector similarity retrieval is fast but blunt — it finds chunks "close" to the query in embedding space, not necessarily the most useful for answering the question. The reranker takes the top-k candidates and reorders them based on actual semantic relevance to the query. Less noise, better context, better answers. Worth the extra step.

**Generation — `gemma-4-31B`**

256K context window and native tool use. The tool support is what makes this interesting: instead of a static pipeline that always retrieves the same way, I can build an agent that decides dynamically how to search — whether to query once, refine, or pull from different sources based on what it finds.

## The full picture

```
NotebookLM notebooks → ingestion via MCP → ChromaDB
                                               ↓
          query → LlamaIndex → Qwen3-Reranker → gemma-4-31B → answer
```

One query engine over all notebooks. Theory and labs in the same index. Every new notebook I create as I progress through PortSwigger gets added to the same store — no manual cross-referencing.

## When will I actually build this

No deadline. This is an idea I've been thinking through for a few days, and writing it out is part of deciding whether it's worth the time. The shape feels right — the problem is real, the stack makes sense, and the ingestion layer is genuinely interesting to figure out.

When I do start, I'll begin with the ingestion pipeline, because that's the unknown. The rest is variation on things I've done before. Getting sources out of NotebookLM in a clean, structured format is the new problem.

And when I build it, I'll write about what actually happened. Which will almost certainly not match what I just described.

## Takeaways

- NotebookLM notebooks are isolated by design — good for depth, limiting for breadth
- Fan-out aggregation and real RAG are different; the difference is where synthesis happens
- A complete RAG pipeline has three stages: embedding, reranking, generation — the reranking step is the one most people skip and the one that matters most for quality
- The interesting engineering problem here isn't the RAG itself, it's the ingestion from a tool that has no public API
