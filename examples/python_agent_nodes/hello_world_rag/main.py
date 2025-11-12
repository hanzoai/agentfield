"""
Hello World RAG - Minimal vector-backed retrieval example

Demonstrates:
- Using AgentField memory vectors without any extra services
- One skill to ingest documents (path or raw text)
- One reasoner to answer questions using similarity search + LLM synthesis
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional

from agentfield import Agent, AIConfig
from agentfield.logger import log_info
from fastembed import TextEmbedding
from pydantic import BaseModel

# Initialize agent
app = Agent(
    node_id="hello-world-rag",
    agentfield_server=os.getenv("AGENTFIELD_SERVER", "http://localhost:8080"),
    ai_config=AIConfig(
        model=os.getenv("SMALL_MODEL", "openrouter/meta-llama/llama-4-maverick")
    ),
)


# ========= Embedding helpers =========

_EMBED_MODEL_NAME = os.getenv("EMBED_MODEL", "BAAI/bge-small-en-v1.5")
_EMBED_MODEL = TextEmbedding(model_name=_EMBED_MODEL_NAME)


def _embed_texts(texts: List[str]) -> List[List[float]]:
    """Use FastEmbed to produce high-quality embeddings."""
    embeddings = list(_EMBED_MODEL.embed(texts))
    return [emb.tolist() for emb in embeddings]


def _chunk_text(text: str, size: int = 400, overlap: int = 50) -> List[str]:
    """Simple fixed-size chunker with overlap to keep context coherent."""
    chunks: List[str] = []
    start = 0
    end = len(text)
    while start < end:
        chunk = text[start : start + size]
        chunks.append(chunk.strip())
        start += max(size - overlap, 1)
    return [chunk for chunk in chunks if chunk]


def _load_source_text(path: Optional[str], text: Optional[str]) -> str:
    if text and text.strip():
        return text.strip()
    if not path:
        raise ValueError("Either 'text' or 'path' must be provided.")
    data = Path(path).read_text(encoding="utf-8")
    return data.strip()


# ===================== Schemas =====================


class IngestResult(BaseModel):
    """Skill output summarizing ingestion."""

    document_id: str
    chunk_count: int


class SourceChunk(BaseModel):
    """Chunk metadata returned to the caller."""

    document_id: str
    chunk_id: str
    text: str
    score: float


class QAResponse(BaseModel):
    """Reasoner output with synthesized answer + supporting text."""

    answer: str
    sources: List[SourceChunk]


class _AnswerOnly(BaseModel):
    """Internal schema for prompting the LLM."""

    answer: str


# ===================== Skill: document ingestion =====================


@app.skill()
async def ingest_document(
    document_id: str, path: Optional[str] = None, text: Optional[str] = None
) -> IngestResult:
    """
    Store a document's chunks + embeddings into AgentField memory vectors.
    """
    body = _load_source_text(path, text)
    chunks = _chunk_text(body)
    embeddings = _embed_texts(chunks) if chunks else []

    global_memory = app.memory.global_scope

    for idx, (chunk, embedding) in enumerate(zip(chunks, embeddings)):
        chunk_id = f"{document_id}:{idx}"
        metadata = {
            "text": chunk,
            "document_id": document_id,
            "chunk_id": chunk_id,
        }
        await global_memory.set_vector(
            key=chunk_id,
            embedding=embedding,
            metadata=metadata,
        )

    return IngestResult(document_id=document_id, chunk_count=len(chunks))


# ===================== Reasoner: question answering =====================


@app.reasoner()
async def answer_question(question: str, top_k: int = 3) -> QAResponse:
    """
    Embed the question, run similarity search, and summarize via LLM.
    """
    query_embedding = _embed_texts([question])[0]
    global_memory = app.memory.global_scope
    hits = await global_memory.similarity_search(
        query_embedding=query_embedding,
        top_k=top_k,
    )

    if not hits:
        return QAResponse(answer="I do not have information on that yet.", sources=[])

    context_blocks = []
    sources: List[SourceChunk] = []
    for hit in hits:
        metadata = hit.get("metadata", {})
        text = metadata.get("text", "")
        document_id = metadata.get("document_id", "unknown")
        chunk_id = metadata.get("chunk_id", hit.get("key", ""))
        context_blocks.append(f"[{document_id}] {text}")
        sources.append(
            SourceChunk(
                document_id=document_id,
                chunk_id=chunk_id,
                text=text,
                score=hit.get("score", 0.0),
            )
        )

    prompt = f"""You are a concise assistant. Use only the provided context.
Context:
{os.linesep.join(context_blocks)}

Question: {question}
Answer in 2-3 sentences."""

    ai_result = await app.ai(
        system="Answer using only supplied context. Cite document ids inline when possible.",
        user=prompt,
        schema=_AnswerOnly,
    )

    # Enrich AI response with the actual retrieved snippets
    return QAResponse(answer=ai_result.answer, sources=sources)


# ===================== Entry point =====================

if __name__ == "__main__":
    # Warm up embedding model so first request isn't slow
    try:
        _embed_texts(["embedding warmup"])
        log_info("FastEmbed model warmed up")
    except Exception as warmup_error:
        log_info(f"FastEmbed warmup failed: {warmup_error}")

    print("🚀 Hello World RAG Agent")
    print("📍 Node: hello-world-rag")
    print(f"🌐 Control Plane: {app.agentfield_server}")
    print("Skills:")
    print("  • ingest_document(document_id, path|text)")
    print("Reasoners:")
    print("  • answer_question(question)")
    app.run(auto_port=True)
"""
Hello World Agent - Minimal Agentfield Example

Demonstrates:
- One skill (deterministic function)
- Two reasoners (AI-powered functions)
- Call graph: say_hello → get_greeting (skill) + add_emoji (reasoner)
"""

from agentfield import Agent
from agentfield import AIConfig
from pydantic import BaseModel
import os

# Initialize agent
app = Agent(
    node_id="hello-world",
    agentfield_server="http://localhost:8080",
    ai_config=AIConfig(
        model=os.getenv("SMALL_MODEL", "openai/gpt-4o-mini"), temperature=0.7
    ),
)

# ============= SKILL (DETERMINISTIC) =============


@app.skill()
def get_greeting(name: str) -> dict:
    """Returns a greeting template (deterministic - no AI)"""
    return {"message": f"Hello, {name}! Welcome to Agentfield."}


# ============= REASONERS (AI-POWERED) =============


class EmojiResult(BaseModel):
    """Simple schema for emoji addition"""

    text: str
    emoji: str


@app.reasoner()
async def add_emoji(text: str) -> EmojiResult:
    """Uses AI to add an appropriate emoji to text"""
    return await app.ai(
        user=f"Add one appropriate emoji to this greeting: {text}", schema=EmojiResult
    )


@app.reasoner()
async def say_hello(name: str) -> dict:
    """
    Main entry point - orchestrates skill and reasoner.

    Call graph:
    say_hello (entry point)
    ├─→ get_greeting (skill)
    └─→ add_emoji (reasoner)
    """
    # Step 1: Get greeting from skill (deterministic)
    greeting = get_greeting(name)

    # Step 2: Add emoji using AI (reasoner)
    result = await add_emoji(greeting["message"])

    return {"greeting": result.text, "emoji": result.emoji, "name": name}


# ============= START SERVER OR CLI =============

if __name__ == "__main__":
    print("🚀 Hello World Agent")
    print("📍 Node: hello-world")
    print("🌐 Control Plane: http://localhost:8080")

    # Universal entry point - auto-detects CLI vs server mode
    app.run(auto_port=True)
