import datetime
import logging
import os
import uuid

import inngest
import inngest.fast_api
from dotenv import load_dotenv
from fastapi import FastAPI
from google import genai
from google.genai import types

from backend.api.investigations import (
    router as investigations_router,
)
from backend.database.qdrant import QdrantStorage
from backend.investigation.engine import investigate_content
from backend.investigation.models import (
    RAGChunkAndSrc,
    RAGQueryResult,
    RAGSearchResult,
    RAGUpsertResult,
)
from backend.investigation.types import (
    InvestigationRequest,
    InvestigationResult,
)
from backend.utils.data_loader import (
    EMBED_DIM,
    embed_texts,
    load_and_chunk_pdf,
)


load_dotenv()

gemini_api_key = os.getenv("GEMINI_API_KEY")

if not gemini_api_key:
    raise ValueError(
        "GEMINI_API_KEY is missing. Add it to your .env file."
    )

gemini_client = genai.Client(
    api_key=gemini_api_key
)

GENERATION_MODEL = "gemini-flash-latest"


# ---------------------------------------------------------
# Inngest configuration
# ---------------------------------------------------------

inngest_client = inngest.Inngest(
    app_id="sentinel_ai",
    logger=logging.getLogger("uvicorn"),
    is_production=False,
    serializer=inngest.PydanticSerializer(),
)


# ---------------------------------------------------------
# Existing RAG PDF ingestion workflow
# ---------------------------------------------------------

@inngest_client.create_function(
    fn_id="RAG: Ingest PDF",
    trigger=inngest.TriggerEvent(
        event="rag/ingest_pdf"
    ),
    throttle=inngest.Throttle(
        limit=2,
        period=datetime.timedelta(minutes=1),
    ),
    rate_limit=inngest.RateLimit(
        limit=1,
        period=datetime.timedelta(hours=4),
        key="event.data.source_id",
    ),
)
async def rag_ingest_pdf(
    ctx: inngest.Context,
) -> dict:
    def _load() -> RAGChunkAndSrc:
        pdf_path = ctx.event.data.get(
            "pdf_path"
        )

        if not pdf_path:
            raise ValueError(
                "Missing required field: event.data.pdf_path"
            )

        source_id = ctx.event.data.get(
            "source_id",
            pdf_path,
        )

        source_id = str(source_id).strip()

        if not source_id:
            raise ValueError(
                "source_id cannot be empty."
            )

        chunks = load_and_chunk_pdf(
            pdf_path
        )

        print(f"PDF PATH: {pdf_path}")
        print(f"SOURCE ID: {source_id}")
        print(f"TOTAL CHUNKS: {len(chunks)}")

        for index, chunk in enumerate(
            chunks
        ):
            print(
                f"\n--- CHUNK {index + 1} ---"
            )
            print(chunk[:500])

        return RAGChunkAndSrc(
            chunks=chunks,
            source_id=source_id,
        )

    def _upsert(
        chunks_and_source: RAGChunkAndSrc,
    ) -> RAGUpsertResult:
        chunks = chunks_and_source.chunks
        source_id = (
            chunks_and_source.source_id
        )

        if not source_id:
            raise ValueError(
                "source_id cannot be empty."
            )

        vectors = embed_texts(chunks)

        ids = [
            str(
                uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    f"{source_id}:{index}",
                )
            )
            for index in range(len(chunks))
        ]

        payloads = [
            {
                "source": source_id,
                "text": chunk,
                "chunk_index": index,
            }
            for index, chunk in enumerate(
                chunks
            )
        ]

        store = QdrantStorage(
            dim=EMBED_DIM
        )

        store.upsert(
            ids=ids,
            vectors=vectors,
            payloads=payloads,
        )

        return RAGUpsertResult(
            ingested=len(chunks)
        )

    chunks_and_source = (
        await ctx.step.run(
            "load-and-chunk",
            _load,
            output_type=RAGChunkAndSrc,
        )
    )

    ingestion_result = (
        await ctx.step.run(
            "embed-and-upsert",
            lambda: _upsert(
                chunks_and_source
            ),
            output_type=RAGUpsertResult,
        )
    )

    return ingestion_result.model_dump()


# ---------------------------------------------------------
# Existing RAG PDF query workflow
# ---------------------------------------------------------

@inngest_client.create_function(
    fn_id="RAG: Query PDF",
    trigger=inngest.TriggerEvent(
        event="rag/query_pdf_ai"
    ),
)
async def rag_query_pdf_ai(
    ctx: inngest.Context,
) -> dict:
    def _search(
        question: str,
        top_k: int,
        source_id: str,
    ) -> RAGSearchResult:
        query_vectors = embed_texts(
            [question]
        )

        if not query_vectors:
            raise RuntimeError(
                "Gemini did not return a query embedding."
            )

        query_vector = query_vectors[0]

        store = QdrantStorage(
            dim=EMBED_DIM
        )

        found = store.search(
            query_vector=query_vector,
            top_k=top_k,
            source_id=source_id,
        )

        return RAGSearchResult(
            contexts=found["contexts"],
            sources=found["sources"],
        )

    def _generate_answer(
        question: str,
        search_result: RAGSearchResult,
    ) -> str:
        context_block = "\n\n".join(
            (
                f"[Context {index + 1}]\n"
                f"{context}"
            )
            for index, context in enumerate(
                search_result.contexts
            )
        )

        prompt = (
            "Answer the user's question using only the "
            "provided document context.\n\n"
            "If the answer is not present in the context, "
            "say: \"I could not find that information in "
            "the uploaded document.\"\n\n"
            f"Document context:\n{context_block}\n\n"
            f"Question: {question}"
        )

        response = (
            gemini_client.models.generate_content(
                model=GENERATION_MODEL,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=(
                        "You are a document question-answering "
                        "assistant. Use only the supplied document "
                        "context and do not invent information."
                    ),
                    temperature=0.2,
                    max_output_tokens=1024,
                ),
            )
        )

        answer = response.text

        if not answer:
            raise RuntimeError(
                "Gemini returned an empty answer."
            )

        return answer.strip()

    question = ctx.event.data.get(
        "question"
    )

    if not question:
        raise ValueError(
            "Missing required field: event.data.question"
        )

    question = str(question).strip()

    if not question:
        raise ValueError(
            "The question cannot be empty."
        )

    source_id = ctx.event.data.get(
        "source_id"
    )

    if not source_id:
        raise ValueError(
            "Missing required field: event.data.source_id"
        )

    source_id = str(source_id).strip()

    if not source_id:
        raise ValueError(
            "source_id cannot be empty."
        )

    try:
        top_k = int(
            ctx.event.data.get(
                "top_k",
                5,
            )
        )
    except (TypeError, ValueError) as error:
        raise ValueError(
            "top_k must be a valid integer."
        ) from error

    if top_k < 1:
        raise ValueError(
            "top_k must be at least 1."
        )

    found = await ctx.step.run(
        "embed-and-filtered-search",
        lambda: _search(
            question=question,
            top_k=top_k,
            source_id=source_id,
        ),
        output_type=RAGSearchResult,
    )

    if not found.contexts:
        result = RAGQueryResult(
            answer=(
                "I could not find relevant information "
                "in the selected document."
            ),
            sources=[],
            num_contexts=0,
        )

        return result.model_dump()

    answer = await ctx.step.run(
        "gemini-answer",
        lambda: _generate_answer(
            question,
            found,
        ),
    )

    result = RAGQueryResult(
        answer=answer,
        sources=found.sources,
        num_contexts=len(
            found.contexts
        ),
    )

    return result.model_dump()


# ---------------------------------------------------------
# Sentinel structured investigation workflow
# ---------------------------------------------------------

@inngest_client.create_function(
    fn_id="Sentinel: Investigate Content",
    trigger=inngest.TriggerEvent(
        event="sentinel/investigate"
    ),
)
async def sentinel_investigate(
    ctx: inngest.Context,
) -> dict:
    def _investigate() -> InvestigationResult:
        event_data = ctx.event.data

        content = event_data.get(
            "content"
        )

        if not content:
            raise ValueError(
                "Missing required field: event.data.content"
            )

        content = str(content).strip()

        if len(content) < 10:
            raise ValueError(
                "Content must contain at least 10 characters."
            )

        input_type = event_data.get(
            "input_type",
            "text",
        )

        source_name = event_data.get(
            "source_name"
        )

        claimed_company = event_data.get(
            "claimed_company"
        )

        sender_email = event_data.get(
            "sender_email"
        )

        follow_up_answers = event_data.get(
            "follow_up_answers",
            {},
        )

        if not isinstance(
            follow_up_answers,
            dict,
        ):
            raise ValueError(
                "follow_up_answers must be a JSON object."
            )

        request = InvestigationRequest(
            content=content,
            input_type=input_type,
            source_name=source_name,
            claimed_company=claimed_company,
            sender_email=sender_email,
            follow_up_answers=follow_up_answers,
        )

        return investigate_content(
            request
        )

    result = await ctx.step.run(
        "structured-investigation",
        _investigate,
        output_type=InvestigationResult,
    )

    return result.model_dump()


# ---------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------

app = FastAPI(
    title="Sentinel AI",
    description=(
        "AI-powered digital safety investigation platform "
        "for analyzing suspicious messages, scams, phishing, "
        "job offers, and online fraud."
    ),
    version="2.0.0",
)


# Register REST API routes.
#
# This adds:
# POST /api/investigations
# GET  /api/investigations
# GET  /api/investigations/{investigation_id}
app.include_router(
    investigations_router
)


@app.get(
    "/",
    tags=["System"],
)
def root() -> dict[str, str]:
    return {
        "status": "running",
        "application": "Sentinel AI",
        "version": "2.0.0",
    }


@app.get(
    "/health",
    tags=["System"],
)
def health() -> dict[str, str]:
    return {
        "status": "healthy",
        "api": "connected",
    }


# ---------------------------------------------------------
# Register Inngest workflows with FastAPI
# ---------------------------------------------------------

inngest.fast_api.serve(
    app,
    inngest_client,
    [
        rag_ingest_pdf,
        rag_query_pdf_ai,
        sentinel_investigate,
    ],
)