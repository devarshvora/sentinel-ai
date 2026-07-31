from typing import Any

from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance,
    FieldCondition,
    Filter,
    MatchValue,
    PointStruct,
    VectorParams,
)


class QdrantStorage:
    def __init__(
        self,
        url: str = "http://localhost:6333",
        collection: str = "docs_gemini",
        dim: int = 768,
    ) -> None:
        self.client = QdrantClient(
            url=url,
            timeout=30,
        )

        self.collection = collection
        self.dim = dim

        # Create the collection only if it does not already exist.
        if not self.client.collection_exists(
            collection_name=self.collection
        ):
            self.client.create_collection(
                collection_name=self.collection,
                vectors_config=VectorParams(
                    size=self.dim,
                    distance=Distance.COSINE,
                ),
            )

    def upsert(
        self,
        ids: list[str],
        vectors: list[list[float]],
        payloads: list[dict[str, Any]],
    ) -> None:
        """
        Store document chunk vectors and their metadata in Qdrant.
        """

        if not (
            len(ids) == len(vectors) == len(payloads)
        ):
            raise ValueError(
                "ids, vectors, and payloads must have equal lengths."
            )

        if not ids:
            raise ValueError(
                "No vectors were provided for insertion."
            )

        # Ensure every Gemini embedding has the expected dimension.
        for index, vector in enumerate(vectors):
            if len(vector) != self.dim:
                raise ValueError(
                    f"Vector at index {index} has {len(vector)} dimensions. "
                    f"Expected {self.dim} dimensions."
                )

        points = [
            PointStruct(
                id=point_id,
                vector=vector,
                payload=payload,
            )
            for point_id, vector, payload in zip(
                ids,
                vectors,
                payloads,
            )
        ]

        self.client.upsert(
            collection_name=self.collection,
            points=points,
            wait=True,
        )

    def search(
        self,
        query_vector: list[float],
        top_k: int = 5,
        source_id: str | None = None,
    ) -> dict[str, list[str]]:
        """
        Search Qdrant for document chunks that are semantically
        similar to the question embedding.

        When source_id is provided, search only chunks belonging
        to that document.
        """

        if not query_vector:
            raise ValueError(
                "The query vector cannot be empty."
            )

        if len(query_vector) != self.dim:
            raise ValueError(
                f"Query vector has {len(query_vector)} dimensions. "
                f"Expected {self.dim} dimensions."
            )

        if top_k < 1:
            raise ValueError(
                "top_k must be at least 1."
            )

        # Remove accidental whitespace from the document identifier.
        normalized_source_id = (
            source_id.strip()
            if source_id
            else None
        )

        # By default, no filter is applied.
        query_filter: Filter | None = None

        # When a source is supplied, limit retrieval to chunks whose
        # payload contains the same exact source value.
        if normalized_source_id:
            query_filter = Filter(
                must=[
                    FieldCondition(
                        key="source",
                        match=MatchValue(
                            value=normalized_source_id
                        ),
                    )
                ]
            )

        response = self.client.query_points(
            collection_name=self.collection,
            query=query_vector,
            query_filter=query_filter,
            with_payload=True,
            limit=top_k,
        )

        results = response.points

        contexts: list[str] = []
        sources: set[str] = set()

        for result in results:
            payload = getattr(
                result,
                "payload",
                None,
            ) or {}

            text = payload.get("text", "")
            source = payload.get("source", "")

            if text:
                contexts.append(text)

            if source:
                sources.add(source)

        return {
            "contexts": contexts,
            "sources": sorted(sources),
        }