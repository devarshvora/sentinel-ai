import os

from dotenv import load_dotenv
from google import genai
from google.genai import types
from llama_index.core.node_parser import SentenceSplitter
from llama_index.readers.file import PDFReader


load_dotenv()

gemini_api_key = os.getenv("GEMINI_API_KEY")

if not gemini_api_key:
    raise ValueError(
        "GEMINI_API_KEY is missing. Add it to your .env file."
    )

client = genai.Client(api_key=gemini_api_key)

EMBED_MODEL = "gemini-embedding-001"

# We explicitly request 768-dimensional vectors.
# Qdrant must use the same dimension.
EMBED_DIM = 768

splitter = SentenceSplitter(
    chunk_size=1000,
    chunk_overlap=200,
)


def load_and_chunk_pdf(path: str) -> list[str]:
    """
    Read a PDF, extract its text, and divide it into overlapping chunks.
    """

    if not os.path.exists(path):
        raise FileNotFoundError(f"PDF was not found: {path}")

    documents = PDFReader().load_data(file=path)

    texts = [
        document.text
        for document in documents
        if getattr(document, "text", None)
    ]

    chunks: list[str] = []

    for text in texts:
        chunks.extend(splitter.split_text(text))

    if not chunks:
        raise ValueError(
            "No readable text was extracted from the PDF. "
            "The PDF may be empty or image-based."
        )

    return chunks


def embed_texts(texts: list[str]) -> list[list[float]]:
    """
    Convert multiple text strings into Gemini embedding vectors.
    """

    if not texts:
        return []

    response = client.models.embed_content(
        model=EMBED_MODEL,
        contents=texts,
        config=types.EmbedContentConfig(
            output_dimensionality=EMBED_DIM,
        ),
    )

    if not response.embeddings:
        raise RuntimeError("Gemini returned no embeddings.")

    vectors = [
        embedding.values
        for embedding in response.embeddings
        if embedding.values is not None
    ]

    if len(vectors) != len(texts):
        raise RuntimeError(
            f"Expected {len(texts)} embeddings, "
            f"but Gemini returned {len(vectors)}."
        )

    return vectors