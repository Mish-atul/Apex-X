"""
Officer Co-Pilot RAG (Retrieval-Augmented Generation)
Indexes investigation artifacts into ChromaDB and retrieves relevant 
context to answer investigator queries using the local LLM.
"""

import os
import json
import logging
from typing import List

from app.config import settings
from app.engines.intelligence import llm_client

logger = logging.getLogger(__name__)

try:
    import chromadb
    from chromadb.config import Settings as ChromaSettings
    CHROMA_AVAILABLE = True
except ImportError:
    CHROMA_AVAILABLE = False
    logger.warning("chromadb not installed. Co-Pilot RAG disabled. Install: pip install chromadb")

# Local persistent store so RAG needs no separate ChromaDB server
_CHROMA_PATH = settings.CHROMA_DIR


def _split_text(text: str, chunk_size: int = 1000, overlap: int = 200) -> List[str]:
    """Dependency-free chunker: splits on paragraph/line boundaries with overlap."""
    text = text or ""
    if len(text) <= chunk_size:
        return [text] if text.strip() else []
    chunks, start = [], 0
    while start < len(text):
        end = min(start + chunk_size, len(text))
        # Prefer to break on a newline near the chunk boundary for cleaner chunks
        if end < len(text):
            nl = text.rfind("\n", start + chunk_size - overlap, end)
            if nl > start:
                end = nl
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
        if end >= len(text):
            break
        start = max(end - overlap, start + 1)
    return chunks


def _get_chroma_client():
    if not CHROMA_AVAILABLE:
        return None
    # Prefer a configured ChromaDB server; fall back to an embedded local store
    try:
        if getattr(settings, "CHROMADB_HOST", None):
            return chromadb.HttpClient(
                host=settings.CHROMADB_HOST,
                port=settings.CHROMADB_PORT,
                settings=ChromaSettings(allow_reset=True),
            )
    except Exception as e:
        logger.info(f"ChromaDB server unavailable ({e}); using local persistent store")
    try:
        os.makedirs(_CHROMA_PATH, exist_ok=True)
        return chromadb.PersistentClient(path=_CHROMA_PATH)
    except Exception as e:
        logger.error(f"Failed to initialise local ChromaDB: {e}")
        return None


def index_case_artifacts(case_id: str, case_dir: str) -> bool:
    """
    Reads all JSON reports for a case, converts them to text chunks, 
    and indexes them into ChromaDB for RAG queries.
    """
    client = _get_chroma_client()
    if not client:
        return False

    try:
        collection = client.get_or_create_collection(name="investigation_reports")
        
        # 1. Gather all reports
        texts_to_index = []
        
        # Static
        static_path = os.path.join(case_dir, "static_analysis", "static_report.json")
        if os.path.exists(static_path):
            with open(static_path, "r") as f:
                data = json.load(f)
                texts_to_index.append(f"STATIC ANALYSIS REPORT:\n{json.dumps(data, indent=2)}")
                
        # Dynamic
        dynamic_path = os.path.join(case_dir, "dynamic_analysis", "dynamic_report.json")
        if os.path.exists(dynamic_path):
            with open(dynamic_path, "r") as f:
                data = json.load(f)
                texts_to_index.append(f"DYNAMIC ANALYSIS REPORT:\n{json.dumps(data, indent=2)}")

        # C2
        c2_path = os.path.join(case_dir, "c2_intelligence", "c2_report.json")
        if os.path.exists(c2_path):
            with open(c2_path, "r") as f:
                data = json.load(f)
                texts_to_index.append(f"C2 INTELLIGENCE REPORT:\n{json.dumps(data, indent=2)}")

        # Vuln
        vuln_path = os.path.join(case_dir, "vulnerability_analysis", "vulnerability_report.json")
        if os.path.exists(vuln_path):
            with open(vuln_path, "r") as f:
                data = json.load(f)
                texts_to_index.append(f"VULNERABILITY REPORT:\n{json.dumps(data, indent=2)}")

        # Threat Narrative
        narrative_path = os.path.join(case_dir, "intelligence_analysis", "threat_narrative.json")
        if os.path.exists(narrative_path):
            with open(narrative_path, "r") as f:
                data = json.load(f)
                texts_to_index.append(f"THREAT NARRATIVE:\n{data.get('narrative_text', '')}")

        if not texts_to_index:
            logger.warning(f"No artifacts found to index for case {case_id}")
            return False

        # 2. Chunk text
        chunks = []
        for text in texts_to_index:
            chunks.extend(_split_text(text, chunk_size=1000, overlap=200))

        # 3. Add to ChromaDB
        # We use ChromaDB's default embedding function (all-MiniLM-L6-v2) for simplicity
        # and to save RAM, since loading another local LLM for embeddings would violate
        # the 16GB strict constraint.
        ids = [f"{case_id}_chunk_{i}" for i in range(len(chunks))]
        metadatas = [{"case_id": case_id} for _ in range(len(chunks))]
        
        # Upsert in small batches
        batch_size = 100
        for i in range(0, len(chunks), batch_size):
            collection.upsert(
                documents=chunks[i:i+batch_size],
                metadatas=metadatas[i:i+batch_size],
                ids=ids[i:i+batch_size]
            )
            
        logger.info(f"Indexed {len(chunks)} chunks for case {case_id}")
        return True

    except Exception as e:
        logger.error(f"Failed to index artifacts for case {case_id}: {e}")
        return False


def retrieve_context(case_id: str, query: str, n_results: int = 5) -> str:
    """
    Retrieve relevant chunks for a case based on a query.
    """
    client = _get_chroma_client()
    if not client:
        return "RAG database not available."

    try:
        collection = client.get_collection(name="investigation_reports")
        
        results = collection.query(
            query_texts=[query],
            n_results=n_results,
            where={"case_id": case_id}
        )
        
        documents = results.get("documents", [[]])[0]
        if not documents:
            return "No relevant case data found."
            
        return "\n\n---\n\n".join(documents)

    except Exception as e:
        logger.error(f"RAG retrieval error: {e}")
        return f"Error retrieving context: {e}"


def answer_query(case_id: str, query: str) -> str:
    """
    Full RAG pipeline: Retrieve context -> Call LLM -> Return answer.
    This is used by the REST API, not the WebSocket (which uses streaming).
    """
    context = retrieve_context(case_id, query)
    
    system_prompt = (
        "You are the APEX-X Officer Co-Pilot. Answer the investigator's question "
        "using ONLY the provided context from the case file. If the context does not "
        "contain the answer, state that clearly. Do not hallucinate."
    )
    
    full_prompt = f"Context from Case {case_id}:\n{context}\n\nInvestigator Question: {query}"
    
    return llm_client.generate(
        prompt=full_prompt,
        model=llm_client.MODEL_CODER,
        system=system_prompt,
        temperature=0.2
    )

def stream_answer(case_id: str, query: str):
    """
    Streaming RAG pipeline. Yields tokens as they are generated.
    """
    context = retrieve_context(case_id, query)
    
    system_prompt = (
        "You are the APEX-X Officer Co-Pilot, an AI assistant for cybercrime investigators. "
        "Answer the investigator's question based ONLY on the provided case context. "
        "If you don't know, say so. Keep it professional, concise, and highlight key IOCs."
    )
    
    full_prompt = f"Case {case_id} Context:\n{context}\n\nQuestion: {query}"
    
    yield from llm_client.generate_streaming(
        prompt=full_prompt,
        model=llm_client.MODEL_CODER,
        system=system_prompt,
        temperature=0.2
    )
