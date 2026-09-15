import os
import json
from typing import List, Dict, Any
from app.rag.vector_store import HybridRetriever

def chunk_text(text: str, chunk_size: int = 500, overlap: int = 50) -> List[str]:
    """Splits input text into semantic chunks of target chunk_size with overlap."""
    chunks = []
    start = 0
    text_len = len(text)
    
    while start < text_len:
        end = start + chunk_size
        chunk = text[start:end]
        chunks.append(chunk.strip())
        if end >= text_len:
            break
        start += (chunk_size - overlap)
        
    return [c for c in chunks if c]

def load_runbook(file_path: str) -> List[Dict[str, Any]]:
    """Loads a markdown runbook and returns semantic chunk documents."""
    if not os.path.exists(file_path):
        return []
        
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
        
    raw_chunks = chunk_text(content, chunk_size=500, overlap=50)
    filename = os.path.basename(file_path)
    
    documents = []
    for idx, chunk in enumerate(raw_chunks):
        documents.append({
            "id": f"runbook-{filename}-{idx}",
            "content": chunk,
            "metadata": {
                "source": filename,
                "type": "runbook",
                "chunk_index": idx
            }
        })
    return documents

def load_sample_logs(file_path: str) -> List[Dict[str, Any]]:
    """Loads JSON sample log entries as document items."""
    if not os.path.exists(file_path):
        return []
        
    with open(file_path, "r", encoding="utf-8") as f:
        logs = json.load(f)
        
    documents = []
    for log in logs:
        alert_id = log.get("alert_id", "unknown")
        content_text = (
            f"Alert ID: {alert_id} | Event: {log.get('event_type')} | "
            f"Source IP: {log.get('source_ip')} | Target User: {log.get('target_user')} | "
            f"Description: {log.get('description')} | Raw Log: {log.get('raw_log')}"
        )
        documents.append({
            "id": f"log-{alert_id}",
            "content": content_text,
            "metadata": {
                "source": "sample_logs.json",
                "type": "log_entry",
                "alert_id": alert_id,
                "event_type": log.get("event_type", "")
            }
        })
    return documents

def ingest_knowledge_base(
    runbook_path: str = "data/runbooks/brute_force_mitigation.md",
    logs_path: str = "data/sample_logs.json",
    retriever: HybridRetriever = None
) -> HybridRetriever:
    """Ingests runbooks and log files into the hybrid retriever."""
    if retriever is None:
        retriever = HybridRetriever()

    all_docs = []
    all_docs.extend(load_runbook(runbook_path))
    all_docs.extend(load_sample_logs(logs_path))

    if all_docs:
        retriever.add_documents(all_docs)
        print(f"Ingested {len(all_docs)} documents into HybridRetriever (ChromaDB + BM25).")

    return retriever

if __name__ == "__main__":
    ingest_knowledge_base()
