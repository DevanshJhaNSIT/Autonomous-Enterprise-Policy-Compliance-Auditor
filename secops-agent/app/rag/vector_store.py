import os
import math
from typing import List, Dict, Any, Tuple
from rank_bm25 import BM25Okapi
import chromadb
from chromadb.config import Settings as ChromaSettings
from app.config import settings

class HybridRetriever:
    """
    Hybrid Retriever combining ChromaDB (Dense Vector Search) and BM25 (Sparse Keyword Search)
    with Reciprocal Rank Fusion (RRF) re-ranking.
    """
    def __init__(self, persist_dir: str = None):
        self.persist_dir = persist_dir or settings.CHROMA_PERSIST_DIR
        os.makedirs(self.persist_dir, exist_ok=True)
        
        # Initialize ChromaDB client
        self.chroma_client = chromadb.PersistentClient(path=self.persist_dir)
        self.collection = self.chroma_client.get_or_create_collection(
            name="secops_runbooks_and_logs"
        )
        
        self.bm25 = None
        self.documents: List[Dict[str, Any]] = []
        self._tokenized_corpus = []

    def _pseudo_embed(self, text: str) -> List[float]:
        """Simple deterministic hash-based pseudo vector embedding for fallback/testing."""
        vector = [0.0] * 1536
        for i, char in enumerate(text[:500]):
            vector[i % 1536] += ord(char) / 255.0
        norm = math.sqrt(sum(x * x for x in vector)) or 1.0
        return [x / norm for x in vector]

    def add_documents(self, docs: List[Dict[str, Any]]):
        """
        Adds a list of document dicts to both ChromaDB vector store and BM25 index.
        Each doc is expected to have 'id', 'content', and optional 'metadata'.
        """
        if not docs:
            return

        ids = [doc["id"] for doc in docs]
        contents = [doc["content"] for doc in docs]
        metadatas = [doc.get("metadata", {}) for doc in docs]

        # Populate ChromaDB
        embeddings = [self._pseudo_embed(c) for c in contents]
        self.collection.upsert(
            ids=ids,
            documents=contents,
            embeddings=embeddings,
            metadatas=metadatas
        )

        # Update in-memory documents list and BM25 index
        self.documents = docs
        self._tokenized_corpus = [doc["content"].lower().split() for doc in docs]
        if self._tokenized_corpus:
            self.bm25 = BM25Okapi(self._tokenized_corpus)

    def dense_search(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """Perform dense vector search on ChromaDB."""
        if self.collection.count() == 0:
            return []

        query_emb = self._pseudo_embed(query)
        res = self.collection.query(
            query_embeddings=[query_emb],
            n_results=min(top_k, self.collection.count())
        )

        dense_docs = []
        if res and res.get("documents") and res["documents"][0]:
            for i in range(len(res["documents"][0])):
                doc_id = res["ids"][0][i]
                content = res["documents"][0][i]
                meta = res["metadatas"][0][i] if res.get("metadatas") else {}
                dense_docs.append({"id": doc_id, "content": content, "metadata": meta})
        return dense_docs

    def sparse_search(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """Perform sparse BM25 keyword search."""
        if not self.bm25 or not self.documents:
            return []

        tokenized_query = query.lower().split()
        scores = self.bm25.get_scores(tokenized_query)
        
        # Pair documents with scores
        doc_scores = list(zip(self.documents, scores))
        doc_scores.sort(key=lambda x: x[1], reverse=True)
        
        sparse_docs = [doc for doc, score in doc_scores[:top_k] if score > 0.0]
        if not sparse_docs and self.documents:
            # Fallback if score is 0 across all
            sparse_docs = self.documents[:top_k]
        return sparse_docs

    def reciprocal_rank_fusion(
        self,
        dense_results: List[Dict[str, Any]],
        sparse_results: List[Dict[str, Any]],
        k: int = 60,
        top_k: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Merges dense and sparse search results using Reciprocal Rank Fusion (RRF).
        RRF Score(d) = sum( 1 / (k + rank(d)) )
        """
        rrf_scores: Dict[str, float] = {}
        doc_map: Dict[str, Dict[str, Any]] = {}

        # Process dense results
        for rank, doc in enumerate(dense_results, start=1):
            doc_id = doc["id"]
            doc_map[doc_id] = doc
            rrf_scores[doc_id] = rrf_scores.get(doc_id, 0.0) + (1.0 / (k + rank))

        # Process sparse results
        for rank, doc in enumerate(sparse_results, start=1):
            doc_id = doc["id"]
            doc_map[doc_id] = doc
            rrf_scores[doc_id] = rrf_scores.get(doc_id, 0.0) + (1.0 / (k + rank))

        # Sort documents by total RRF score descending
        sorted_doc_ids = sorted(rrf_scores.keys(), key=lambda x: rrf_scores[x], reverse=True)
        
        fused_docs = []
        for doc_id in sorted_doc_ids[:top_k]:
            doc = doc_map[doc_id].copy()
            doc["rrf_score"] = rrf_scores[doc_id]
            fused_docs.append(doc)
            
        return fused_docs

    def hybrid_search(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """Retrieve documents using combined Hybrid Search (Dense + Sparse + RRF)."""
        dense_res = self.dense_search(query, top_k=top_k)
        sparse_res = self.sparse_search(query, top_k=top_k)
        return self.reciprocal_rank_fusion(dense_res, sparse_res, k=60, top_k=top_k)
