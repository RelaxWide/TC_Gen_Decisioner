import unittest

from shared.rag_client import generate_rag_response
from shared.spec_chunks import load_chunks, search_chunks


class TestRagClient(unittest.TestCase):
    def test_real_index_loads(self):
        chunks = load_chunks()
        self.assertGreater(len(chunks), 500)  # 969 real chunks as of the checked-in index

    def test_command_name_query_scores_higher_than_bare_hex(self):
        # Measured against the real index: a bare opcode scores ~2, a command
        # name scores ~20+. If this regresses, judge.py's RAG grounding goes
        # back to being nearly useless for QST/PULSEFZ failures.
        named = search_chunks("Dataset Management command timeout behavior", top_k=3)
        bare = search_chunks("NVMe opcode 0x09 expected behavior on timeout/error", top_k=3)
        self.assertGreater(named[0]["score"], 15)
        self.assertLess(bare[0]["score"] if bare else 0, named[0]["score"])

    def test_doc_filter_matches_real_chunk_titles(self):
        # The seed index's spec_doc strings must be substrings of the real
        # "NVM-Express-..." titles, or doc_filter silently returns nothing.
        results = search_chunks("Dataset Management", top_k=5,
                                 doc_filter=["NVM-Express-NVM-Command-Set-Specification"])
        self.assertGreater(len(results), 0)
        for r in results:
            self.assertIn("NVM-Express-NVM-Command-Set-Specification", r["doc"])

    def test_generate_rag_response_is_not_dummy(self):
        r = generate_rag_response("Identify command", top_k=2)
        self.assertFalse(r["is_dummy"])
        self.assertTrue(all(c["chunk_id"] for c in r["chunks"]))


if __name__ == "__main__":
    unittest.main()
