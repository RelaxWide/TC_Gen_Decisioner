import argparse

from log_judge.ingest.pulsefz_ingestor import ingest_pulsefz
from log_judge.ingest.qst_ingestor import ingest_qst

SOURCES = ("qst", "pulsefz")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", choices=SOURCES + ("all",), default="all")
    parser.add_argument("--force", action="store_true", help="re-ingest already-processed log files")
    args = parser.parse_args()

    sources = SOURCES if args.source == "all" else (args.source,)
    if "qst" in sources:
        results = ingest_qst(force=args.force)
        print(f"qst: {len(results)} failure context(s) ingested")
    if "pulsefz" in sources:
        results = ingest_pulsefz(force=args.force)
        print(f"pulsefz: {len(results)} failure context(s) ingested")


if __name__ == "__main__":
    main()
