import argparse

from report.aggregator import build_log_model, build_tc_model
from report.html_report import write_log_report, write_tc_report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Regenerate the HTML reports.")
    parser.add_argument("--kind", choices=("logs", "tc", "all"), default="all",
                        help="logs: QST/PULSEFZ log judgment, tc: TC generation and spec coverage")
    args = parser.parse_args(argv)
    if args.kind in ("logs", "all"):
        print(f"log judgment report written to {write_log_report(build_log_model())}")
    if args.kind in ("tc", "all"):
        print(f"TC coverage report written to {write_tc_report(build_tc_model())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
