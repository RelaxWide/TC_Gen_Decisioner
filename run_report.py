from report.aggregator import build_report_model
from report.html_report import write_report


def main():
    model = build_report_model()
    path = write_report(model)
    print(f"report written to {path}")


if __name__ == "__main__":
    main()
