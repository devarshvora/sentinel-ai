import json

from backend.investigation.vision import analyze_screenshot


def main() -> None:
    result = analyze_screenshot(
        "uploads/test_scam.png"
    )

    print(json.dumps(result, indent=2, ensure_ascii=True))


if __name__ == "__main__":
    main()