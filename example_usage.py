import sys, json
from client import DocumentRedactionPiiScrubber

def main():
    print("Testing DocumentRedactionPiiScrubber...")
    scrubber = DocumentRedactionPiiScrubber()
    res = scrubber.run_benchmark_pii_scrubbing()
    print(json.dumps(res, indent=2))
    assert res["benchmark_status"] == "PASSED"
    assert res["mask_redactions_total"] >= 5
    assert res["unmask_integrity_verified"] is True
    print("All Document Redaction PII Scrubber tests passed successfully!")

if __name__ == "__main__":
    main()
