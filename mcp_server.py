import sys, json
from client import DocumentRedactionPiiScrubber

def main():
    scrubber = DocumentRedactionPiiScrubber()
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print(json.dumps(scrubber.run_benchmark_pii_scrubbing(), indent=2))
        return

    for line in sys.stdin:
        if not line.strip(): continue
        try:
            req = json.loads(line)
            method = req.get("method")
            params = req.get("params", {})
            rid = req.get("id")

            if method == "tools/list":
                res = {
                    "tools": [
                        {"name": "scrub_text", "description": "Mask or tokenize PII entities (SSN, credit card, email, phone, API keys)."},
                        {"name": "validate_luhn_checksum", "description": "Check if a numeric string is a valid credit card."},
                        {"name": "unmask_text", "description": "Revert tokenized text using the salt token map."},
                        {"name": "run_benchmark_pii_scrubbing", "description": "Run PII scrubbing and verification test suite."}
                    ]
                }
            elif method == "tools/call":
                tname = params.get("name")
                args = params.get("arguments", {})
                if tname == "scrub_text":
                    out = scrubber.scrub_text(args.get("text", ""), args.get("mode", "mask"), args.get("salt_secret", "alpha_salt_2026"))
                elif tname == "validate_luhn_checksum":
                    out = {"is_valid_luhn": scrubber.validate_luhn_checksum(args.get("number_str", ""))}
                elif tname == "unmask_text":
                    out = {"unmasked_text": scrubber.unmask_text(args.get("sanitized_text", ""), args.get("token_map", {}))}
                elif tname == "run_benchmark_pii_scrubbing":
                    out = scrubber.run_benchmark_pii_scrubbing()
                else:
                    out = {"error": f"Unknown tool {tname}"}
                res = {"content": [{"type": "text", "text": json.dumps(out)}]}
            else:
                res = {"error": "Unsupported method"}
            print(json.dumps({"jsonrpc": "2.0", "id": rid, "result": res}), flush=True)
        except Exception as e:
            print(json.dumps({"jsonrpc": "2.0", "error": {"code": -32603, "message": str(e)}}), flush=True)

if __name__ == "__main__":
    main()
