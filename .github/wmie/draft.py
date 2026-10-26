"""Report protocol errors to the running reviewer before native submission."""

import json
import sys

from core import GovernanceError, read_json
from review import validate_record


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 .github/wmie/draft.py MANIFEST_JSON DRAFT_RECORD_JSON", file=sys.stderr)
        return 2
    try:
        record = validate_record(read_json(sys.argv[2]), read_json(sys.argv[1]))
        print(json.dumps({"state": "accepted", "verdict": record["verdict"], "complete": record["complete"]}))
        return 0
    except GovernanceError as error:
        print(json.dumps({"state": "needs_correction", "code": error.code, "detail": error.detail,
                          "action": "Correct the reported references or missing paths, then validate the draft again."}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
