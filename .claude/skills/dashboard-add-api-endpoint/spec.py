"""Print the contract of backend endpoints from the live Ianua OpenAPI spec.

Usage: python -I spec.py <path-substring> [<path-substring> ...]
Example: python -I spec.py webhooks

Fetches the Scalar reference page, extracts the embedded OpenAPI JSON, and for
every path containing a substring prints each method with its parameters,
request body and responses, with $ref schemas resolved inline.

Reads the hosted API by default. Set IANUA_API_SPEC_URL to another backend's
reference page (for example a local one) to read its spec instead.
"""

import json
import os
import re
import sys
import urllib.request

URL = os.environ.get("IANUA_API_SPEC_URL", "https://api.ianua.io/api/v1/reference")
METHODS = ("get", "post", "put", "patch", "delete")


def load_spec():
    # The host answers 403 to Python's default user agent.
    request = urllib.request.Request(URL, headers={"User-Agent": "curl/8.0"})
    with urllib.request.urlopen(request, timeout=60) as response:
        html = response.read().decode("utf-8")
    match = re.search(r'<script\s+id="api-reference"[^>]*>(.*?)</script>', html, re.S)
    if not match:
        sys.exit("Spec not found in the reference page. Check " + URL)
    return json.loads(match.group(1))


def resolve(node, spec, depth=0):
    """Inline $ref schemas, with a depth cap so recursive types terminate."""
    if isinstance(node, dict):
        if "$ref" in node:
            name = node["$ref"].split("/")[-1]
            if depth > 6:
                return "<" + name + ">"
            target = spec
            for part in node["$ref"].lstrip("#/").split("/"):
                target = target[part]
            return {"$schema": name, **resolve(target, spec, depth + 1)}
        return {key: resolve(value, spec, depth) for key, value in node.items()}
    if isinstance(node, list):
        return [resolve(item, spec, depth) for item in node]
    return node


def main():
    needles = [arg.lower() for arg in sys.argv[1:]]
    if not needles:
        sys.exit(__doc__)
    spec = load_spec()
    found = False
    for path, item in spec["paths"].items():
        if not any(needle in path.lower() for needle in needles):
            continue
        for method in METHODS:
            operation = item.get(method)
            if not operation:
                continue
            found = True
            params = [resolve(p, spec) for p in operation.get("parameters", [])]
            print("=" * 78)
            print(method.upper(), path)
            print("summary:", operation.get("summary"))
            print("params:", json.dumps(params, indent=1))
            body = operation.get("requestBody")
            if body:
                print("request:", json.dumps(resolve(body, spec), indent=1))
            # Error bodies share one envelope (see the API introduction), so only
            # success responses are expanded.
            responses = {
                code: resolve(value, spec) if code.startswith("2") else value.get("description")
                for code, value in operation.get("responses", {}).items()
            }
            print("responses:", json.dumps(responses, indent=1))
    if not found:
        sys.exit("No path contains: " + ", ".join(needles))


if __name__ == "__main__":
    main()
