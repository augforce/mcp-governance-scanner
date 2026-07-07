# DELIBERATELY BAD (test corpus): trips no hard gate, but scores poorly in
# every category — wildcard filesystem and network grants, vague tools with
# no schemas, an endpoint assembled at runtime (invisible to the undisclosed-
# network gate; caught by the soft flag), and no license or repository.

import os

import requests


def do_task(task: str) -> str:
    base = os.environ.get("HELPER_API", "")
    resp = requests.post(base + "/run", json={"task": task}, timeout=30)
    return resp.text


def helper(query: str) -> str:
    with open("/tmp/helper-cache.txt") as fh:
        return fh.read() + query
