"""Protected-base PR change guard. Must execute only from protected master, never PR code.

This is a read-only policy oracle with narrowly bounded GitHub REST requests;
it is NOT itself a Sigstore/Host/CAS or independent Check publisher.
"""
import json
import os
import re
import sys
import urllib.error
import urllib.request

REPO = "olivesoup/jm-gate-witness"
SHA = re.compile(r"^[0-9a-f]{40}$")
MAX_FILES = 300
ALLOWED = re.compile(r"^(?:README\.md|public-notes/[A-Za-z0-9_.-]+\.md)$")


class Blocked(RuntimeError):
    pass


def validate_identifiers(pr, head, base):
    if type(pr) is not int or not 1 <= pr <= 2147483647:
        raise Blocked("BAD_PR_NUMBER")
    if not all(type(v) is str and SHA.fullmatch(v) for v in (head, base)):
        raise Blocked("BAD_EXACT_SHA")


def assess(pr_metadata, files, *, pr, head, base):
    """Pure deterministic fail-closed classifier. No PR text is ever executed."""
    validate_identifiers(pr, head, base)
    if type(pr_metadata) is not dict or type(files) is not list:
        raise Blocked("INVALID_REST_PAYLOAD")
    if (pr_metadata.get("number") != pr or
            pr_metadata.get("state") != "open" or
            type(pr_metadata.get("head")) is not dict or
            type(pr_metadata.get("base")) is not dict):
        raise Blocked("PR_IDENTITY_OR_STATE")
    phead = pr_metadata["head"]
    pbase = pr_metadata["base"]
    if (phead.get("sha") != head or pbase.get("sha") != base or
            pbase.get("ref") != "master" or
            type(phead.get("repo")) is not dict or
            phead["repo"].get("full_name") != REPO or
            type(pbase.get("repo")) is not dict or
            pbase["repo"].get("full_name") != REPO):
        raise Blocked("REPO_REF_EXACT_HEAD_BASE_MISMATCH")
    count = pr_metadata.get("changed_files")
    if type(count) is not int or not 1 <= count <= MAX_FILES:
        raise Blocked("PR_CHANGED_FILE_COUNT")
    if len(files) != count:
        raise Blocked("PAGINATION_OR_FILE_COUNT_INCOMPLETE")
    paths = set()
    for f in files:
        if type(f) is not dict or type(f.get("filename")) is not str:
            raise Blocked("FILE_METADATA_INVALID")
        name = f["filename"]
        if (not name or len(name) > 255 or
                name.startswith("/") or ".." in name or "\\" in name or
                not ALLOWED.fullmatch(name)):
            raise Blocked("PROTECTED_PATH_OR_UNLISTED_CHANGE")
        if name in paths:
            raise Blocked("DUPLICATE_FILE")
        paths.add(name)
        if f.get("status") not in ("added", "modified"):
            raise Blocked("UNTRUSTED_FILE_CHANGE_TYPE")
        if "previous_filename" in f:
            raise Blocked("RENAME_NOT_ALLOWED")
    return "PROTECTED_MASTER_ORACLE_SOURCE_POLICY_PASS_NOT_HOST_GATE"


def _api(path, token):
    req = urllib.request.Request(
        "https://api.github.com/repos/" + REPO + path,
        method="GET",
        headers={"Accept": "application/vnd.github+json",
                 "Authorization": "Bearer " + token,
                 "X-GitHub-Api-Version": "2022-11-28",
                 "User-Agent": "jm-witness-protected-oracle"})
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            if response.status != 200:
                raise Blocked("GITHUB_RESPONSE_NON200")
            raw = response.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise Blocked("GITHUB_RESPONSE_OVERSIZE")
            return json.loads(raw)
    except (urllib.error.URLError, ValueError, OSError) as exc:
        # Do not leak token, URL, or user-supplied PR text.
        raise Blocked("GITHUB_API_UNAVAILABLE_OR_MALFORMED") from exc


def main():
    if os.environ.get("GITHUB_REPOSITORY") != REPO or (
            os.environ.get("GITHUB_EVENT_NAME") != "pull_request_target"):
        raise Blocked("UNTRUSTED_WORKFLOW_CONTEXT")
    token = os.environ.get("GITHUB_TOKEN", "")
    if len(token) < 20:
        raise Blocked("GITHUB_READ_ONLY_TOKEN_MISSING")
    pr_s = os.environ.get("EXPECTED_PR", "")
    if not pr_s.isdecimal() or len(pr_s) > 10:
        raise Blocked("PR_NUMBER_INVALID")
    pr = int(pr_s)
    head = os.environ.get("EXPECTED_HEAD", "")
    base = os.environ.get("EXPECTED_BASE", "")
    validate_identifiers(pr, head, base)
    meta = _api("/pulls/" + str(pr), token)
    if type(meta) is not dict or type(meta.get("changed_files")) is not int:
        raise Blocked("CHANGED_FILE_COUNT_MISSING")
    count = meta["changed_files"]
    if not 1 <= count <= MAX_FILES:
        raise Blocked("CHANGED_FILE_COUNT_OUT_OF_BOUNDS")
    files = []
    # Check every page; do not trust an unverified single-page partial list.
    for page in range(1, (count + 99) // 100 + 1):
        chunk = _api("/pulls/" + str(pr) + "/files?per_page=100&page=" + str(page), token)
        if type(chunk) is not list or not (1 <= len(chunk) <= 100):
            raise Blocked("FILE_PAGE_INVALID")
        files.extend(chunk)
    verdict = assess(meta, files, pr=pr, head=head, base=base)
    print(verdict)
    print("JM_WITNESS_REAL_HOST_GATE=BLOCK_NOT_ATTESTED")


if __name__ == "__main__":
    try:
        main()
    except Blocked as exc:
        print("PROTECTED_ORACLE_DENIED_" + str(exc), file=sys.stderr)
        raise SystemExit(2)
