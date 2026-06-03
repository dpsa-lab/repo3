#!/usr/bin/env python3
"""
Zscaler SaaS Security API - GitHub DLP File Scan Sample
========================================================
Demonstrates DLP detection of AWS Access Key IDs embedded in GitHub files.

AWS Access Key ID regex pattern used by Zscaler DLP:
  \b(AKIA|ASIA|AIDA|AROA|AGPA|A3T[A-Z0-9])([A-Z0-9]{16})\b

Prefix meanings:
  AKIA  – Long-term IAM user access key
  ASIA  – Temporary STS session key
  AIDA  – IAM user/role ID (not a key, but detectable)
  AROA  – IAM role ID
  AGPA  – IAM group ID
  A3Tx  – AWS internal / service-specific key

Dummy credentials are used — replace with real values before use.
"""

import re
import json
import time
import base64
import requests

# ---------------------------------------------------------------------------
# Configuration (replace with real values)
# ---------------------------------------------------------------------------

ZSCALER_BASE_URL = "https://zsapi.zscaler.net/api/v1"   # Change tenant hostname
ZSCALER_API_KEY  = "DUMMY_ZSCALER_API_KEY_1234567890"    # ZIA API Key
ZSCALER_USERNAME = "admin@example.com"                   # ZIA Admin username
ZSCALER_PASSWORD = "DummyP@ssw0rd!"                      # ZIA Admin password

GITHUB_TOKEN     = "ghp_DUMMY_GITHUB_TOKEN_ABCDEFGHIJ"  # GitHub Personal Access Token
GITHUB_OWNER     = "your-org"                            # GitHub org or user
GITHUB_REPO      = "your-repo"                           # Repository name
GITHUB_FILE_PATH = "config/aws_credentials.txt"         # File path in repo
GITHUB_BRANCH    = "main"

# ---------------------------------------------------------------------------
# AWS Access Key ID regex  (same pattern registered in Zscaler DLP dictionary)
# ---------------------------------------------------------------------------

AWS_KEY_PATTERN = re.compile(
    r'\b(AKIA|ASIA|AIDA|AROA|AGPA|A3T[A-Z0-9])([A-Z0-9]{16})\b'
)

# Dummy keys — each matches the regex above and represents one key-type variant
DUMMY_AWS_KEYS = {
    "AKIA (Long-term IAM key)":       "AKIAIOSFODNN7EXAMPLE",
    "ASIA (STS temporary key)":       "ASIAIOSFODNN7EXAMPLE",
    "AIDA (IAM user/role ID)":        "AIDAIOSFODNN7EXAMPLE",
    "AROA (IAM role ID)":             "AROAIOSFODNN7EXAMPLE",
    "AGPA (IAM group ID)":            "AGPAIOSFODNN7EXAMPLE",
    "A3T0 (Service-specific key)":    "A3T0IOSFODNN7EXAMPLE",
}

# ---------------------------------------------------------------------------
# Step 0: Local pre-scan — validate dummy keys against the regex
# ---------------------------------------------------------------------------

def local_prescan() -> None:
    """
    Validate that all dummy keys match the Zscaler DLP regex before sending
    to the API.  Useful for testing custom dictionary patterns offline.
    """
    print("\n[Pre-scan] Validating dummy AWS keys against regex pattern...")
    print(f"  Pattern: {AWS_KEY_PATTERN.pattern}\n")

    all_pass = True
    for label, key in DUMMY_AWS_KEYS.items():
        m = AWS_KEY_PATTERN.search(key)
        status = "✓ MATCH" if m else "✗ NO MATCH"
        if not m:
            all_pass = False
        print(f"  {status}  {key}  ({label})")

    if all_pass:
        print("\n  [+] All dummy keys match the regex — safe to submit to Zscaler.\n")
    else:
        print("\n  [!] Some keys did NOT match. Review the pattern.\n")


# ---------------------------------------------------------------------------
# Step 1: Authenticate to Zscaler
# ---------------------------------------------------------------------------

def zscaler_login(base_url: str, username: str, password: str, api_key: str) -> requests.Session:
    """
    Authenticate against the Zscaler ZIA API.
    Returns an authenticated requests.Session with the JSESSIONID cookie set.

    Reference: https://help.zscaler.com/zia/getting-started-zia-api
    """
    session = requests.Session()
    timestamp = str(int(time.time() * 1000))
    obfuscated_key = _obfuscate_api_key(api_key, timestamp)

    payload = {
        "username":  username,
        "password":  password,
        "apiKey":    obfuscated_key,
        "timestamp": timestamp,
    }

    url = f"{base_url}/authenticatedSession"
    resp = session.post(url, json=payload, headers={"Content-Type": "application/json"})
    resp.raise_for_status()

    print(f"[+] Authenticated to Zscaler as {username}")
    return session


def _obfuscate_api_key(api_key: str, timestamp: str) -> str:
    """Zscaler API key obfuscation per the ZIA API guide."""
    high = timestamp[-6:]
    low  = str(int(high) >> 1).zfill(6)
    return "".join(api_key[int(c)] for c in high) + \
           "".join(api_key[int(c) + 2] for c in low)


# ---------------------------------------------------------------------------
# Step 2: Fetch file from GitHub
# ---------------------------------------------------------------------------

def fetch_github_file(owner: str, repo: str, file_path: str,
                      branch: str, github_token: str) -> dict:
    """
    Retrieve file metadata and Base64-encoded content via the GitHub REST API.

    Returns a dict with: name, path, size, download_url, decoded_content
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{file_path}"
    headers = {
        "Authorization":        f"Bearer {github_token}",
        "Accept":               "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    resp = requests.get(url, headers=headers, params={"ref": branch})
    resp.raise_for_status()
    data = resp.json()

    # Decode inline Base64 content returned by the GitHub API
    data["decoded_content"] = base64.b64decode(data["content"]).decode("utf-8", errors="replace")

    print(f"[+] Fetched from GitHub: {data['path']}  ({data['size']} bytes)")
    return data


# ---------------------------------------------------------------------------
# Step 3: Local regex scan on file content (mirrors Zscaler DLP dictionary)
# ---------------------------------------------------------------------------

def local_regex_scan(content: str) -> list[dict]:
    """
    Scan file content with the same AWS key regex used in the Zscaler DLP
    custom dictionary.  Returns a list of match detail dicts.
    """
    matches = []
    for m in AWS_KEY_PATTERN.finditer(content):
        matches.append({
            "full_key":    m.group(0),
            "prefix":      m.group(1),
            "suffix":      m.group(2),
            "start_pos":   m.start(),
            "end_pos":     m.end(),
        })
    return matches


# ---------------------------------------------------------------------------
# Step 4: Submit file to Zscaler SaaS Security API for DLP scan
# ---------------------------------------------------------------------------

def submit_dlp_scan(session: requests.Session, base_url: str,
                    file_info: dict) -> dict:
    """
    POST the file's download URL to the Zscaler SaaS Security scan endpoint.

    Zscaler will independently fetch and inspect the file content using all
    configured DLP rules — including the AWS Access Key ID custom dictionary.

    NOTE: Endpoint path / payload schema may vary by tenant version.
    """
    url     = f"{base_url}/saasSecurityApi/scanFile"
    payload = {
        "fileUrl":   file_info["download_url"],
        "fileName":  file_info["name"],
        "fileSize":  file_info["size"],
        "scanType":  "CLOUD_APP",
        "cloudApp":  "GITHUB",
        # To restrict to AWS key detection only, uncomment:
        # "ruleName": "AWS Access Key ID",
    }

    resp = session.post(url, json=payload, headers={"Content-Type": "application/json"})
    resp.raise_for_status()

    result = resp.json()
    print(f"[+] Scan submitted.  Response: {json.dumps(result, indent=2)}")
    return result


# ---------------------------------------------------------------------------
# Step 5: Poll for async scan result
# ---------------------------------------------------------------------------

def poll_scan_result(session: requests.Session, base_url: str,
                     scan_id: str, max_retries: int = 10, interval: int = 5) -> dict:
    """Poll GET /saasSecurityApi/scanFile/{scanId} until scan is complete."""
    url = f"{base_url}/saasSecurityApi/scanFile/{scan_id}"

    for attempt in range(1, max_retries + 1):
        resp = session.get(url)
        resp.raise_for_status()
        result = resp.json()
        status = result.get("status", "UNKNOWN")

        print(f"  [{attempt}/{max_retries}] status={status}")
        if status in ("COMPLETED", "FAILED", "ERROR"):
            return result

        time.sleep(interval)

    raise TimeoutError(f"Scan {scan_id} did not complete within {max_retries * interval}s")


# ---------------------------------------------------------------------------
# Step 6: Display findings
# ---------------------------------------------------------------------------

def display_findings(scan_result: dict, local_matches: list[dict]) -> None:
    """Display both local regex hits and Zscaler API DLP findings."""
    print("\n" + "=" * 65)
    print("  ZSCALER DLP SCAN RESULT — AWS Access Key ID Detection")
    print("=" * 65)

    # --- Local regex results ---
    print(f"\n  [Local Regex]  Matches found: {len(local_matches)}")
    if local_matches:
        for i, m in enumerate(local_matches, 1):
            # Mask middle of key for safe display
            key    = m["full_key"]
            masked = key[:4] + "****" + key[-4:]
            print(f"    [{i}] {masked}  prefix={m['prefix']}  pos={m['start_pos']}-{m['end_pos']}")

    # --- Zscaler API results ---
    status   = scan_result.get("status", "N/A")
    findings = scan_result.get("dlpMatches", [])

    print(f"\n  [Zscaler API]  Status: {status}  |  Violations: {len(findings)}")
    print("-" * 65)

    if not findings:
        print("  No DLP violations reported by Zscaler API.")
    else:
        for i, match in enumerate(findings, 1):
            print(f"\n  [{i}] Rule        : {match.get('ruleName', 'N/A')}")
            print(f"      Dictionary  : {match.get('dictionaryName', 'N/A')}")
            print(f"      Severity    : {match.get('severity', 'N/A')}")
            print(f"      Match count : {match.get('matchCount', 'N/A')}")
            print(f"      Matched text: *** (redacted) ***")

    print("=" * 65 + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("Zscaler SaaS DLP – GitHub AWS Access Key Detection Demo")
    print("-" * 55)

    # 0. Local pre-scan: confirm dummy keys match the regex
    local_prescan()

    # 1. Authenticate to Zscaler
    session = zscaler_login(
        ZSCALER_BASE_URL, ZSCALER_USERNAME, ZSCALER_PASSWORD, ZSCALER_API_KEY
    )

    # 2. Fetch target file from GitHub
    file_info = fetch_github_file(
        GITHUB_OWNER, GITHUB_REPO, GITHUB_FILE_PATH, GITHUB_BRANCH, GITHUB_TOKEN
    )

    # 3. Local regex scan (mirrors Zscaler custom dictionary)
    print("[+] Running local regex scan on file content...")
    local_matches = local_regex_scan(file_info["decoded_content"])
    print(f"    Found {len(local_matches)} AWS key match(es) locally.")

    # 4. Submit to Zscaler SaaS Security API
    scan_response = submit_dlp_scan(session, ZSCALER_BASE_URL, file_info)

    # 5. Handle sync vs async response
    scan_id = scan_response.get("scanId")
    if scan_id:
        print(f"[+] Async scan started (ID: {scan_id}). Polling...")
        scan_result = poll_scan_result(session, ZSCALER_BASE_URL, scan_id)
    else:
        scan_result = scan_response

    # 6. Display combined findings
    display_findings(scan_result, local_matches)


if __name__ == "__main__":
    main()
