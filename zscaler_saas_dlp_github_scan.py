#!/usr/bin/env python3
"""
Zscaler SaaS Security API - GitHub DLP File Scan Sample
========================================================
Uses the Zscaler SaaS Security API (formerly CASB) to trigger a DLP scan
on a file hosted in a GitHub repository.

API Reference:
  https://help.zscaler.com/zia/saas-security-api

Dummy credentials are used — replace with real values before use.
"""

import requests
import json
import time

# ---------------------------------------------------------------------------
# Configuration (replace with real values)
# ---------------------------------------------------------------------------

ZSCALER_BASE_URL   = "https://zsapi.zscaler.net/api/v1"   # Change tenant hostname
ZSCALER_API_KEY    = "DUMMY_ZSCALER_API_KEY_1234567890"    # ZIA API Key
ZSCALER_USERNAME   = "admin@example.com"                   # ZIA Admin username
ZSCALER_PASSWORD   = "DummyP@ssw0rd!"                      # ZIA Admin password

GITHUB_TOKEN       = "ghp_DUMMY_GITHUB_TOKEN_ABCDEFGHIJ"   # GitHub PAT
GITHUB_OWNER       = "your-org"                            # GitHub org or user
GITHUB_REPO        = "your-repo"                           # GitHub repository name
GITHUB_FILE_PATH   = "docs/sample_pii.txt"                 # Path to file in repo
GITHUB_BRANCH      = "main"                                # Branch name


# ---------------------------------------------------------------------------
# Step 1: Authenticate to Zscaler and obtain a session cookie
# ---------------------------------------------------------------------------

def zscaler_login(base_url: str, username: str, password: str, api_key: str) -> requests.Session:
    """
    Authenticate against the Zscaler API.
    Returns an authenticated requests.Session.

    The Zscaler API uses an obfuscated key + timestamp for authentication.
    Reference: https://help.zscaler.com/zia/getting-started-zia-api
    """
    session = requests.Session()

    # Build obfuscated API key
    timestamp = str(int(time.time() * 1000))
    obfuscated_key = _obfuscate_api_key(api_key, timestamp)

    payload = {
        "username": username,
        "password": password,
        "apiKey":   obfuscated_key,
        "timestamp": timestamp,
    }

    url = f"{base_url}/authenticatedSession"
    resp = session.post(url, json=payload, headers={"Content-Type": "application/json"})
    resp.raise_for_status()

    print(f"[+] Authenticated to Zscaler as {username}")
    return session


def _obfuscate_api_key(api_key: str, timestamp: str) -> str:
    """Zscaler API key obfuscation as documented in the ZIA API guide."""
    high = timestamp[-6:]
    low  = str(int(high) >> 1)
    low  = low.zfill(6)

    obfuscated = ""
    for i, c in enumerate(high):
        obfuscated += api_key[int(c)]
    for i, c in enumerate(low):
        obfuscated += api_key[int(c) + 2]

    return obfuscated


# ---------------------------------------------------------------------------
# Step 2: Fetch the target file from GitHub
# ---------------------------------------------------------------------------

def fetch_github_file(owner: str, repo: str, file_path: str,
                      branch: str, github_token: str) -> dict:
    """
    Retrieve file metadata and raw content from GitHub via the REST API.
    Returns a dict with keys: name, path, size, download_url, content_b64
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{file_path}"
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    params = {"ref": branch}

    resp = requests.get(url, headers=headers, params=params)
    resp.raise_for_status()
    data = resp.json()

    print(f"[+] Fetched file from GitHub: {data['path']} ({data['size']} bytes)")
    return data


# ---------------------------------------------------------------------------
# Step 3: Submit the file to Zscaler SaaS Security for DLP scan
# ---------------------------------------------------------------------------

def submit_dlp_scan(session: requests.Session, base_url: str,
                    file_info: dict) -> dict:
    """
    Submit a file URL to the Zscaler SaaS Security API for DLP scanning.

    Endpoint: POST /saasSecurityApi/scanFile
    Body fields:
      - fileUrl      : Publicly accessible (or token-auth) download URL of the file
      - fileName     : Original filename
      - fileSize     : Size in bytes
      - scanType     : "CLOUD_APP" for SaaS/CASB context
      - cloudApp     : "GITHUB" — identifies the cloud application
      - ruleName     : (optional) specific DLP rule to evaluate against

    NOTE: The actual Zscaler SaaS Security API endpoint path and payload schema
          may differ based on your tenant version.  Adjust accordingly.
    """
    url = f"{base_url}/saasSecurityApi/scanFile"

    payload = {
        "fileUrl":   file_info["download_url"],
        "fileName":  file_info["name"],
        "fileSize":  file_info["size"],
        "scanType":  "CLOUD_APP",
        "cloudApp":  "GITHUB",
        # Optional: specify a DLP rule name, e.g. "PII - Japan My Number"
        # "ruleName": "PII - Japan My Number",
    }

    headers = {"Content-Type": "application/json"}
    resp = session.post(url, json=payload, headers=headers)
    resp.raise_for_status()

    result = resp.json()
    print(f"[+] DLP scan submitted. Response: {json.dumps(result, indent=2)}")
    return result


# ---------------------------------------------------------------------------
# Step 4: Poll for scan result (if async)
# ---------------------------------------------------------------------------

def poll_scan_result(session: requests.Session, base_url: str,
                     scan_id: str, max_retries: int = 10, interval: int = 5) -> dict:
    """
    Poll the scan status endpoint until the result is available.
    Endpoint: GET /saasSecurityApi/scanFile/{scanId}
    """
    url = f"{base_url}/saasSecurityApi/scanFile/{scan_id}"

    for attempt in range(1, max_retries + 1):
        resp = session.get(url)
        resp.raise_for_status()
        result = resp.json()

        status = result.get("status", "UNKNOWN")
        print(f"[{attempt}/{max_retries}] Scan status: {status}")

        if status in ("COMPLETED", "FAILED", "ERROR"):
            return result

        time.sleep(interval)

    raise TimeoutError(f"Scan {scan_id} did not complete within {max_retries * interval}s")


# ---------------------------------------------------------------------------
# Step 5: Parse and display DLP findings
# ---------------------------------------------------------------------------

def display_findings(scan_result: dict) -> None:
    """Pretty-print DLP scan findings."""
    print("\n" + "=" * 60)
    print("  ZSCALER DLP SCAN RESULT")
    print("=" * 60)

    status   = scan_result.get("status", "N/A")
    findings = scan_result.get("dlpMatches", [])

    print(f"  Status       : {status}")
    print(f"  Total matches: {len(findings)}")
    print("-" * 60)

    if not findings:
        print("  No DLP violations detected.")
    else:
        for i, match in enumerate(findings, start=1):
            print(f"\n  [{i}] Rule       : {match.get('ruleName', 'N/A')}")
            print(f"      Dictionary  : {match.get('dictionaryName', 'N/A')}")
            print(f"      Severity    : {match.get('severity', 'N/A')}")
            print(f"      Match count : {match.get('matchCount', 'N/A')}")
            # Redact actual matched content for safety
            print(f"      Matched text: *** (redacted) ***")

    print("=" * 60 + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("Zscaler SaaS DLP – GitHub File Scan Demo")
    print("-" * 45)

    # 1. Authenticate
    session = zscaler_login(
        ZSCALER_BASE_URL, ZSCALER_USERNAME, ZSCALER_PASSWORD, ZSCALER_API_KEY
    )

    # 2. Fetch file info from GitHub
    file_info = fetch_github_file(
        GITHUB_OWNER, GITHUB_REPO, GITHUB_FILE_PATH, GITHUB_BRANCH, GITHUB_TOKEN
    )

    # 3. Submit for DLP scan
    scan_response = submit_dlp_scan(session, ZSCALER_BASE_URL, file_info)

    # 4. Handle sync vs async response
    scan_id = scan_response.get("scanId")
    if scan_id:
        # Asynchronous: poll for result
        print(f"[+] Async scan started (ID: {scan_id}). Polling for result...")
        scan_result = poll_scan_result(session, ZSCALER_BASE_URL, scan_id)
    else:
        # Synchronous: result is inline
        scan_result = scan_response

    # 5. Display findings
    display_findings(scan_result)


if __name__ == "__main__":
    main()
