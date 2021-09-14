# Supported Attack Vectors

## Category: Broken Access Control

### Check: Anonymous write access is possible

| Property | Value |
|---------|-------------|
| ID    | nc-vZOwFwjN |
| Name    | Anonymous write access is possible |
| Severity    | HIGH |
| CVE    |  |
| Categories    | accesscontrol |

Checks wether PostServlet is exposed and anonymous write access is possible.
It is possible to post a stored XSS payload with the utilized user.

### Check: Default credentials allow to write to UGC

| Property | Value |
|---------|-------------|
| ID    | nc-ad2tyTdw |
| Name    | Default credentials allow to write to UGC |
| Severity    | HIGH |
| CVE    |  |
| Categories    | accesscontrol |

Checks wether PostServlet is exposed and write access with default credentials is possible.
It is possible to post a stored XSS payload with the utilized user.

### Check: PostServlet writes to DAM

| Property | Value |
|---------|-------------|
| ID    | nc-DnrZ3xas |
| Name    | PostServlet writes to DAM |
| Severity    | HIGH |
| CVE    |  |
| Categories    | accesscontrol |

Checks wether the PostServlet is exposed and writes to DAM without any additional credentials set.
It might be possible to use it for posting a stored XSS payload.

## Category: Broken Access Control

### Check: CRX DE is exposed

| Property | Value |
|---------|-------------|
| ID    | nc-crxJ17Jbp |
| Name    | CRX DE is exposed |
| Severity    | HIGH |
| CVE    |  |
| Categories    | crx, dispatcher |

Checks wether crx/de and related tools are exposed and can be reached from the outside world.
Checks for:
* /crx/de
* /crx/explorer
* /crx/packmgr

CRX and related tools e.g. package manager should not be accessible

### Check: CRX DE is exposed

| Property | Value |
|---------|-------------|
| ID    | nc-crxlogsJbp |
| Name    | CRX logs are exposed |
| Severity    | HIGH |
| CVE    |  |
| Categories    | crx, dispatcher |

Checks if CRX logs are accessible.

### Check: XXE via Webdav in Jackrabbit

| Property | Value |
|---------|-------------|
| ID    | nc-xxe324Jbp |
| Name    | XXE via Webdav in Jackrabbit |
| Severity    | HIGH |
| CVE    |  |
| Categories    | crx, dispatcher |

XML external entity (XXE) vulnerability in Apache Jackrabbit before 2.10.1 allows remote attackers
to read arbitrary files and send requests to intranet servers via a crafted WebDAV request.
This check verifies if POSTs to save /crx/repository/test.sh is possible.

## Category: Dispatcher Bypasses

### Check: Servlet Endpoint /bin exposed

| Property | Value |
|---------|-------------|
| ID    | nc-XjJ17Jbp |
| Name    | Servlet Endpoint /bin exposed |
| Severity    | HIGH |
| CVE    | CWE-200 |
| Categories    | dispatcher |

Checks if sensitive information via AEM's /bin servlet endpoint is exposed.

### Check: cqactions servlet exposed

| Property | Value |
|---------|-------------|
| ID    | nc-wMGJvmKd |
| Name    | cqactions servlet exposed |
| Severity    | HIGH |
| CVE    | CWE-749 |
| Categories    | dispatcher |

Checks if the CQActionsServlet is exposed and leaks information about access rights and the repository structure.

### Check: Dispatcher invalidation is unprotected

| Property | Value |
|---------|-------------|
| ID    | nc-disJ17inv |
| Name    | Dispatcher invalidation is unprotected |
| Severity    | HIGH |
| CVE    | CWE-749 |
| Categories    | dispatcher |

Dispatchers can be invalidated from an untrusted external system.
This would allow an attacker to render the caching layer completely useless and force the AEM publishing instances to handle all incoming load.

### Check: ExtTreeServlet is exposed

| Property | Value |
|---------|-------------|
| ID    | nc-etcJ17pac |
| Name    | ExtTreeServlet is exposed |
| Severity    | HIGH |
| CVE    | CWE-749 |
| Categories    | dispatcher |

Packages and related meta information under /etc/packages and other paths can be accessed and downloaded as the .ext. selector exposes the ExtTreeServlet.

... TODO ... add all other checks