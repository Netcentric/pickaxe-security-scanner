## Supported Features

| Feature    | Status |
|---------|-------------|
| Category based loading of checks | done |
| Multiple targets within the same domain | done |
| Extended Reporting: simple HTML | done |
| Script binding for dsl and model packages to avoid imports and HttpSecurityCheck.create terminology. | done | 
| Build in authentication (Basic auth for a scan (done for non preemptive basic auth)) | done | 
| Include of custom scans through the maven plugin  | done |
| Extended builtin checks: module dispatcher checks | done |
| Extended builtin checks: module user checks  | done |
| Extended builtin checks: module authentication bypass checks  | done |
| Extended builtin checks: module SSRF checks  | done |
| Extended builtin checks: module UGC write access checks | done |
| Extended builtin checks: UGC write access checks  | done |
| Persistence for authentication credentials, cookies etc for a test cycle (done via cookie jar)  | done |
| Test suite cache for credentials and headers  | done |
| Detection methods for headers  | done |
| Chained tests  | done |
| Reporting of executed tests  | done |
| Async multi threaded http client with throttling support to allow faster scans  | done |
| Chained tests | done |
| Reporting of executed tests  | done |


## Work Backlog

| Feature    | Type |
|---------|-------------|
| Extended examples module | General |
| More Documentation on project customizations | General|
| Customizable HTML reports, Jira, Email | Reporting |
| Stronger support for YAMl based multistep checks |Config|
| Easy  commandline runner (e.g. using a containerized version) |General|
| Build in form based authentication on a per scan level | Authentication |
| Login token support | Authentication |
| Differentiate between author and publish checks | Scan Engine |
| Detection methods for the raw response | Scan Engine |
| Detection methods for mimetype | Scan Engine |
| Detection methods for redirects | Scan Engine |
| Kill pill to stop a check after the first detected issue | Scan Engine |
| Following the redirect | Scan Engine |
| Network test suite to probe the LB and the actual hardening of the AEM server infrastructure | Scan Engine (potentially just go for Google Tsunami) |

