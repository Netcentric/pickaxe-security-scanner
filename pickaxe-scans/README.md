# Pickaxe Scan Module 

Ths module provides the docker and CLI interface classes and 
packages everything with a set of pre-build security checks. See the supported attack vectors section.

# Commandline and Dockerinterface

See the following documentation chapters for details.

* [Run from Commandline](../documentation/run-with-cli.md)
* [Run via Docker](../documentation/run-with-docker.md)

# Supported Attack Vectors

The following security checks are included in the buildin package and executed with each scan run.
For the case you need to integrate custom checks e.g. 
to test a new security vulnerability or to cater with custom project requirements 
please read the [Pickaxe Custom Checks Documentation](../documentation/custom-checks.md)


| Property | Value |
|---------|-------------|
|ID           | nc-oK6X4NAp |
|Name         | XSS: Reflected XSS vulnerability caused by mimetype switch |
|Categories   | xss,dispatcher | 
|CVE          |  | 
|Description  | Reflected XSS vulnerability caused by mimetype switch when design is called with childlist selector. It reflects the requested payload in the suffix and makes it executable by rendering it as html instead of json. Mimetype switch happens in the dispatcher. | 
|Remediaton   | AEM's Dispatcher must be configured to block the .childlist. selector requests on the respective instance. Especially with .html extensions. | 


| Property | Value |
|---------|-------------|
|ID           | nc-d9XVxDQF |
|Name         | Potential RCE: Exposed Felix System Console |
|Categories   | dispatcher | 
|CVE          | CWE-749 | 
|Description  | The Felix login status servlet is exposed and can be used to bruteforce credentials.";" | 
|Remediaton   | Block the path through AEM dispatcher rules. Restrict access completly | 


| Property | Value |
|---------|-------------|
|ID           | nc-xgxxe4gH |
|Name         | XXE: XXE vulnerability in AEM Forms Guidance Servlet |
|Categories   | xxe,dispatcher | 
|CVE          |  | 
|Description  | GuideInternalSubmitServlet is exposed, XXE is possible. | 
|Remediaton   | Update AEM to the most recent version. Block access to the .af. selector if not explicitly needed for any AEM Forms use cases as it exposes a number of vulnerabilities. If really needed allow only for distinct paths and avoid restrict the ability to create create and edit nodes as it is possible to trigger the servlet by sling:resourceType |


| Property | Value |
|---------|-------------|
|ID           | nc-DnrZ3xas |
|Name         | Broken Access Control: PostServlet writes to DAM |
|Categories   | accesscontrol | 
|CVE          |  | 
|Description  | PostServlet is exposed. It might be possible to use it for posting a stored XSS payload. | 
|Remediaton   | Block POST operations with the dispatcher. Do not allow write access for anonymous users. | 


| Property | Value |
|---------|-------------|
|ID           | nc-XjJ15JKp |
|Name         | Information Disclosure: GQL Servlet exposed |
|Categories   | dispatcher | 
|CVE          | CWE-749 | 
|Description  | Sensitive information might be exposed via AEM\'s GQLServlet. Be aware that bypasses using image/* mimetype extensions e.g. *.ico may render in a browser as an image but if you rename the file with the ending *.txt you will see the output. | 
|Remediaton   | Block the path through AEM dispatcher rules. Restrict access completly. | 


| Property | Value |
|---------|-------------|
|ID           | nc-XNBpkC0s |
|Name         | Information Disclosure: AEM MsmAuditServlet exposed |
|Categories   | aem-misconfig,dispatcher | 
|CVE          | CWE-668 | 
|Description  | AuditServletDetector exposed and might expose audit log information. See https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps?slide=96 | 
|Remediaton   | Block to the audit servlet on publish through AEM dispatcher rules. |


| Property | Value |
|---------|-------------|
|ID           | nc-AVySnyIS |
|Name         | Information Disclosure: AEM WCMSuggestionsServlet exposed |
|Categories   | aem-misconfig,dispatcher | 
|CVE          | CWE-668 | 
|Description  | WCMSuggestionsServlet exposed and might result in reflected XSS. See - https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps?slide=96 | 
|Remediaton   |  Disable the debug servlet on production instances. Block to the debug servlet path on publish through AEM dispatcher rules. | 


| Property | Value |
|---------|-------------|
|ID           | nc-s55ibLtb |
|Name         | Information Disclosure: Querybuilder Exposed |
|Categories   | dispatcher | 
|CVE          | CWE-749 | 
|Description  | Sensitive information might be exposed via AEMs QueryBuilderServlet or QueryBuilderFeedServlet. Be aware that bypasses using image/* mimetype extensions e.g. *.ico may render in a browser as an image but if you rename the file with the ending *.txt you will see the querybuilder output | 
|Remediaton   | Block the path through AEM dispatcher rules. Restrict access completly. | 


| Property | Value |
|---------|-------------|
|ID           | nc-UniC7eLvR |
|Name         | Information Disclosure and Enumeration: AEM Unicode Dispatcher Bypass |
|Categories   | aem-misconfig,dispatcher | 
|CVE          |  | 
|Description  | Assess to pages with numeric selectors and e.g. json renderers should be blocked. Latin characters could be substituted for an equivalent number in another language, bypassing the dispatcher rule that only looks for Latin characters and allows content grabbing. | 
|Remediaton   | Allow only known sling selectors in latin languages. |


| Property | Value |
|---------|-------------|
|ID           | nc-etcJ17pac |
|Name         | Information Disclosure: ExtTreeServlet is exposed |
|Categories   | crx,dispatcher | 
|CVE          | CVE-2016-0957 | 
|Description  | Packages and related metainformation under /etc/packages and other paths can be accessed and downloaded as the .ext. selector exposes the ExtTreeServlet. | 
|Remediaton   | Block access through AEM dispatcher rules. Set permissions accordingly and prevent anonymous access. | 


| Property | Value |
|---------|-------------|
|ID           | nc-XjJ17Jbp |
|Name         | Information Disclosure: Servlet Endpoint /bin exposed |
|Categories   | dispatcher | 
|CVE          | CWE-200 | 
|Description  | Sensitive information might be exposed via AEM\'s /bin servlet endpoint.  | 
|Remediaton   | Block the path through AEM dispatcher rules. Restrict access completly. | 


| Property | Value |
|---------|-------------|
|ID           | nc-SSRFpkC0s |
|Name         | Server-Side Request Forgery: Potential Server-Side Request Forgery through Sales Force Servlet |
|Categories   | aem-misconfig,dispatcher,ssrf | 
|CVE          | CWE-918 | 
|Description  | An attacker could exploit this issue to target internal systems behind the firewall, or services running on the local server’s loopback network interface, which are typically inaccessible from the outside world. By using a Server-Side Request Forgery attacks it is possible to scan and attack systems on the internal network inside the perimeter firewall, enumerate and attack services that are running on these hosts and to bypass host-based authentication services if the vulnerable server is whitelisted. This check does only verify if the known endpoint could be accessed. |
|Remediaton   | Block access to the affected servlet on publish through AEM dispatcher rules or disable it completely. |


| Property | Value |
|---------|-------------|
|ID           | nc-crxJ17Jbp |
|Name         | Information Disclosure: CRX DE is exposed |
|Categories   | crx,dispatcher | 
|CVE          |  | 
|Description  | CRX and related tools e.g. package manager should not be accessible | 
|Remediaton   | Block CRX access through AEM dispatcher rules. | 


| Property | Value |
|---------|-------------|
|ID           | nc-uinfUpkCs |
|Name         | Credential Leakage: Userinfo Servlet is exposed |
|Categories   | aem-misconfig,dispatcher | 
|CVE          | CWE-200 | 
|Description  | It is possible to harvest valid usernames from jcr:createdBy, jcr:lastModifiedBy, cq:LastModifiedBy attributes of any JCR node which can be used to bruteforce into the system. | 
|Remediaton   | Block access to the affected servlet on publish through AEM dispatcher rules or disable it completely. | 


| Property | Value |
|---------|-------------|
|ID           | nc-uinfUpkCs |
|Name         | Information Leakage: AEM Reports exposed |
|Categories   | aem-misconfig,dispatcher | 
|CVE          | CWE-668 | 
|Description  | AEM report are exposed and can be called. Despite providing internal information report generation can be considered expensive. | 
|Remediaton   | Block access to the affected url on publish through AEM dispatcher rules or disable it completely. | 


| Property | Value |
|---------|-------------|
|ID           | nc-crxlogsJbp |
|Name         | Information Disclosure: CRX logs are exposed |
|Categories   | crx,dispatcher | 
|CVE          |  | 
|Description  | CRX logs should not be accessible | 
|Remediaton   | Block CRX logs access through AEM dispatcher rules. | 


| Property | Value |
|---------|-------------|
|ID           | nc-Ow67Lufxx |
|Name         | Denial of Service: Denial of Service possible through children enumeration selector |
|Categories   | dispatcher,dos | 
|CVE          | CWE-668 | 
|Description  | Calling any URL with the supplied pattern /......children.-1.... in combination with a a dispatcher bypass will cause an infinte traversal of the page tree starting from the actual entrypoint. Therefore it must be appended to an existing URL. | 
|Remediaton   | Block the pattern *.children.-{0-9}*. selector via WAF, proxy  or dispatcher rule and harden dispatcher against other bypasses. |


| Property | Value |
|---------|-------------|
|ID           | nc-xxe324Jbp |
|Name         | XXE: XXE via Webdav in Jackrabbit |
|Categories   | crx,webdav | 
|CVE          | CVE-2015-1833 | 
|Description  | XML external entity (XXE) vulnerability in Apache Jackrabbit before 2.10.1 allows remote attackers to read arbitrary files and send requests to intranet servers via a crafted WebDAV request.  | 
|Remediaton   | Disable webdav on the affected instance or install the respective fix. | 


| Property | Value |
|---------|-------------|
|ID           | nc-autoPXcd3 |
|Name         | Potential RCE: Server-Side Request Forgery through Autoprovisioning Servlet may lead to RCE |
|Categories   | aem-misconfig,rce,ssrf | 
|CVE          |  | 
|Description  | An SSRF in the autoprovisioning servlet can be used to smuggle in requests to the TopologyConnectorServlet and to silently add a fake malicious AEM node with active reverse replication which is initiated automatically. This would open the environment to RCE. | 
|Remediaton   | Block access to the affected servlet on publish through AEM dispatcher rules or disable it completely. | 


| Property | Value |
|---------|-------------|
|ID           | nc-thncam33x |
|Name         | Information Disclosure and Enumeration: AEM Communities selector and extensions are whitelisted to generously |
|Categories   |  | 
|CVE          |  | 
|Description  | The page is leaking information which is not supposed to be shared with the outside world. AEM's dispatcher must block access to any URL that leaks metadata. Please check the URL's manually. | 
|Remediaton   | Allow only known sling selectors and URL extensions based on on whitelist. |


| Property | Value |
|---------|-------------|
|ID           | nc-jyD3urmc |
|Name         | XSS: Reflected XSS vulnerability caused by mimetype switch and privilege parameter reflection |
|Categories   | xss,dispatcher | 
|CVE          |  | 
|Description  | Reflected XSS vulnerability caused by mimetype switch when design is called with permissions selector. It reflects the requested payload in the suffix and makes it executable by rendering it as html instead of json. Mimetype switch happens in the dispatcher. | 
|Remediaton   | AEM's Dispatcher must be configured to block the .permissions. selector requests on the respective instance. Especially with .html extensions. | 


| Property | Value |
|---------|-------------|
|ID           | nc-I56crx6W |
|Name         | XSS: Reflected XSS DAM metadata merge |
|Categories   | xss,crx | 
|CVE          |  | 
|Description  | Meta data merge dialog can be used to trigger a reflected XSS.
Provoking an error when calling the preferences dialog directly causes an XSS if the response does not return the application/json content type as a response header.
The response might then be interpreted as an html and the output encoding is rendered useless. |
|Remediaton   | Update AEM to the most recent version and make sure the content-type header is set correctly. |


| Property | Value |
|---------|-------------|
|ID           | nc-I56crx6W |
|Name         | XSS: Reflected XSS in crx setPreferences |
|Categories   | xss,crx | 
|CVE          |  | 
|Description  | Checks wether setPreferences in /crx/de is accessible and can be used to trigger a reflected XSS.
Provoking an error when calling the preferences dialog directly causes an XSS in the error page. |
|Remediaton   | Update AEM to the most recent version and use a custom error page for errors coming back from CRX | 


| Property | Value |
|---------|-------------|
|ID           | nc-QF6uCeYQ |
|Name         | Failure to Restrict URL Access: Exposed Felix Login Servlet |
|Categories   | dispatcher | 
|CVE          | CWE-749 | 
|Description  | The Felix console is exposed. It is an administrative backend which provides full access to the AEM installation and allows to install own code. It can be considered a potential Remote Code Execution vulnerabilty.";" | 
|Remediaton   | Block the path through AEM dispatcher rules. Restrict access completly | 


| Property | Value |
|---------|-------------|
|ID           | nc-OwJ7gLvR |
|Name         | Information Disclosure and Enumeration: Forms servlet url allows to read access protected resources in the repository tree |
|Categories   | dispatcher | 
|CVE          | CWE-668 | 
|Description  | The .form.pdf selector combination can be used to access and also traverse any path following it as an HTTP suffix. | 
|Remediaton   | Allow only known sling selectors and URL extensions based on on whitelist. | 


| Property | Value |
|---------|-------------|
|ID           | nc-curUpkC0s |
|Name         | Credential Leakage: CurrentUserServlet is exposed |
|Categories   | aem-misconfig,dispatcher | 
|CVE          | CWE-200 | 
|Description  | It is possible to harvest valid usernames from jcr:createdBy, jcr:lastModifiedBy, cq:LastModifiedBy attributes of any JCR node which can be used to bruteforce into the system. | 
|Remediaton   | Block access to the affected servlet on publish through AEM dispatcher rules or disable it completely. | 


| Property | Value |
|---------|-------------|
|ID           | nc-OYJ7eLvR |
|Name         | Information Disclosure and Enumeration: AEM default renderers exposed |
|Categories   | aem-misconfig,dispatcher | 
|CVE          | CWE-668 | 
|Description  | The page is leaking information which is not supposed to be shared with the outside world. AEM's dispatcher must block access to any URL that leaks metadata. Please check the URL's manually. | 
|Remediaton   | Allow only known sling selectors and URL extensions based on on whitelist. |


| Property | Value |
|---------|-------------|
|ID           | nc-xgqEM4gH |
|Name         | XSS: Reflected XSS vulnerabilities in AEM hosted SWFs |
|Categories   | xss,dispatcher | 
|CVE          | CWE-749 | 
|Description  | AEM provides a number of based SWF tools such as viewers that might be vulnerable. | 
|Remediaton   | AEM's Dispatcher must be configured to block the respective paths, to prevent them from beeing delivered. | 


| Property | Value |
|---------|-------------|
|ID           | nc-thfontm1cx |
|Name         | Information Disclosure and Enumeration: Font file extensions and suffixes are whitelisted to generously |
|Categories   | aem-misconfig, dispatcher| 
|CVE          |  | 
|Description  | The page is leaking information which is not supposed to be shared with the outside world. AEM's dispatcher must block access to any URL that leaks metadata. Please check the URL's manually. | 
|Remediaton   | Allow only known sling selectors and URL extensions based on on whitelist. |


| Property | Value |
|---------|-------------|
|ID           | nc-I43wlg6M |
|Name         | XSS: Reflected XSS on savedsearch selector error page |
|Categories   | xss,dispatcher | 
|CVE          |  | 
|Description  | Checks wether AEM saved search selector triggered error page reflects the path parameter into a link which is reflected XSS triggering on click in the context of the target website | 
|Remediaton   | Overwrite the actual error page and do not reflect any inputs in there. | 


| Property | Value |
|---------|-------------|
|ID           | nc-ad2tyTdw |
|Name         | Broken Access Control: Default credentials allow to write to UGC |
|Categories   | accesscontrol | 
|CVE          |  | 
|Description  | PostServlet is exposed and anonymous write access is possible. It might be possible to post a stored XSS payload resource with the utilized user. | 
|Remediaton   | Block POST operations with the dispatcher. Do not allow write access for anonymous users. | 


| Property | Value |
|---------|-------------|
|ID           | nc-wMGJvmKd |
|Name         | Potential Information leakage: cqactions servlet exposed |
|Categories   | dispatcher | 
|CVE          | CWE-749 | 
|Description  | The CQActionsServlet is exposed an allows to leak information about access rights and the repository structure. It can be used to bypass dispatcher filters for content grabbing. | 
|Remediaton   | Block the CQActionsServlet or disable it | 


| Property | Value |
|---------|-------------|
|ID           | nc-disJ17inv |
|Name         | Denial of Service: Dispatcher invalidation is unprotected |
|Categories   | crx,dispatcher | 
|CVE          |  | 
|Description  | Dispatchers can be invalidated from an untrusted external system. This would allow an attacker render the caching layer completely useless and force the AEM publishing instances to handle all incoming load. | 
|Remediaton   | Do not allow invalidation from any untrusted source. Block access to the URls and introduce authentication and/or IP whitelisting. | 


| Property | Value |
|---------|-------------|
|ID           | nc-vZOwFwjN |
|Name         | Broken Access Control: Anonymous write access is possible |
|Categories   | accesscontrol | 
|CVE          |  | 
|Description  | PostServlet is exposed and anonymous write access is possible. It might be possible to post a stored XSS payload resource with the utilized user. | 
|Remediaton   | Block POST operations with the dispatcher. Do not allow write access for anonymous users. | 


| Property | Value |
|---------|-------------|
|ID           | nc-opsoPXcd1 |
|Name         | SSRF: Server-Side Request Forgery via Opensocial (shindig) proxy |
|Categories   | aem-misconfig,dispatcher,ssrf | 
|CVE          |  | 
|Description  | An SSRf via the intrgated Opensocial (shindig) proxy which is supposed to host social apps. | 
|Remediaton   | Access to shindig proxy should be restricted e.g. via AEM dispatcher rules or disable it completely. | 


| Property | Value |
|---------|-------------|
|ID           | nc-rOU34Y8n |
|Name         | Information Disclosure: AEM WCMDebugFilter exposed |
|Categories   | aem-misconfig,dispatcher | 
|CVE          | CWE-668 | 
|Description  | Sensitive information might be exposed via AEM 's WCMDebugFilter. It will render a backend interface which provides additional attack surface and might be vulnerable to reflected XSS (CVE-2016-7882). See - https://medium.com/@jonathanbouman/reflected-xss-at-philips-com-e48bf8f9cd3c. Please check the URL's manually. | 
|Remediaton   |  Disable the debug filter on production instances. Block to the debug filter servlet on publish through AEM dispatcher rules. |


| Property | Value |
|---------|-------------|
|ID           | nc-Ow57Pirox |
|Name         | Path traversal vulnerability: Path traversal vulnerability in jetty path normalization |
|Categories   | dispatcher,jetty,traversal | 
|CVE          | CWE-668 | 
|Description  | Path traversal vulnerability due to a flaw in path normalization handling for HTTP Path parameters in Jetty which comes prepackaged with AEM and takes effect there. The token /..;/ a valid directory name in reverse proxies such as the dispatcher module while it means parent folder in jetty. Usually it requires another bypass to be effective. | 
|Remediaton   | Block the pattern /..;/ via WAF, proxy  or dispatcher rule and harden dispatcher against other bypasses. |


# How to build this module

Just run your maven build to build the executable jar as well as the docker container.

    mvn clean install