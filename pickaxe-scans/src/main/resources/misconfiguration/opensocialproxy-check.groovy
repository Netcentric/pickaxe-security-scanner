import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import biz.netcentric.security.checkerdsl.model.Severity
import biz.netcentric.security.checkerdsl.payload.Generator

HttpSecurityCheck.create {

    id "nc-opsoPXcd1"

    name "Server-Side Request Forgery via Opensocial (shindig) proxy"

    vulnerability {
        name "SSRF: ${name}"
        description """An SSRf via the intrgated Opensocial (shindig) proxy which is supposed to host social apps."""
        remediation "Access to shindig proxy should be restricted e.g. via AEM dispatcher rules or disable it completely."
        cve ""
        severity Severity.HIGH
    }

    categories "aem-misconfig", "dispatcher", "ssrf"

    steps([
            {
                name "GET to Opensocial (shindig) proxy is possible"

                paths {
                    ["/libs/opensocial/proxy",
                     "///libs///opensocial///proxy"]
                }

                def placeholder = "{0}"
                def cacheBuster = Generator.cacheBuster()
                def fileExtensions  = [
                        '', '.json', '.1.json', '.4.2.1...json', '.html',
                        '.{0}.css', '.{0}.js', '.{0}.png', '.{0}.ico', '.{0}.bmp', '.{0}.gif', '.{0}.html',
                        '/{0}.1.json', '/{0}.4.2.1...json', '/{0}.css', '/{0}.js', '/{0}.png', '/{0}.bmp', ';%0a{0}.css', ';%0a{0}.js',
                        ';%0a{0}.png', ';%0a{0}.html', ';%0a{0}.ico', ';%0a{0}.png', '/{0}.ico', './{0}.html']

                querystring "container=default&url=http://someunknownendpoint.com/"

                extensions {
                    fileExtensions.stream()
                            .map{ext ->
                                ext.replace(placeholder, cacheBuster)
                            }
                            .toList()
                }

                body "text/html", "UTF-8", { data }

                method "GET"
                detect {
                    all {
                        checkStatusCode 200
                    }

                    all {
                        checkStatusCode 302
                    }

                    all {
                        checkStatusCode 301
                    }
                }
            }
    ])
}