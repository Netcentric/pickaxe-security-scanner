def cl = {
    name "CRX Test"

    vulnerability {
        name "Information Disclosure"
        description "CRX should not be accessible"
        remediation "Block CRX access through AEM dispatcher rules."
        cve ""
        severity Severity.HIGH
    }

    paths { '/crx/de' }
    paths {
        ['/crx/de/index.jsp']
    }

    extensions {
        ['.json']
    }
    method "GET"
    detect {
        isStatusCode 200
        bodyContains "CRX", "Explorer"
    }
}
cl