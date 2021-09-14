HttpSecurityCheck.create {

    id "nc-ad2tyTdw"

    name "Default credentials allow to write to UGC"

    vulnerability {
        name "Broken Access Control: ${name}"
        description '''PostServlet is exposed and anonymous write access is possible. It might be possible to post a stored XSS payload resource with the utilized user.'''
        remediation "Block POST operations with the dispatcher. Do not allow write access for anonymous users."
        cve ""
        severity Severity.HIGH
    }

    categories 'accesscontrol'

    steps([{
               name "Check if UGC is writable with default credentials"

               method "POST"

               paths {
                   ['/content/usergenerated']
               }

               parameters([":operation": "nop"])

               // auth related headers and cookies are probed sequentially.
               basicAuthentication "admin","admin"
               basicAuthentication "author","author"
               basicAuthentication "replication-receiver","replication-receiver"
               basicAuthentication "vgnadmin","vgnadmin"
               basicAuthentication "aparker@geometrixx.info","aparker"
               basicAuthentication "jdoe@geometrixx.info","jdoe"

               detect {
                   all {
                       checkStatusCode 200
                       bodyContains "<td>Parent Location</td>"
                   }
               }
           }
    ])
}