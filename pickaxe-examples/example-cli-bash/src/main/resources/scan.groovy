package biz.netcentric.security.scans

def scan = {

    /* Configures the base URL */
    target "http://localhost:45181/content/we-retail/us/en.html"

    /* Sets the scan configuration */
    config {
        authentication {
            username "admin"
            password "admin123"
        }

        categories "xss", "dispatcher"
    }

    /* Registers additional external checks */
    register {

    }

    /* Configures the reporting strategy */
    reporter {
        register "json-pretty", "html-table"
        config {
            setOutputLocation "/Users/thomas/temp"
        }
    }
}

scan