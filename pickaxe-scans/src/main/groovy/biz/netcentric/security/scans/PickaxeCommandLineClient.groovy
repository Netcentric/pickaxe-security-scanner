/*
 * (C) Copyright 2020 Netcentric AG.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package biz.netcentric.security.scans

import biz.netcentric.security.checkerdsl.ScanClient
import biz.netcentric.security.checkerdsl.dsl.Scan
import biz.netcentric.security.checkerdsl.dsl.ScanDelegate
import biz.netcentric.security.checkerdsl.dsl.SecurityCheckProvider
import biz.netcentric.security.checkerdsl.model.AuthType
import groovy.cli.picocli.CliBuilder
import groovy.util.logging.Slf4j

/**
 * Compile and call with url and output folder e.g.
 * biz.netcentric.security.aemchecks.AemCheckerClient --url http://localhost:45181/content/we-retail/us/en.html --output /Users/<your-username>/temp
 * All checks are managed via a SecurityCheckProvider which is owned by the CLI client.
 * Makes sure the output folder exists.
 */
@Slf4j
class PickaxeCommandLineClient {

    SecurityCheckProvider securityCheckProvider = new SecurityCheckProvider()

    static final String LOGO = """
MMMMMMMMMMMMMMMMMMMMMMMMNX0dcco0WMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMWWMW0o;:xNMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMWMMMMMX:.,dXWMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMWMMMMNx. ..,lONMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMWNd. .... .;kNMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMWNKOo,,oO0d;. ;0WMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMWXKKKXXXWMMMNOc..oXWWMMM
MMMMMMMMMMMMMMMMMMMMMMMWNXKKKXNWMWMMMMMMW0l.,OWMMM
MMMMMMMMMMMMMMMMMMMMMMNXKKKXNWWMMMMMMMMMMMW0c,dNMM
MM                                              XM
MM (  _ \\(  )/ __)(  / ) / _\\ ( \\/ )(  __)   MM
MM ) __/ )(( (__  )  ( /    \\ )  (  ) _)       MM
MM (__)  (__)\\___)(__\\_)\\_/\\_/(_/\\_)(____) MM
MM                                            WKKW
MMMMMMMMMMMMMMMMNKKKKXNWMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMNx,,oOXWMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMNkc,..,kWMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMW0c;c;.lKMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMXo. ..;OWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMNk,   'xNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
    """

    static void main(String[] args) {

        CliBuilder cli = createCommandLineOptions()
        def arguments = trimWrappingQuotes(args)
        def options = cli.parse(arguments)
        assert "Missing mandatory properties. Please check the help." | options // would be null (false) on failure
        // only the URL is mandatory.
        // if location is missing then we fall back to the build in scans

        def aemChecker = new PickaxeCommandLineClient()
        if (!options.getProperty('id') && !options.getProperty('checks')) {
            println options
            assert "Missing mandatory property: --url" | options.getProperty('url')
            assert "Missing mandatory property: --output" | options.getProperty('output')

            options.arguments()
        }

        if (log.isInfoEnabled()) {
            log.info ""
            log.info LOGO
            log.info ""
            log.info "NETCENTRIC PICKAXE"
            log.info "Security Probing and Scanning Toolkit"
            log.info ""
            log.info ""
        }
        aemChecker.run(options)
    }

    private static String[] trimWrappingQuotes(args){
        //get rid of wrapping double quotes. They might appear when calling the cli command using docker and cause the parser to fail
        List cleanedArgs = []
        args.each { argument ->
            String processedArgument = argument
            if (argument.length() >= 2 && argument.charAt(0) == '"' && argument.charAt(argument.length() - 1) == '"') {
                processedArgument = argument.substring(1, argument.length() - 1);
            }

            cleanedArgs << processedArgument
        }
        cleanedArgs
    }

    private static CliBuilder createCommandLineOptions() {
        def cli = new CliBuilder()
        cli.l(longOpt: 'load', args: 1, argName: 'location', 'Defines the location where SecurityCheck files should be loaded from. This can be a directory or a single file')
        cli.s(longOpt: 'scan', args: 1, argName: 'scan', 'Defines the location where ScanDelegate config files should be loaded from. This should be a single file. Uses the default scan config if not set.')
        cli.o(longOpt: 'output', args: 1, argName: 'output', 'Define output folder where results are stored')
        cli.c(longOpt: 'categories', args: 1, argName: 'categories', 'Define the SecurityCheck categories which should be executed')
        cli.ig(longOpt: 'ignored', args: 1, argName: 'ignored', 'Define which checks are ignored and never executed')
        cli.fp(longOpt: 'falsepositives', args: 1, argName: 'falsepositives', 'Define which checks are not considered in the results list')
        cli.n(longOpt: 'names', args: 1, argName: 'names', 'Define the SecurityCheck names which should be executed')
        cli.a(longOpt: 'authtype', args: 1, argName: 'authtype', 'Authentication type, it can be simple (Basic auth) or preemptive')
        cli.u(longOpt: 'username', args: 1, argName: 'username', 'Username for authentication')
        cli.p(longOpt: 'password', args: 1, argName: 'password', 'Password for authentication')
        cli.ta(longOpt: 'targets', args: 1, argName: 'targets', 'Define which additional paths should be added to the scan. only an extension to url. The url property has to be defined.')
        cli.i(longOpt: 'id', args: 0, argName: 'ids', 'Retrieve a unique id')
        cli.ch(longOpt: 'checks', args: 0, argName: 'checks', 'Retrieves all installed checks including their descriptive information')
        cli._(longOpt: 'url', args: 1, argName: 'URL', 'Defines which url to scan. The URL must contain a hostname and should contain a path.')
        cli
    }

    private run(def options) {

        def scanClient = new ScanClient()

        // we need to pre-initialize the loader as the scan client does
        // not know about the buildin checks which are located in this project and not the core framework
        BuildinAEMChecksLoader buildInAemChecksLoader = new BuildinAEMChecksLoader(securityCheckProvider: securityCheckProvider)
        buildInAemChecksLoader.init()

        // generate a check id
        if (options.id) {
            // generates a unique one and checks with the security check provider if it does not yet exist
            def id = scanClient.provideUniqueCheckId securityCheckProvider

            log.info "Providing new check id: {}", id
            println id

            return
        }

        // print out infos about checks
        if (options.checks) {
            List httpSecChecks = buildInAemChecksLoader.getRegisteredChecks()

            log.info "Show check description option selected."
            log.info "Found ${httpSecChecks.size()} security checks"
            httpSecChecks.each { check ->
                String categories = check.getCategories().join(",")
                String lineBreak = System.lineSeparator()

                def descriptiveText = """ID: ${check.getId()} ${lineBreak}Name: ${check.getName()} ${lineBreak}Categories: ${categories}${lineBreak}"""

                log.info descriptiveText
            }

            return
        }

        log.info "Initialize security check for URL: {}", options.url
        log.info "Output folder location: {}", options.output

        // check if scan option set which is basically an externally defined scan closure.
        log.info "Check for custom scan config."
        if (options.scan) {
            List httpSecChecks = buildInAemChecksLoader.getRegisteredChecks()
            log.info "Custom scan config in use: {}", options.scan
            return scanClient.executeScan(options.scan, securityCheckProvider, [])
        }

        if (options.location) {
            // no custom scan option set - uses the build-in checks
            log.info "Loading files from: {}", options.location
        }

        if (options.categories) {
            log.info "Using the following categories: {}", options.categories
        }

        ScanDelegate scanDelegate = createFromBuildInScanConfig(options)
        scanClient.executeScan scanDelegate
    }

    private List<String> getSelectedNames(def options) {
        retrieveCommaSeparatedList options.getProperty('names')
    }

    private List<String> getSelectedCategories(def options) {
        retrieveCommaSeparatedList options.getProperty('categories')
    }

    private List<String> getContentTargets(def options) {
        retrieveCommaSeparatedList options.getProperty('targets')
    }

    private List<String> getSelectedLocations(def options) {
        retrieveCommaSeparatedList options.getProperty('load')
    }

    private List<String> getParameters(def propertyName, def options) {
        retrieveCommaSeparatedList options.getProperty(propertyName)
    }

    private List<String> retrieveCommaSeparatedList(def parameter) {
        if (parameter && parameter?.trim() && parameter != "false") {
            return parameter.split(",")
        }

        []
    }

    ScanDelegate createFromBuildInScanConfig(def options) {

        def targetUrl = options.url
        def outputLocation = options.output
        def contentTargets = getContentTargets(options)
        def selectedCategories = getSelectedCategories(options)
        def selectedLocations = getSelectedLocations(options)
        def selectedNames = getSelectedNames(options)
        def ignoredChecks = getParameters "ignored", options
        def falsePositives = getParameters "falsepositives", options

        def authConfig = null
        if (options.authtype != false) {
            AuthType authType = options.authtype == "preemptive" ? AuthType.PRE_EMPTIVE : AuthType.SIMPLE

            authConfig = {
                authenticationType authType

                username options.username

                password options.password
            }
        }

        // The following hierarchy applies in terms of selecting the tests:
        // all > categories > names

        def selectedChecksConfig = {

            authentication authConfig

            runAllChecks true

            ignored(ignoredChecks)
        }

        // if we have categories then we do not use run all
        if (selectedCategories.size() > 0) {
            selectedChecksConfig = {

                authentication authConfig

                categories(selectedCategories)

                ignored(ignoredChecks)
            }
        }

        // if we have names then we do not use categories or run all
        if (selectedNames.size() > 0) {
            selectedChecksConfig = {

                authentication authConfig

                names(selectedNames)

                runAllChecks false

                ignored(ignoredChecks)
            }
        }

        return Scan.create(securityCheckProvider) {

            /* Configures the base URL */
            target targetUrl, contentTargets

            /* Sets the scan configuration */
            config selectedChecksConfig

            /* Registers additional external checks */
            register selectedLocations

            /* Configures the reporting strategy */
            reporter {
                register "json-pretty", "html-table"

                config {
                    log.info "Reporting to " + outputLocation
                    setOutputLocation outputLocation
                }
            }

            /* Loads additional buildin scans and initializes them */
            BuildinAEMChecksLoader checks = new BuildinAEMChecksLoader(securityCheckProvider: securityCheckProviderDelegate)
            checks.init()
        }
    }


}
