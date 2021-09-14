## Reporting Settings

The scan engine supports various different reporting respectively output handling options which can be chained and are executed sequentially.
The register option allows to declare which report handlers are used to process the scan results.
The following example for instance uses the json pretty printer, an html table and a build breaker. Please see the overview table for details

    reporter {
        register "json-pretty", "html-table", "console-log-build-breaker"
        config {
            setOutputLocation "your output location"
        }
    }

The following reporter handlers are available and can be registered

| Name    | Description |
|---------|-------------|
| default-console | Logs the scan results to the output console using sl4j |
| json-pretty   | Renders the scan results as a JSON object into a json file. The file is written to the configured output location. | 
| html-table  |   Renders the scan results as a a formatted HTML table into an HTML file. The file is written to the configured output location. |  
| console-log-build-breaker  |  Logs the scan results to the output console using sl4j. It throws an exception to break the build after successfully logging all output. This report handler can e.g. be used in a maven build to fail the build when security defects are detected. |    

The setOutputLocation parameter is mandatory whenever it is expected to write scan results to a file system and the output location differs from the general one.