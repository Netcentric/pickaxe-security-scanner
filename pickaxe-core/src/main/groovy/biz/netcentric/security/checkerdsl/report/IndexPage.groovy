/*
 * (C) Copyright 2020 Netcentric - a Cognizant Digital Business
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package biz.netcentric.security.checkerdsl.report

class IndexPage {

    static final String INDEX_FILE_NAME = "index.html"

    List<File> outputFiles

    IndexPage(List<File> outputFiles) {
        this.outputFiles = outputFiles
    }

    void write(File destinationDirectory) {
        String markup = createMarkup(destinationDirectory)

        // we need to get rid of existing index files else we end up appending the results on each iteration
        cleanupExistingIndexFiles(destinationDirectory)

        final FileTreeBuilder treeBuilder = new FileTreeBuilder(destinationDirectory)
        treeBuilder.file(INDEX_FILE_NAME, markup)
    }

    private void cleanupExistingIndexFiles(File destinationDirectory) {
        def existingIndexFile = new File(destinationDirectory, INDEX_FILE_NAME)
        if (existingIndexFile != null && existingIndexFile.exists()) {
            existingIndexFile.delete()
        }
    }

    String createMarkup(File destinationDirectory) {
        def writer = new StringWriter()  // html is written here by markup builder
        def markup = new groovy.xml.MarkupBuilder(writer)  // the builder


        String destinationDirectoryPath = destinationDirectory.absolutePath

        markup.html {
            head {
                title "AEM Security Check: Overview"
                style "color:black;"
            }
            body(id: "main", style: "float:left;font-family:sans-serif;") {
                h1 id: "header-overview", style: "color:blue;", "Available Reports"
                div {
                    table {
                        outputFiles.each { outputFile ->
                            if(outputFile != null){
                                String path = outputFile.absolutePath
                                String relativePath = path.replaceAll(destinationDirectoryPath + "/", "")

                                tr {
                                    td(class: "description", "Report: ")
                                    td(class:"relative-path") {
                                        a href: "$relativePath", "$relativePath"
                                    }
                                    td(class:"absolute-path") {
                                        "$path"
                                    }
                                }

                                br()
                            }
                        }
                    }
                }
            }
        }

        writer
    }


}
