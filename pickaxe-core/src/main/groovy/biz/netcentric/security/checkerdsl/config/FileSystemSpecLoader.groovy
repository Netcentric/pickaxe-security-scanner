/*
 *
 *  * (C) Copyright 2020 Netcentric AG.
 *  *
 *  * All rights reserved. This program and the accompanying materials
 *  * are made available under the terms of the Eclipse Public License v1.0
 *  * which accompanies this distribution, and is available at
 *  * http://www.eclipse.org/legal/epl-v10.html
 *
 */
package biz.netcentric.security.checkerdsl.config

import groovy.io.FileType
import groovy.util.logging.Slf4j

import java.nio.file.*
import java.nio.file.attribute.BasicFileAttributes

/**
 * Loads security check specs from a filesystem.
 * It can load either distinct files or traverse folders
 *
 * Any loadable spec file must have the extension .groovy or .yaml
 */
@Slf4j
class FileSystemSpecLoader implements SpecLoader {

    /**
     * Loads a list of Specs via a URI e.g. pointing to a spec located inside a JAR
     * @param resource The resource providing the location
     * @return List
     */
    List<Spec> loadFromLocation(URI uri) {
        File file = new File(uri)

        List<Spec> scripts = []
        if (file.isDirectory()) {
            file.eachFileRecurse(FileType.FILES, { fi ->
                addIfMatchingScript(scripts, fi)
            })
        } else {
            addIfMatchingScript(scripts, file)
        }

        scripts
    }

    /**
     * Loads a list of Specs via a URL e.g. pointing to a spec located inside a JAR
     * @param resource The resource providing the location
     * @return List
     */
    List<Spec> loadFromLocation(URL resource) {
        URI uri = resource.toURI()
        loadFromLocation(uri)
    }

    /**
     * Loads a list of Specs from a certain location defined as a String. Usually when the spec is somewhere on a filesystem.
     * Does recursively go through the whole folder.
     *
     * @param location Location of the specs. Can be a folder.
     * @return List
     */
    List<Spec> loadFromLocation(String location) {
        log.info "Loading checks from: ${location}"

        URL resource = getClass().getResource(location)

        // load contents from jar file
        if (resource != null && resource.getProtocol().equals("jar")) {
            FileSystem fileSystem
            try {
                URI uri = resource.toURI()
                fileSystem = FileSystems.newFileSystem(uri, Collections.emptyMap(), null)
                fileSystem.getRootDirectories().each { path ->

                }
                Path folderPath = fileSystem.getPath(location)

                readSpecsFromFolder(folderPath)
            } catch (IOException e) {
                throw new RuntimeException(e)
            } finally {
                if (fileSystem != null) {
                    fileSystem.close()
                }
            }
        } else if (resource != null) {
            // load from resource
            loadFromLocation(resource)
        } else {
            // we do not have a resource so let's check plain nio API
            // this is e.g. the case when referencing an absolte path somewhere on the local filesystem
            Path folderPath = Paths.get(location)
            readSpecsFromFolder(folderPath)
        }
    }

    private List<Spec> readSpecsFromFolder(Path folderPath) {
        List<Spec> scripts = []
        if (folderPath != null) {
            String currentDir = new File(".").getAbsolutePath()
            String workingDirectory = currentDir - "/."
            log.info("Working directory ${workingDirectory}")
            Files.walkFileTree(folderPath, new FileVisitor<Path>() {

                @Override
                FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
                    return FileVisitResult.CONTINUE
                }

                @Override
                FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    InputStream is
                    try {
                        is = Files.newInputStream(file, StandardOpenOption.READ)
                        Path fileName = file.getFileName()
                        SpecFormat specFormat = fileName.toString().endsWithAny("yaml", "yml") ? SpecFormat.YAML : SpecFormat.GROOVY
                        scripts << new Spec([content: is.text, location: file.toUri().toString(), name: file.fileName.toString(), specFormat: specFormat])
                    } catch (Exception ex) {
                        log.error("", ex)
                    } finally {
                        if (is != null) is.close()
                    }

                    return FileVisitResult.CONTINUE
                }

                @Override
                FileVisitResult visitFileFailed(Path file, IOException exc) throws IOException {
                    log.error("Unable to parse directory tree ${folderPath.toString()}. ", exc)
                    return FileVisitResult.TERMINATE
                }

                @Override
                FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                    return FileVisitResult.CONTINUE
                }
            })
        }
        scripts
    }
}