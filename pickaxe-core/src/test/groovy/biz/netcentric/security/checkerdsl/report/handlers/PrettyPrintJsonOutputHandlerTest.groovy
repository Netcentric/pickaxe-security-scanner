package biz.netcentric.security.checkerdsl.report.handlers

import biz.netcentric.security.checkerdsl.model.Issue
import biz.netcentric.security.checkerdsl.model.Severity
import biz.netcentric.security.checkerdsl.model.VulnerabilityDescription
import biz.netcentric.security.checkerdsl.report.Format
import biz.netcentric.security.checkerdsl.report.data.ScanResultReport
import groovy.json.JsonSlurper
import groovy.util.logging.Slf4j
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths

import static org.junit.jupiter.api.Assertions.*

@Slf4j
class PrettyPrintJsonOutputHandlerTest {

    @TempDir
    public static Path tempDir;

    @TempDir
    public static Path additionalTempDir;

    PrettyPrintJsonOutputHandler handler

    @BeforeAll
    static void setUp() {
        assertTrue(Files.isDirectory(tempDir));
    }

    @BeforeEach
    void setUpEach() {
        this.handler = new PrettyPrintJsonOutputHandler(outputFolder: tempDir.toFile())
        generateOutputFile()
    }

    @AfterEach
    void afterEach() {
        File file = this.handler.getOutputFile()
        if (file != null && file.exists()) {
            file.delete()
        }
    }

    @Test
    void "file is correctly written"() {
        File outputFile = this.handler.getOutputFile()

        assertTrue(outputFile.exists())
        assertTrue(outputFile.text != null && outputFile.text.length() > 0)
    }

    @Test
    void "contains all issues rendered as json"() {
        File outputFile = this.handler.getOutputFile()

        String fileContent = outputFile.text

        def jsonSlurper = new JsonSlurper()
        Object parsedJson = jsonSlurper.parseText(fileContent)

        parsedJson.get("findings").eachWithIndex { item, index ->
            def url = "${item.url.scheme}:${item.url.schemeSpecificPart}"
            log.info(url)
            log.info("http://localhost:8080/test${index}")
            assertEquals "http://localhost:8080/test${index}", url
        }
    }

    private void generateOutputFile() {
        VulnerabilityDescription expectedVuln = new VulnerabilityDescription(name: "xss", description: "very severe", remediation: "output encoding", cve: ["cve-1234", "cve-7890"], severity: Severity.HIGH)

        ScanResultReport resultReport = new ScanResultReport()
        resultReport.setFindings([
                new Issue(url: new URI("http://localhost:8080/test0"), vulnerability: expectedVuln),
                new Issue(url: new URI("http://localhost:8080/test1"), vulnerability: expectedVuln),
                new Issue(url: new URI("http://localhost:8080/test2"), vulnerability: expectedVuln),
        ])

        this.handler.writeReport("ReportName", resultReport)
    }

    @Test
    void "name is correct"() {
        assertEquals PrettyPrintJsonOutputHandler.NAME, this.handler.getName()
    }

    @Test
    void "format is JSON"() {
        assertEquals Format.JSON, this.handler.getOutputFormat()
    }

    @Test
    void "change output location "() {
        String path = tempDir.toString() + "/newone"
        Path outputDirectoryReplacement = Paths.get(path)
        Files.createDirectories(outputDirectoryReplacement)

        this.handler.setOutputLocation(new File(outputDirectoryReplacement.toString()))

        assertNotEquals tempDir.toFile().toString(), this.handler.getOutputFolder().toString()
        assertEquals outputDirectoryReplacement.toFile().toString(), this.handler.getOutputFolder().toString()
    }

    @Test
    void getOutputFile() {
        assertEquals tempDir.toString(), this.handler.getOutputFolder().toString()
    }
}