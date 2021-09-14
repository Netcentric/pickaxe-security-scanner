package biz.netcentric.security.checkerdsl.report.handlers

import biz.netcentric.security.checkerdsl.report.data.ScanResultReport
import biz.netcentric.security.checkerdsl.report.data.SecurityCheckReportEntity
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir

import java.nio.file.Files
import java.nio.file.Path

import static org.junit.jupiter.api.Assertions.assertTrue

class HtmlTableOutputHandlerTest {

    String folder = "/Users/thomas/temp/groovytemp"

    String resultFile = folder + "/testresult.html"

    @TempDir
    public static Path tempDir;

    HtmlTableOutputHandler handler

    @BeforeAll
    static void setUp() {
    }

    @BeforeEach
    void setUpEach() {
    }

    @AfterEach
    void afterEach() {
    }

    @Test
    void "report correctly generated"() {


    }


    ScanResultReport createScanResultReport() {
        ScanResultReport report = new ScanResultReport()

        report.target = "http://localhost:4502/target/system"
        report.executedChecks << new SecurityCheckReportEntity([id: "da34eada",name:"Vulnerability XYZ Example 1",cve:"CVE-2015-31", vulnerabilityName:"Vuln Name", vulnerabilityDescription:"Vuln Description",suggestedMitigation:"Vuln Mitigation", numberOfFindings:2])
        report.executedChecks << new SecurityCheckReportEntity([id: "da44eada",name:"Vulnerability XYZ Example 2",cve:"CVE-2015-30", vulnerabilityName:"Vuln Name 2", vulnerabilityDescription:"Vuln Description 2",suggestedMitigation:"Vuln Mitigation 2", numberOfFindings:0])
        report.executedChecks << new SecurityCheckReportEntity([id: "ee34eada",name:"Vulnerability XYZ Example 3",cve:"CVE-2015-32", vulnerabilityName:"Vuln Name 3", vulnerabilityDescription:"Vuln Description 3",suggestedMitigation:"Vuln Mitigation 3", numberOfFindings:0])

        report.findings = []
        report.numberOfFindings = 2

        report
    }

    SecurityCheckReportEntity createReportEntity(){
        new SecurityCheckReportEntity()
    }
}