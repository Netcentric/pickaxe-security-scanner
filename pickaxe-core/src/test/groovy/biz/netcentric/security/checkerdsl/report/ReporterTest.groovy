package biz.netcentric.security.checkerdsl.report

import biz.netcentric.security.checkerdsl.model.Issue
import biz.netcentric.security.checkerdsl.model.ScanExecutionResult
import biz.netcentric.security.checkerdsl.report.data.ScanResultReport
import org.junit.Assert
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test


class ReporterTest {

    Reporter delegate

    @BeforeEach
    void before(){
        delegate = new Reporter()
    }


    @Test
    void "open folder"() {

    }

    @Test
    void "register multiple keys"() {
        delegate.register("json", "html", "console")

        Assert.assertTrue delegate.selectedReporterHandlers.contains("json")
        Assert.assertTrue delegate.selectedReporterHandlers.contains("html")
        Assert.assertTrue delegate.selectedReporterHandlers.contains("console")
    }

    @Test
    void "register key closure"() {
        delegate.register({"json"})
        delegate.register({"html"})

        Assert.assertTrue delegate.selectedReporterHandlers.contains("json")
        Assert.assertTrue delegate.selectedReporterHandlers.contains("html")
    }

    @Test
    void "add new reporthandler closure"() {
        delegate.handler {
            new ReportHandler() {

                @Override
                String getName() {
                    return "custom"
                }

                @Override
                Format getOutputFormat() {
                    return Format.TXT
                }

                @Override
                void setOutputLocation(File file) {
                    // not implemented
                }

                @Override
                File getOutputFile() {
                    return null
                }

                @Override
                void writeReport(String reportName, ScanResultReport scanResultReport) {

                }

                @Override
                void postProcessingAction(ScanResultReport scanResultReport) {

                }
            }
        }

        Assert.assertTrue delegate.selectedReporterHandlers.contains("custom")

        ReportHandler reportHandler = delegate.availableHandlers.get("custom")
        Assert.assertEquals "custom", reportHandler.getName()
    }

    @Test
    void "report generation"() {
    }
}
