package biz.netcentric.security.maven;

import biz.netcentric.security.checkerdsl.ScanClient;
import biz.netcentric.security.checkerdsl.dsl.ScanDelegate;
import biz.netcentric.security.checkerdsl.dsl.SecurityCheckProvider;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

@Mojo(name = "start")
public class AemSecurityCheckMojo extends AbstractMojo {

    private SecurityCheckProvider securityCheckProvider = new SecurityCheckProvider();

    @Parameter
    private Scan scan;

    @Parameter(property = "session.executionRootDirectory")
    private String executionRootDirectory;

    @Parameter(property = "basedir")
    private String basedir;

    @Parameter(property="runOnlyOnExecutionRoot", defaultValue = "true")
    private boolean runOnlyOnExecutionRoot;

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        getLog().info("Starting scan initialization.");

        if (runOnlyOnExecutionRoot && !isRunningOnRootModule()) {
            getLog().info("Skipping scan for this module as it's not the execution root module");
        } else {
            ScanDelegate scanDelegate = initializeScanDelegate();
            startScan(scanDelegate);
        }
    }

    ScanDelegate initializeScanDelegate() {
        ScanDelegate scanDelegate = scan.toScanDelegate(this.securityCheckProvider);
        getLog().info("initialized scan delegate for target: " + scan.getTarget());
        return scanDelegate;
    }

    void startScan(ScanDelegate scanDelegate) {
        ScanClient scanClient = new ScanClient();
        scanClient.executeScan(scanDelegate);
    }

    private boolean isRunningOnRootModule() {
        return basedir.equals(executionRootDirectory);
    }
}
