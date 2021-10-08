# AEM Security Checks Automation

## How to scan from maven

Add the plugin configuration to your project

    <build>
        <plugins>
            
            ...
            
            <plugin>
                <groupId>biz.netcentric.security</groupId>
                <artifactId>aem-security-maven-plugin</artifactId>
                <version>${plugin.version}</version>
                <configuration>
                    <-- Use an existing path as it is reuired as a base for content grabbing scans -->
                    <target>http://localhost:4503/content/we-retail</target>
                    <outputLocation>/Users/<your-user>/temp</outputLocation>
                </configuration>
            </plugin>
            
            ...
            
        </plugins>
    </build>

Then trigger the scan execution or bind the plugin execution to a profile
 
    mvn biz.netcentric.maven.security:aem-security-maven-plugin:start

## How to debug the build

Run the maven plugin using mvndebug.

    mvn biz.netcentric.maven.security:aem-security-maven-plugin:start
    
Maven will wait till a remote debugger on port 8000 is registered.    
So connect your IDE's remote debugger and trigger the build.