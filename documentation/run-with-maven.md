# Integrate Pickaxe into your Maven build

Add the plugin configuration to your project

    <build>
        <plugins> 
            ...
            <plugin>
                <groupId>biz.netcentric.security</groupId>
                <artifactId>pickaxe-maven-plugin</artifactId>
                <version>${plugin.version}</version>
                <configuration>
                    <scan>
                        <!-- Mandatory: target URL - Should be some valid page -->
                        <target>http://localhost:45181/content/we-retail.html</target>
                        
                        
                        <!-- Optional: Additonal target URLs - Should point to some valid page within the same domain -->
                        <!-- Supports absolute URLs, paths and relative paths -->
                        <targets>
                        	<location>http://localhost:45181/content/wkdyn/en/products.html</location>
                        	<location>/content/wkdyn/en/products.html</location>
                            <location>/content/dam/en/products</location>
                            <location>etc/tools</location>
                        </targets>

                        <!-- Mandatory: Default output location which will be used if the scanReporters do not provide one. -->
                        <outputLocation>/Users/your-account/temp</outputLocation>

                        <!-- Defines the scan scope in term of utilized checks -->
                        <scope>
                            <!-- Optional: default is true -->
                            <runAllChecks>false</runAllChecks>
                            <!-- Optional: setting any category it will disable runAllChecks by setting it to true -->
                            <categories>
                                <category>xss</category>
                            </categories>
                        </scope>

                        <!-- Defines how to deal with identified issues in terms of reporting. -->
                        <scanReporters>
                            <scanReporter>
                                <!-- mandatory: examples are e.g. default-console and json-pretty, ... -->
                                json-pretty
                            </scanReporter>
                            <scanReporter>
                            <!-- mandatory: examples are e.g. default-console and json-pretty, ... -->
                                html-table
                            </scanReporter>
                        </scanReporters>
                    </scan>
                </configuration>
            </plugin>
            ...
        </plugins>
    </build>

Then trigger the scan execution or bind the plugin execution to a profile

    mvn biz.netcentric.maven.security:pickaxe-maven-plugin:start
