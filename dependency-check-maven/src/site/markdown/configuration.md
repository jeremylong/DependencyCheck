Configuration
====================
The following properties can be set on the dependency-check-maven plugin.

Property             | Description                        | Default Value
---------------------|------------------------------------|------------------
aggregate            | Sets whether report aggregation will be performed for multi-module site reports. This option only affects the report generation when configured within the reporting section. | false
autoUpdate           | Sets whether auto-updating of the NVD CVE/CPE data is enabled. It is not recommended that this be turned to false. | true
outputDirectory      | The location to write the report(s). Note, this is not used if generating the report as part of a `mvn site` build | 'target'
failBuildOnCVSS      | Specifies if the build should be failed if a CVSS score above a specified level is identified. The default is 11 which means since the CVSS scores are 0-10, by default the build will never fail.         | 11
format               | The report format to be generated (HTML, XML, VULN, ALL). This configuration option has no affect if using this within the Site plugin unless the externalReport is set to true. | HTML
logFile              | The file path to write verbose logging information. | &nbsp;
suppressionFile      | The file path to the XML suppression file \- used to suppress [false positives](../suppression.html) | &nbsp;
skipTestScope        | Should be skip analysis for artifacts with Test Scope | true
skipProvidedScope    | Should be skip analysis for artifacts with Provided Scope | false
skipRuntimeScope     | Should be skip analysis for artifacts with Runtime Scope | false

Analyzer Configuration
====================
The following properties are used to configure the various file type analyzers.
These properties can be used to turn off specific analyzers if it is not needed.
Note, that specific analyzers will automatically disable themselves if no file
types that they support are detected - so specifically disabling them may not
be needed.

Property                | Description                                                               | Default Value
------------------------|---------------------------------------------------------------------------|------------------
archiveAnalyzerEnabled  | Sets whether the Archive Analyzer will be used.                           | true
zipExtensions           | A comma-separated list of additional file extensions to be treated like a ZIP file, the contents will be extracted and analyzed. | &nbsp;
jarAnalyzer             | Sets whether Jar Analyzer will be used.                                   | true
nexusAnalyzerEnabled    | Sets whether Nexus Analyzer will be used.                                 | true
nexusUrl                | Defines the Nexus Pro Server URL. If not set the Nexus Analyzer will be disabled. | &nbsp;
nexusUsesProxy          | Whether or not the defined proxy should be used when connecting to Nexus. | true
nuspecAnalyzerEnabled   | Sets whether or not the .NET Nuget Nuspec Analyzer will be used.          | true
assemblyAnalyzerEnabled | Sets whether or not the .NET Assembly Analyzer should be used.            | true
pathToMono              | The path to Mono for .NET assembly analysis on non-windows systems.       | &nbsp;

Advanced Configuration
====================
The following properties can be configured in the plugin. However, they are less frequently changed. One exception
may be the cvedUrl properties, which can be used to host a mirror of the NVD within an enterprise environment.

Property             | Description                                                              | Default Value
---------------------|--------------------------------------------------------------------------|------------------
cveUrl12Modified     | URL for the modified CVE 1.2.                                            | http://nvd.nist.gov/download/nvdcve-modified.xml
cveUrl20Modified     | URL for the modified CVE 2.0.                                            | http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-modified.xml
cveUrl12Base         | Base URL for each year's CVE 1.2, the %d will be replaced with the year. | http://nvd.nist.gov/download/nvdcve-%d.xml
cveUrl20Base         | Base URL for each year's CVE 2.0, the %d will be replaced with the year. | http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-%d.xml
connectionTimeout    | Sets the URL Connection Timeout used when downloading external data.     | &nbsp;
dataDirectory        | Sets the data directory to hold SQL CVEs contents. This should generally not be changed.    | &nbsp;
databaseDriverName   | The name of the database driver. Example: org.h2.Driver.                                    | &nbsp;
databaseDriverPath   | The path to the database driver JAR file; only used if the driver is not in the class path. | &nbsp;
connectionString     | The connection string used to connect to the database.                                      | &nbsp;
databaseUser         | The username used when connecting to the database.                                          | &nbsp;
databasePassword     | The password used when connecting to the database.                                          | &nbsp;
metaFileName         | Sets the name of the file to use for storing the metadata about the project.                | dependency-check.ser

Proxy Configuration
====================
Use [Maven's settings](https://maven.apache.org/settings.html#Proxies) to configure a proxy server. If multiple proxies
are configured in the Maven settings file you must tell dependency-check which proxy to use with the following property:

Property             | Description                                                                          | Default Value
---------------------|--------------------------------------------------------------------------------------|------------------
mavenSettingsProxyId | The id for the proxy, configured via settings.xml, that dependency-check should use. | &nbsp;

