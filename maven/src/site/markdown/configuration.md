Goals
====================

Goal        | Description
------------|-----------------------
aggregate   | Runs dependency-check against the child projects and aggregates the results into a single report. **Warning**: if the aggregate goal is used within the site reporting a blank report will likely be present for any goal beyond site:site (i.e. site:stage or site:deploy will likely result in blank reports being staged or deployed); however, site:site will work. See issue [#325](https://github.com/jeremylong/DependencyCheck/issues/325) for more information.
check       | Runs dependency-check against the project and generates a report.
update-only | Updates the local cache of the NVD data from NIST.
purge       | Deletes the local copy of the NVD. This is used to force a refresh of the data.

Configuration
====================
The following properties can be set on the dependency-check-maven plugin.

Property                    | Description                        | Default Value
----------------------------|------------------------------------|------------------
autoUpdate                  | Sets whether auto-updating of the NVD CVE/CPE data is enabled. It is not recommended that this be turned to false. | true
cveValidForHours            | Sets the number of hours to wait before checking for new updates from the NVD.                                     | 4
format                      | The report format to be generated (HTML, XML, CSV, JSON, JUNIT, ALL). This configuration is ignored if `formats` is defined. This configuration option has no affect if using this within the Site plugin unless the externalReport is set to true. | HTML
formats                     | A list of report formats to be generated (HTML, XML, CSV, JSON, JUNIT, ALL). This configuration overrides the value from `format`. This configuration option has no affect if using this within the Site plugin unless the externalReport is set to true. | &nbsp;
junitFailOnCVSS             | If using the JUNIT report format the junitFailOnCVSS sets the CVSS score threshold that is considered a failure.   | 0
prettyPrint                 | Whether the XML and JSON formatted reports should be pretty printed.                                               | false
failBuildOnCVSS             | Specifies if the build should be failed if a CVSS score equal to or above a specified level is identified. The default is 11 which means since the CVSS scores are 0-10, by default the build will never fail. | 11
failBuildOnAnyVulnerability | Specific that if any vulnerability is identified, the build will fail. | false
failOnError                 | Whether the build should fail if there is an error executing the dependency-check analysis. | true
name                        | The name of the report in the site. | dependency-check or dependency-check:aggregate
outputDirectory             | The location to write the report(s). Note, this is not used if generating the report as part of a `mvn site` build. | 'target'
scanSet                     | An optional collection of filesets that specify additional files and/or directories to analyze as part of the scan. If not specified, defaults to standard Maven conventions. | src/main/resources, src/main/filters, src/main/webapp
skip                        | Skips the dependency-check analysis.                       | false
skipProvidedScope           | Skip analysis for artifacts with Provided Scope.           | false
skipRuntimeScope            | Skip analysis for artifacts with Runtime Scope.            | false
skipSystemScope             | Skip analysis for artifacts with System Scope.             | false
skipTestScope               | Skip analysis for artifacts with Test Scope.               | true
skipDependencyManagement    | Skip analysis for dependencyManagement sections.           | true
skipArtifactType            | A regular expression used to filter/skip artifact types.   | &nbsp;
suppressionFiles            | The file paths to the XML suppression files \- used to suppress [false positives](../general/suppression.html). The configuration value can be a local file path, a URL to a suppression file, or even a reference to a file on the class path (see https://github.com/jeremylong/DependencyCheck/issues/1878#issuecomment-487533799) | &nbsp;
hintsFile                   | The file path to the XML hints file \- used to resolve [false negatives](../general/hints.html).       | &nbsp;
enableExperimental          | Enable the [experimental analyzers](../analyzers/index.html). If not enabled the experimental analyzers (see below) will not be loaded or used. | false
enableRetired               | Enable the [retired analyzers](../analyzers/index.html). If not enabled the retired analyzers (see below) will not be loaded or used. | false
versionCheckEnabled         | Whether dependency-check should check if a new version of dependency-check-maven exists. | true

Analyzer Configuration
====================
The following properties are used to configure the various file type analyzers.
These properties can be used to turn off specific analyzers if it is not needed.
Note, that specific analyzers will automatically disable themselves if no file
types that they support are detected - so specifically disabling them may not
be needed.

Property                      | Description                                                               | Default Value
------------------------------|---------------------------------------------------------------------------|------------------
archiveAnalyzerEnabled        | Sets whether the Archive Analyzer will be used.                           | true
zipExtensions                 | A comma-separated list of additional file extensions to be treated like a ZIP file, the contents will be extracted and analyzed. | &nbsp;
jarAnalyzerEnabled            | Sets whether Jar Analyzer will be used.                                   | true
centralAnalyzerEnabled        | Sets whether Central Analyzer will be used. If this analyzer is being disabled there is a good chance you also want to disable the Nexus Analyzer (see below). | true
centralAnalyzerUseCache       | Sets whether the Central Analyer will cache results. Cached results expire after 30 days.                  | true
ossIndexAnalyzerEnabled       | Sets whether the OSS Index Analyzer will be enabled.                      | true
ossindexAnalyzerUseCache      | Sets whether the OSS Index Analyzer will cache results. Cached results expire after 24 hours.              | true
nexusAnalyzerEnabled          | Sets whether Nexus Analyzer will be used (requires Nexus Pro). This analyzer is superceded by the Central Analyzer; however, you can configure this to run against a Nexus Pro installation. | true
nexusUrl                      | Defines the Nexus Server's web service end point (example http://domain.enterprise/service/local/). If not set the Nexus Analyzer will be disabled. | &nbsp;
nexusServerId                 | The id of a server defined in the settings.xml that configures the credentials (username and password) for a Nexus server's REST API end point. When not specified the communication with the Nexus server's REST API will be unauthenticated. | &nbsp;
nexusUsesProxy                | Whether or not the defined proxy should be used when connecting to Nexus. | true
artifactoryAnalyzerEnabled    | Sets whether Artifactory analyzer will be used | false
artifactoryAnalyzerUrl        | The Artifactory server URL. | &nbsp;
artifactoryAnalyzerUseProxy   | Whether Artifactory should be accessed through a proxy or not. | false
artifactoryAnalyzerParallelAnalysis | Whether the Artifactory analyzer should be run in parallel or not | true
artifactoryAnalyzerServerId   | The id of a server defined in the settings.xml to retrieve the credentials (username and API token) to connect to Artifactory instance. It is used in priority to artifactoryAnalyzerUsername and artifactoryAnalyzerApiToken | artifactory
artifactoryAnalyzerUsername   | The user name (only used with API token) to connect to Artifactory instance | &nbsp;
artifactoryAnalyzerApiToken   | The API token to connect to Artifactory instance, only used if the username or the API key are not defined by artifactoryAnalyzerServerId,artifactoryAnalyzerUsername or artifactoryAnalyzerApiToken | &nbsp;
artifactoryAnalyzerBearerToken   | The bearer token to connect to Artifactory instance                                                     | &nbsp;
pyDistributionAnalyzerEnabled | Sets whether the [experimental](../analyzers/index.html) Python Distribution Analyzer will be used.        | true
pyPackageAnalyzerEnabled      | Sets whether the [experimental](../analyzers/index.html) Python Package Analyzer will be used.             | true
rubygemsAnalyzerEnabled       | Sets whether the [experimental](../analyzers/index.html) Ruby Gemspec Analyzer will be used.               | true
opensslAnalyzerEnabled        | Sets whether the openssl Analyzer should be used.                                                          | true
cmakeAnalyzerEnabled          | Sets whether the [experimental](../analyzers/index.html) CMake Analyzer should be used.                    | true
autoconfAnalyzerEnabled       | Sets whether the [experimental](../analyzers/index.html) autoconf Analyzer should be used.                 | true
composerAnalyzerEnabled       | Sets whether the [experimental](../analyzers/index.html) PHP Composer Lock File Analyzer should be used.   | true
nodeAnalyzerEnabled           | Sets whether the [retired](../analyzers/index.html) Node.js Analyzer should be used.                       | true
nodeAuditAnalyzerEnabled      | Sets whether the Node Audit Analyzer should be used.                                                       | true
nodeAuditAnalyzerUseCache     | Sets whether the Node Audit Analyzer will cache results. Cached results expire after 24 hours.             | true
retireJsAnalyzerEnabled       | Sets whether the [experimental](../analyzers/index.html) RetireJS Analyzer should be used.                 | true
retireJsUrl                   | The URL to the Retire JS repository.                                                                       | https://raw.githubusercontent.com/Retirejs/retire.js/master/repository/jsrepository.json
nuspecAnalyzerEnabled         | Sets whether the .NET Nuget Nuspec Analyzer will be used.                                                  | true
nugetconfAnalyzerEnabled      | Sets whether the [experimental](../analyzers/index.html) .NET Nuget packages.config Analyzer will be used. | true
cocoapodsAnalyzerEnabled      | Sets whether the [experimental](../analyzers/index.html) Cocoapods Analyzer should be used.                | true
bundleAuditAnalyzerEnabled    | Sets whether the [experimental](../analyzers/index.html) Bundle Audit Analyzer should be used.             | true
bundleAuditPath               | Sets the path to the bundle audit executable; only used if bundle audit analyzer is enabled and experimental analyzers are enabled.  | &nbsp;
swiftPackageManagerAnalyzerEnabled | Sets whether the [experimental](../analyzers/index.html) Swift Package Analyzer should be used.       | true
assemblyAnalyzerEnabled       | Sets whether the .NET Assembly Analyzer should be used.                                                    | true
pathToMono                    | The path to Mono for .NET assembly analysis on non-windows systems.                                        | &nbsp;

RetireJS Configuration
====================
If using the [experimental](../analyzers/index.html) RetireJS Analyzer the following configuration options are available
to control the included JS files

###Example
<pre>
    &lt;retirejs&gt;
        &lt;filters&gt;
            &lt;filter&gt;Copyright\(c\) Jeremy Long&lt;/filter&gt;
        &lt;/filters&gt;
        &lt;filterNonVulnerable&gt;true&lt;/filterNonVulnerable&gt;
    &lt;/retirejs&gt;
</pre>

Property            | Description                                                                                                                                                                                                            | Default Value
--------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------
filters             | A list of file content filters used to exclude JS files based on content. This is most commonly used to exclude JS files based on your organizations copyright so that your JS files do not get listed as a dependency.| &nbsp;
filterNonVulnerable | A boolean controlling whether or not the Retire JS Analyzer should exclude non-vulnerable JS files from the report.                                                                                                    | false

Advanced Configuration
====================
The following properties can be configured in the plugin. However, they are less frequently changed. One exception
may be the cveUrl properties, which can be used to host a mirror of the NVD within an enterprise environment.

Property             | Description                                                                                                          | Default Value                                                       |
---------------------|----------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------|
cveUrlModified       | URL for the modified CVE JSON data feed.  When mirroring the NVD you must mirror the *.json.gz and the *.meta files. | https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.gz |
cveUrlBase           | Base URL for each year's CVE JSON data feed, the %d will be replaced with the year.                                  | https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-%d.json.gz       |
connectionTimeout    | Sets the URL Connection Timeout used when downloading external data.                                                 | &nbsp;                                                              |
dataDirectory        | Sets the data directory to hold SQL CVEs contents. This should generally not be changed.                             | ~/.m2/repository/org/owasp/dependency-check-data/                   |
databaseDriverName   | The name of the database driver. Example: org.h2.Driver.                                                             | &nbsp;                                                              |
databaseDriverPath   | The path to the database driver JAR file; only used if the driver is not in the class path.                          | &nbsp;                                                              |
connectionString     | The connection string used to connect to the database.                                                               | &nbsp;                                                              |
serverId             | The id of a server defined in the settings.xml; this can be used to encrypt the database password. See [password encryption](http://maven.apache.org/guides/mini/guide-encryption.html) for more information. | &nbsp; |
databaseUser         | The username used when connecting to the database.                                                                   | &nbsp;                                                              |
databasePassword     | The password used when connecting to the database.                                                                   | &nbsp;                                                              |

Proxy Configuration
====================
Use [Maven's settings](https://maven.apache.org/settings.html#Proxies) to configure a proxy server. Please see the
dependency-check [proxy configuration](../data/proxy.html) page for additional problem solving techniques. If multiple proxies
are configured in the Maven settings file you must tell dependency-check which proxy to use with the following property:

Property             | Description                                                                          | Default Value |
---------------------|--------------------------------------------------------------------------------------|---------------|
mavenSettingsProxyId | The id for the proxy, configured via settings.xml, that dependency-check should use. | &nbsp;        |
