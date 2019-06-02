Command Line Arguments
======================

The following table lists the command line arguments:

| Short | Argument Name | Parameter | Description | Requirement |
|-------|---------------|-----------|-------------|-------------|
|       | \-\-project            | \<name\>        | The name of the project being scanned. | Optional |
| \-s   | \-\-scan               | \<path\>        | The path to scan \- this option can be specified multiple times. It is also possible to specify Ant style paths (e.g. directory/**/*.jar). | Required |
|       | \-\-exclude            | \<pattern\>     | The path patterns to exclude from the scan \- this option can be specified multiple times. This accepts Ant style path patterns (e.g. **/exclude/**). | Optional |
|       | \-\-symLink            | \<depth\>       | The depth that symbolic links will be followed; the default is 0 meaning symbolic links will not be followed. | Optional |
| \-o   | \-\-out                | \<path\>        | The folder to write reports to. This defaults to the current directory. If the format is not set to ALL one could specify a specific file name. | Optional |
| \-f   | \-\-format             | \<format\>      | The output format to write to (XML, HTML, CSV, JSON, JUNIT, ALL). Multiple formats can be specified by specifying the parameter multiple times. The default is HTML. | Required |
|       | \-\-junitFailOnCVSS    | \<score\>       | If using the JUNIT report format the junitFailOnCVSS sets the CVSS score threshold that is considered a failure. The default is 0. | Optional |
|       | \-\-prettyPrint        |                 | When specified the JSON and XML report formats will be pretty printed. | Optional |
|       | \-\-failOnCVSS         | \<score\>       | If the score set between 0 and 10 the exit code from dependency-check will indicate if a vulnerability with a CVSS score equal to or higher was identified. | Optional |
| \-l   | \-\-log                | \<file\>        | The file path to write verbose logging information. | Optional |
| \-n   | \-\-noupdate           |                 | Disables the automatic updating of the CPE data. | Optional |
|       | \-\-suppression        | \<files\>       | The file paths to the suppression XML files; used to suppress [false positives](../general/suppression.html). This can be specified more than once to utilize multiple suppression files. The argument can be a local file path, a URL to a suppression file, or even a reference to a file on the class path (see https://github.com/jeremylong/DependencyCheck/issues/1878#issuecomment-487533799) | Optional |
| \-h   | \-\-help               |                 | Print the help message. | Optional |
|       | \-\-advancedHelp       |                 | Print the advanced help message. | Optional |
| \-v   | \-\-version            |                 | Print the version information. | Optional |
|       | \-\-cveValidForHours   | \<hours\>       | The number of hours to wait before checking for new updates from the NVD. The default is 4 hours. | Optional |
|       | \-\-enableExperimental |                 | Enable the [experimental analyzers](../analyzers/index.html). If not set the analyzers marked as experimental below will not be loaded or used. | Optional |
|       | \-\-enableRetired      |                 | Enable the [retired analyzers](../analyzers/index.html). If not set the analyzers marked as retired below will not be loaded or used. | Optional |

Advanced Options
================
| Short | Argument Name                          | Parameter       | Description                                                                                                                  | Default Value |
|-------|----------------------------------------|-----------------|------------------------------------------------------------------------------------------------------------------------------|---------------|
|       | \-\-cveUrlModified                     | \<url\>         | URL for the modified CVE JSON data feed. When mirroring the NVD you must mirror the *.json.gz and the *.meta files.          | https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.gz |
|       | \-\-cveUrlBase                         | \<url\>         | Base URL for each year's CVE JSON data feed, the %d will be replaced with the year.                                          | https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-%d.json.gz |
| \-P   | \-\-propertyfile                       | \<file\>        | Specifies a file that contains properties to use instead of application defaults.                                             | &nbsp; |
|       | \-\-updateonly                         |                 | If set only the update phase of dependency-check will be executed; no scan will be executed and no report will be generated. | &nbsp; |
|       | \-\-disablePyDist                      |                 | Sets whether the [experimental](../analyzers/index.html) Python Distribution Analyzer will be used.                          | false |
|       | \-\-disablePyPkg                       |                 | Sets whether the [experimental](../analyzers/index.html) Python Package Analyzer will be used.                               | false |
|       | \-\-disableNodeJS                      |                 | Sets whether the Node.js Package Analyzer will be used.                                   | false |
|       | \-\-disableNodeAudit                   |                 | Sets whether the Node Audit Analyzer will be used.                                                                           | false |
|       | \-\-disableNodeAuditCache              |                 | When the argument is present the Node Audit Analyzer will not cache results. By default the results are cached for 24 hours. | false |  
|       | \-\-disableRetireJS                    |                 | Sets whether the [experimental](../analyzers/index.html) RetireJS Analyzer will be used.                                     | false |
|       | \-\-retireJsUrl                        | \<url\>         | The URL to the Retire JS repository.                                                                                         | https://raw.githubusercontent.com/Retirejs/retire.js/master/repository/jsrepository.json |
|       | \-\-retirejsFilter                     | \<pattern\>     | The RetireJS Analyzers content filter used to exclude JS files when the content contains the given regular expression; this option can be specified multiple times. | &nbsp; |
|       | \-\-retirejsFilterNonVulnerable        |                 | Specifies that the Retire JS Analyzer should filter out non-vulnerable JS files from the report.                             | &nbsp; |
|       | \-\-disableRubygems                    |                 | Sets whether the [experimental](../analyzers/index.html) Ruby Gemspec Analyzer will be used.                                 | false |
|       | \-\-disableBundleAudit                 |                 | Sets whether the [experimental](../analyzers/index.html) Ruby Bundler Audit Analyzer will be used.                           | false |
|       | \-\-disableCocoapodsAnalyzer           |                 | Sets whether the [experimental](../analyzers/index.html) Cocoapods Analyzer will be used.                                    | false |
|       | \-\-disableSwiftPackageManagerAnalyzer |                 | Sets whether the [experimental](../analyzers/index.html) Swift Package Manager Analyzer will be used.                        | false |
|       | \-\-disableAutoconf                    |                 | Sets whether the [experimental](../analyzers/index.html) Autoconf Analyzer will be used.                                     | false |
|       | \-\-disableOpenSSL                     |                 | Sets whether the OpenSSL Analyzer will be used.                                                                              | false |
|       | \-\-disableCmake                       |                 | Sets whether the [experimental](../analyzers/index.html) Cmake Analyzer will be disabled.                                    | false |
|       | \-\-disableArchive                     |                 | Sets whether the Archive Analyzer will be disabled.                                                                          | false |
|       | \-\-zipExtensions                      | \<strings\>     | A comma-separated list of additional file extensions to be treated like a ZIP file, the contents will be extracted and analyzed. | &nbsp; |
|       | \-\-disableJar                         |                 | Sets whether the Jar Analyzer will be disabled.                                                                              | false |
|       | \-\-disableComposer                    |                 | Sets whether the [experimental](../analyzers/index.html) PHP Composer Lock File Analyzer will be disabled.                   | false |
|       | \-\-disableOssIndex                    |                 | Sets whether the OSS Index Analyzer will be disabled.                                                                        | false |
|       | \-\-disableOssIndexCache               |                 | When the argument is present the OSS Index Analyzer will not cache results. By default results are cached for 24 hours.      | false |
|       | \-\-disableCentral                     |                 | Sets whether the Central Analyzer will be used. **Disabling this analyzer is not recommended as it could lead to false negatives (e.g. libraries that have vulnerabilities may not be reported correctly).** If this analyzer is being disabled there is a good chance you also want to disable the Nexus Analyzer. | false |
|       | \-\-disableCentralCache                |                 | When the argument is present the Central Analyzer will not cache results locally. By default results are cached locally for 30 days.  | false |
|       | \-\-disableNexus                       |                 | Sets whether the Nexus Analyzer will be used (requires Nexus v2 or Pro v3). Note, this has been superceded by the Central Analyzer. However, you can configure the Nexus URL to utilize an internally hosted Nexus server. | false |
|       | \-\-enableArtifactory                  |                 | Sets whether Artifactory analyzer will be used                                                                               | false |
|       | \-\-artifactoryUrl                     | \<url\>         | The Artifactory server URL.                                                                                                  | &nbsp; |
|       | \-\-artifactoryUseProxy                | \<true\|false\> | Whether Artifactory should be accessed through a proxy or not.                                                               | false |
|       | \-\-artifactoryParallelAnalysis        | \<true\|false\> | Whether the Artifactory analyzer should be run in parallel or not                                                            | true |
|       | \-\-artifactoryUsername                | \<username\>    | The user name (only used with API token) to connect to Artifactory instance                                                  | &nbsp; |
|       | \-\-artifactoryApiToken                | \<token\>       | The API token to connect to Artifactory instance, only used if the username or the API key are not defined by artifactoryAnalyzerServerId,artifactoryAnalyzerUsername or artifactoryAnalyzerApiToken | &nbsp; |
|       | \-\-artifactoryBearerToken             | \<token\>       | The bearer token to connect to Artifactory instance                                                                          | &nbsp; |
|       | \-\-nexus                              | \<url\>         | The url to the Nexus Server's web service end point (example: http://domain.enterprise/nexus/service/local/). If not set the Nexus Analyzer will be disabled. | &nbsp; |
|       | \-\-nexusUsesProxy                     | \<true\|false\> | Whether or not the defined proxy should be used when connecting to Nexus.                                                    | true |
|       | \-\-disableNuspec                      |                 | Sets whether or not the .NET Nuget Nuspec Analyzer will be used.                                                             | false |
|       | \-\-disableNugetconf                   |                 | Sets whether or not the [experimental](../analyzers/index.html) .NET Nuget packages.config Analyzer will be used.            | false |
|       | \-\-disableAssembly                    |                 | Sets whether or not the .NET Assembly Analyzer should be used.                                                               | false |
|       | \-\-mono                               | \<path\>        | The path to Mono for .NET Assembly analysis on non-windows systems.                                                          | &nbsp; |
|       | \-\-bundleAudit                        |                 | The path to the bundle-audit executable.                                                                                     | &nbsp; |
|       | \-\-proxyserver                        | \<server\>      | The proxy server to use when downloading resources; see the [proxy configuration](../data/proxy.html) page for more information. | &nbsp; |
|       | \-\-proxyport                          | \<port\>        | The proxy port to use when downloading resources.                                                                            | &nbsp; |
|       | \-\-connectiontimeout                  | \<timeout\>     | The connection timeout (in milliseconds) to use when downloading resources.                                                  | &nbsp; |
|       | \-\-proxypass                          | \<pass\>        | The proxy password to use when downloading resources.                                                                        | &nbsp; |
|       | \-\-proxyuser                          | \<user\>        | The proxy username to use when downloading resources.                                                                        | &nbsp; |
|       | \-\-connectionString                   | \<connStr\>     | The connection string to the database.                                                                                       | &nbsp; |
|       | \-\-dbDriverName                       | \<driver\>      | The database driver name.                                                                                                    | &nbsp; |
|       | \-\-dbDriverPath                       | \<path\>        | The path to the database driver; note, this does not need to be set unless the JAR is outside of the class path.             | &nbsp; |
|       | \-\-dbPassword                         | \<password\>    | The password for connecting to the database.                                                                                 | &nbsp; |
|       | \-\-dbUser                             | \<user\>        | The username used to connect to the database.                                                                                | &nbsp; |
| \-d   | \-\-data                               | \<path\>        | The location of the data directory used to store persistent data. This option should generally not be set.                   | &nbsp; |
|       | \-\-purge                              |                 | Delete the local copy of the NVD. This is used to force a refresh of the data.                                               | &nbsp; |
