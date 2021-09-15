Tasks
====================

Task                                               | Description
---------------------------------------------------|-----------------------
[dependencyCheckAnalyze](configuration.html)       | Runs dependency-check against the project and generates a report.
dependencyCheckAggregate                           | Runs dependency-check against a multi-project build and generates a report.
[dependencyCheckUpdate](configuration-update.html) | Updates the local cache of the NVD data from NIST.
[dependencyCheckPurge](configuration-purge.html)   | Deletes the local copy of the NVD. This is used to force a refresh of the data.

Configuration:
====================

```groovy
buildscript {
    repositories {
        mavenCentral()
    }
    dependencies {
        classpath 'org.owasp:dependency-check-gradle:${project.version}'
    }
}
apply plugin: 'org.owasp.dependencycheck'

check.dependsOn dependencyCheckAggregate
```

Property             | Description                                                                                                        | Default Value
---------------------|--------------------------------------------------------------------------------------------------------------------|------------------
autoUpdate           | Sets whether auto-updating of the NVD CVE/CPE data is enabled. It is not recommended that this be turned to false. | true
analyzedTypes        | The default artifact types that will be analyzed.                                                                  | ['jar', 'aar', 'js', 'war', 'ear', 'zip']
cveValidForHours     | Sets the number of hours to wait before checking for new updates from the NVD.                                     | 4
format               | The report format to be generated (HTML, XML, CSV, JSON, JUNIT, SARIF, ALL).                                              | HTML
formats              | A list of report formats to be generated (HTML, XML, CSV, JSON, JUNIT, SARIF, ALL).                                       | &nbsp;
junitFailOnCVSS      | If using the JUNIT report format the junitFailOnCVSS sets the CVSS score threshold that is considered a failure.   | 0
failBuildOnCVSS      | Specifies if the build should be failed if a CVSS score equal to or above a specified level is identified. The default is 11; since the CVSS scores are 0-10, by default the build will never fail.  More information on CVSS scores can be found at the [NVD](https://nvd.nist.gov/vuln-metrics/cvss)| 11
failOnError          | Fails the build if an error occurs during the dependency-check analysis.                                           | true
outputDirectory      | The location to write the report(s). This directory will be located in the build directory.                        | build/reports
skipTestGroups       | When set to true (the default) all dependency groups that being with 'test' will be skipped.                       | true
suppressionFile      | The file path to the XML suppression file \- used to suppress [false positives](../general/suppression.html). The configured value can be a local file path, a URL to a suppression file, or even a reference to a file on the class path (see https://github.com/jeremylong/DependencyCheck/issues/1878#issuecomment-487533799) | &nbsp;
suppressionFiles     | A list of file paths to the XML suppression files \- used to suppress [false positives](../general/suppression.html). The configured values can be a local file path, a URL to a suppression file, or even a reference to a file on the class path (see https://github.com/jeremylong/DependencyCheck/issues/1878#issuecomment-487533799) | &nbsp;
hintsFile            | The file path to the XML hints file \- used to resolve [false negatives](../general/hints.html)                    | &nbsp;
skip                 | If set to true dependency-check analysis will be skipped.                                                          | false
skipConfigurations   | A list of configurations that will be skipped. This is mutually exclusive with the scanConfigurations property.    | `[]` which means no configuration is skipped.
scanConfigurations   | A list of configurations that will be scanned, all other configurations are skipped. This is mutually exclusive with the skipConfigurations property. | `[]` which implicitly means all configurations are scanned.
scanProjects         | A list of projects that will be scanned, all other projects are skipped. The list or projects to skip must include a preceding colon: `scanProjects = [':app']`. This is mutually exclusive with the `skipProjects` property. | `[]` which implicitly means all projects get scanned.
skipProjects         | A list of projects that will be skipped.  The list or projects to skip must include a preceding colon: `skipProjects = [':sub1']`. This is mutually exclusive with the `scanProjects` property. | `[]` which means no projects are skipped.
scanSet              | A list of directories that will be scanned for additional dependencies.                                            | ['src/main/resources','src/main/webapp', './package.json', './package-lock.json', './npm-shrinkwrap.json', './Gopkg.lock', './go.mod']

#### Example
```groovy
dependencyCheck {
    autoUpdate=false
    cveValidForHours=1
    format='ALL'
}
```

### Proxy Configuration

Config Group | Property          | Description                                | Default Value
-------------|-------------------|------------------------------------|------------------
proxy        | server            | The proxy server; see the [proxy configuration](../data/proxy.html) page for more information. | &nbsp;
proxy        | port              | The proxy port.                            | &nbsp;
proxy        | username          | Defines the proxy user name.               | &nbsp;
proxy        | password          | Defines the proxy password.                | &nbsp;
proxy        | nonProxyHosts     | The list of hosts that do not use a proxy. | &nbsp;

#### Example
```groovy
dependencyCheck {
    proxy {
        server=some.proxy.server
        port=8989
    }
}
```

### Advanced Configuration

The following properties can be configured in the dependencyCheck task. However, they are less frequently changed. One exception
may be the cvedUrl properties, which can be used to host a mirror of the NVD within an enterprise environment.
Note, if ANY of the cve configuration group are set - they should all be set to ensure things work as expected.

Config Group | Property          | Description                                                                                                  | Default Value                                                       |
-------------|-------------------|--------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------|
cve          | urlModified    | URL for the modified CVE JSON data feed.                                                                        | https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz |
cve          | urlBase        | Base URL for each year's CVE JSON data feed, the %d will be replaced with the year.                             | https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%d.json.gz       |
data         | directory         | Sets the data directory to hold SQL CVEs contents. This should generally not be changed.                     | &nbsp;                                                              |
data         | driver            | The name of the database driver. Example: org.h2.Driver.                                                     | &nbsp;                                                              |
data         | driverPath        | The path to the database driver JAR file; only used if the driver is not in the class path.                  | &nbsp;                                                              |
data         | connectionString  | The connection string used to connect to the database. See using a [database server](../data/database.html). | &nbsp;                                                              |
data         | username          | The username used when connecting to the database.                                                           | &nbsp;                                                              |
data         | password          | The password used when connecting to the database.                                                           | &nbsp;                                                              |

#### Example
```groovy
dependencyCheck {
    data {
        directory='d:/nvd'
    }
}
```

### Analyzer Configuration

In addition to the above, the dependencyCheck plugin can be configured to enable or disable specific
analyzers by configuring the `analyzers` section. Note, specific file type analyzers will automatically
disable themselves if no file types that they support are detected - so specifically disabling the
analyzers is likely not needed.

Config Group | Property              | Description                                                                                                       | Default Value
-------------|-----------------------|-------------------------------------------------------------------------------------------------------------------|------------------
analyzers    | experimentalEnabled   | Sets whether the [experimental analyzers](../analyzers/index.html) will be used. If not set to true the analyzers marked as experimental (see below) will not be used | false
analyzers    | archiveEnabled        | Sets whether the Archive Analyzer will be used.                                                                   | true
analyzers    | zipExtensions         | A comma-separated list of additional file extensions to be treated like a ZIP file, the contents will be extracted and analyzed. | &nbsp;
analyzers    | jarEnabled            | Sets whether Jar Analyzer will be used.                                                                           | true
analyzers    | centralEnabled        | Sets whether Central Analyzer will be used; by default in the Maven plugin this analyzer is disabled as all information gained from Central is already available in the build. | false
analyzers    | nexusEnabled          | Sets whether Nexus Analyzer will be used (requires Nexus Pro). This analyzer is superceded by the Central Analyzer; however, you can configure this to run against a Nexus Pro installation. | true
analyzers    | nexusUrl              | Defines the Nexus Server's web service end point (example http://domain.enterprise/service/local/). If not set the Nexus Analyzer will be disabled. | &nbsp;
analyzers    | nexusUsesProxy        | Whether or not the defined proxy should be used when connecting to Nexus.                                         | true
analyzers    | pyDistributionEnabled | Sets whether the [experimental](../analyzers/index.html) Python Distribution Analyzer will be used. `experimentalEnabled` must be set to true. | true
analyzers    | pyPackageEnabled      | Sets whether the [experimental](../analyzers/index.html) Python Package Analyzer will be used. `experimentalEnabled` must be set to true. | true
analyzers    | rubygemsEnabled       | Sets whether the [experimental](../analyzers/index.html) Ruby Gemspec Analyzer will be used. `experimentalEnabled` must be set to true. | true
analyzers    | opensslEnabled        | Sets whether or not the openssl Analyzer should be used.                                                          | true
analyzers    | nuspecEnabled         | Sets whether or not the .NET Nuget Nuspec Analyzer will be used.                                                  | true
analyzers    | nugetconfEnabled      | Sets whether or not the [experimental](../analyzers/index.html) .NET Nuget packages.config Analyzer will be used. `experimentalEnabled` must be set to true. | true
analyzers    | assemblyEnabled       | Sets whether or not the .NET Assembly Analyzer should be used.                                                    | true
analyzers    | msbuildEnabled        | Sets whether or not the MS Build Analyzer should be used.                                                         | true
analyzers    | pathToDotnet          | The path to dotnet core - needed on some systems to analyze .net assemblies.                                      | &nbsp;
analyzers    | cmakeEnabled          | Sets whether or not the [experimental](../analyzers/index.html) CMake Analyzer should be used. `experimentalEnabled` must be set to true. | true
analyzers    | autoconfEnabled       | Sets whether or not the [experimental](../analyzers/index.html) autoconf Analyzer should be used. `experimentalEnabled` must be set to true. | true
analyzers    | composerEnabled       | Sets whether or not the [experimental](../analyzers/index.html) PHP Composer Lock File Analyzer should be used. `experimentalEnabled` must be set to true. | true
analyzers    | cpanEnabled           | Sets whether or not the [experimental](../analyzers/index.html) Perl CPAN File Analyzer should be used. `experimentalEnabled` must be set to true. | true
analyzers    | nodeEnabled           | Sets whether or not the Node.js Analyzer should be used.                                                          | true
analyzers    | cocoapodsEnabled      | Sets whether or not the [experimental](../analyzers/index.html) Cocoapods Analyzer should be used. `experimentalEnabled` must be set to true. | true
analyzers    | swiftEnabled          | Sets whether or not the [experimental](../analyzers/index.html) Swift Package Manager Analyzer should be used. `experimentalEnabled` must be set to true. | true
analyzers    | swiftPackageResolvedEnabled | Sets whether or not the [experimental](../analyzers/index.html) Swift Package Resolved Analyzer should be used. `experimentalEnabled` must be set to true. | true
analyzers    | bundleAuditEnabled    | Sets whether or not the [experimental](../analyzers/index.html) Ruby Bundle Audit Analyzer should be used. `experimentalEnabled` must be set to true. | true
analyzers    | pathToBundleAudit     | The path to bundle audit.                                                                                         | &nbsp;
analyzers    | golangDepEnabled      | Sets whether or not the [experimental](../analyzers/index.html) Golang Dependency Analyzer should be used. `experimentalEnabled` must be set to true. | true
analyzers    | golangModEnabled      | Sets whether or not the [experimental](../analyzers/index.html) Goland Module Analyzer should be used; requies `go` to be installed. `experimentalEnabled` must be set to true. | true
analyzers    | pathToGo              | The path to `go`.                                                                                                 | &nbsp;

#### Additional Configuration

Config Group | Property              | Description                                                                                                       | Default Value
-------------|-----------------------|-------------------------------------------------------------------------------------------------------------------|------------------
artifactory  | enabled               | Sets whether Artifactory analyzer will be used.                                                                   | false
artifactory  | url                   | The Artifactory server URL.                                                                                       | &nbsp;
artifactory  | usesProxy             | Whether Artifactory should be accessed through a proxy or not.                                                    | false
artifactory  | parallelAnalysis      | Whether the Artifactory analyzer should be run in parallel or not.                                                | true
artifactory  | username              | The user name (only used with API token) to connect to Artifactory instance.                                      | &nbsp;
artifactory  | apiToken              | The API token to connect to Artifactory instance, only used if the username or the API key are not defined by artifactoryAnalyzerServerId,artifactoryAnalyzerUsername or artifactoryAnalyzerApiToken | &nbsp;
artifactory  | bearerToken           | The bearer token to connect to Artifactory instance.                                                              | &nbsp;
nodeAudit    | enabled               | Sets whether the Node Audit Analyzer should be used. This analyzer requires an internet connection.               | true
nodeAudit    | useCache              | Sets whether the Node Audit Analyzer should cache results locally.                                                | true
nodeAudit    | skipDevDependencies   | Sets whether the Node Audit Analyzer should skip devDependencies.                                                 | false
nodeAudit    | yarnEnabled           | Sets whether the Yarn Audit Analyzer should be used. This analyzer requires yarn and an internet connection.      | true
nodeAudit    | yarnPath              | Sets the path to the `yarn` executable.                                                                           | &nbsp;
retirejs     | enabled               | Sets whether the RetireJS Analyzer should be used.                                                                | true
retirejs     | forceupdate           | Sets whether the RetireJS Analyzer should update regardless of the `autoupdate` setting.                          | false
retirejs     | retireJsUrl           | The URL to the Retire JS repository.                                                                              | https://raw.githubusercontent.com/Retirejs/retire.js/master/repository/jsrepository.json
retirejs     | filterNonVulnerable   | Configures the RetireJS Analyzer to remove non-vulnerable JS dependencies from the report.                        | false
retirejs     | filters               | Configures the list of regular expessions used to filter JS files based on content.                               | &nbsp;
ossIndex     | enabled               | Sets whether [OSS Index Analyzer](../analyzers/oss-index-analyzer.html) will be used. This analyzer requires an internet connection. | true
ossIndex     | username              | The optional user name to connect to Sonatype's OSS Index.                                                        | &nbsp;
ossIndex     | password              | The password or API token to connect to Sonatype's OSS Index.                                                     | &nbsp;
slack        | enabled               | Whether or not slack notifications are enabled.                                                                   | false
slack        | webhookUrl            | The custom incoming webhook URL to receive notifications.                                                         | &nbsp;


#### Example
```groovy
dependencyCheck {
    analyzers {
        assemblyEnabled=false
        artifactory {
            enabled=true
            url='https://internal.artifactory.url'
        }
        retirejs {
            filters = ['(i)copyright Jeremy Long']
        }
    }
}
```
