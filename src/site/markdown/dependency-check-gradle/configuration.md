Tasks
====================

Task                                                     | Description
---------------------------------------------------------|-----------------------
dependencyCheckAnalyze                                   | Runs dependency-check against the project and generates a report.
[dependencyCheckAggregate](configuration-aggregate.html) | Runs dependency-check against a multi-project build and generates a report.
[dependencyCheckUpdate](configuration-update.html)       | Updates the local cache of the NVD data from NIST.
[dependencyCheckPurge](configuration-purge.html)         | Deletes the local copy of the NVD. This is used to force a refresh of the data.

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

check.dependsOn dependencyCheckAnalyze
```

Property             | Description                        | Default Value
---------------------|------------------------------------|------------------
autoUpdate           | Sets whether auto-updating of the NVD CVE/CPE data is enabled. It is not recommended that this be turned to false. | true
cveValidForHours     | Sets the number of hours to wait before checking for new updates from the NVD.                                     | 4
failOnError          | Fails the build if an error occurs during the dependency-check analysis.                                           | true
failBuildOnCVSS      | Specifies if the build should be failed if a CVSS score equal to or above a specified level is identified. The default is 11; since the CVSS scores are 0-10, by default the build will never fail. | 11
format               | The report format to be generated (HTML, XML, CSV, JSON, VULN, ALL).                                               | HTML
outputDirectory      | The location to write the report(s). This directory will be located in the build directory.                        | build/reports
skipTestGroups       | When set to true (the default) all dependency groups that being with 'test' will be skipped.                       | true
suppressionFile      | The file path to the XML suppression file \- used to suppress [false positives](../general/suppression.html)       | &nbsp;
hintsFile            | The file path to the XML hints file \- used to resolve [false negatives](../general/hints.html)                    | &nbsp;
skip                 | If set to true dependency-check analysis will be skipped.                                                          | false
skipConfigurations   | A list of configurations that will be skipped. This is mutually exclusive with the scanConfigurations property.    | `[]` which means no configuration is skipped.
scanConfigurations   | A list of configurations that will be scanned, all other configurations are skipped. This is mutually exclusive with the skipConfigurations property.    | `[]` which implicitly means all configurations get scanned.

#### Example
```groovy
dependencyCheck {
    autoUpdate=false
    cveValidForHours=1
    format='ALL'
}
```

### Proxy Configuration

Config Group | Property          | Description                        | Default Value
-------------|-------------------|------------------------------------|------------------
proxy        | server            | The proxy server; see the [proxy configuration](../data/proxy.html) page for more information. | &nbsp;
proxy        | port              | The proxy port.                    | &nbsp;
proxy        | username          | Defines the proxy user name.       | &nbsp;
proxy        | password          | Defines the proxy password.        | &nbsp;

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

Config Group | Property          | Description                                                                                 | Default Value
-------------|-------------------|---------------------------------------------------------------------------------------------|------------------
cve          | url12Modified     | URL for the modified CVE 1.2.                                                               | https://nvd.nist.gov/feeds/xml/cve/1.2/nvdcve-modified.xml.gz
cve          | url20Modified     | URL for the modified CVE 2.0.                                                               | https://nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-Modified.xml.gz
cve          | url12Base         | Base URL for each year's CVE 1.2, the %d will be replaced with the year.                    | https://nvd.nist.gov/feeds/xml/cve/1.2/nvdcve-%d.xml.gz
cve          | url20Base         | Base URL for each year's CVE 2.0, the %d will be replaced with the year.                    | https://nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-%d.xml.gz
data         | directory         | Sets the data directory to hold SQL CVEs contents. This should generally not be changed.    | &nbsp;
data         | driver            | The name of the database driver. Example: org.h2.Driver.                                    | &nbsp;
data         | driverPath        | The path to the database driver JAR file; only used if the driver is not in the class path. | &nbsp;
data         | connectionString  | The connection string used to connect to the database.                                      | &nbsp;
data         | username          | The username used when connecting to the database.                                          | &nbsp;
data         | password          | The password used when connecting to the database.                                          | &nbsp;

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
analyzers    | centralEnabled        | Sets whether Central Analyzer will be used. If this analyzer is being disabled there is a good chance you also want to disable the Nexus Analyzer (see below). | true
analyzers    | nexusEnabled          | Sets whether Nexus Analyzer will be used (requires Nexus Pro). This analyzer is superceded by the Central Analyzer; however, you can configure this to run against a Nexus Pro installation. | true
analyzers    | nexusUrl              | Defines the Nexus Server's web service end point (example http://domain.enterprise/service/local/). If not set the Nexus Analyzer will be disabled. | &nbsp;
analyzers    | nexusUsesProxy        | Whether or not the defined proxy should be used when connecting to Nexus.                                         | true
analyzers    | pyDistributionEnabled | Sets whether the [experimental](../analyzers/index.html) Python Distribution Analyzer will be used.               | true
analyzers    | pyPackageEnabled      | Sets whether the [experimental](../analyzers/index.html) Python Package Analyzer will be used.                    | true
analyzers    | rubygemsEnabled       | Sets whether the [experimental](../analyzers/index.html) Ruby Gemspec Analyzer will be used.                      | true
analyzers    | opensslEnabled        | Sets whether or not the openssl Analyzer should be used.                                                          | true
analyzers    | nuspecEnabled         | Sets whether or not the .NET Nuget Nuspec Analyzer will be used.                                                  | true
analyzers    | assemblyEnabled       | Sets whether or not the .NET Assembly Analyzer should be used.                                                    | true
analyzers    | pathToMono            | The path to Mono for .NET assembly analysis on non-windows systems.                                               | &nbsp;
analyzers    | cmakeEnabled          | Sets whether or not the [experimental](../analyzers/index.html) CMake Analyzer should be used.                    | true
analyzers    | autoconfEnabled       | Sets whether or not the [experimental](../analyzers/index.html) autoconf Analyzer should be used.                 | true
analyzers    | composerEnabled       | Sets whether or not the [experimental](../analyzers/index.html) PHP Composer Lock File Analyzer should be used.   | true
analyzers    | nodeEnabled           | Sets whether or not the [retired](../analyzers/index.html) Node.js Analyzer should be used.                  | true
analyzers    | nspEnabled            | Sets whether the NSP Analyzer should be used.                                                                     | true
analyzers    | cocoapodsEnabled      | Sets whether or not the [experimental](../analyzers/index.html) Cocoapods Analyzer should be used.                | true
analyzers    | swiftEnabled          | Sets whether or not the [experimental](../analyzers/index.html) Swift Package Manager Analyzer should be used.    | true
analyzers    | bundleAuditEnabled    | Sets whether or not the [experimental](../analyzers/index.html) Ruby Bundle Audit Analyzer should be used.        | true
analyzers    | pathToBundleAudit     | The path to bundle audit.                                                                                         | &nbsp;
analyzers    | retiredEnabled        | Sets whether the [retired analyzers](../analyzers/index.html) will be used. If not set to true the analyzers marked as experimental (see below) will not be used | false

#### Additional Analyzer Configuration

Config Group | Property              | Description                                                                                                       | Default Value
-------------|-----------------------|-------------------------------------------------------------------------------------------------------------------|------------------
artifactory  | enabled               | Sets whether Artifactory analyzer will be used                                                                    | false
artifactory  | url                   | The Artifactory server URL.                                                                                       | &nbsp;
artifactory  | usesProxy             | Whether Artifactory should be accessed through a proxy or not.                                                    | false
artifactory  | parallelAnalysis      | Whether the Artifactory analyzer should be run in parallel or not.                                                | true
artifactory  | username              | The user name (only used with API token) to connect to Artifactory instance.                                      | &nbsp;
artifactory  | apiToken              | The API token to connect to Artifactory instance, only used if the username or the API key are not defined by artifactoryAnalyzerServerId,artifactoryAnalyzerUsername or artifactoryAnalyzerApiToken | &nbsp;
artifactory  | bearerToken           | The bearer token to connect to Artifactory instance                                                               | &nbsp;
retirejs     | enabled               | Sets whether the [experimental](../analyzers/index.html) RetireJS Analyzer should be used.                        | true
retirejs     | filterNonVulnerable   | Configures the RetireJS Analyzer to remove non-vulnerable JS dependencies from the report.                        | false
retirejs     | filters               | Configures the list of regular expessions used to filter JS files based on content.                               | &nbsp;


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
