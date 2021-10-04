Tasks
====================

Task                                                     | Description
---------------------------------------------------------|-----------------------
[dependencyCheckAnalyze](configuration.html)             | Runs dependency-check against the project and generates a report.
[dependencyCheckAggregate](configuration-aggregate.html) | Runs dependency-check against a multi-project build and generates a report.
dependencyCheckUpdate                                    | Updates the local cache of the NVD data from NIST.
[dependencyCheckPurge](configuration-purge.html)         | Deletes the local copy of the NVD. This is used to force a refresh of the data.

Configuration
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

check.dependsOn dependencyCheckUpdate
```

Property             | Description                        | Default Value
---------------------|------------------------------------|------------------
cveValidForHours     | Sets the number of hours to wait before checking for new updates from the NVD.                                     | 4
failOnError          | Fails the build if an error occurs during the dependency-check analysis.                                           | true

#### Example
```groovy
dependencyCheck {
    cveValidForHours=1
}
```

### Proxy Configuration

Config Group | Property          | Description                                | Default Value
-------------|-------------------|--------------------------------------------|------------------
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
cve          | urlModified       | URL for the modified CVE JSON data feed.                                                                     | https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz |
cve          | urlBase           | Base URL for each year's CVE JSON data feed, the %d will be replaced with the year.                          | https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%d.json.gz       |
cve          | waitTime          | The time in milliseconds to wait between downloads from the NVD.                                             | 4000                                                                |
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
