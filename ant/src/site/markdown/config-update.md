Configuration
====================
The dependency-check-update task downloads and updates the local copy of the NVD.
There are several reasons that one may want to use this task; primarily, creating
an update that will be run only once a day or once every few days (but not greater
than 7 days) and then use the `autoUpdate="false"` setting on individual
dependency-check scans. See [Internet Access Required](https://jeremylong.github.io/DependencyCheck/data/index.html)
for more information on why this task would be used.

```xml
<target name="dependency-check-update" description="Dependency-Check Update">
    <dependency-check-update />
</target>
```

Configuration: dependency-check-update Task
--------------------
The following properties can be set on the dependency-check task.

Property              | Description                                                             | Default Value
----------------------|-------------------------------------------------------------------------|------------------
proxyServer           | The Proxy Server.                                                       | &nbsp;
proxyPort             | The Proxy Port.                                                         | &nbsp;
proxyUsername         | Defines the proxy user name.                                            | &nbsp;
proxyPassword         | Defines the proxy password.                                             | &nbsp;
nonProxyHosts         | Defines the hosts that will not be proxied.                             | &nbsp;
connectionTimeout     | The URL Connection Timeout.                                             | &nbsp;
failOnError           | Whether the build should fail if there is an error executing the update | true

Advanced Configuration
====================
The following properties can be configured in the plugin. However, they are less frequently changed. One exception
may be the cvedUrl properties, which can be used to host a mirror of the NVD within an enterprise environment.

Property             | Description                                                                                                          | Default Value
---------------------|----------------------------------------------------------------------------------------------------------------------|------------------
cveUrlModified       | URL for the modified CVE JSON data feed. When mirroring the NVD you must mirror the *.json.gz and the *.meta files. Optional if your custom cveUrlBase is just a domain name change.  | https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz
cveUrlBase           | Base URL for each year's CVE JSON data feed, the %d will be replaced with the year.                                  | https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%d.json.gz
dataDirectory        | Data directory that is used to store the local copy of the NVD. This should generally not be changed.                | data
databaseDriverName   | The name of the database driver. Example: org.h2.Driver.                                                             | &nbsp;
databaseDriverPath   | The path to the database driver JAR file; only used if the driver is not in the class path.                          | &nbsp;
connectionString     | The connection string used to connect to the database. See using a [database server](../data/database.html).         | &nbsp;
databaseUser         | The username used when connecting to the database.                                                                   | &nbsp;
databasePassword     | The password used when connecting to the database.                                                                   | &nbsp;
