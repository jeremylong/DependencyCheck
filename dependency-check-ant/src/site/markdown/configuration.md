Configuration
====================
To configure the dependency-check task you can add it to a target and include a
file based [resource collection](http://ant.apache.org/manual/Types/resources.html#collection)
such as a [FileSet](http://ant.apache.org/manual/Types/fileset.html), [DirSet](http://ant.apache.org/manual/Types/dirset.html),
or [FileList](http://ant.apache.org/manual/Types/filelist.html) that includes
the project's dependencies.

```xml
<target name="dependency-check" description="Dependency-Check Analysis">
    <dependency-check applicationname="Hello World"
                      reportoutputdirectory="${basedir}"
                      reportformat="ALL">

        <fileset dir="lib">
            <include name="**/*.jar"/>
        </fileset>
    </dependency-check>
</target>
```

Configuration
====================
The following properties can be set on the dependency-check-maven plugin.

Property             | Description                        | Default Value
---------------------|------------------------------------|------------------
autoUpdate           | Sets whether auto-updating of the NVD CVE/CPE data is enabled. It is not recommended that this be turned to false. | true
externalReport       | When using as a Site plugin this parameter sets whether or not the external report format should be used. | false
outputDirectory      | The location to write the report(s). Note, this is not used if generating the report as part of a `mvn site` build | 'target'
failBuildOnCVSS      | Specifies if the build should be failed if a CVSS score above a specified level is identified. The default is 11 which means since the CVSS scores are 0-10, by default the build will never fail.         | 11
format               | The report format to be generated (HTML, XML, VULN, ALL). This configuration option has no affect if using this within the Site plugin unless the externalReport is set to true. | HTML
logFile              | The file path to write verbose logging information. | &nbsp;
suppressionFile      | The file path to the XML suppression file \- used to suppress [false positives](../suppression.html) | &nbsp;
proxyUrl             | The Proxy URL.                     | &nbsp;
proxyPort            | The Proxy Port.                    | &nbsp;
proxyUsername        | Defines the proxy user name.       | &nbsp;
proxyPassword        | Defines the proxy password.        | &nbsp;
connectionTimeout    | The URL Connection Timeout.        | &nbsp;

Analyzer Configuration
====================
The following properties are used to configure the various file type analyzers.
These properties can be used to turn off specific analyzers if it is not needed.
Note, that specific analyzers will automatically disable themselves if no file
types that they support are detected - so specifically disabling them may not
be needed.

Property                | Description                        | Default Value
------------------------|------------------------------------|------------------
archiveAnalyzerEnabled  | Sets whether the Archive Analyzer will be used.                    | true
zipExtensions           | A comma-separated list of additional file extensions to be treated like a ZIP file, the contents will be extracted and analyzed. | &nbsp;
jarAnalyzer             | Sets whether Jar Analyzer will be used.                            | true
nexusAnalyzerEnabled    | Sets whether Nexus Analyzer will be used.                          | true
nexusUrl                | Defines the Nexus URL. | https://repository.sonatype.org/service/local/
nexusUsesProxy          | Whether or not the defined proxy should be used when connecting to Nexus. | true
nuspecAnalyzerEnabled  | Sets whether or not the .NET Nuget Nuspec Analyzer will be used.   | true
assemblyAnalyzerEnabled | Sets whether or not the .NET Assembly Analyzer should be used.     | true
pathToMono              | The path to Mono for .NET assembly analysis on non-windows systems | &nbsp;

Advanced Configuration
====================
The following properties can be configured in the plugin. However, they are less frequently changed. One exception
may be the cvedUrl properties, which can be used to host a mirror of the NVD within an enterprise environment.

Property             | Description                                                             | Default Value
---------------------|-------------------------------------------------------------------------|------------------
cveUrl12Modified     | URL for the modified CVE 1.2                                            | http://nvd.nist.gov/download/nvdcve-modified.xml
cveUrl20Modified     | URL for the modified CVE 2.0                                            | http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-modified.xml
cveUrl12Base         | Base URL for each year's CVE 1.2, the %d will be replaced with the year | http://nvd.nist.gov/download/nvdcve-%d.xml
cveUrl20Base         | Base URL for each year's CVE 2.0, the %d will be replaced with the year | http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-%d.xml
dataDirectory        | Data directory to hold SQL CVEs contents. This should generally not be changed.             | &nbsp;
databaseDriverName   | The name of the database driver. Example: org.h2.Driver.                                    | &nbsp;
databaseDriverPath   | The path to the database driver JAR file; only used if the driver is not in the class path. | &nbsp;
connectionString     | The connection string used to connect to the database.                                      | &nbsp;
databaseUser         | The username used when connecting to the database.                                          | &nbsp;
databasePassword     | The password used when connecting to the database.                                          | &nbsp;
