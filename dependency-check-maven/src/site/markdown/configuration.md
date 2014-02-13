Configuration
====================
The following properties can be set on the dependency-check-maven plugin.

Property            | Description                        | Default Value
--------------------|------------------------------------|------------------
autoUpdate          | Sets whether auto-updating of the NVD CVE/CPE data is enabled. It is not recommended that this be turned to false. | true
externalReport      | When using as a Site plugin this parameter sets whether or not the external report format should be used. | false
failBuildOnCVSS     | Specifies if the build should be failed if a CVSS score above a specified level is identified. The default is 11 which means since the CVSS scores are 0-10, by default the build will never fail.         | 11
format              | The report format to be generated (HTML, XML, VULN, ALL). This configuration option has no affect if using this within the Site plugin unless the externalReport is set to true. | HTML
logFile             | The file path to write verbose logging information. |
suppressionFile     | The file path to the XML suppression file \- used to suppress [false positives](../suppression.html) |
connectionTimeout   | The Connection Timeout.            |
proxyUrl            | The Proxy URL.                     |
proxyPort           | The Proxy Port.                    |
proxyUsername       | Defines the proxy user name.       |
proxyPassword       | Defines the proxy password.        |
nexusAnalyzerEnabled  | The connection timeout used when downloading data files from the Internet. |
nexusUrl              | The connection timeout used when downloading data files from the Internet. |
databaseDriverName    | The name of the database driver. Example: org.h2.Driver. |
databaseDriverPath    | The path to the database driver JAR file; only used if the driver is not in the class path. |
connectionString      | The connection string used to connect to the database. |
databaseUser          | The username used when connecting to the database. |
databasePassword      | The password used when connecting to the database. |
extraExtensions      | List of extra extensions to be scanned. |
