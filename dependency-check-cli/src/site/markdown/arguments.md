Command Line Arguments
======================

The following table lists the command line arguments:

Short  | Argument&nbsp;Name&nbsp;&nbsp; | Parameter       | Description | Requirement
-------|-----------------------|-----------------|-------------|------------
 \-a   | \-\-app               | \<name\>        | The name of the application being scanned. This is a required argument. | Required
 \-s   | \-\-scan              | \<path\>        | The path to scan \- this option can be specified multiple times. It is also possible to specify specific file types that should be scanned by supplying a scan path of '[path]/[to]/[scan]/*.zip'. The wild card can only be used to denote any file-name with a specific extension. | Required
 \-o   | \-\-out               | \<folder\>      | The folder to write reports to. This defaults to the current directory. | Optional
 \-f   | \-\-format            | \<format\>      | The output format to write to (XML, HTML, VULN, ALL). The default is HTML. | Required
 \-l   | \-\-log               | \<file\>        | The file path to write verbose logging information. | Optional
 \-n   | \-\-noupdate          |                 | Disables the automatic updating of the CPE data. | Optional
       | \-\-suppression       | \<file\>        | The file path to the suppression XML file; used to suppress [false positives](../suppression.html). | Optional
 \-h   | \-\-help              |                 | Print the help message. | Optional
       | \-\-advancedHelp      |                 | Print the advanced help message. | Optional
 \-v   | \-\-version           |                 | Print the version information. | Optional

Advanced Options
================
Short  | Argument&nbsp;Name&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Parameter       | Description | Default&nbsp;Value
-------|-----------------------|-----------------|-------------|---------------
       | \-\-disableArchive    |                 | Sets whether the Archive Analyzer will be used.                      | false
       | \-\-zipExtensions     | \<strings\>     | A comma-separated list of additional file extensions to be treated like a ZIP file, the contents will be extracted and analyzed. | &nbsp;
       | \-\-disableJar        |                 | Sets whether Jar Analyzer will be used.                              | false
       | \-\-disableNexus      |                 | Sets whether Nexus Analyzer will be used.                            | false
       | \-\-nexus             | \<url\>         | The url to the Nexus Server. | https://repository.sonatype.org/service/local/
       | \-\-nexusUsesProxy    | \<true\|false\> | Whether or not the defined proxy should be used when connecting to Nexus. | true
       | \-\-disableNuspec     |                 | Sets whether or not the .NET Nuget Nuspec Analyzer will be used.     | false
       | \-\-disableAssembly   |                 | Sets whether or not the .NET Assembly Analyzer should be used.       | false
       | \-\-pathToMono        | \<path\>        | The path to Mono for .NET Assembly analysis on non-windows systems.  | &nbsp;
       | \-\-proxyserver       | \<server\>      | The proxy server to use when downloading resources. | &nbsp;
       | \-\-proxyport         | \<port\>        | The proxy port to use when downloading resources. | &nbsp;
       | \-\-connectiontimeout | \<timeout\>     | The connection timeout (in milliseconds) to use when downloading resources. | &nbsp;
       | \-\-proxypass         | \<pass\>        | The proxy password to use when downloading resources. | &nbsp;
       | \-\-proxyuser         | \<user\>        | The proxy username to use when downloading resources. | &nbsp;
       | \-\-connectionString  | \<connStr\>     | The connection string to the database. | &nbsp;
       | \-\-dbDriverName      | \<driver\>      | The database driver name. | &nbsp;
       | \-\-dbDriverPath      | \<path\>        | The path to the database driver; note, this does not need to be set unless the JAR is outside of the class path. | &nbsp;
       | \-\-dbPassword        | \<password\>    | The password for connecting to the database. | &nbsp;
       | \-\-dbUser            | \<user\>        | The username used to connect to the database. | &nbsp;
 \-d   | \-\-data              | \<path\>        | The location of the data directory used to store persistent data. This option should generally not be set. | &nbsp;
