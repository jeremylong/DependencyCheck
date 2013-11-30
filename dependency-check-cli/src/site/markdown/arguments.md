Command Line Arguments
====================

The following table lists the command line arguments:

Short  | Argument Name         | Parameter   | Description | Requirement
-------|-----------------------|-------------|-------------|------------
 \-a   | \-\-app               | \<name\>    | The name of the application being scanned. This is a required argument. |
 \-c   | \-\-connectiontimeout | \<timeout\> | The connection timeout (in milliseconds) to use when downloading resources. | Optional
 \-d   | \-\-data              | \<path\>    | The location of the data directory used to store persistent data. This option should generally not be set. | Optional
 \-f   | \-\-format            | \<format\>  | The output format to write to (XML, HTML, VULN, ALL). The default is HTML. |
 \-h   | \-\-help              |             | Print the help message. | Optional
 \-l   | \-\-log               | \<file\>    | The file path to write verbose logging information. | Optional
 \-n   | \-\-noupdate          |             | Disables the automatic updating of the CPE data. | Optional
 \-o   | \-\-out               | \<folder\>  | The folder to write reports to. This defaults to the current directory. | Optional
 \-p   | \-\-proxyport         | \<port\>    | The proxy port to use when downloading resources. | Optional
 \-pp  | \-\-proxypass         | \<pass\>    | The proxy password to use when downloading resources. | Optional
 \-pu  | \-\-proxyuser         | \<user\>    | The proxy username to use when downloading resources. | Optional
 \-s   | \-\-scan              | \<path\>    | The path to scan \- this option can be specified multiple times. |
 \-sf  | \-\-suppression       | \<file\>    | The file path to the suppression XML file. | Optional
 \-u   | \-\-proxyurl          | \<url\>     | The proxy url to use when downloading resources. | Optional
 \-v   | \-\-version           |             | Print the version information. | Optional