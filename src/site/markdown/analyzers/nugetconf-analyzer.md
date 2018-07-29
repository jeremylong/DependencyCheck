Nugetconf Analyzer
==============

*Experimental*: This analyzer is considered experimental. While this analyzer may 
be useful and provide valid results more testing must be completed to ensure that
the false negative/false positive rates are acceptable. 

OWASP dependency-check includes an analyzer that will scan NuGet's packages.config files to
collect information about the component being used. The evidence collected
is used by other analyzers to determine if there are any known vulnerabilities
associated with the component.

Files Scanned: packages.config
