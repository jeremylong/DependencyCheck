Nuspec Analyzer
==============

OWASP dependency-check includes an analyzer that will scan NuGet's Nuspec file to
collect information about the component being used. The evidence collected
is used by other analyzers to determine if there are any known vulnerabilities
associated with the component.

Note, the Nuspec Analyzer does not scan dependencies defined. However, if
the dependencies have been downloaded and may be included in the scan depending
on configuration.

Files Types Scanned: NUSPEC
