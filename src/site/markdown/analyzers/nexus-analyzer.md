Nexus Analyzer
==============
**Requires Nexus Pro**

The Nexus Analyzer will check for the Maven GAV (Group/Artifact/Version) information
for artifacts in the scanned area. This is done by determining if an artifact exists
in a Nexus Pro installation using the SHA-1 hash of the artifact scanned. If the
artifact's hash is found in the configured Nexus repository, its GAV is recorded as
an Identifier and the Group is collected as Vendor evidence, the Artifact is
collected as Product evidence, and the Version is collected as Version evidence.

The Nexus Analyzer has been superceded by the Central Analyzer. If both the
Central Analyzer and Nexus Analyzer are enabled and the Nexus URL has not
been configured to point to an instance of Nexus Pro the Nexus Analyzer will
disable itself.

Logging
-------
You may see a log message similar to the following during analysis:

    Mar 31, 2014 9:15:12 AM org.owasp.dependencycheck.analyzer.NexusAnalyzer initializeFileTypeAnalyzer
    WARNING: There was an issue getting Nexus status. Disabling analyzer.

At the beginning of analysis, a check is made by the Nexus analyzer to see if it
is able to reach the configured Nexus service, and if it cannot be reached, the
analyzer will be disabled. If you see this message, you can use the configuration
settings described in either the CLI, Ant, Maven, or Jenkins plugins to resolve
the issue, or disable the analyzer altogether.

[1]: http://search.maven.org/            "Maven Central"
[2]: https://repository.sonatype.org/    "Sonatype Nexus Repository"
