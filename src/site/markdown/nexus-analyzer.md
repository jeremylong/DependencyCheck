Nexus Analyzer
==============

Dependency Check includes an analyzer which will check for the Maven GAV
(Group/Artifact/Version) information for artifacts in the scanned area. By
default the information comes from [Maven Central][1], but can be configured to
use a local repository if necessary. If the artifact's hash is found in the
configured Nexus repository, its GAV is recorded as an Identifier and the Group
is collected as Vendor evidence, the Artifact is collected as Product evidence,
and the Version is collected as Version evidence.

Default Configuration
---------------------

By default, the Nexus analyzer uses the [Sonatype Nexus Repository][2] to search
for SHA-1 hashes of dependencies. If the proxy is configured for Dependency
Check, that proxy is used in order to connect to the Nexus Central repository.
So if you're using `--proxyurl` on the command-line, the `proxyUrl` setting in
the Maven plugin, or the `proxyUrl` attribute in the Ant task, that proxy will
be used by default. Also, the proxy port, user, and password configured globally
are used as well.

Overriding Defaults
-------------------

If you have an internal Nexus repository you want to use, Dependency Check can
be configured to use this repository rather than Sonatype. This needs to be a
Nexus repository (support for Artifactory is planned). For a normal installation
of Nexus, you would append `/service/local/` to the root of the URL to your
Nexus repository. This URL can be set as:

* `analyzer.nexus.url` in `dependencycheck.properties`
* `--nexus <url>` in the CLI
* The `nexusUrl` property in the Maven plugin
* The `nexusUrl` attribute in the Ant task

If this repository is internal and should not use the proxy, you can disable the
proxy for just the Nexus analyzer. Setting this makes no difference if a proxy
is not configured.

* `analyzer.nexus.proxy=false` in `dependencycheck.properties`
* `--nexusUsesProxy false` in the CLI
* The `nexusUsesProxy` property in the Maven plugin
* The `nexusUsesProxy` attribute in the Ant task

Finally, the Nexus analyzer can be disabled altogether.

* `analyzer.nexus.enabled=false` in `dependencycheck.properties`
* `--disableNexus` in the CLI
* `nexusAnalyzerEnabled` property in the Maven plugin
* `nexusAnalyzerEnabled` attribute in the Ant task

Logging
-------

You may see a log message similar to the following during analysis:

    Mar 31, 2014 9:15:12 AM org.owasp.dependencycheck.analyzer.NexusAnalyzer initializeFileTypeAnalyzer
    WARNING: There was an issue getting Nexus status. Disabling analyzer.

At the beginning of analysis, a check is made by the Nexus analyzer to see if it
is able to reach the configured Nexus service, and if it cannot be reached, the
analyzer will be disabled. If you see this message, you can use the
configuration settings described above to resolve the issue, or disable the
analyzer altogether.

[1]: http://search.maven.org/            "Maven Central"
[2]: https://repository.sonatype.org/    "Sonatype Nexus Repository"
