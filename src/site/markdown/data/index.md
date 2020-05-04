Internet Access Required
==================================
There are two reasons dependency-check needs access to the Internet. Below you will find
a discussion of each problem and possibly resolutions if you are facing organizational
constraints.

Local NVD Database
----------------------------------
OWASP dependency-check maintains a local copy of the NVD CVE data hosted by NIST. By default,
a local [H2 database](http://www.h2database.com/html/main.html) instance is used.
As each instance maintains its own copy of the NVD the machine will need access
to nvd.nist.gov in order to download the NVD data feeds. While the initial download of the NVD
data feed is large, if after the initial download the tool is run at least once every seven
days only two small XML files containing the recent modifications will need to be downloaded.

In some installations OpenJDK may not be able to download the NVD CVE data. Please see the
[TLS Failures article](./tlsfailure.html) for more information.

If your build servers are using dependency-check and are unable to access the Internet you
have a few options:

1. Configure the [proxy settings](proxy.html) so that the build server can access the Internet
2. [Mirror the NVD](./mirrornvd.html) locally within your organization
3. Use a more robust [centralized database](./database.html) with a single update node


## Downloading Additional Information

### Central Repository

If the machine that is running dependency-check cannot reach the [Central Repository](http://search.maven.org)
the analysis may result in false negatives. This is because some POM files, that are not
contained within the JAR file itself, contain evidence that is used to accurately identify
a library. If using the Ant plugin or CLI and Central cannot be reached, it is highly recommended to setup a
Nexus server within your organization and to configure dependency-check to use the local
Nexus server. **Notes:**
1. If using any build plugin except Ant - there is no benefit to setting up a Nexus server for use by dependency-check.
2. Even with a Nexus server setup we have seen dependency-check CLI be
re-directed to other repositories on the Internet to download the actual POM file; this
happened due to a rare circumstance where the Nexus instance used by dependency-check
was not the instance of Nexus used to build the application (i.e. the dependencies
were not actually present in the Nexus used by dependency-check).

### Retire JS Repository

The RetireJS Analyzes must download the RetireJS Repository. If this is blocked users
must either mirror the [JS Repository](./mirrornvd.html) or disable the Retire JS Analyzer.

### Sonatype OSS Index

OWASP dependency-check includes support to consult the [Sonatype OSS Index](https://ossindex.sonatype.org)
to enrich the report with supplemental vulnerability information.

For more details on this integration see [Sonatype OSS Index](./ossindex.html).
