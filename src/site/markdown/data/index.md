Local Database Updates
====================
OWASP dependency-check maintains a local copy of the NVD data hosted by NIST. By default,
a local [H2 database](http://www.h2database.com/html/main.html) instance is used.
This works well for local storage of the NVD data used by dependency-check. This requires
each instance of dependency-check to create its own database and the machine will need access
to nvd.nist.gov in order to download the NVD data feeds. While the initial download of the NVD
data feed is large, if after the initial download the tool is run at least once every seven
days only two small XML files containing the recent modifications will need to be downloaded.

If your build servers are using dependency-check and are unable to access the Internet you
have a few options:

1) Configure the [proxy settings](proxy.md) so that the build server can access the Internet
2) [Mirror the NVD](./mirrornvd.md) locally within your organization
3) Use a more robust [centralized database](./database.md) with a single update node

However, if the machine that is running dependency-check cannot reach the [Central Repository](http://search.maven.org)
the analysis may result in false negatives. This is because some POM files, that are not
contained within the JAR file itself, contain evidence that is used to create an accurate
library identification. If Central cannot be reached, it is highly recommended to setup a
Nexus server within your organization and to configure dependency-check to use the local
Nexus server if the machine running dependency-check cannot connect to the Internet.
**Note**, even with a Nexus server setup I have seen dependency-check be directed to other
repositories on the Internet to download the actual POM file.
