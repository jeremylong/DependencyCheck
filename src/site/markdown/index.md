About
====================
Dependency-check is an open source solution the OWASP Top 10 2013 entry: [A9 -
Using Components with Known Vulnerabilities](https://www.owasp.org/index.php/Top_10_2013-A9-Using_Components_with_Known_Vulnerabilities).
Dependency-check can currently be used to scan Java applications (and their
dependent libraries) to identify known vulnerable components.

The problem with using known vulnerable components was covered in a paper by Jeff
Williams and Arshan Dabirsiaghi titled, "[The Unfortunate Reality of Insecure
Libraries](https://www.aspectsecurity.com/uploads/downloads/2012/03/Aspect-Security-The-Unfortunate-Reality-of-Insecure-Libraries.pdf)".
The gist of the paper is that we as a development community include third party
libraries in our applications that contain well known published vulnerabilities
\(such as those at the [National Vulnerability Database](http://web.nvd.nist.gov/view/vuln/search)\).

More information about dependency-check can be found here:

* [How does dependency-check work](./internals.html)
* [How to read the report](./thereport.html)

**IMPORTANT NOTE**: Dependency-check automatically updates itself using the NVD Data Feeds hosted by
NIST. **The initial download of the data may take fifteen minutes
or more**, if you run the tool at least once every seven days only a small XML file
needs to be downloaded to keep the local copy of the data current.

Dependency-check's core analysis library is exposed in various forms:

-  [Command Line Tool](dependency-check-cli/index.html)
-  [Maven Plugin](dependency-check-maven/usage.html)
-  [Ant Task](dependency-check-ant/installation.html)
-  [Jenkins Plugin](dependency-check-jenkins/index.html)
