About
=====
Dependency-check-core is the primary library that contains analyzers used to scan
(java) application dependencies. The purpose of the analysis is to identify the
library used and subsequently report on any CVE entries related to the library.

The core engine can be extended by implementing new Analyzers; see the project
[wiki](https://github.com/jeremylong/DependencyCheck/wiki/Making-a-new-Analyzer)
for details.

The engine is currently exposed via:

- [Command Line Tool](../dependency-check-cli/index.html)
- [Maven Plugin](../dependency-check-maven/index.html)
- [Ant Task](../dependency-check-ant/index.html)
- [Jenkins Plugin](../dependency-check-jenkins/index.html)
