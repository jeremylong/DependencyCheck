Node.js Analyzer
================

*Experimental*: This analyzer is considered experimental. While this analyzer may 
be useful and provide valid results more testing must be completed to ensure that
the false negative/false positive rates are acceptable. 

OWASP dependency-check includes an analyzer that will scan [Node Package Manager](https://www.npmjs.com/)
package specification files. The analyzer will collect as much information as
it can about the package. The information collected is internally referred to
as evidence and is grouped into vendor, product, and version buckets. Other
analyzers later use this evidence to identify any Common Platform Enumeration
(CPE) identifiers that apply.

*Note*: Consider using [Retire.js](http://retirejs.github.io/retire.js/) or the
Node Security Project auditing tool, [nsp](https://nodesecurity.io/tools) instead
of, or in addition to OWASP dependency-check to analyze Node.js packages.

Files Types Scanned: [package.json](https://docs.npmjs.com/files/package.json)
