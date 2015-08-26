Node.js Analyzer
================

OWASP dependency-check includes an analyzer that will scan [Node Package Manager](https://www.npmjs.com/)
package specification files. The analyzer(s) will collect as much information
it can about the package. The information collected is internally referred to
as evidence and is grouped into vendor, product, and version buckets. Other
analyzers later use this evidence to identify any Common Platform Enumeration
(CPE) identifiers that apply.

__Note:__ Also consider using the Node Security Project auditing tool,
[nsp](https://nodesecurity.io/tools).

Files Types Scanned: [package.json](https://docs.npmjs.com/files/package.json)
