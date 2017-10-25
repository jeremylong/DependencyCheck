Node.js Analyzer
================

*Retired*: This analyzer has been retired due to an extremely high false positive
rate. 

OWASP dependency-check includes an analyzer that will scan [Node Package Manager](https://www.npmjs.com/)
package specification files. The analyzer will collect as much information as
it can about the package. The information collected is internally referred to
as evidence and is grouped into vendor, product, and version buckets. Other
analyzers later use this evidence to identify any Common Platform Enumeration
(CPE) identifiers that apply.

Files Types Scanned: [package.json](https://docs.npmjs.com/files/package.json)
