Node.js Analyzer
================

OWASP dependency-check includes a [Node Security Project (NSP)](https://nodesecurity.io)
analyzer that will scan `package.json` files. The analyzer will filter the given
package.json down to a specific white-list of allowed entries and submit the data
to the NSP for analysis.

This analyzer is enabled by default and requires that the machine performing the
analysis can reach out to the Internet.

White-list of entries sent to NSP include: name, version, engine, dependencies, 
devDependencies, optionalDependencies, peerDependencies, bundleDependencies, and
bundledDependencies

Files Types Scanned: [package.json](https://docs.npmjs.com/files/package.json)
