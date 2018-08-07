Node Audit Analyzer
================

OWASP dependency-check includes a Node Audit Analyzer that scans `package-lock.json`
files. The analyzer submits the lock files to the [NPM Audit](https://www.npmjs.com/) 
API for analysis, returning a list of advisories which get incorporated into the 
dependency check reports.

This analyzer is enabled by default and requires that the machine performing 
the analysis can reach out to the Internet.

Files Types Scanned: [package-lock.json](https://docs.npmjs.com/files/package-lock.json)
