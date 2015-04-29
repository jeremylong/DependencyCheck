Jar Analyzer
==============

OWASP dependency-check includes an analyzer that scans JAR files and collect as
much information it can about the file as it can. The information collected
is internally referred to as evidence and is grouped into vendor, product, and version
buckets. Other analyzers later use this evidence to identify any Common Platform
Enumeration (CPE) identifiers that apply. Additionally, if a POM is present
the analyzer will add the Maven group, artifact, and version (GAV).

Files Types Scanned: JAR, WAR
