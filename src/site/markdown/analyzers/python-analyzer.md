Python Analyzer
==============

OWASP dependency-check includes an analyzer that will scan Python artifacts. The
analyzer(s) will collect as much information it can about the python artifacts.
The information collected is internally referred to as evidence and is grouped into
vendor, product, and version buckets. Other analyzers later use this evidence to
identify any Common Platform Enumeration (CPE) identifiers that apply.

Files Types Scanned: py, whl, egg, zip, PKG-INFO, and METADATA
