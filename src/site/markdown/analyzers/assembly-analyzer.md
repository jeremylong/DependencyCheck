Assembly Analyzer
==============

OWASP dependency-check includes an analyzer that scans .NET dll and exe files and collect as
much information it can about the files as it can. The information collected
is internally referred to as evidence and is grouped into vendor, product, and version
buckets. Other analyzers later use this evidence to identify any Common Platform
Enumeration (CPE) identifiers that apply.

If dependency-check is being run on a linux system `mono-runtime` and `mono-devel` needs to be
installed for this analyzer to work.

Files Types Scanned: EXE, DLL
