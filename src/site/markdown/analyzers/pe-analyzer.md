PE Analyzer
==============

OWASP dependency-check includes an analyzer that scans PE dll and exe files and 
collect as much information it can about the files as it can. The information collected
from the PE headers and is internally referred to as evidence and is grouped into vendor,
product, and version buckets. Other analyzers later use this evidence to identify any
Common Platform Enumeration (CPE) identifiers that apply.

Files Types Scanned: EXE, DLL
