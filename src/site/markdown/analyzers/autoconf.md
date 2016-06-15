Autoconf Analyzer
=================

*Experimental*: This analyzer is considered experimental. While this analyzer may 
be useful and provide valid results more testing must be completed to ensure that
the false negative/false positive rates are acceptable. 

OWASP dependency-check includes an analyzer that will scan Autoconf project
configuration files. The analyzer will collect as much information it can
about the project. The information collected is internally referred to as
evidence and is grouped into vendor, product, and version buckets. Other
analyzers later use this evidence to identify any Common Platform Enumeration
(CPE) identifiers that apply.

File names scanned: configure, configure.in, configure.ac
