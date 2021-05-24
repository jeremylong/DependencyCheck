Pip Analyzer
============

*Experimental*: This analyzer is considered experimental, and will
therefore be enabled only with the option `--enableExperimental`.
While this analyzer may be useful and provide valid results more
testing must be completed to ensure that the false negative/false
positive rates are acceptable.

OWASP dependency-check includes an analyzer that will scan Python Pip
artifacts called `requirements.txt`, commonly generated with a command
like:

    pip freeze > requirements.txt

The analyzer(s) will collect as much information it can about the
Python artifacts.  The information collected is internally referred to
as evidence and is grouped into vendor, product, and version buckets.
Other analyzers later use this evidence to identify any Common
Platform Enumeration (CPE) identifiers that apply.

Files Scanned: files named exactly `requirements.txt`.
