OpenSSL Analyzer
================

OWASP dependency-check includes an analyzer that will scan OpenSSL source code
files for the OpenSSL version information. The information collected is
internally referred to as evidence and is grouped into vendor, product, and
version buckets. Other analyzers later use this evidence to identify any
Common Platform Enumeration (CPE) identifiers that apply.

File names scanned: opensslv.h