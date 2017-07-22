Ruby Gemspec Analyzer
=====================

*Experimental*: This analyzer is considered experimental. While this analyzer may 
be useful and provide valid results more testing must be completed to ensure that
the false negative/false positive rates are acceptable. 

OWASP dependency-check includes an analyzer that will scan [Ruby Gem](https://rubygems.org/)
[specifications](http://guides.rubygems.org/specification-reference/). The
analyzer will collect as much information as it can about the Gem. The
information collected is internally referred to as evidence and is grouped
into vendor, product, and version buckets. Other analyzers later use this
evidence to identify any Common Platform Enumeration (CPE) identifiers that
apply.

*Note*: It is highly recommended that Ruby projects use
[bundler-audit](https://github.com/rubysec/bundler-audit#readme). It is possible
to incorporate the results of bundle-audit into the dependency-check report(s) by
using the [bundle-audit analyzer](./bundle-audit.html).

Files Types Scanned: Rakefile, \*.gemspec