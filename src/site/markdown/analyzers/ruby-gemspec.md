Ruby Gemspec Analyzer
=====================

OWASP dependency-check includes an analyzer that will scan [Ruby Gem](https://rubygems.org/)
[specifications](http://guides.rubygems.org/specification-reference/). The
analyzer will collect as much information as it can about the Gem. The
information collected is internally referred to as evidence and is grouped
into vendor, product, and version buckets. Other analyzers later use this
evidence to identify any Common Platform Enumeration (CPE) identifiers that
apply.

__Note:__ Also consider using the Ruby 
[bundler-audit](https://github.com/rubysec/bundler-audit#readme) tool.

Files Types Scanned: Rakefile, \*.gemspec