CPAN File Analyzer
==============

*Experimental*: This analyzer is considered experimental. While this analyzer may 
be useful and provide valid results more testing must be completed to ensure that
the false negative/false positive rates are acceptable. 

OWASP dependency-check includes an analyzer that can scan a `cpanfile` to exact 
dependency information from Perl projects. The analyzer does not yet differentiate
develop and test dependencies from required dependencies. Nor does the
analyzer support `cpanfile.snapshot` files yet. Finally, version ranges are
not yet correctly handled either and only the first version in the range is used.
