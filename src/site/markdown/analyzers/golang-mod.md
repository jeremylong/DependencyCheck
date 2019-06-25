Golang Mod Analyzer
==============

*Experimental*: This analyzer is considered experimental. While this analyzer may 
be useful and provide valid results more testing must be completed to ensure that
the false negative/false positive rates are acceptable. 

OWASP dependency-check includes an analyzer that will utilize `go mod` to determine
the go applications dependencies. Note, this requires that `go` is installed and
may require users to configure the path to `go` if it is not on the system path.

File names scanned: go.mod

