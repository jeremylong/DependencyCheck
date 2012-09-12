About:
DependencyCheck is a simple utility that attempts to detect publically disclosed
vulnerabilities contained within project dependencies. It does this by determining
if there is a Common Product Enumeration (CPE) identifier for a given dependency. 
If found, it will generate a report linking to the associated CVE entries.

Usage:
$ mvn package
$ cd target
$ java -jar dependencycheck-0.1.jar -h
$ java -jar DependencyCheck-0.1.jar -a Testing -out . -scan ./test-classes/org.mortbay.jetty.jar -scan struts2-core-2.1.2.jar -scan ./lib


Author: Jeremy Long (jeremy.long@gmail.com)

Copyright (c) 2012 Jeremy Long. All Rights Reserved.
