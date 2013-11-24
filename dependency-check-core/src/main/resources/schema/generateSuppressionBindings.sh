#!/bin/sh

if [ -n "$JAVA_HOME" ]
then
    XJC="$JAVA_HOME/bin/xjc.exe"
else
    XJC=xjc.exe
fi

exec "$XJC" -extension -d ../../java -p "org.owasp.dependencycheck.jaxb.suppressions.generated" -mark-generated "suppression.xsd"
