#!/bin/sh

if [ -n "$JAVA_HOME" ]
then
    XJC="$JAVA_HOME/bin/xjc.exe"
else
    XJC=xjc.exe
fi

exec "$XJC" -extension -d ../../../java -p "org.codesecure.dependencycheck.analyzer.pom.generated" -mark-generated "maven-v4_0_0.xsd"
