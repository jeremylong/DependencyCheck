#!/bin/sh

if [ -n "$JAVA_HOME" ]
then
    XJC="$JAVA_HOME/bin/xjc.exe"
else
    XJC=xjc.exe
fi

exec "$XJC" -extension -d ../../../java -b "bindings.xml" -p "org.codesecure.dependencycheck.data.nvdcve.generated" -mark-generated "nvd-cve-feed_2.0.xsd"

echo '--------------------------------------------------------------'
echo 'IMPORTANT!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'
echo 'You must add the following annotation to the VulnerabilityType'
echo '@XmlRootElement(name = "vulnerabilityType", namespace = "http://scap.nist.gov/schema/vulnerability/0.4")'
echo '--------------------------------------------------------------'