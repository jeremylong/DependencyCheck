if not "%JAVA_HOME%" == "" goto JAVA_HOME_DEFINED

:NO_JAVA_HOME
set XJC=xjc.exe
goto LAUNCH

:JAVA_HOME_DEFINED
set XJC="%JAVA_HOME%\bin\xjc.exe"
goto LAUNCH

:LAUNCH
%XJC% -extension -d ..\..\..\java -b "bindings.xml" -p "org.codesecure.dependencycheck.data.nvdcve.generated" -mark-generated "nvd-cve-feed_2.0.xsd"

echo --------------------------------------------------------------
echo IMPORTANT!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
echo You must add the following annotation to the VulnerabilityType
echo @XmlRootElement(name = "vulnerabilityType", namespace = "http://scap.nist.gov/schema/vulnerability/0.4")
echo --------------------------------------------------------------