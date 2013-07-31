if not "%JAVA_HOME%" == "" goto JAVA_HOME_DEFINED

:NO_JAVA_HOME
set XJC=xjc.exe
goto LAUNCH

:JAVA_HOME_DEFINED
set XJC="%JAVA_HOME%\bin\xjc.exe"
goto LAUNCH

:LAUNCH
%XJC% -extension -d ..\..\..\java -p "org.owasp.dependencycheck.jaxb.pom.generated" -mark-generated "maven-v4_0_0.xsd"
