Proxy Configuration
===================
All of the dependency-check clients (CLI, Maven, Gradle, Ant, Jenkins) can be configured
to use a proxy to connect to the Internet. See the configuration settings for each:

* [Maven Plugin](https://jeremylong.github.io/DependencyCheck/dependency-check-maven/configuration.html)
* [Gradle Plugin](https://jeremylong.github.io/DependencyCheck/dependency-check-gradle/configuration.html)
* [Ant Task](https://jeremylong.github.io/DependencyCheck/dependency-check-ant/configuration.html)
* [Command Line](https://jeremylong.github.io/DependencyCheck/dependency-check-cli/arguments.html)

Note, it may also be possible to use the core [Java proxy](https://docs.oracle.com/javase/8/docs/technotes/guides/net/proxies.html)
system properties instead of the configuration above.

Certificate Errors
------------------
In some cases if you setup a proxy the connection may still fail due to certificate
errors (see the log file from dependency-check). If you know which cert it's failing 
on (either your proxy or NVD/CVE) you can either add the certificate itself or the 
signing chain to your trust store. If you don't have access to modify the system 
trust store (in $JAVA_HOME/lib/security/cacerts) you can copy it elsewhere and 
import it using keytool, then specify that trust store on the command line 
(`mvn -Djavax.net.ssl.trustStore=/path/to/cacerts`) or if you need to always 
have that set, you can set the environment variable `JAVA_TOOL_OPTIONS` to have 
`-Djavax.net.ssl.trustStore=/path/to/cacerts`.

Still failing?
--------------
In some cases the proxy is configured to block `HEAD` requests. While an attempt
is made by dependency-check to identify this situation it does not appear to be
100% successful. As such, the last thing to try is to add the property 
`mvn -Ddownloader.quick.query.timestamp=false`.

If trying the above and it still fails please open a ticket in the 
[github repo](https://github.com/jeremylong/DependencyCheck/issues).