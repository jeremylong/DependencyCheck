NVD CVE Download Failures
=========================
In some installations of the JRE (such as  OpenJDK on CentOS/RHEL/Amazon Linux) do not
have the correct libraries to support EC cryptography. If you run into problems running
dependency-check you may need to install Bouncy Castle and configure Java to use the
more robust cryptographic provider.

Helpful Links
* [Stackoverflow discussion](http://stackoverflow.com/a/33521718/1995422)
* [Bouncy Castle](https://www.bouncycastle.org/java.html)