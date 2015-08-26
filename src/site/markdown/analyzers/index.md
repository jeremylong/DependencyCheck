File Type Analyzers
====================
OWASP dependency-check contains several file type analyzers that are used
to extract identification information from the files analyzed.

| Analyzer | File Types Scanned | Analysis Method |
| -------- | ------------------ | --------------- |
| [Archive Analyzer](./archive-analyzer.html) | Zip archive format (\*.zip, \*.ear, \*.war, \*.jar, \*.sar, \*.apk, \*.nupkg); Tape Archive Format (\*.tar); Gzip format (\*.gz, \*.tgz); Bzip2 format (\*.bz2, \*.tbz2) | Extracts archive contents, then scans contents with all available analyzers. |
| [Assembly Analyzer](./assembly-analyzer.html) | .NET Assemblies (\*.exe, \*.dll) | Uses [GrokAssembly.exe](https://github.com/colezlaw/GrokAssembly), which requires .NET Framework or Mono runtime to be installed. |
| [Autoconf Analyzer](./autoconf-analyzer.html) | Autoconf project configuration files (configure, configure.in, configure.ac) | Regex scan for AC_INIT metadata, including in generated configuration script. |
| [Central Analyzer](./central-analyzer.html) | Java archive files (\*.jar) | Searches Maven Central or a configured Nexus repository for the file's SHA1 hash. |
| [Jar Analyzer](./jar-analyzer.html) | Java archive files (\*.jar); Web application archive (\*.war) | Examines archive manifest metadata, and Maven Project Object Model files (pom.xml). |
| [Nexus Analyzer](./nexus-analyzer.html) | Java archive files (\*.jar) | Searches Sonatype or a configured Nexus repository for the file's SHA1 hash. In most cases, superceded by Central Analyzer. |
| [Node.js Package Analyzer](./nodejs-analyzer.html) | NPM package specification files (package.json) | Parse JSON format for metadata. |
| [Nuspec Analyzer](./nuspec-analyzer.html) | Nuget package specification file (\*.nuspec) | Uses XPath to parse specification XML. |
| [OpenSSL Analyzer](./openssl-analyzer.html) | OpenSSL Version Source Header File (opensslv.h) | Regex parse of the OPENSSL_VERSION_NUMBER macro definition. |
| [Python Analyzer](./python-analyzer.html) | Python source files (\*.py); Package metadata files (PKG-INFO, METADATA); Package Distribution Files (\*.whl, \*.egg, \*.zip) | Regex scan of Python source files for setuptools metadata; Parse RFC822 header format for metadata in all other artifacts. |
