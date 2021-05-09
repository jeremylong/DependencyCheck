Archive Analyzer
==============

OWASP dependency-check includes an analyzer an archive analyzer that will attempt
to extract files from the archive that are supported by the other file type
analyzers.

Files Types Scanned: ZIP, EAR, WAR, JAR, SAR, APK, NUPKG, TAR, GZ, TGZ, RPM

Additional file extensions for ZIP archives can be added, see the configuration
section in the Maven, Ant, or CLI interfaces for more information on configuration.

Note, since this analyzer does examine the contents of a JAR file there are times
that you may see additional entries in the report and/or warnings in the log file (if used)
for DLL or EXE files contained within the JAR file. In almost all cases these can
be ignored as it is fairly rare to have a .NET dll or exe within a JAR file.
