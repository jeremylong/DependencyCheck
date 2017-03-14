Tasks
====================

Task                                                | Description
----------------------------------------------------|-----------------------
[dependencyCheck](configuration.html)               | Runs dependency-check against the project and generates a report.
[dependencyCheckUpdate](configuration-update.html)  | Updates the local cache of the NVD data from NIST.
dependencyCheckPurge                                | Deletes the local copy of the NVD. This is used to force a refresh of the data.

Configuration: dependencyCheckPurge
====================
The following properties can be configured for the dependencyCheckPurge task:

Property             | Description                        | Default Value
---------------------|------------------------------------|------------------
failOnError          | Fails the build if an error occurs during the dependency-check analysis.                                           | true

#### Example
```groovy
dependencyCheckPurge {
}
```

### Advanced Configuration

The following properties can be configured in the dependencyCheckPurge task. However, they are less frequently changed.

Config Group | Property          | Description                                                                                 | Default Value
-------------|-------------------|---------------------------------------------------------------------------------------------|------------------
data         | directory         | Sets the data directory to hold SQL CVEs contents. This should generally not be changed.    | &nbsp;

#### Example
```groovy
dependencyCheckPurge {
    data {
        directory='d:/nvd'
    }
}
```
