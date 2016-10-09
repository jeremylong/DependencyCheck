Configuration
====================
The dependency-check-purge task deletes the local copy of the NVD. This task
should rarely be used, if ever. This is included as a convenience method in
the rare circumstance that the local H2 database becomes corrupt.

```xml
<target name="dependency-check-purge" description="Dependency-Check purge">
    <dependency-check-purge />
</target>
```

Configuration: dependency-check-purge Task
--------------------
The following properties can be set on the dependency-check-purge task.

Property              | Description                                                            | Default Value
----------------------|------------------------------------------------------------------------|------------------
dataDirectory         | Data directory that is used to store the local copy of the NVD         | data
failOnError           | Whether the build should fail if there is an error executing the purge | true
