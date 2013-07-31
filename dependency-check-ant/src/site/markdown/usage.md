Usage
====================
First, add the dependency-check-ant taskdef to your build.xml:

```xml
<taskdef name="dependency-check" classname="org.owasp.dependencycheck.taskdefs.DependencyCheckTask"/>
```

Next, add the task to a target of your choosing:

```xml
<target name="dependency-check" description="Dependency-Check Analysis">
    <dependency-check applicationname="Hello World"
                      autoupdate="true"
                      reportoutputdirectory="${basedir}"
                      reportformat="HTML">

        <fileset dir="lib">
            <include name="**/*.jar"/>
        </fileset>
    </dependency-check>
</target>
```

See the [configuration guide](configuration.html) for more information.
