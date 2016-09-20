Resolving False Negatives
====================
Due to how dependency-check identifies libraries false negatives may occur (a CPE was identified that is incorrect). Suppressing these false positives is fairly easy using the HTML report. In the report next to each CPE identified (and on CVE entries) there is a suppress button. Clicking the suppression button will create a dialogue box which you can simple hit Control-C to copy the XML that you would place into a suppression XML file. If this is the first time you are creating the suppression file you should click the "Complete XML Doc" button on the top of the dialogue box to add the necessary schema elements.

A sample hints file would look like:

```xml
<?xml version="1.0" encoding="UTF-8"?>

```
The above XML file will

The following shows some other ways to

```xml
<?xml version="1.0" encoding="UTF-8"?>

```

The full schema for hints files can be found here: [dependency-hint.xsd](https://github.com/jeremylong/DependencyCheck/blob/master/dependency-check-core/src/main/resources/schema/dependency-hint.1.1.xsd "Hint Schema")

Please see the appropriate configuration option in each interfaces configuration guide:

-  [Command Line Tool](../dependency-check-cli/arguments.html)
-  [Maven Plugin](../dependency-check-maven/configuration.html)
-  [Ant Task](../dependency-check-ant/configuration.html)
-  [Jenkins Plugin](../dependency-check-jenkins/index.html)
