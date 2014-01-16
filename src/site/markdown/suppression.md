Suppressing False Positives
====================
Due to how dependency-check identifies libraries false positives may occur (a CPE was identified that is incorrect). Suppressing these false positives is fairly easy using the HTML report. In the report next to each CPE identified (and on CVE entries) there is a suppress button. Clicking the suppression button will create a dialogue box which you can simple hit Control-C to copy the XML that you would place into a suppression XML file. If this is the first time you are creating the suppression file you should click the "Complete XML Doc" button on the top of the dialogue box to add the necessary schema elements.

A sample suppression file would look like:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<suppressions xmlns="https://www.owasp.org/index.php/OWASP_Dependency_Check_Suppression">
   <suppress>
      <notes><![CDATA[
      file name: some.jar
      ]]></notes>
      <sha1>66734244CE86857018B023A8C56AE0635C56B6A1</sha1>
      <cpe>cpe:/a:apache:struts:2.0.0</cpe>
   </suppress>
</suppressions>
```
The above XML file will suppress the cpe:/a:apache:struts:2.0.0 from any file with the a matching SHA1 hash.

The full schema for suppression files can be found here: [suppression.xsd](https://github.com/jeremylong/DependencyCheck/blob/master/dependency-check-core/src/main/resources/schema/suppression.xsd "Suppression Schema")

Please see the appropriate configuration option in each interfaces configuration guide:

-  [Command Line Tool](dependency-check-cli/arguments.html)
-  [Maven Plugin](dependency-check-maven/configuration.html)
-  [Ant Task](dependency-check-ant/configuration.html)
-  [Jenkins Plugin](dependency-check-jenkins/index.html)
