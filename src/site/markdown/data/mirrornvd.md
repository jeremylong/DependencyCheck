Mirroring External Resources
============================================================
If an organization blocks the servers performing dependency-check scans from
downloading content on the internet they will need to mirror two data sources:
The NVD JSON data feeds and the Retire JS repository.


Mirroring the NVD from NIST
------------------------------------------------------------
Several organizations have opted to mirror the NVD on an internal server
and have the dependency-check clients simply pull the updates from the
mirror. This setup is fairly simple:

<ol>
<li>Setup a nightly job to pull down the latest NVD files files from NIST
 <ul>
   <li>Note, both the *.json.gz and *.meta files for the JSON data feeds must be downloaded/mirrored from the NVD.</li>
   <li>See the <a href="https://github.com/stevespringett/nist-data-mirror/">Nist-Data-Mirror</a> project on github.</li>
 </ul>
</li>
<li>Configure the dependency-check clients to use the internal CVE urls. Note, both URLs
   must be specified (see the configuration for the specific dependency-check client used):
   <ul>
     <li>cveUrlModified</li>
     <li>cveUrlBase</li>
   </ul>
</li>
</ol>

Mirroring Retire JS Repository
------------------------------------------------------------
The Retire JS Respository is located at:

```
https://raw.githubusercontent.com/Retirejs/retire.js/master/repository/jsrepository.json
```

The Retire JS repository can be configured using the `retireJsUrl` configuration option.
See the configuration for the specific dependency-check client used for more information.