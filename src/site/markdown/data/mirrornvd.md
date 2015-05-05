Mirroring the NVD from NIST
===========================
Several organizations have opted to mirror the NVD on an internal server
and have the dependency-check clients simply pull the updates from the
mirror. This setup is fairly simple:

<ol>
<li>Setup a nightly job to pull down the latest NVD files files from NIST
 <ul>
   <li>Note, all of the NVD files must be downloaded: both 1.2 and 2.0 schema for 2002 on.</li>
   <li>See the <a href="https://github.com/stevespringett/nist-data-mirror/">Nist-Data-Mirror</a> project on github.</li>
 </ul>
</li>
<li>Configure the dependency-check clients to use the internal CVE urls. Note, all four URLs
   must be specified (see the configuration for the specific dependency-check client used):
   <ul>
     <li>cveUrl12Modified</li>
     <li>cveUrl20Modified</li>
     <li>cveUrl12Base</li>
     <li>cveUrl20Base</li>
   </ul>
</li>
</ol>
