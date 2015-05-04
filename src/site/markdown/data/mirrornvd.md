Mirroring the NVD from NIST
===========================
Several organizations have opted to mirror the NVD on an internal server
and have the dependency-check clients simply pull the updates from the
mirror. This setup is fairly simple:

1) Setup a nightly job to pull down the latest NVD files files from NIST
 * See the [Nist-Data-Mirror](https://github.com/stevespringett/nist-data-mirror/)
   project on github.
 * All of the NVD
2) Configure the dependency-check clients to use the internal CVE urls. Note, all four URLs
   must be specified (see the configuration for the specific dependency-check client used):
 * cveUrl12Modified
 * cveUrl20Modified
 * cveUrl12Base
 * cveUrl20Base
