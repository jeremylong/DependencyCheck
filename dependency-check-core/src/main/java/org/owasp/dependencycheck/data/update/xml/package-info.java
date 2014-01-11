/**
 * <html>
 * <head>
 * <title>org.owasp.dependencycheck.data.nvdcve.xml</title>
 * </head>
 * <body>
 * <p>Contains classes used to parse the NVD CVE XML file.</p>
 * <p>The basic use is that the Importer is called to import an NVD CVE file.
 * The Importer instantiates an Indexer object (which extends Index). The
 * Indexer creates a partial-unmarshalling SAX parser (implemented in the
 * NvdCveXmlFilter) that extracts VulnerabilityTypes (aka Entry) from the NVD
 * CVE data file and stores these into a Lucene Index.</p>
 * </body>
 * </html>
 */
package org.owasp.dependencycheck.data.update.xml;
