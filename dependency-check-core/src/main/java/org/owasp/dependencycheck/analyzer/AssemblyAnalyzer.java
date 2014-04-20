/*
 * This file is part of dependency-check-core.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
import org.owasp.dependencycheck.utils.Settings;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

/**
 * Analyzer for getting company, product, and version information from a .NET assembly.
 *
 * @author colezlaw
 *
 */
public class AssemblyAnalyzer extends AbstractFileTypeAnalyzer {

    /**
     * The analyzer name
     */
    private static final String ANALYZER_NAME = "Assembly Analyzer";
    /**
     * The analysis phase
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.INFORMATION_COLLECTION;
    /**
     * The list of supported extensions
     */
    private static final Set<String> SUPORTED_EXTENSIONS = newHashSet("dll", "exe");
    /**
     * The temp value for GrokAssembly.exe
     */
    private File grokAssemblyExe = null;
    /**
     * The DocumentBuilder for parsing the XML
     */
    private DocumentBuilder builder;
    /**
     * Logger
     */
    private static final Logger LOGGER = Logger.getLogger(AssemblyAnalyzer.class.getName());

    /**
     * Builds the beginnings of a List for ProcessBuilder
     *
     * @return the list of arguments to begin populating the ProcessBuilder
     */
    private List<String> buildArgumentList() {
        // Use file.separator as a wild guess as to whether this is Windows
        final List<String> args = new ArrayList<String>();
        if (!"\\".equals(System.getProperty("file.separator"))) {
            if (Settings.getString(Settings.KEYS.ANALYZER_ASSEMBLY_MONO_PATH) != null) {
                args.add(Settings.getString(Settings.KEYS.ANALYZER_ASSEMBLY_MONO_PATH));
            } else {
                args.add("mono");
            }
        }
        args.add(grokAssemblyExe.getPath());

        return args;
    }

    /**
     * Performs the analysis on a single Dependency.
     *
     * @param dependency the dependency to analyze
     * @param engine the engine to perform the analysis under
     * @throws AnalysisException if anything goes sideways
     */
    @Override
    public void analyzeFileType(Dependency dependency, Engine engine)
            throws AnalysisException {
        if (grokAssemblyExe == null) {
            LOGGER.warning("GrokAssembly didn't get deployed");
            return;
        }

        final List<String> args = buildArgumentList();
        args.add(dependency.getActualFilePath());
        final ProcessBuilder pb = new ProcessBuilder(args);
        BufferedReader rdr = null;
        try {
            final Process proc = pb.start();
            // Try evacuating the error stream
            rdr = new BufferedReader(new InputStreamReader(proc.getErrorStream(), "UTF-8"));
            String line = null;
            while (rdr.ready() && (line = rdr.readLine()) != null) {
                LOGGER.log(Level.WARNING, "Error from GrokAssembly: {0}", line);
            }
            int rc = 0;
            final Document doc = builder.parse(proc.getInputStream());
            final XPath xpath = XPathFactory.newInstance().newXPath();

            // First, see if there was an error
            final String error = xpath.evaluate("/assembly/error", doc);
            if (error != null && !"".equals(error)) {
                throw new AnalysisException(error);
            }

            final String version = xpath.evaluate("/assembly/version", doc);
            if (version != null) {
                dependency.getVersionEvidence().addEvidence(new Evidence("grokassembly", "version",
                        version, Confidence.HIGHEST));
            }

            final String vendor = xpath.evaluate("/assembly/company", doc);
            if (vendor != null) {
                dependency.getVendorEvidence().addEvidence(new Evidence("grokassembly", "vendor",
                        vendor, Confidence.HIGH));
            }

            final String product = xpath.evaluate("/assembly/product", doc);
            if (product != null) {
                dependency.getProductEvidence().addEvidence(new Evidence("grokassembly", "product",
                        product, Confidence.HIGH));
            }

            try {
                rc = proc.waitFor();
            } catch (InterruptedException ie) {
                return;
            }
            if (rc == 3) {
                LOGGER.log(Level.INFO, "{0} is not a valid assembly", dependency.getActualFilePath());
                return;
            } else if (rc != 0) {
                LOGGER.log(Level.WARNING, "Return code {0} from GrokAssembly", rc);
            }

        } catch (IOException ioe) {
            throw new AnalysisException(ioe);
        } catch (SAXException saxe) {
            throw new AnalysisException("Couldn't parse GrokAssembly result", saxe);
        } catch (XPathExpressionException xpe) {
            // This shouldn't happen
            throw new AnalysisException(xpe);
        } finally {
            if (rdr != null) {
                try {
                    rdr.close();
                } catch (IOException ex) {
                    LOGGER.log(Level.FINEST, "ignore", ex);
                }
            }
        }
    }

    /**
     * Initialize the analyzer. In this case, extract GrokAssembly.exe to a temporary location.
     *
     * @throws Exception if anything goes wrong
     */
    @Override
    public void initializeFileTypeAnalyzer() throws Exception {
        final File tempFile = File.createTempFile("GKA", ".exe", Settings.getTempDirectory());
        FileOutputStream fos = null;
        InputStream is = null;
        try {
            fos = new FileOutputStream(tempFile);
            is = AssemblyAnalyzer.class.getClassLoader().getResourceAsStream("GrokAssembly.exe");
            final byte[] buff = new byte[4096];
            int bread = -1;
            while ((bread = is.read(buff)) >= 0) {
                fos.write(buff, 0, bread);
            }
            grokAssemblyExe = tempFile;
            // Set the temp file to get deleted when we're done
            grokAssemblyExe.deleteOnExit();
            LOGGER.log(Level.FINE, "Extracted GrokAssembly.exe to {0}", grokAssemblyExe.getPath());
        } catch (IOException ioe) {
            LOGGER.log(Level.WARNING, "Could not extract GrokAssembly.exe: {0}", ioe.getMessage());
            throw new AnalysisException("Could not extract GrokAssembly.exe", ioe);
        } finally {
            if (fos != null) {
                try {
                    fos.close();
                } catch (Throwable e) {
                    LOGGER.fine("Error closing output stream");
                }
            }
            if (is != null) {
                try {
                    is.close();
                } catch (Throwable e) {
                    LOGGER.fine("Error closing input stream");
                }
            }
        }

        // Now, need to see if GrokAssembly actually runs from this location.
        final List<String> args = buildArgumentList();
        BufferedReader rdr = null;
        try {
            final ProcessBuilder pb = new ProcessBuilder(args);
            final Process p = pb.start();
            // Try evacuating the error stream
            rdr = new BufferedReader(new InputStreamReader(p.getErrorStream(), "UTF-8"));
            String line;
            while (rdr.ready() && (line = rdr.readLine()) != null) {
                // We expect this to complain
            }
            final Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(p.getInputStream());
            final XPath xpath = XPathFactory.newInstance().newXPath();
            final String error = xpath.evaluate("/assembly/error", doc);
            if (p.waitFor() != 1 || error == null || "".equals(error)) {
                LOGGER.warning("An error occured with the .NET AssemblyAnalyzer, please see the log for more details.");
                LOGGER.fine("GrokAssembly.exe is not working properly");
                grokAssemblyExe = null;
                throw new AnalysisException("Could not execute .NET AssemblyAnalyzer");
            }
        } catch (Throwable e) {
            LOGGER.warning("An error occured with the .NET AssemblyAnalyzer; "
                    + "this can be ignored unless you are scanning .NET dlls. Please see the log for more details.");
            LOGGER.log(Level.FINE, "Could not execute GrokAssembly {0}", e.getMessage());
            throw new AnalysisException("An error occured with the .NET AssemblyAnalyzer", e);
        } finally {
            if (rdr != null) {
                try {
                    rdr.close();
                } catch (IOException ex) {
                    LOGGER.log(Level.FINEST, "ignore", ex);
                }
            }
        }

        builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
    }

    @Override
    public void close() throws Exception {
        super.close();
        try {
            if (grokAssemblyExe != null && !grokAssemblyExe.delete()) {
                grokAssemblyExe.deleteOnExit();
            }
        } catch (SecurityException se) {
            LOGGER.fine("Can't delete temporary GrokAssembly.exe");
        }
    }

    /**
     * Gets the set of extensions supported by this analyzer.
     *
     * @return the list of supported extensions
     */
    @Override
    public Set<String> getSupportedExtensions() {
        return SUPORTED_EXTENSIONS;
    }

    /**
     * Gets this analyzer's name.
     *
     * @return the analyzer name
     */
    @Override
    public String getName() {
        return ANALYZER_NAME;
    }

    /**
     * Returns the phase this analyzer runs under.
     *
     * @return the phase this runs under
     */
    @Override
    public AnalysisPhase getAnalysisPhase() {
        return ANALYSIS_PHASE;
    }

    /**
     * Returns the key used in the properties file to reference the analyzer's enabled property.
     *
     * @return the analyzer's enabled property setting key
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_ASSEMBLY_ENABLED;
    }
}
