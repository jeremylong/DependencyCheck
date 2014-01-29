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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * Analyzer for getting company, product, and version information
 * from a .NET assembly. 
 *
 * @author colezlaw
 *
 */
public class AssemblyAnalyzer extends AbstractAnalyzer {
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
    private File grokAssemblyExe;
    /**
     * The DocumentBuilder for parsing the XML
     */
    private DocumentBuilder builder;
    /**
     * Logger
     */
    private static final Logger LOG = Logger.getLogger(AbstractAnalyzer.class.getName());
    
    /**
     * Performs the analysis on a single Dependency.
     * @param dependency the dependency to analyze
     * @param engine the engine to perform the analysis under
     * @throws AnalysisException if anything goes sideways
     */
    @Override
    public void analyze(Dependency dependency, Engine engine)
            throws AnalysisException {
        if (grokAssemblyExe == null) {
            LOG.warning("GrokAssembly didn't get deployed");
            return;
        }
        
        // Use file.separator as a wild guess as to whether this is Windows
        List<String> args = new ArrayList<String>();
        if (! "\\".equals(System.getProperty("file.separator"))) {
            args.add("mono");
        }
        args.add(grokAssemblyExe.getPath());
        args.add(dependency.getActualFilePath());
        ProcessBuilder pb = new ProcessBuilder(args);
        try {
            Process proc = pb.start();
            Document doc = builder.parse(proc.getInputStream());
            XPath xpath = XPathFactory.newInstance().newXPath();
            String version = xpath.evaluate("/assembly/version", doc);
            if (version != null) {
                dependency.getVersionEvidence().addEvidence(new Evidence("grokassembly", "version",
                        version, Confidence.HIGHEST));
            }
            
            String vendor = xpath.evaluate("/assembly/company", doc);
            if (vendor != null) {
                dependency.getVendorEvidence().addEvidence(new Evidence("grokassembly", "vendor",
                        vendor, Confidence.HIGH));
            }
            
            String product = xpath.evaluate("/assembly/product", doc);
            if (product != null) {
                dependency.getProductEvidence().addEvidence(new Evidence("grokassembly", "product",
                        product, Confidence.HIGH));
            }
            
            NodeList types = (NodeList)xpath.evaluate("/assembly/types/type/text()", doc, XPathConstants.NODESET);
            for (int i = 0; i < types.getLength(); i++) {
                Node type = types.item(i);
                // System.out.println(type.getTextContent());
            }
        } catch (IOException ioe) {
            throw new AnalysisException(ioe);
        } catch (SAXException saxe) {
            throw new AnalysisException("Couldn't parse GrokAssembly result", saxe);
        } catch (XPathExpressionException xpe) {
            // This shouldn't happen
            throw new AnalysisException(xpe);
        }
        
    }

    /**
     * Initialize the analyzer. In this case, extract GrokAssembly.exe
     * to a temporary location.
     */
    @Override
    public void initialize() throws Exception {
        super.initialize();
        File tempFile = File.createTempFile("GKA", ".exe");
        FileOutputStream fos = null;
        InputStream is = null;
        try {
            fos = new FileOutputStream(tempFile);
            is = AssemblyAnalyzer.class.getClassLoader().getResourceAsStream("GrokAssembly.exe");
            byte[] buff = new byte[4096];
            int bread = -1;
            while((bread = is.read(buff)) >= 0) {
                fos.write(buff, 0, bread);
            }
            grokAssemblyExe = tempFile;
            // Set the temp file to get deleted when we're done
            grokAssemblyExe.deleteOnExit();
            LOG.log(Level.INFO, "Extracted GrokAssembly.exe to {0}", grokAssemblyExe.getPath());
            builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        } finally {
            if (fos != null) {
                try { fos.close(); } catch (Exception e) {}
            }
            if (is != null) {
                try { is.close(); } catch (Exception e) {}
            }
        }
    }

    @Override
    public void close() throws Exception {
        super.close();
        try {
            grokAssemblyExe.delete();
        } catch (SecurityException se) {
            
        }
    }

    /**
     * Gets the set of extensions supported by this analyzer.
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
     * Gets whether the analyzer supports the provided extension.
     * @param extension the extension to check
     * @return whether the analyzer supports the extension
     */
    @Override
    public boolean supportsExtension(String extension) {
        return SUPORTED_EXTENSIONS.contains(extension);
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
}
