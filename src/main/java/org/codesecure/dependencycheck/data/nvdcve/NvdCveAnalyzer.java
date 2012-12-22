package org.codesecure.dependencycheck.data.nvdcve;
/*
 * This file is part of DependencyCheck.
 *
 * DependencyCheck is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * DependencyCheck is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * DependencyCheck. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import org.apache.lucene.document.Document;
import org.apache.lucene.index.Term;
import org.apache.lucene.search.*;
import org.codesecure.dependencycheck.analyzer.AnalysisException;
import org.codesecure.dependencycheck.analyzer.AnalysisPhase;
import org.codesecure.dependencycheck.data.nvdcve.generated.VulnerabilityReferenceType;
import org.codesecure.dependencycheck.data.nvdcve.generated.VulnerabilityType;
import org.codesecure.dependencycheck.dependency.Dependency;
import org.codesecure.dependencycheck.dependency.Vulnerability;
import org.codesecure.dependencycheck.dependency.Identifier;
import org.codesecure.dependencycheck.dependency.Reference;

/**
 * NvdCveAnalyzer is a utility class that takes a project dependency and
 * attempts to decern if there is an associated CVEs. It uses the the
 * identifiers found by other analyzers to lookup the CVE data.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class NvdCveAnalyzer implements org.codesecure.dependencycheck.analyzer.Analyzer {

    /**
     * The maximum number of query results to return.
     */
    static final int MAX_QUERY_RESULTS = 100;
    /**
     * The CVE Index.
     */
    protected Index cve = null;
    /**
     * The Lucene IndexSearcher.
     */
    private IndexSearcher indexSearcher = null;

    /**
     * Opens the data source.
     *
     * @throws IOException when the Lucene directory to be querried does not
     * exist or is corrupt.
     */
    public void open() throws IOException {
        cve = new Index();
        cve.open();
        indexSearcher = cve.getIndexSearcher();
    }

    /**
     * Closes the data source.
     */
    public void close() {
        indexSearcher = null;
        cve.close();
    }

    /**
     * Returns the status of the data source - is the index open.
     *
     * @return true or false.
     */
    public boolean isOpen() {
        return (cve == null) ? false : cve.isOpen();
    }

    /**
     * Ensures that the Lucene index is closed.
     *
     * @throws Throwable when a throwable is thrown.
     */
    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        if (isOpen()) {
            close();
        }
    }

    /**
     * Analyzes a dependency and attempts to determine if there are any CPE
     * identifiers for this dependency.
     *
     * @param dependency The Dependency to analyze.
     * @throws AnalysisException is thrown if there is an issue analyzing the
     * dependency.
     */
    public void analyze(Dependency dependency) throws AnalysisException {
        for (Identifier id : dependency.getIdentifiers()) {
            if ("cpe".equals(id.getType())) {
                try {
                    String value = id.getValue();
                    Term term1 = new Term(Fields.VULNERABLE_CPE, value);
                    Query query1 = new TermQuery(term1);

                    //need to get the cpe:/a:vendor:product - some CVEs are referenced very broadly.
                    //find the index of the colon after the product of the cpe value
                    //cpe:/a:microsoft:anti-cross_site_scripting_library:3.1
                    int pos = value.indexOf(":", 7) + 1;
                    pos = value.indexOf(":", pos);
                    String productVendor = value.substring(0, pos);
                    Term term2 = new Term(Fields.VULNERABLE_CPE, productVendor);
                    Query query2 = new TermQuery(term2);

                    BooleanQuery query = new BooleanQuery();
                    query.add(query1, BooleanClause.Occur.SHOULD);
                    query.add(query2, BooleanClause.Occur.SHOULD);

                    TopDocs docs = indexSearcher.search(query, MAX_QUERY_RESULTS);
                    for (ScoreDoc d : docs.scoreDocs) {
                        Document doc = indexSearcher.doc(d.doc);
                        String xml = doc.get(Fields.XML);
                        Vulnerability vuln;
                        try {
                            vuln = parseVulnerability(xml);
                            dependency.addVulnerability(vuln);
                        } catch (JAXBException ex) {
                            Logger.getLogger(NvdCveAnalyzer.class.getName()).log(Level.SEVERE, null, ex);
                            dependency.addAnalysisException(new AnalysisException("Unable to retrieve vulnerability data", ex));
                        } catch (UnsupportedEncodingException ex) {
                            Logger.getLogger(NvdCveAnalyzer.class.getName()).log(Level.SEVERE, null, ex);
                            dependency.addAnalysisException(new AnalysisException("Unable to retrieve vulnerability data - utf-8", ex));
                        }
                    }
                } catch (IOException ex) {
                    Logger.getLogger(NvdCveAnalyzer.class.getName()).log(Level.SEVERE, null, ex);
                    throw new AnalysisException("Exception occured while determining CVEs", ex);
                }
            }
        }
    }

    /**
     * Returns true because this analyzer supports all dependency types.
     *
     * @return true.
     */
    public Set<String> getSupportedExtensions() {
        return null;
    }

    /**
     * Returns the name of this analyzer.
     *
     * @return the name of this analyzer.
     */
    public String getName() {
        return "NVD CVE Analyzer";
    }

    /**
     * Returns true because this analyzer supports all dependency types.
     *
     * @param extension the file extension of the dependency being analyzed.
     * @return true.
     */
    public boolean supportsExtension(String extension) {
        return true;
    }

    /**
     * Returns the analysis phase that this analyzer should run in.
     *
     * @return the analysis phase that this analyzer should run in.
     */
    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.FINDING_ANALYSIS;
    }

    /**
     * Opens the NVD CVE Lucene Index.
     *
     * @throws Exception is thrown if there is an issue opening the index.
     */
    public void initialize() throws Exception {
        this.open();
    }

    private Vulnerability parseVulnerability(String xml) throws JAXBException, UnsupportedEncodingException {

        JAXBContext jaxbContext = JAXBContext.newInstance(VulnerabilityType.class);
        Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
        ByteArrayInputStream input = new ByteArrayInputStream(xml.getBytes("UTF-8"));
        VulnerabilityType cvedata = (VulnerabilityType) unmarshaller.unmarshal(input);
        if (cvedata == null) {
            return null;
        }

        Vulnerability vuln = new Vulnerability();
        vuln.setName(cvedata.getId());
        vuln.setDescription(cvedata.getSummary());
        if (cvedata.getReferences() != null) {
            for (VulnerabilityReferenceType r : cvedata.getReferences()) {
                Reference ref = new Reference();
                ref.setName(r.getReference().getValue());
                ref.setSource(r.getSource());
                ref.setUrl(r.getReference().getHref());
                vuln.addReference(ref);
            }
        }
        return vuln;
    }
}
