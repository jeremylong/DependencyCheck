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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.lucene.document.Document;
import org.apache.lucene.index.CorruptIndexException;
import org.apache.lucene.queryparser.classic.ParseException;
import org.apache.lucene.search.ScoreDoc;
import org.apache.lucene.search.TopDocs;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.cpe.CpeMemoryIndex;
import org.owasp.dependencycheck.data.cpe.Fields;
import org.owasp.dependencycheck.data.cpe.IndexEntry;
import org.owasp.dependencycheck.data.cpe.IndexException;
import org.owasp.dependencycheck.data.lucene.LuceneUtils;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
import org.owasp.dependencycheck.dependency.EvidenceCollection;
import org.owasp.dependencycheck.dependency.Identifier;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.utils.DependencyVersion;
import org.owasp.dependencycheck.utils.DependencyVersionUtil;

/**
 * CPEAnalyzer is a utility class that takes a project dependency and attempts to discern if there is an associated CPE.
 * It uses the evidence contained within the dependency to search the Lucene index.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class CPEAnalyzer implements Analyzer {
    /**
     * The Logger.
     */
    private static final Logger LOGGER = Logger.getLogger(CPEAnalyzer.class.getName());
    /**
     * The maximum number of query results to return.
     */
    static final int MAX_QUERY_RESULTS = 25;
    /**
     * The weighting boost to give terms when constructing the Lucene query.
     */
    static final String WEIGHTING_BOOST = "^5";
    /**
     * A string representation of a regular expression defining characters utilized within the CPE Names.
     */
    static final String CLEANSE_CHARACTER_RX = "[^A-Za-z0-9 ._-]";
    /**
     * A string representation of a regular expression used to remove all but alpha characters.
     */
    static final String CLEANSE_NONALPHA_RX = "[^A-Za-z]*";
    /**
     * The additional size to add to a new StringBuilder to account for extra data that will be written into the string.
     */
    static final int STRING_BUILDER_BUFFER = 20;
    /**
     * The CPE in memory index.
     */
    private CpeMemoryIndex cpe;
    /**
     * The CVE Database.
     */
    private CveDB cve;

    /**
     * Returns the name of this analyzer.
     *
     * @return the name of this analyzer.
     */
    @Override
    public String getName() {
        return "CPE Analyzer";
    }

    /**
     * Returns the analysis phase that this analyzer should run in.
     *
     * @return the analysis phase that this analyzer should run in.
     */
    @Override
    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.IDENTIFIER_ANALYSIS;
    }

    /**
     * Creates the CPE Lucene Index.
     *
     * @throws Exception is thrown if there is an issue opening the index.
     */
    @Override
    public void initialize() throws Exception {
        this.open();
    }

    /**
     * Opens the data source.
     *
     * @throws IOException when the Lucene directory to be queried does not exist or is corrupt.
     * @throws DatabaseException when the database throws an exception. This usually occurs when the database is in use
     * by another process.
     */
    public void open() throws IOException, DatabaseException {
        LOGGER.log(Level.FINE, "Opening the CVE Database");
        cve = new CveDB();
        cve.open();
        LOGGER.log(Level.FINE, "Creating the Lucene CPE Index");
        cpe = CpeMemoryIndex.getInstance();
        try {
            cpe.open(cve);
        } catch (IndexException ex) {
            LOGGER.log(Level.FINE, "IndexException", ex);
            throw new DatabaseException(ex);
        }
    }

    /**
     * Closes the data sources.
     */
    @Override
    public void close() {
        if (cpe != null) {
            cpe.close();
        }
        if (cve != null) {
            cve.close();
        }
    }

    /**
     * Searches the data store of CPE entries, trying to identify the CPE for the given dependency based on the evidence
     * contained within. The dependency passed in is updated with any identified CPE values.
     *
     * @param dependency the dependency to search for CPE entries on.
     * @throws CorruptIndexException is thrown when the Lucene index is corrupt.
     * @throws IOException is thrown when an IOException occurs.
     * @throws ParseException is thrown when the Lucene query cannot be parsed.
     */
    protected void determineCPE(Dependency dependency) throws CorruptIndexException, IOException, ParseException {
        Confidence confidence = Confidence.HIGHEST;

        String vendors = addEvidenceWithoutDuplicateTerms("", dependency.getVendorEvidence(), confidence);
        String products = addEvidenceWithoutDuplicateTerms("", dependency.getProductEvidence(), confidence);
        /* bug fix for #40 - version evidence is not showing up as "used" in the reports if there is no
         * CPE identified. As such, we are "using" the evidence and ignoring the results. */
        addEvidenceWithoutDuplicateTerms("", dependency.getVersionEvidence(), confidence);

        int ctr = 0;
        do {
            if (!vendors.isEmpty() && !products.isEmpty()) {
                final List<IndexEntry> entries = searchCPE(vendors, products, dependency.getProductEvidence().getWeighting(),
                        dependency.getVendorEvidence().getWeighting());

                for (IndexEntry e : entries) {
                    if (verifyEntry(e, dependency)) {
                        final String vendor = e.getVendor();
                        final String product = e.getProduct();
                        determineIdentifiers(dependency, vendor, product);
                    }
                }
            }
            confidence = reduceConfidence(confidence);
            if (dependency.getVendorEvidence().contains(confidence)) {
                vendors = addEvidenceWithoutDuplicateTerms(vendors, dependency.getVendorEvidence(), confidence);
            }
            if (dependency.getProductEvidence().contains(confidence)) {
                products = addEvidenceWithoutDuplicateTerms(products, dependency.getProductEvidence(), confidence);
            }
            /* bug fix for #40 - version evidence is not showing up as "used" in the reports if there is no
             * CPE identified. As such, we are "using" the evidence and ignoring the results. */
            if (dependency.getVersionEvidence().contains(confidence)) {
                addEvidenceWithoutDuplicateTerms("", dependency.getVersionEvidence(), confidence);
            }
        } while ((++ctr) < 4);
    }

    /**
     * Returns the text created by concatenating the text and the values from the EvidenceCollection (filtered for a
     * specific confidence). This attempts to prevent duplicate terms from being added.<br/<br/> Note, if the evidence
     * is longer then 200 characters it will be truncated.
     *
     * @param text the base text.
     * @param ec an EvidenceCollection
     * @param confidenceFilter a Confidence level to filter the evidence by.
     * @return the new evidence text
     */
    private String addEvidenceWithoutDuplicateTerms(final String text, final EvidenceCollection ec, Confidence confidenceFilter) {
        final String txt = (text == null) ? "" : text;
        final StringBuilder sb = new StringBuilder(txt.length() + (20 * ec.size()));
        sb.append(' ').append(txt).append(' ');
        for (Evidence e : ec.iterator(confidenceFilter)) {
            String value = e.getValue();

            //hack to get around the fact that lucene does a really good job of recognizing domains and not
            // splitting them. TODO - put together a better lucene analyzer specific to the domain.
            if (value.startsWith("http://")) {
                value = value.substring(7).replaceAll("\\.", " ");
            }
            if (value.startsWith("https://")) {
                value = value.substring(8).replaceAll("\\.", " ");
            }
            if (sb.indexOf(" " + value + " ") < 0) {
                sb.append(value).append(' ');
            }
        }
        return sb.toString().trim();
    }

    /**
     * Reduces the given confidence by one level. This returns LOW if the confidence passed in is not HIGH.
     *
     * @param c the confidence to reduce.
     * @return One less then the confidence passed in.
     */
    private Confidence reduceConfidence(final Confidence c) {
        if (c == Confidence.HIGHEST) {
            return Confidence.HIGH;
        } else if (c == Confidence.HIGH) {
            return Confidence.MEDIUM;
        } else {
            return Confidence.LOW;
        }
    }

    /**
     * <p>
     * Searches the Lucene CPE index to identify possible CPE entries associated with the supplied vendor, product, and
     * version.</p>
     *
     * <p>
     * If either the vendorWeightings or productWeightings lists have been populated this data is used to add weighting
     * factors to the search.</p>
     *
     * @param vendor the text used to search the vendor field
     * @param product the text used to search the product field
     * @param vendorWeightings a list of strings to use to add weighting factors to the vendor field
     * @param productWeightings Adds a list of strings that will be used to add weighting factors to the product search
     * @return a list of possible CPE values
     * @throws CorruptIndexException when the Lucene index is corrupt
     * @throws IOException when the Lucene index is not found
     * @throws ParseException when the generated query is not valid
     */
    protected List<IndexEntry> searchCPE(String vendor, String product,
            Set<String> vendorWeightings, Set<String> productWeightings)
            throws CorruptIndexException, IOException, ParseException {
        final ArrayList<IndexEntry> ret = new ArrayList<IndexEntry>(MAX_QUERY_RESULTS);

        final String searchString = buildSearch(vendor, product, vendorWeightings, productWeightings);
        if (searchString == null) {
            return ret;
        }

        final TopDocs docs = cpe.search(searchString, MAX_QUERY_RESULTS);
        for (ScoreDoc d : docs.scoreDocs) {
            if (d.score >= 0.08) {
                final Document doc = cpe.getDocument(d.doc);
                final IndexEntry entry = new IndexEntry();
                entry.setVendor(doc.get(Fields.VENDOR));
                entry.setProduct(doc.get(Fields.PRODUCT));
//                if (d.score < 0.08) {
//                    System.out.print(entry.getVendor());
//                    System.out.print(":");
//                    System.out.print(entry.getProduct());
//                    System.out.print(":");
//                    System.out.println(d.score);
//                }
                entry.setSearchScore(d.score);
                if (!ret.contains(entry)) {
                    ret.add(entry);
                }
            }
        }
        return ret;
    }

    /**
     * <p>
     * Builds a Lucene search string by properly escaping data and constructing a valid search query.</p>
     *
     * <p>
     * If either the possibleVendor or possibleProducts lists have been populated this data is used to add weighting
     * factors to the search string generated.</p>
     *
     * @param vendor text to search the vendor field
     * @param product text to search the product field
     * @param vendorWeighting a list of strings to apply to the vendor to boost the terms weight
     * @param productWeightings a list of strings to apply to the product to boost the terms weight
     * @return the Lucene query
     */
    protected String buildSearch(String vendor, String product,
            Set<String> vendorWeighting, Set<String> productWeightings) {
        final String v = vendor; //.replaceAll("[^\\w\\d]", " ");
        final String p = product; //.replaceAll("[^\\w\\d]", " ");
        final StringBuilder sb = new StringBuilder(v.length() + p.length()
                + Fields.PRODUCT.length() + Fields.VENDOR.length() + STRING_BUILDER_BUFFER);

        if (!appendWeightedSearch(sb, Fields.PRODUCT, p, productWeightings)) {
            return null;
        }
        sb.append(" AND ");
        if (!appendWeightedSearch(sb, Fields.VENDOR, v, vendorWeighting)) {
            return null;
        }
        return sb.toString();
    }

    /**
     * This method constructs a Lucene query for a given field. The searchText is split into separate words and if the
     * word is within the list of weighted words then an additional weighting is applied to the term as it is appended
     * into the query.
     *
     * @param sb a StringBuilder that the query text will be appended to.
     * @param field the field within the Lucene index that the query is searching.
     * @param searchText text used to construct the query.
     * @param weightedText a list of terms that will be considered higher importance when searching.
     * @return if the append was successful.
     */
    private boolean appendWeightedSearch(StringBuilder sb, String field, String searchText, Set<String> weightedText) {
        sb.append(" ").append(field).append(":( ");

        final String cleanText = cleanseText(searchText);

        if ("".equals(cleanText)) {
            return false;
        }

        if (weightedText == null || weightedText.isEmpty()) {
            LuceneUtils.appendEscapedLuceneQuery(sb, cleanText);
        } else {
            final StringTokenizer tokens = new StringTokenizer(cleanText);
            while (tokens.hasMoreElements()) {
                final String word = tokens.nextToken();
                String temp = null;
                for (String weighted : weightedText) {
                    final String weightedStr = cleanseText(weighted);
                    if (equalsIgnoreCaseAndNonAlpha(word, weightedStr)) {
                        temp = LuceneUtils.escapeLuceneQuery(word) + WEIGHTING_BOOST;
                        if (!word.equalsIgnoreCase(weightedStr)) {
                            temp += " " + LuceneUtils.escapeLuceneQuery(weightedStr) + WEIGHTING_BOOST;
                        }
                    }
                }
                if (temp == null) {
                    temp = LuceneUtils.escapeLuceneQuery(word);
                }
                sb.append(" ").append(temp);
            }
        }
        sb.append(" ) ");
        return true;
    }

    /**
     * Removes characters from the input text that are not used within the CPE index.
     *
     * @param text is the text to remove the characters from.
     * @return the text having removed some characters.
     */
    private String cleanseText(String text) {
        return text.replaceAll(CLEANSE_CHARACTER_RX, " ");
    }

    /**
     * Compares two strings after lower casing them and removing the non-alpha characters.
     *
     * @param l string one to compare.
     * @param r string two to compare.
     * @return whether or not the two strings are similar.
     */
    private boolean equalsIgnoreCaseAndNonAlpha(String l, String r) {
        if (l == null || r == null) {
            return false;
        }

        final String left = l.replaceAll(CLEANSE_NONALPHA_RX, "");
        final String right = r.replaceAll(CLEANSE_NONALPHA_RX, "");
        return left.equalsIgnoreCase(right);
    }

    /**
     * Ensures that the CPE Identified matches the dependency. This validates that the product, vendor, and version
     * information for the CPE are contained within the dependencies evidence.
     *
     * @param entry a CPE entry.
     * @param dependency the dependency that the CPE entries could be for.
     * @return whether or not the entry is valid.
     */
    private boolean verifyEntry(final IndexEntry entry, final Dependency dependency) {
        boolean isValid = false;

        if (collectionContainsString(dependency.getProductEvidence(), entry.getProduct())
                && collectionContainsString(dependency.getVendorEvidence(), entry.getVendor())) {
            //&& collectionContainsVersion(dependency.getVersionEvidence(), entry.getVersion())
            isValid = true;
        }
        return isValid;
    }

    /**
     * Used to determine if the EvidenceCollection contains a specific string.
     *
     * @param ec an EvidenceCollection
     * @param text the text to search for
     * @return whether or not the EvidenceCollection contains the string
     */
    private boolean collectionContainsString(EvidenceCollection ec, String text) {

        //<editor-fold defaultstate="collapsed" desc="This code fold contains an old version of the code, delete once more testing is done">
        //        String[] splitText = text.split("[\\s_-]");
        //
        //        for (String search : splitText) {
        //            //final String search = text.replaceAll("[\\s_-]", "").toLowerCase();
        //            if (ec.containsUsedString(search)) {
        //                return true;
        //            }
        //        }
        //</editor-fold>
        //TODO - likely need to change the split... not sure if this will work for CPE with special chars
        if (text == null) {
            return false;
        }
        final String[] words = text.split("[\\s_-]");
        final List<String> list = new ArrayList<String>();
        String tempWord = null;
        for (String word : words) {
            /*
             single letter words should be concatenated with the next word.
             so { "m", "core", "sample" } -> { "mcore", "sample" }
             */
            if (tempWord != null) {
                list.add(tempWord + word);
                tempWord = null;
            } else if (word.length() <= 2) {
                tempWord = word;
            } else {
                list.add(word);
            }
        }
        if (tempWord != null && !list.isEmpty()) {
            final String tmp = list.get(list.size() - 1) + tempWord;
            list.add(tmp);
        }
        boolean contains = true;
        for (String word : list) {
            contains &= ec.containsUsedString(word);
        }
        return contains;
    }

    /**
     * Analyzes a dependency and attempts to determine if there are any CPE identifiers for this dependency.
     *
     * @param dependency The Dependency to analyze.
     * @param engine The analysis engine
     * @throws AnalysisException is thrown if there is an issue analyzing the dependency.
     */
    @Override
    public void analyze(Dependency dependency, Engine engine) throws AnalysisException {
        try {
            determineCPE(dependency);
        } catch (CorruptIndexException ex) {
            throw new AnalysisException("CPE Index is corrupt.", ex);
        } catch (IOException ex) {
            throw new AnalysisException("Failure opening the CPE Index.", ex);
        } catch (ParseException ex) {
            throw new AnalysisException("Unable to parse the generated Lucene query for this dependency.", ex);
        }
    }

    /**
     * Retrieves a list of CPE values from the CveDB based on the vendor and product passed in. The list is then
     * validated to find only CPEs that are valid for the given dependency. It is possible that the CPE identified is a
     * best effort "guess" based on the vendor, product, and version information.
     *
     * @param dependency the Dependency being analyzed
     * @param vendor the vendor for the CPE being analyzed
     * @param product the product for the CPE being analyzed
     * @throws UnsupportedEncodingException is thrown if UTF-8 is not supported
     */
    private void determineIdentifiers(Dependency dependency, String vendor, String product) throws UnsupportedEncodingException {
        final Set<VulnerableSoftware> cpes = cve.getCPEs(vendor, product);
        DependencyVersion bestGuess = new DependencyVersion("-");
        Confidence bestGuessConf = null;
        final List<IdentifierMatch> collected = new ArrayList<IdentifierMatch>();
        for (Confidence conf : Confidence.values()) {
            for (Evidence evidence : dependency.getVersionEvidence().iterator(conf)) {
                final DependencyVersion evVer = DependencyVersionUtil.parseVersion(evidence.getValue());
                if (evVer == null) {
                    continue;
                }
                for (VulnerableSoftware vs : cpes) {
                    DependencyVersion dbVer;
                    if (vs.getRevision() != null && !vs.getRevision().isEmpty()) {
                        dbVer = DependencyVersionUtil.parseVersion(vs.getVersion() + "." + vs.getRevision());
                    } else {
                        dbVer = DependencyVersionUtil.parseVersion(vs.getVersion());
                    }
                    if (dbVer == null //special case, no version specified - everything is vulnerable
                            || evVer.equals(dbVer)) { //yeah! exact match
                        final String url = String.format("http://web.nvd.nist.gov/view/vuln/search?cpe=%s", URLEncoder.encode(vs.getName(), "UTF-8"));
                        final IdentifierMatch match = new IdentifierMatch("cpe", vs.getName(), url, IdentifierConfidence.EXACT_MATCH, conf);
                        collected.add(match);
                    } else {
                        //TODO the following isn't quite right is it? need to think about this guessing game a bit more.
                        if (evVer.getVersionParts().size() <= dbVer.getVersionParts().size()
                                && evVer.matchesAtLeastThreeLevels(dbVer)) {
                            if (bestGuessConf == null || bestGuessConf.compareTo(conf) > 0) {
                                if (bestGuess.getVersionParts().size() < dbVer.getVersionParts().size()) {
                                    bestGuess = dbVer;
                                    bestGuessConf = conf;
                                }
                            }
                        }
                    }
                }
                if (bestGuessConf == null || bestGuessConf.compareTo(conf) > 0) {
                    if (bestGuess.getVersionParts().size() < evVer.getVersionParts().size()) {
                        bestGuess = evVer;
                        bestGuessConf = conf;
                    }
                }
            }
        }
        final String cpeName = String.format("cpe:/a:%s:%s:%s", vendor, product, bestGuess.toString());
        final String url = null; //String.format("http://web.nvd.nist.gov/view/vuln/search?cpe=%s", URLEncoder.encode(cpeName, "UTF-8"));
        if (bestGuessConf == null) {
            bestGuessConf = Confidence.LOW;
        }
        final IdentifierMatch match = new IdentifierMatch("cpe", cpeName, url, IdentifierConfidence.BEST_GUESS, bestGuessConf);
        collected.add(match);

        Collections.sort(collected);
        final IdentifierConfidence bestIdentifierQuality = collected.get(0).getConfidence();
        final Confidence bestEvidenceQuality = collected.get(0).getEvidenceConfidence();
        for (IdentifierMatch m : collected) {
            if (bestIdentifierQuality.equals(m.getConfidence())
                    && bestEvidenceQuality.equals(m.getEvidenceConfidence())) {
                final Identifier i = m.getIdentifier();
                if (bestIdentifierQuality == IdentifierConfidence.BEST_GUESS) {
                    i.setConfidence(Confidence.LOW);
                } else {
                    i.setConfidence(bestEvidenceQuality);
                }
                dependency.addIdentifier(i);
            }
        }
    }

    /**
     * The confidence whether the identifier is an exact match, or a best guess.
     */
    private enum IdentifierConfidence {

        /**
         * An exact match for the CPE.
         */
        EXACT_MATCH,
        /**
         * A best guess for the CPE.
         */
        BEST_GUESS
    }

    /**
     * A simple object to hold an identifier and carry information about the confidence in the identifier.
     */
    private static class IdentifierMatch implements Comparable<IdentifierMatch> {

        /**
         * Constructs an IdentifierMatch.
         *
         * @param type the type of identifier (such as CPE)
         * @param value the value of the identifier
         * @param url the URL of the identifier
         * @param identifierConfidence the confidence in the identifier: best guess or exact match
         * @param evidenceConfidence the confidence of the evidence used to find the identifier
         */
        IdentifierMatch(String type, String value, String url, IdentifierConfidence identifierConfidence, Confidence evidenceConfidence) {
            this.identifier = new Identifier(type, value, url);
            this.confidence = identifierConfidence;
            this.evidenceConfidence = evidenceConfidence;
        }
        //<editor-fold defaultstate="collapsed" desc="Property implementations: evidenceConfidence, confidence, identifier">
        /**
         * The confidence in the evidence used to identify this match.
         */
        private Confidence evidenceConfidence;

        /**
         * Get the value of evidenceConfidence
         *
         * @return the value of evidenceConfidence
         */
        public Confidence getEvidenceConfidence() {
            return evidenceConfidence;
        }

        /**
         * Set the value of evidenceConfidence
         *
         * @param evidenceConfidence new value of evidenceConfidence
         */
        public void setEvidenceConfidence(Confidence evidenceConfidence) {
            this.evidenceConfidence = evidenceConfidence;
        }
        /**
         * The confidence whether this is an exact match, or a best guess.
         */
        private IdentifierConfidence confidence;

        /**
         * Get the value of confidence.
         *
         * @return the value of confidence
         */
        public IdentifierConfidence getConfidence() {
            return confidence;
        }

        /**
         * Set the value of confidence.
         *
         * @param confidence new value of confidence
         */
        public void setConfidence(IdentifierConfidence confidence) {
            this.confidence = confidence;
        }
        /**
         * The CPE identifier.
         */
        private Identifier identifier;

        /**
         * Get the value of identifier.
         *
         * @return the value of identifier
         */
        public Identifier getIdentifier() {
            return identifier;
        }

        /**
         * Set the value of identifier.
         *
         * @param identifier new value of identifier
         */
        public void setIdentifier(Identifier identifier) {
            this.identifier = identifier;
        }
        //</editor-fold>
        //<editor-fold defaultstate="collapsed" desc="Standard implementations of toString, hashCode, and equals">

        /**
         * Standard toString() implementation.
         *
         * @return the string representation of the object
         */
        @Override
        public String toString() {
            return "IdentifierMatch{" + "evidenceConfidence=" + evidenceConfidence
                    + ", confidence=" + confidence + ", identifier=" + identifier + '}';
        }

        /**
         * Standard hashCode() implementation.
         *
         * @return the hashCode
         */
        @Override
        public int hashCode() {
            int hash = 5;
            hash = 97 * hash + (this.evidenceConfidence != null ? this.evidenceConfidence.hashCode() : 0);
            hash = 97 * hash + (this.confidence != null ? this.confidence.hashCode() : 0);
            hash = 97 * hash + (this.identifier != null ? this.identifier.hashCode() : 0);
            return hash;
        }

        /**
         * Standard equals implementation.
         *
         * @param obj the object to compare
         * @return true if the objects are equal, otherwise false
         */
        @Override
        public boolean equals(Object obj) {
            if (obj == null) {
                return false;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }
            final IdentifierMatch other = (IdentifierMatch) obj;
            if (this.evidenceConfidence != other.evidenceConfidence) {
                return false;
            }
            if (this.confidence != other.confidence) {
                return false;
            }
            if (this.identifier != other.identifier && (this.identifier == null || !this.identifier.equals(other.identifier))) {
                return false;
            }
            return true;
        }
        //</editor-fold>

        /**
         * Standard implementation of compareTo that compares identifier confidence, evidence confidence, and then the
         * identifier.
         *
         * @param o the IdentifierMatch to compare to
         * @return the natural ordering of IdentifierMatch
         */
        @Override
        public int compareTo(IdentifierMatch o) {
            int conf = this.confidence.compareTo(o.confidence);
            if (conf == 0) {
                conf = this.evidenceConfidence.compareTo(o.evidenceConfidence);
                if (conf == 0) {
                    conf = identifier.compareTo(o.identifier);
                }
            }
            return conf;
        }
    }
}
