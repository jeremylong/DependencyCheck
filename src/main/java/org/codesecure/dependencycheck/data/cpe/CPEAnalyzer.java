package org.codesecure.dependencycheck.data.cpe;
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

import java.io.IOException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.StringTokenizer;
import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.document.Document;
import org.apache.lucene.index.CorruptIndexException;
import org.apache.lucene.queryparser.classic.ParseException;
import org.apache.lucene.queryparser.classic.QueryParser;
//TODO convert to the analyzing query parser
//import org.apache.lucene.queryparser.analyzing.AnalyzingQueryParser;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.ScoreDoc;
import org.apache.lucene.search.TopDocs;
import org.apache.lucene.util.Version;
import org.codesecure.dependencycheck.analyzer.AnalysisException;
import org.codesecure.dependencycheck.analyzer.AnalysisPhase;
import org.codesecure.dependencycheck.data.lucene.LuceneUtils;
import org.codesecure.dependencycheck.dependency.Dependency;
import org.codesecure.dependencycheck.dependency.Evidence;
import org.codesecure.dependencycheck.dependency.Evidence.Confidence;
import org.codesecure.dependencycheck.dependency.EvidenceCollection;

/**
 * CPEAnalyzer is a utility class that takes a project dependency and attempts
 * to decern if there is an associated CPE. It uses the evidence contained
 * within the dependency to search the Lucene index.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class CPEAnalyzer implements org.codesecure.dependencycheck.analyzer.Analyzer {

    /**
     * The maximum number of query results to return.
     */
    static final int MAX_QUERY_RESULTS = 10;
    /**
     * The weighting boost to give terms when constructing the Lucene query.
     */
    static final String WEIGHTING_BOOST = "^5";
    /**
     * A string representation of a regular expression defining characters
     * utilized within the CPE Names.
     */
    static final String CLEANSE_CHARACTER_RX = "[^A-Za-z0-9 ._-]";
    /*
     * A string representation of a regular expression used to remove all but
     * alpha characters.
     */
    static final String CLEANSE_NONALPHA_RX = "[^A-Za-z]*";
    /**
     * The additional size to add to a new StringBuilder to account for extra
     * data that will be written into the string.
     */
    static final int STRING_BUILDER_BUFFER = 20;
    /**
     * The CPE Index.
     */
    protected Index cpe = null;
    /**
     * The Lucene IndexSearcher.
     */
    private IndexSearcher indexSearcher = null;
    /**
     * The Lucene QueryParser.
     */
    private QueryParser queryParser = null;

    /**
     * Opens the data source.
     *
     * @throws IOException when the Lucene directory to be querried does not
     * exist or is corrupt.
     */
    public void open() throws IOException {
        cpe = new Index();
        cpe.open();
        indexSearcher = cpe.getIndexSearcher();
        Analyzer analyzer = cpe.getAnalyzer();
        queryParser = new QueryParser(Version.LUCENE_40, Fields.NAME, analyzer);
    }

    /**
     * Closes the data source.
     */
    public void close() {
        queryParser = null;
        indexSearcher = null;
        cpe.close();
    }

    /**
     * Returns the status of the data source - is the index open.
     *
     * @return true or false.
     */
    public boolean isOpen() {
        return (cpe == null) ? false : cpe.isOpen();
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
     * Searches the data store of CPE entries, trying to identify the CPE for
     * the given dependency based on the evidence contained within. The
     * depencency passed in is updated with any identified CPE values.
     *
     * @param dependency the dependency to search for CPE entries on.
     * @throws CorruptIndexException is thrown when the Lucene index is corrupt.
     * @throws IOException is thrown when an IOException occurs.
     * @throws ParseException is thrown when the Lucene query cannot be parsed.
     */
    protected void determineCPE(Dependency dependency) throws CorruptIndexException, IOException, ParseException {
        Confidence vendorConf = Confidence.HIGH;
        Confidence productConf = Confidence.HIGH;
        Confidence versionConf = Confidence.HIGH;

        String vendors = addEvidenceWithoutDuplicateTerms("", dependency.getVendorEvidence(), vendorConf);
        String products = addEvidenceWithoutDuplicateTerms("", dependency.getProductEvidence(), productConf);
        String versions = addEvidenceWithoutDuplicateTerms("", dependency.getVersionEvidence(), versionConf);

        boolean found = false;
        int ctr = 0;
        do {
            List<Entry> entries = searchCPE(vendors, products, versions, dependency.getProductEvidence().getWeighting(),
                    dependency.getVendorEvidence().getWeighting());


            for (Entry e : entries) {
                if (verifyEntry(e, dependency)) {
                    found = true;

                    dependency.addIdentifier(
                            "cpe",
                            e.getName(),
                            "http://web.nvd.nist.gov/view/vuln/search?cpe="
                            + URLEncoder.encode(e.getName(), "UTF-8"));
                }
            }

            if (!found) {
                int round = ctr % 3;
                if (round == 0) {
                    vendorConf = reduceConfidence(vendorConf);
                    if (dependency.getVendorEvidence().contains(vendorConf)) {
                        //vendors += " " + dependency.getVendorEvidence().toString(vendorConf);
                        vendors = addEvidenceWithoutDuplicateTerms(vendors, dependency.getVendorEvidence(), vendorConf);
                    } else {
                        ctr += 1;
                        round += 1;
                    }
                }
                if (round == 1) {
                    productConf = reduceConfidence(productConf);
                    if (dependency.getProductEvidence().contains(productConf)) {
                        //products += " " + dependency.getProductEvidence().toString(productConf);
                        products = addEvidenceWithoutDuplicateTerms(products, dependency.getProductEvidence(), productConf);
                    } else {
                        ctr += 1;
                        round += 1;
                    }
                }
                if (round == 2) {
                    versionConf = reduceConfidence(versionConf);
                    if (dependency.getVersionEvidence().contains(versionConf)) {
                        //versions += " " + dependency.getVersionEvidence().toString(versionConf);
                        versions = addEvidenceWithoutDuplicateTerms(versions, dependency.getVersionEvidence(), versionConf);
                    }
                }
            }
        } while (!found && (++ctr) < 9);
    }

    /**
     * Returns the text created by concatenating the text and the values from
     * the EvidenceCollection (filtered for a specific confidence). This
     * attempts to prevent duplicate terms from being added.<br/<br/> Note, if
     * the evidence is longer then 200 characters it will be truncated.
     *
     * @param text the base text.
     * @param ec an EvidenceCollection
     * @param confidenceFilter a Confidence level to filter the evidence by.
     * @return
     */
    private String addEvidenceWithoutDuplicateTerms(final String text, final EvidenceCollection ec, Confidence confidenceFilter) {
        String txt = (text == null) ? "" : text;
        StringBuilder sb = new StringBuilder(txt.length() + (20 * ec.size()));
        sb.append(txt);
        for (Evidence e : ec.iterator(confidenceFilter)) {
            String value = e.getValue();

            //hack to get around the fact that lucene does a realy good job of recognizing domains and not
            // splitting them. TODO - put together a better lucene analyzer specific to the domain.
            if (value.startsWith("http://")) {
                value = value.substring(7).replaceAll("\\.", " ");
            }
            if (value.startsWith("https://")) {
                value = value.substring(8).replaceAll("\\.", " ");
            }
            if (sb.indexOf(value) < 0) {
//                if (value.length() > 200) {
//                    sb.append(value.substring(0, 200)).append(' ');
//                } else {
                sb.append(value).append(' ');
//                }
            }
        }
        return sb.toString();
    }

    /**
     * Reduces the given confidence by one level. This returns LOW if the
     * confidence passed in is not HIGH.
     *
     * @param c the confidence to reduce.
     * @return One less then the confidence passed in.
     */
    private Confidence reduceConfidence(final Confidence c) {
        if (c == Confidence.HIGH) {
            return Confidence.MEDIUM;
        } else {
            return Confidence.LOW;
        }
    }

    /**
     * Searches the Lucene CPE index to identify possible CPE entries associated
     * with the supplied vendor, product, and version.
     *
     * @param vendor the text used to search the vendor field.
     * @param product the text used to search the product field.
     * @param version the text used to search the version field.
     * @return a list of possible CPE values.
     * @throws CorruptIndexException when the Lucene index is corrupt.
     * @throws IOException when the Lucene index is not found.
     * @throws ParseException when the generated query is not valid.
     */
    protected List<Entry> searchCPE(String vendor, String product, String version)
            throws CorruptIndexException, IOException, ParseException {
        return searchCPE(vendor, product, version, null, null);
    }

    /**
     * <p>Searches the Lucene CPE index to identify possible CPE entries
     * associated with the supplied vendor, product, and version.</p>
     *
     * <p>If either the vendorWeightings or productWeightings lists have been
     * populated this data is used to add weighting factors to the search.</p>
     *
     * @param vendor the text used to search the vendor field.
     * @param product the text used to search the product field.
     * @param version the text used to search the version field.
     * @param vendorWeightings a list of strings to use to add weighting factors
     * to the vendor field.
     * @param productWeightings Adds a list of strings that will be used to add
     * weighting factors to the product search.
     * @return a list of possible CPE values.
     * @throws CorruptIndexException when the Lucene index is corrupt.
     * @throws IOException when the Lucene index is not found.
     * @throws ParseException when the generated query is not valid.
     */
    protected List<Entry> searchCPE(String vendor, String product, String version,
            Set<String> vendorWeightings, Set<String> productWeightings)
            throws CorruptIndexException, IOException, ParseException {
        ArrayList<Entry> ret = new ArrayList<Entry>(MAX_QUERY_RESULTS);

        String searchString = buildSearch(vendor, product, version, vendorWeightings, productWeightings);
        if (searchString == null) {
            return ret;
        }
        Query query = queryParser.parse(searchString);
        TopDocs docs = indexSearcher.search(query, MAX_QUERY_RESULTS);
        for (ScoreDoc d : docs.scoreDocs) {
            Document doc = indexSearcher.doc(d.doc);
            Entry entry = Entry.parse(doc);
            entry.setSearchScore(d.score);
            if (!ret.contains(entry)) {
                ret.add(entry);
            }
        }
        return ret;
    }

    /**
     * <p>Builds a Lucene search string by properly escaping data and
     * constructing a valid search query.</p>
     *
     * <p>If either the possibleVendor or possibleProducts lists have been
     * populated this data is used to add weighting factors to the search string
     * generated.</p>
     *
     * @param vendor text to search the vendor field.
     * @param product text to search the product field.
     * @param version text to search the version field.
     * @param vendorWeighting a list of strings to apply to the vendor to boost
     * the terms weight.
     * @param produdctWeightings a list of strings to apply to the product to
     * boost the terms weight.
     * @return the Lucene query.
     */
    protected String buildSearch(String vendor, String product, String version,
            Set<String> vendorWeighting, Set<String> produdctWeightings) {

        StringBuilder sb = new StringBuilder(vendor.length() + product.length()
                + version.length() + Fields.PRODUCT.length() + Fields.VERSION.length()
                + Fields.VENDOR.length() + STRING_BUILDER_BUFFER);

        if ("".equals(version)) {
            return null;
        }

        if (!appendWeightedSearch(sb, Fields.PRODUCT, product.toLowerCase(), produdctWeightings)) {
            return null;
        }
        sb.append(" AND ");
        if (!appendWeightedSearch(sb, Fields.VENDOR, vendor.toLowerCase(), vendorWeighting)) {
            return null;
        }
        sb.append(" AND ");

        sb.append(Fields.VERSION).append(":(");
        if (sb.indexOf("^") > 0) {
            //if we have a weighting on something else, reduce the weighting on the version a lot
            for (String v : version.split(" ")) {
                LuceneUtils.appendEscapedLuceneQuery(sb, cleanseText(v));
                sb.append("^0.2 ");
            }
        } else {
            //LuceneUtils.appendEscapedLuceneQuery(sb, version);
            //if we have a weighting on something else, reduce the weighting on the version a lot
            for (String v : version.split(" ")) {
                LuceneUtils.appendEscapedLuceneQuery(sb, cleanseText(v));
                sb.append("^0.7 ");
            }
        }
        sb.append(")");

        return sb.toString();
    }

    /**
     * This method constructs a Lucene query for a given field. The searchText
     * is split into seperate words and if the word is within the list of
     * weighted words then an additional weighting is applied to the term as it
     * is appended into the query.
     *
     * @param sb a StringBuilder that the query text will be appended to.
     * @param field the field within the Lucene index that the query is
     * searching.
     * @param searchText text used to construct the query.
     * @param weightedText a list of terms that will be considered higher
     * importance when searching.
     * @return if the append was successful.
     */
    private boolean appendWeightedSearch(StringBuilder sb, String field, String searchText, Set<String> weightedText) {
        //TODO add a mutator or special analyzer that combines words next to each other and adds them as a key.
        sb.append(" ").append(field).append(":( ");

        String cleanText = cleanseText(searchText);

        if ("".equals(cleanText)) {
            return false;
        }

        if (weightedText == null || weightedText.isEmpty()) {
            LuceneUtils.appendEscapedLuceneQuery(sb, cleanText);
        } else {
            StringTokenizer tokens = new StringTokenizer(cleanText);
            while (tokens.hasMoreElements()) {
                String word = tokens.nextToken();
                String temp = null;
                for (String weighted : weightedText) {
                    String weightedStr = cleanseText(weighted);
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
     * Removes characters from the input text that are not used within the CPE
     * index.
     *
     * @param text is the text to remove the characters from.
     * @return the text having removed some characters.
     */
    private String cleanseText(String text) {
        return text.replaceAll(CLEANSE_CHARACTER_RX, " ");
    }

    /**
     * Compares two strings after lower casing them and removing the non-alpha
     * characters.
     *
     * @param l string one to compare.
     * @param r string two to compare.
     * @return whether or not the two strings are similar.
     */
    private boolean equalsIgnoreCaseAndNonAlpha(String l, String r) {
        if (l == null || r == null) {
            return false;
        }

        String left = l.replaceAll(CLEANSE_NONALPHA_RX, "");
        String right = r.replaceAll(CLEANSE_NONALPHA_RX, "");
        return left.equalsIgnoreCase(right);
    }

    /**
     * Ensures that the CPE Identified matches the dependency. This validates
     * that the product, vendor, and version information for the CPE are
     * contained within the dependencies evidence.
     *
     * @param entry a CPE entry.
     * @param dependency the dependency that the CPE entries could be for.
     * @return whether or not the entry is valid.
     */
    private boolean verifyEntry(final Entry entry, final Dependency dependency) {
        boolean isValid = false;
        if (dependency.getProductEvidence().containsUsedString(entry.getProduct())
                && dependency.getVendorEvidence().containsUsedString(entry.getVendor())) {
            //TODO - determine if this is right? Should we be carrying too much about the
            //  version at this point? Likely need to implement the versionAnalyzer....
            if (dependency.getVersionEvidence().containsUsedString(entry.getVersion())) {
                isValid = true;
            }
        }
        return isValid;
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
        return "CPE Analyzer";
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
        return AnalysisPhase.IDENTIFIER_ANALYSIS;
    }

    /**
     * Opens the CPE Lucene Index.
     *
     * @throws Exception is thrown if there is an issue opening the index.
     */
    public void initialize() throws Exception {
        this.open();
    }
}
