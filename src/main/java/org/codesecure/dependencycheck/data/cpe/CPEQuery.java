package org.codesecure.dependencycheck.data.cpe;
/*
 * This file is part of DependencyCheck.
 *
 * DependencyCheck is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * DependencyCheck is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with DependencyCheck. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.document.Document;
import org.apache.lucene.index.CorruptIndexException;
import org.apache.lucene.index.IndexReader;
import org.apache.lucene.queryParser.ParseException;
import org.apache.lucene.queryParser.QueryParser;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.ScoreDoc;
import org.apache.lucene.search.TopDocs;
import org.apache.lucene.store.Directory;
import org.apache.lucene.util.Version;
import org.codesecure.dependencycheck.data.LuceneUtils;
import org.codesecure.dependencycheck.scanner.Dependency;
import org.codesecure.dependencycheck.scanner.Evidence.Confidence;

/**
 * CPEQuery is a utility class that takes a project dependency and attempts
 * to decern if there is an associated CPE. It uses the evidence contained
 * within the dependency to search the Lucene index.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class CPEQuery {

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
    static final String CLEANSE_CHARACTER_RX = "[^A-Za-z0-9 _-]";
    /* A string representation of a regular expression used to remove all but
     * alpha characters.
     */
    static final String CLEANSE_NONALPHA_RX = "[^A-Za-z]*";
    /**
     * The additional size to add to a new StringBuilder to account for extra
     * data that will be written into the string.
     */
    static final int STRING_BUILDER_BUFFER = 20;
    /**
     * The Lucene IndexReader.
     */
    private IndexReader indexReader = null;
    /**
     * The Lucene IndexSearcher.
     */
    private IndexSearcher indexSearcher = null;
    /**
     * The Lucene directory.
     */
    private Directory directory = null;
    /**
     * The Lucene Analyzer.
     */
    private Analyzer analyzer = null;
    /**
     * The Lucene QueryParser.
     */
    private QueryParser queryParser = null;
    /**
     * Indicates whether or not the Lucene Index is open.
     */
    private boolean indexOpen = false;

    /**
     * Opens the data source.
     *
     * @throws IOException when the Lucene directory to be querried does not exist or is corrupt.
     */
    public void open() throws IOException {
        directory = Index.getDirectory();
        indexReader = IndexReader.open(directory, true);
        indexSearcher = new IndexSearcher(indexReader);
        analyzer = Index.createAnalyzer(); //use the same analyzer as used when indexing
        //TITLE is the default field because it contains venddor, product, and version all in one.
        queryParser = new QueryParser(Version.LUCENE_35, Fields.TITLE, analyzer);
        indexOpen = true;
    }

    /**
     * Closes the data source.
     */
    public void close() {
        analyzer.close();
        analyzer = null;
        queryParser = null;
        try {
            indexSearcher.close();
        } catch (IOException ex) {
            Logger.getLogger(CPEQuery.class.getName()).log(Level.SEVERE, null, ex);
        }
        indexSearcher = null;
        try {
            indexReader.close();
        } catch (IOException ex) {
            Logger.getLogger(CPEQuery.class.getName()).log(Level.SEVERE, null, ex);
        }
        indexReader = null;
        try {
            directory.close();
        } catch (IOException ex) {
            Logger.getLogger(CPEQuery.class.getName()).log(Level.SEVERE, null, ex);
        }
        directory = null;
        indexOpen = false;
    }

    /**
     * Returns the status of the data source - is the index open.
     * @return true or false.
     */
    public boolean isOpen() {
        return indexOpen;
    }

    /**
     * Ensures that the Lucene index is closed.
     * @throws Throwable when a throwable is thrown.
     */
    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        if (indexOpen) {
            close();
        }
    }

    /**
     * Searches the data store of CPE entries, trying to identify the CPE for the given
     * dependency based on the evidence contained within. The depencency passed in is
     * updated with any identified CPE values.
     *
     * @param dependency the dependency to search for CPE entries on.
     * @throws CorruptIndexException is thrown when the Lucene index is corrupt.
     * @throws IOException is thrown when an IOException occurs.
     * @throws ParseException  is thrown when the Lucene query cannot be parsed.
     */
    public void determineCPE(Dependency dependency) throws CorruptIndexException, IOException, ParseException {
        Confidence vendorConf = Confidence.HIGH;
        Confidence titleConf = Confidence.HIGH;
        Confidence versionConf = Confidence.HIGH;

        String vendors = dependency.getVendorEvidence().toString(vendorConf);
//        if ("".equals(vendors)) {
//            vendors = STRING_THAT_WILL_NEVER_BE_IN_THE_INDEX;
//        }
        String titles = dependency.getTitleEvidence().toString(titleConf);
//        if ("".equals(titles)) {
//            titles = STRING_THAT_WILL_NEVER_BE_IN_THE_INDEX;
//        }
        String versions = dependency.getVersionEvidence().toString(versionConf);
//        if ("".equals(versions)) {
//            versions = STRING_THAT_WILL_NEVER_BE_IN_THE_INDEX;
//        }

        boolean found = false;
        int cnt = 0;
        do {
            List<Entry> entries = searchCPE(vendors, titles, versions, dependency.getTitleEvidence().getWeighting(),
                    dependency.getVendorEvidence().getWeighting());

            if (entries.size() > 0) {
                List<String> verified = verifyEntries(entries, dependency);
                if (verified.size() > 0) {
                    found = true;
                    dependency.setCPEs(verified);
                }
            }

            if (!found) {
                int round = cnt % 3;
                if (round == 0) {
                    vendorConf = reduceConfidence(vendorConf);
                    if (dependency.getVendorEvidence().contains(vendorConf)) {
                        vendors += " " + dependency.getVendorEvidence().toString(vendorConf);
                    } else {
                        cnt += 1;
                        round += 1;
                    }
                }
                if (round == 1) {
                    titleConf = reduceConfidence(titleConf);
                    if (dependency.getTitleEvidence().contains(titleConf)) {
                        titles += " " + dependency.getTitleEvidence().toString(titleConf);
                    } else {
                        cnt += 1;
                        round += 1;
                    }
                }
                if (round == 2) {
                    versionConf = reduceConfidence(versionConf);
                    if (dependency.getVersionEvidence().contains(versionConf)) {
                        versions += " " + dependency.getVersionEvidence().toString(versionConf);
                    }
                }

            }

        } while (!found && (++cnt) < 9);
    }

    /**
     * Reduces the given confidence by one level. This returns LOW if the confidence
     * passed in is not HIGH.
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
     * @param product the text used to search the title field.
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
     * <p>Searches the Lucene CPE index to identify possible CPE entries associated with
     * the supplied vendor, product, and version.</p>
     *
     * <p>If either the vendorWeightings or productWeightings lists have been populated
     * this data is used to add weighting factors to the search.</p>
     *
     * @param vendor the text used to search the vendor field.
     * @param product the text used to search the title field.
     * @param version the text used to search the version field.
     * @param vendorWeightings a list of strings to use to add weighting factors to the vendor field.
     * @param productWeightings Adds a list of strings that will be used to add weighting factors to the title search.
     * @return a list of possible CPE values.
     * @throws CorruptIndexException when the Lucene index is corrupt.
     * @throws IOException when the Lucene index is not found.
     * @throws ParseException when the generated query is not valid.
     */
    protected List<Entry> searchCPE(String vendor, String product, String version,
            List<String> vendorWeightings, List<String> productWeightings)
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
     * <p>Builds a Lucene search string by properly escaping data and constructing a valid search query.</p>
     *
     * <p>If either the possibleVendor or possibleProducts lists have been populated this
     * data is used to add weighting factors to the search string generated.</p>
     *
     * @param vendor text to search the vendor field.
     * @param product text to search the title field.
     * @param version text to search the version field.
     * @param vendorWeighting a list of strings to apply to the vendor
     * to boost the terms weight.
     * @param produdctWeightings a list of strings to apply to the product/title
     * to boost the terms weight.
     * @return the Lucene query.
     */
    protected String buildSearch(String vendor, String product, String version,
            List<String> vendorWeighting, List<String> produdctWeightings) {

        StringBuilder sb = new StringBuilder(vendor.length() + product.length()
                + version.length() + Fields.PRODUCT.length() + Fields.VERSION.length()
                + Fields.VENDOR.length() + STRING_BUILDER_BUFFER);

        if ("".equals(version)) {
            return null;
        }

        if (!appendWeightedSearch(sb, Fields.PRODUCT, product.toLowerCase(), produdctWeightings)) {
            return null;
        }
        if (!appendWeightedSearch(sb, Fields.VENDOR, vendor.toLowerCase(), vendorWeighting)) {
            return null;
        }

        sb.append(Fields.VERSION).append(":(");
        if (sb.indexOf("^") > 0) {
            //if we have a weighting on something else, reduce the weighting on the version a lot
            for (String v : version.split(" ")) {
                LuceneUtils.appendEscapedLuceneQuery(sb, v);
                sb.append("^0.2 ");
            }
        } else {
            LuceneUtils.appendEscapedLuceneQuery(sb, version);
        }
        sb.append(")");

        return sb.toString();
    }

    /**
     * This method constructs a Lucene query for a given field. The searchText
     * is split into seperate words and if the word is within the list of weighted
     * words then an additional weighting is applied to the term as it is appended
     * into the query.
     *
     * @param sb a StringBuilder that the query text will be appended to.
     * @param field the field within the Lucene index that the query is searching.
     * @param searchText text used to construct the query.
     * @param weightedText a list of terms that will be considered higher
     * importance when searching.
     * @return if the append was successful.
     */
    private boolean appendWeightedSearch(StringBuilder sb, String field, String searchText, List<String> weightedText) {
        //TODO add a mutator or special analyzer that combines words next to each other and adds them as a key.
        sb.append(" ").append(field).append(":( ");

        String cleanText = cleanseText(searchText);

        if ("".equals(cleanText)) {
            return false;
        }

        if (weightedText == null || weightedText.isEmpty()) {
            LuceneUtils.appendEscapedLuceneQuery(sb, cleanText);
        } else {
            String[] text = cleanText.split("\\s");
            for (String word : text) {
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
     * Removes characters from the input text that are not used within the CPE index.
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
     * @return whether or not the two strings are similiar.
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
     * Takes a list of entries and a dependency. If the entry has terms that were
     * used (i.e. this CPE entry wasn't identified because the version matched
     * but the product and title did not) then the CPE Entry is returned in a list
     * of possible CPE Entries.
     *
     * @param entries a list of CPE entries.
     * @param dependency the dependency that the CPE entries could be for.
     * @return a list of matched CPE entries.
     */
    private List<String> verifyEntries(final List<Entry> entries, final Dependency dependency) {
        List<String> verified = new ArrayList<String>();
        for (Entry e : entries) {
            if (dependency.getTitleEvidence().containsUsedString(e.getProduct())
                    && dependency.getVendorEvidence().containsUsedString(e.getVendor())) {
                //TODO - determine if this is right? Should we be carrying too much about the
                //  version at this point? Likely need to implement the versionAnalyzer....
                if (dependency.getVersionEvidence().containsUsedString(e.getVersion())) {
                    verified.add(e.getName());
                }
            }
        }
        return verified;
    }
}
