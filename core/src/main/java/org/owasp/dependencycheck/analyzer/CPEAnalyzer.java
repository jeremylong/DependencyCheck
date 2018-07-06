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
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.concurrent.TimeUnit;
import javax.annotation.concurrent.ThreadSafe;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.CompareToBuilder;
import org.apache.lucene.analysis.util.CharArraySet;
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
import org.owasp.dependencycheck.data.lucene.SearchFieldAnalyzer;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.dependency.Identifier;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.DependencyVersion;
import org.owasp.dependencycheck.utils.DependencyVersionUtil;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * CPEAnalyzer is a utility class that takes a project dependency and attempts
 * to discern if there is an associated CPE. It uses the evidence contained
 * within the dependency to search the Lucene index.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class CPEAnalyzer extends AbstractAnalyzer {

    /**
     * The Logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(CPEAnalyzer.class);
    /**
     * The maximum number of query results to return.
     */
    private static final int MAX_QUERY_RESULTS = 25;
    /**
     * The weighting boost to give terms when constructing the Lucene query.
     */
    private static final String WEIGHTING_BOOST = "^5";
    /**
     * A string representation of a regular expression defining characters
     * utilized within the CPE Names. Note, the :/ are included so URLs are
     * passed into the Lucene query so that the specialized tokenizer can parse
     * them.
     */
    private static final String CLEANSE_CHARACTER_RX = "[^A-Za-z0-9 ._:/-]";
    /**
     * A string representation of a regular expression used to remove all but
     * alpha characters.
     */
    private static final String CLEANSE_NONALPHA_RX = "[^A-Za-z]*";
    /**
     * The additional size to add to a new StringBuilder to account for extra
     * data that will be written into the string.
     */
    private static final int STRING_BUILDER_BUFFER = 20;
    /**
     * The URL to perform a search of the NVD CVE data at NIST.
     */
    public static final String NVD_SEARCH_URL = "https://web.nvd.nist.gov/view/vuln/search-results?adv_search=true&cves=on&cpe_version=%s";
    /**
     * The CPE in memory index.
     */
    private CpeMemoryIndex cpe;
    /**
     * The CVE Database.
     */
    private CveDB cve;
    /**
     * The list of ecosystems to skip during analysis. These are skipped because
     * there is generally a more accurate vulnerability analyzer in the
     * pipeline.
     */
    private List<String> skipEcosystems;
    /**
     * A reference to the suppression analyzer; for timing reasons we need to
     * test for suppressions immediately after identifying the match because a
     * higher confidence match on a FP can mask a lower confidence, yet valid
     * match.
     */
    private CpeSuppressionAnalyzer suppression;

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
     * @param engine a reference to the dependency-check engine
     * @throws InitializationException is thrown if there is an issue opening
     * the index.
     */
    @Override
    public void prepareAnalyzer(Engine engine) throws InitializationException {
        super.prepareAnalyzer(engine);
        try {
            this.open(engine.getDatabase());
        } catch (IOException ex) {
            LOGGER.debug("Exception initializing the Lucene Index", ex);
            throw new InitializationException("An exception occurred initializing the Lucene Index", ex);
        } catch (DatabaseException ex) {
            LOGGER.debug("Exception accessing the database", ex);
            throw new InitializationException("An exception occurred accessing the database", ex);
        }
        final String[] tmp = engine.getSettings().getArray(Settings.KEYS.ECOSYSTEM_SKIP_CPEANALYZER);
        if (tmp == null) {
            skipEcosystems = new ArrayList<>();
        } else {
            LOGGER.info("Skipping CPE Analysis for {}", StringUtils.join(tmp, ","));
            skipEcosystems = Arrays.asList(tmp);
        }

        suppression = new CpeSuppressionAnalyzer();
        suppression.initialize(engine.getSettings());
        suppression.prepareAnalyzer(engine);
    }

    /**
     * Opens the data source.
     *
     * @param cve a reference to the NVD CVE database
     * @throws IOException when the Lucene directory to be queried does not
     * exist or is corrupt.
     * @throws DatabaseException when the database throws an exception. This
     * usually occurs when the database is in use by another process.
     */
    public void open(CveDB cve) throws IOException, DatabaseException {
        this.cve = cve;
        this.cpe = CpeMemoryIndex.getInstance();
        try {
            final long creationStart = System.currentTimeMillis();
            cpe.open(cve);
            final long creationSeconds = TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis() - creationStart);
            LOGGER.info("Created CPE Index ({} seconds)", creationSeconds);
        } catch (IndexException ex) {
            LOGGER.debug("IndexException", ex);
            throw new DatabaseException(ex);
        }
    }

    /**
     * Closes the data sources.
     */
    @Override
    public void closeAnalyzer() {
        if (cpe != null) {
            cpe.close();
            cpe = null;
        }
    }

    /**
     * Searches the data store of CPE entries, trying to identify the CPE for
     * the given dependency based on the evidence contained within. The
     * dependency passed in is updated with any identified CPE values.
     *
     * @param dependency the dependency to search for CPE entries on
     * @throws CorruptIndexException is thrown when the Lucene index is corrupt
     * @throws IOException is thrown when an IOException occurs
     * @throws ParseException is thrown when the Lucene query cannot be parsed
     * @throws AnalysisException thrown if the suppression rules failed
     */
    protected void determineCPE(Dependency dependency) throws CorruptIndexException, IOException, ParseException, AnalysisException {
        String vendors = "";
        String products = "";
        for (Confidence confidence : Confidence.values()) {
            if (dependency.contains(EvidenceType.VENDOR, confidence)) {
                vendors = addEvidenceWithoutDuplicateTerms(vendors, dependency.getIterator(EvidenceType.VENDOR, confidence));
                LOGGER.debug("vendor search: {}", vendors);
            }
            if (dependency.contains(EvidenceType.PRODUCT, confidence)) {
                products = addEvidenceWithoutDuplicateTerms(products, dependency.getIterator(EvidenceType.PRODUCT, confidence));
                LOGGER.debug("product search: {}", products);
            }
            if (!vendors.isEmpty() && !products.isEmpty()) {
                final List<IndexEntry> entries = searchCPE(vendors, products, dependency.getVendorWeightings(),
                        dependency.getProductWeightings());
                if (entries == null) {
                    continue;
                }
                boolean identifierAdded = false;
                for (IndexEntry e : entries) {
                    LOGGER.debug("Verifying entry: {}", e);
                    if (verifyEntry(e, dependency)) {
                        final String vendor = e.getVendor();
                        final String product = e.getProduct();
                        LOGGER.debug("identified vendor/product: {}/{}", vendor, product);
                        identifierAdded |= determineIdentifiers(dependency, vendor, product, confidence);
                    }
                }
                if (identifierAdded) {
                    break;
                }
            }
        }
    }

    /**
     * <p>
     * Returns the text created by concatenating the text and the values from
     * the EvidenceCollection (filtered for a specific confidence). This
     * attempts to prevent duplicate terms from being added.</p>
     * <p>
     * Note, if the evidence is longer then 200 characters it will be
     * truncated.</p>
     *
     * @param text the base text
     * @param evidence an iterable set of evidence to concatenate
     * @return the new evidence text
     */
    @SuppressWarnings("null")
    protected String addEvidenceWithoutDuplicateTerms(final String text, final Iterable<Evidence> evidence) {
        final String txt = (text == null) ? "" : text;
        final StringBuilder sb = new StringBuilder(txt.length() * 2);
        sb.append(' ').append(txt).append(' ');
        for (Evidence e : evidence) {
            String value = e.getValue();
            if (value.length() > 1000) {
                value = value.substring(0, 1000);
                final int pos = value.lastIndexOf(" ");
                if (pos > 0) {
                    value = value.substring(0, pos);
                }
            }
            if (sb.indexOf(" " + value + " ") < 0) {
                sb.append(value).append(' ');
            }
        }
        return sb.toString().trim();
    }

    /**
     * <p>
     * Searches the Lucene CPE index to identify possible CPE entries associated
     * with the supplied vendor, product, and version.</p>
     *
     * <p>
     * If either the vendorWeightings or productWeightings lists have been
     * populated this data is used to add weighting factors to the search.</p>
     *
     * @param vendor the text used to search the vendor field
     * @param product the text used to search the product field
     * @param vendorWeightings a list of strings to use to add weighting factors
     * to the vendor field
     * @param productWeightings Adds a list of strings that will be used to add
     * weighting factors to the product search
     * @return a list of possible CPE values
     */
    protected List<IndexEntry> searchCPE(String vendor, String product,
            Set<String> vendorWeightings, Set<String> productWeightings) {

        final List<IndexEntry> ret = new ArrayList<>(MAX_QUERY_RESULTS);

        final String searchString = buildSearch(vendor, product, vendorWeightings, productWeightings);
        if (searchString == null) {
            return ret;
        }
        try {
            final TopDocs docs = cpe.search(searchString, MAX_QUERY_RESULTS);
            for (ScoreDoc d : docs.scoreDocs) {
                if (d.score >= 0.08) {
                    final Document doc = cpe.getDocument(d.doc);
                    final IndexEntry entry = new IndexEntry();
                    entry.setVendor(doc.get(Fields.VENDOR));
                    entry.setProduct(doc.get(Fields.PRODUCT));
                    entry.setSearchScore(d.score);
                    if (!ret.contains(entry)) {
                        ret.add(entry);
                    }
                }
            }
            return ret;
        } catch (ParseException ex) {
            LOGGER.warn("An error occurred querying the CPE data. See the log for more details.");
            LOGGER.info("Unable to parse: {}", searchString, ex);
        } catch (IOException ex) {
            LOGGER.warn("An error occurred reading CPE data. See the log for more details.");
            LOGGER.info("IO Error with search string: {}", searchString, ex);
        }
        return null;
    }

    /**
     * <p>
     * Builds a Lucene search string by properly escaping data and constructing
     * a valid search query.</p>
     *
     * <p>
     * If either the possibleVendor or possibleProducts lists have been
     * populated this data is used to add weighting factors to the search string
     * generated.</p>
     *
     * @param vendor text to search the vendor field
     * @param product text to search the product field
     * @param vendorWeighting a list of strings to apply to the vendor to boost
     * the terms weight
     * @param productWeightings a list of strings to apply to the product to
     * boost the terms weight
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
     * This method constructs a Lucene query for a given field. The searchText
     * is split into separate words and if the word is within the list of
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
        sb.append(field).append(":(");

        final String cleanText = cleanseText(searchText);

        if (cleanText.isEmpty()) {
            return false;
        }

        if (weightedText == null || weightedText.isEmpty()) {
            LuceneUtils.appendEscapedLuceneQuery(sb, cleanText);
        } else {
            boolean addSpace = false;
            final StringTokenizer tokens = new StringTokenizer(cleanText);
            while (tokens.hasMoreElements()) {
                final String word = tokens.nextToken();
                StringBuilder temp = null;
                for (String weighted : weightedText) {
                    final String weightedStr = cleanseText(weighted);
                    if (equalsIgnoreCaseAndNonAlpha(word, weightedStr)) {
                        temp = new StringBuilder(word.length() + 2);
                        LuceneUtils.appendEscapedLuceneQuery(temp, word);
                        temp.append(WEIGHTING_BOOST);
                        if (!word.equalsIgnoreCase(weightedStr)) {
                            if (temp.length() > 0) {
                                temp.append(' ');
                            }
                            LuceneUtils.appendEscapedLuceneQuery(temp, weightedStr);
                            temp.append(WEIGHTING_BOOST);
                        }
                        break;
                    }
                }
                if (addSpace) {
                    sb.append(' ');
                } else {
                    addSpace = true;
                }
                if (temp == null) {
                    LuceneUtils.appendEscapedLuceneQuery(sb, word);
                } else {
                    sb.append(temp);
                }
            }
        }
        sb.append(")");
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

        final String left = l.replaceAll(CLEANSE_NONALPHA_RX, "");
        final String right = r.replaceAll(CLEANSE_NONALPHA_RX, "");
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
    private boolean verifyEntry(final IndexEntry entry, final Dependency dependency) {
        boolean isValid = false;

        //TODO - does this nullify some of the fuzzy matching that happens in the lucene search?
        // for instance CPE some-component and in the evidence we have SomeComponent.
        if (collectionContainsString(dependency.getEvidence(EvidenceType.PRODUCT), entry.getProduct())
                && collectionContainsString(dependency.getEvidence(EvidenceType.VENDOR), entry.getVendor())) {
            //&& collectionContainsVersion(dependency.getVersionEvidence(), entry.getVersion())
            isValid = true;
        }
        return isValid;
    }

    /**
     * Used to determine if the EvidenceCollection contains a specific string.
     *
     * @param evidence an of evidence object to check
     * @param text the text to search for
     * @return whether or not the EvidenceCollection contains the string
     */
    private boolean collectionContainsString(Set<Evidence> evidence, String text) {
        //TODO - likely need to change the split... not sure if this will work for CPE with special chars
        if (text == null) {
            return false;
        }
        final String[] words = text.split("[\\s_-]");
        final List<String> list = new ArrayList<>();
        String tempWord = null;
        final CharArraySet stopWords = SearchFieldAnalyzer.getStopWords();
        for (String word : words) {
            if (stopWords.contains(word)) {
                continue;
            }
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
        if (tempWord != null) {
            if (!list.isEmpty()) {
                final String tmp = list.get(list.size() - 1) + tempWord;
                list.add(tmp);
            } else {
                list.add(tempWord);
            }
        }
        if (list.isEmpty()) {
            return false;
        }
        boolean isValid = true;
        for (String word : list) {
            boolean found = false;
            for (Evidence e : evidence) {
                if (e.getValue().toLowerCase().contains(word.toLowerCase())) {
                    if ("http".equals(word) && e.getValue().contains("http:")) {
                        continue;
                    }
                    found = true;
                    break;
                }
            }
            isValid &= found;
            if (!isValid) {
                break;
            }
        }
        return isValid;
    }

    /**
     * Analyzes a dependency and attempts to determine if there are any CPE
     * identifiers for this dependency.
     *
     * @param dependency The Dependency to analyze.
     * @param engine The analysis engine
     * @throws AnalysisException is thrown if there is an issue analyzing the
     * dependency.
     */
    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        if (skipEcosystems.contains(dependency.getEcosystem())) {
            return;
        }
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
     * Retrieves a list of CPE values from the CveDB based on the vendor and
     * product passed in. The list is then validated to find only CPEs that are
     * valid for the given dependency. It is possible that the CPE identified is
     * a best effort "guess" based on the vendor, product, and version
     * information.
     *
     * @param dependency the Dependency being analyzed
     * @param vendor the vendor for the CPE being analyzed
     * @param product the product for the CPE being analyzed
     * @param currentConfidence the current confidence being used during
     * analysis
     * @return <code>true</code> if an identifier was added to the dependency;
     * otherwise <code>false</code>
     * @throws UnsupportedEncodingException is thrown if UTF-8 is not supported
     * @throws AnalysisException thrown if the suppression rules failed
     */
    protected boolean determineIdentifiers(Dependency dependency, String vendor, String product,
            Confidence currentConfidence) throws UnsupportedEncodingException, AnalysisException {
        final Set<VulnerableSoftware> cpes = cve.getCPEs(vendor, product);
        if (cpes.isEmpty()) {
            return false;
        }
        DependencyVersion bestGuess = new DependencyVersion("-");
        Confidence bestGuessConf = null;
        boolean hasBroadMatch = false;
        final List<IdentifierMatch> collected = new ArrayList<>();

        //TODO the following algorithm incorrectly identifies things as a lower version
        // if there lower confidence evidence when the current (highest) version number
        // is newer then anything in the NVD.
        for (Confidence conf : Confidence.values()) {
            for (Evidence evidence : dependency.getIterator(EvidenceType.VERSION, conf)) {
                final DependencyVersion evVer = DependencyVersionUtil.parseVersion(evidence.getValue());
                if (evVer == null) {
                    continue;
                }
                for (VulnerableSoftware vs : cpes) {
                    final DependencyVersion dbVer;
                    if (vs.getUpdate() != null && !vs.getUpdate().isEmpty()) {
                        dbVer = DependencyVersionUtil.parseVersion(vs.getVersion() + '.' + vs.getUpdate());
                    } else {
                        dbVer = DependencyVersionUtil.parseVersion(vs.getVersion());
                    }
                    if (dbVer == null) { //special case, no version specified - everything is vulnerable
                        hasBroadMatch = true;
                        final String url = String.format(NVD_SEARCH_URL, URLEncoder.encode(vs.getName(), StandardCharsets.UTF_8.name()));
                        final IdentifierMatch match = new IdentifierMatch("cpe", vs.getName(), url, IdentifierConfidence.BROAD_MATCH, conf);
                        collected.add(match);
                    } else if (evVer.equals(dbVer)) { //yeah! exact match
                        final String url = String.format(NVD_SEARCH_URL, URLEncoder.encode(vs.getName(), StandardCharsets.UTF_8.name()));
                        final IdentifierMatch match = new IdentifierMatch("cpe", vs.getName(), url, IdentifierConfidence.EXACT_MATCH, conf);
                        collected.add(match);

                        //TODO the following isn't quite right is it? need to think about this guessing game a bit more.
                    } else if (evVer.getVersionParts().size() <= dbVer.getVersionParts().size()
                            && evVer.matchesAtLeastThreeLevels(dbVer)) {
                        if (bestGuessConf == null || bestGuessConf.compareTo(conf) > 0) {
                            if (bestGuess.getVersionParts().size() < dbVer.getVersionParts().size()) {
                                bestGuess = dbVer;
                                bestGuessConf = conf;
                            }
                        }
                    }
                }
                if ((bestGuessConf == null || bestGuessConf.compareTo(conf) > 0)
                        && bestGuess.getVersionParts().size() < evVer.getVersionParts().size()) {
                    bestGuess = evVer;
                    bestGuessConf = conf;
                }
            }
        }
        final String cpeName = String.format("cpe:/a:%s:%s:%s", vendor, product, bestGuess.toString());
        String url = null;
        if (hasBroadMatch) { //if we have a broad match we can add the URL to the best guess.
            final String cpeUrlName = String.format("cpe:/a:%s:%s", vendor, product);
            url = String.format(NVD_SEARCH_URL, URLEncoder.encode(cpeUrlName, StandardCharsets.UTF_8.name()));
        }
        if (bestGuessConf
                == null) {
            bestGuessConf = Confidence.LOW;
        }
        final IdentifierMatch match = new IdentifierMatch("cpe", cpeName, url, IdentifierConfidence.BEST_GUESS, bestGuessConf);

        collected.add(match);

        Collections.sort(collected);
        final IdentifierConfidence bestIdentifierQuality = collected.get(0).getConfidence();
        final Confidence bestEvidenceQuality = collected.get(0).getEvidenceConfidence();
        boolean identifierAdded = false;
        for (IdentifierMatch m : collected) {
            if (bestIdentifierQuality.equals(m.getConfidence())
                    && bestEvidenceQuality.equals(m.getEvidenceConfidence())) {
                final Identifier i = m.getIdentifier();
                if (bestIdentifierQuality == IdentifierConfidence.BEST_GUESS) {
                    i.setConfidence(Confidence.LOW);
                } else {
                    i.setConfidence(bestEvidenceQuality);
                }
                //TODO - while this gets the job down it is slow; consider refactoring
                dependency.addIdentifier(i);
                suppression.analyze(dependency, null);
                if (dependency.getIdentifiers().contains(i)) {
                    identifierAdded = true;
                }
            }
        }
        return identifierAdded;
    }

    /**
     * <p>
     * Returns the setting key to determine if the analyzer is enabled.</p>
     *
     * @return the key for the analyzer's enabled property
     */
    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return Settings.KEYS.ANALYZER_CPE_ENABLED;
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
        BEST_GUESS,
        /**
         * The entire vendor/product group must be added (without a guess at
         * version) because there is a CVE with a VS that only specifies
         * vendor/product.
         */
        BROAD_MATCH
    }

    /**
     * A simple object to hold an identifier and carry information about the
     * confidence in the identifier.
     */
    private static class IdentifierMatch implements Comparable<IdentifierMatch> {

        /**
         * The confidence in the evidence used to identify this match.
         */
        private Confidence evidenceConfidence;
        /**
         * The confidence whether this is an exact match, or a best guess.
         */
        private IdentifierConfidence confidence;
        /**
         * The CPE identifier.
         */
        private Identifier identifier;

        /**
         * Constructs an IdentifierMatch.
         *
         * @param type the type of identifier (such as CPE)
         * @param value the value of the identifier
         * @param url the URL of the identifier
         * @param identifierConfidence the confidence in the identifier: best
         * guess or exact match
         * @param evidenceConfidence the confidence of the evidence used to find
         * the identifier
         */
        IdentifierMatch(String type, String value, String url, IdentifierConfidence identifierConfidence, Confidence evidenceConfidence) {
            this.identifier = new Identifier(type, value, url);
            this.confidence = identifierConfidence;
            this.evidenceConfidence = evidenceConfidence;
        }

        //<editor-fold defaultstate="collapsed" desc="Property implementations: evidenceConfidence, confidence, identifier">
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
            return !(this.identifier != other.identifier && (this.identifier == null || !this.identifier.equals(other.identifier)));
        }
        //</editor-fold>

        /**
         * Standard implementation of compareTo that compares identifier
         * confidence, evidence confidence, and then the identifier.
         *
         * @param o the IdentifierMatch to compare to
         * @return the natural ordering of IdentifierMatch
         */
        @Override
        public int compareTo(IdentifierMatch o) {
            return new CompareToBuilder()
                    .append(confidence, o.confidence)
                    .append(evidenceConfidence, o.evidenceConfidence)
                    .append(identifier, o.identifier)
                    .toComparison();
        }
    }

    /**
     * Command line tool for querying the Lucene CPE Index.
     *
     * @param args not used
     */
    public static void main(String[] args) {
        final Settings props = new Settings();
        try (Engine en = new Engine(Engine.Mode.EVIDENCE_PROCESSING, props)) {
            en.openDatabase(false, false);
            final CPEAnalyzer analyzer = new CPEAnalyzer();
            analyzer.initialize(props);
            analyzer.prepareAnalyzer(en);
            LOGGER.error("test");
            System.out.println("Memory index query for ODC");
            try (BufferedReader br = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
                while (true) {
                    System.out.print("Vendor: ");
                    final String vendor = br.readLine();
                    System.out.print("Product: ");
                    final String product = br.readLine();
                    final List<IndexEntry> list = analyzer.searchCPE(vendor, product, null, null);
                    if (list == null || list.isEmpty()) {
                        System.out.println("No results found");
                    } else {
                        for (IndexEntry e : list) {
                            System.out.println(String.format("%s:%s (%f)", e.getVendor(), e.getProduct(), e.getSearchScore()));
                        }
                    }
                    System.out.println();
                    System.out.println();
                }
            }
        } catch (InitializationException | IOException ex) {
            System.err.println("Lucene ODC search tool failed:");
            System.err.println(ex.getMessage());
        }
    }
}
