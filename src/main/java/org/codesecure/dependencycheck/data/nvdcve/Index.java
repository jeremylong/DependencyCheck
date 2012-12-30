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
package org.codesecure.dependencycheck.data.nvdcve;

import java.io.*;
import java.net.URLDecoder;
import java.util.*;
import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.core.KeywordAnalyzer;
import org.apache.lucene.analysis.miscellaneous.PerFieldAnalyzerWrapper;
import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.queryparser.classic.QueryParser;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.FSDirectory;
import org.apache.lucene.util.Version;
import org.codesecure.dependencycheck.data.lucene.AbstractIndex;
import org.codesecure.dependencycheck.utils.Settings;

/**
 * The Index class is used to utilize and maintain the NVD CVE Index.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class Index extends AbstractIndex {

    /**
     * Returns the directory that holds the NVD CVE Index. Note, this
     * returns the path where the class or jar file exists.
     *
     * @return the Directory containing the NVD CVE Index.
     * @throws IOException is thrown if an IOException occurs.
     */
    public Directory getDirectory() throws IOException {
        File path = getDataDirectory();
        Directory dir = FSDirectory.open(path);
        return dir;
    }

    /**
     * Retrieves the directory that the JAR file exists in so that
     * we can ensure we always use a common data directory.
     *
     * @return the data directory for this index.
     * @throws IOException is thrown if an IOException occurs of course...
     */
    protected File getDataDirectory() throws IOException {
        String fileName = Settings.getString(Settings.KEYS.CVE_INDEX);
        String filePath = Index.class.getProtectionDomain().getCodeSource().getLocation().getPath();
        String decodedPath = URLDecoder.decode(filePath, "UTF-8");
        File exePath = new File(decodedPath);
        if (exePath.getName().toLowerCase().endsWith(".jar")) {
            exePath = exePath.getParentFile();
        } else {
            exePath = new File(".");
        }
        File path = new File(exePath.getCanonicalFile() + File.separator + fileName);
        path = new File(path.getCanonicalPath());
        if (!path.exists()) {
            if (!path.mkdirs()) {
                throw new IOException("Unable to create NVD CVE Data directory");
            }
        }
        return path;
    }

    /**
     * Creates an Analyzer for the NVD VULNERABLE_CPE Index.
     *
     * @return the VULNERABLE_CPE Analyzer.
     */
    @SuppressWarnings("unchecked")
    public Analyzer createIndexingAnalyzer() {
        Map fieldAnalyzers = new HashMap();

        fieldAnalyzers.put(Fields.CVE_ID, new KeywordAnalyzer());
        fieldAnalyzers.put(Fields.VULNERABLE_CPE, new KeywordAnalyzer());

        PerFieldAnalyzerWrapper wrapper = new PerFieldAnalyzerWrapper(
                new StandardAnalyzer(Version.LUCENE_40), fieldAnalyzers);

        return wrapper;
    }

    /**
     * Creates an Analyzer for the NVD VULNERABLE_CPE Index.
     *
     * @return the VULNERABLE_CPE Analyzer.
     */
    @SuppressWarnings("unchecked")
    public Analyzer createSearchingAnalyzer() {
        Map fieldAnalyzers = new HashMap();

        fieldAnalyzers.put(Fields.CVE_ID, new KeywordAnalyzer());
        fieldAnalyzers.put(Fields.VULNERABLE_CPE, new KeywordAnalyzer());

        PerFieldAnalyzerWrapper wrapper = new PerFieldAnalyzerWrapper(
                new StandardAnalyzer(Version.LUCENE_40), fieldAnalyzers);

        return wrapper;
    }

    /**
     * Creates the Lucene QueryParser used when querying the index
     * @return a QueryParser
     */
    public QueryParser createQueryParser() {
        return new QueryParser(Version.LUCENE_40, Fields.VULNERABLE_CPE, getSearchingAnalyzer());
    }

    /**
     * Resets the searching analyzers
     */
    protected void resetSearchingAnalyzer() {
        //do nothing
    }
}
