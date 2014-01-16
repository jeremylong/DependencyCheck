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
package org.owasp.dependencycheck.data.lucene;

import java.io.IOException;
import java.util.HashMap;
import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.miscellaneous.PerFieldAnalyzerWrapper;
import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.document.TextField;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.IndexReader;
import org.apache.lucene.index.IndexWriter;
import org.apache.lucene.index.IndexWriterConfig;
import org.apache.lucene.queryparser.classic.QueryParser;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.ScoreDoc;
import org.apache.lucene.search.TopScoreDocCollector;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.RAMDirectory;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class FieldAnalyzerTest {

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    @Test
    public void testAnalyzers() throws Exception {

        Analyzer analyzer = new FieldAnalyzer(LuceneUtils.CURRENT_VERSION);
        Directory index = new RAMDirectory();

        String field1 = "product";
        String text1 = "springframework";

        String field2 = "vendor";
        String text2 = "springsource";

        createIndex(analyzer, index, field1, text1, field2, text2);

        //Analyzer searchingAnalyzer = new SearchFieldAnalyzer(LuceneUtils.CURRENT_VERSION);
        String querystr = "product:\"(Spring Framework Core)\" vendor:(SpringSource)";

        SearchFieldAnalyzer searchAnalyzerProduct = new SearchFieldAnalyzer(LuceneUtils.CURRENT_VERSION);
        SearchFieldAnalyzer searchAnalyzerVendor = new SearchFieldAnalyzer(LuceneUtils.CURRENT_VERSION);
        HashMap<String, Analyzer> map = new HashMap<String, Analyzer>();
        map.put(field1, searchAnalyzerProduct);
        map.put(field2, searchAnalyzerVendor);
        PerFieldAnalyzerWrapper wrapper = new PerFieldAnalyzerWrapper(new StandardAnalyzer(LuceneUtils.CURRENT_VERSION), map);
        QueryParser parser = new QueryParser(LuceneUtils.CURRENT_VERSION, field1, wrapper);

        Query q = parser.parse(querystr);
        //System.out.println(q.toString());

        int hitsPerPage = 10;

        IndexReader reader = DirectoryReader.open(index);
        IndexSearcher searcher = new IndexSearcher(reader);
        TopScoreDocCollector collector = TopScoreDocCollector.create(hitsPerPage, true);
        searcher.search(q, collector);
        ScoreDoc[] hits = collector.topDocs().scoreDocs;

        assertEquals("Did not find 1 document?", 1, hits.length);

        searchAnalyzerProduct.clear(); //ensure we don't have anything left over from the previous search.
        searchAnalyzerVendor.clear();
        querystr = "product:(Apache Struts) vendor:(Apache)";
        Query q2 = parser.parse(querystr);
        //System.out.println(q2.toString());
        assertFalse("second parsing contains previousWord from the TokenPairConcatenatingFilter", q2.toString().contains("core"));
    }

    private void createIndex(Analyzer analyzer, Directory index, String field1, String text1, String field2, String text2) throws IOException {
        IndexWriterConfig config = new IndexWriterConfig(LuceneUtils.CURRENT_VERSION, analyzer);
        IndexWriter w = new IndexWriter(index, config);
        addDoc(w, field1, text1, field2, text2);
        w.close();
    }

    private static void addDoc(IndexWriter w, String field1, String text1, String field2, String text2) throws IOException {
        Document doc = new Document();
        doc.add(new TextField(field1, text1, Field.Store.YES));
        doc.add(new TextField(field2, text2, Field.Store.YES));
        w.addDocument(doc);
    }
}
