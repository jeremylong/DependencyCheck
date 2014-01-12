/*
 * This file is part of dependency-check-core.
 *
 * Dependency-check-core is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-check-core is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * dependency-check-core. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.lucene;

import org.owasp.dependencycheck.data.lucene.LuceneUtils;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class LuceneUtilsTest {

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

    /**
     * Test of appendEscapedLuceneQuery method, of class LuceneUtils.
     */
    @Test
    public void testAppendEscapedLuceneQuery() {
        StringBuilder buf = new StringBuilder();
        CharSequence text = "test encoding + - & | ! ( ) { } [ ] ^ \" ~ * ? : \\";
        String expResult = "test encoding \\+ \\- \\& \\| \\! \\( \\) \\{ \\} \\[ \\] \\^ \\\" \\~ \\* \\? \\: \\\\";
        LuceneUtils.appendEscapedLuceneQuery(buf, text);
        assertEquals(expResult, buf.toString());
    }

    /**
     * Test of appendEscapedLuceneQuery method, of class LuceneUtils.
     */
    @Test
    public void testAppendEscapedLuceneQuery_null() {
        StringBuilder buf = new StringBuilder();
        CharSequence text = null;
        LuceneUtils.appendEscapedLuceneQuery(buf, text);
        assertEquals(0, buf.length());
    }

    /**
     * Test of escapeLuceneQuery method, of class LuceneUtils.
     */
    @Test
    public void testEscapeLuceneQuery() {
        CharSequence text = "test encoding + - & | ! ( ) { } [ ] ^ \" ~ * ? : \\";
        String expResult = "test encoding \\+ \\- \\& \\| \\! \\( \\) \\{ \\} \\[ \\] \\^ \\\" \\~ \\* \\? \\: \\\\";
        String result = LuceneUtils.escapeLuceneQuery(text);
        assertEquals(expResult, result);
    }

    /**
     * Test of escapeLuceneQuery method, of class LuceneUtils.
     */
    @Test
    public void testEscapeLuceneQuery_null() {
        CharSequence text = null;
        String expResult = null;
        String result = LuceneUtils.escapeLuceneQuery(text);
        assertEquals(expResult, result);
    }
}
