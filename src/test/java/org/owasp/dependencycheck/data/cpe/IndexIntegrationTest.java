/*
 * This file is part of Dependency-Check.
 *
 * Dependency-Check is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Check is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Check. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.cpe;

import java.io.File;
import java.io.IOException;
import org.apache.lucene.store.Directory;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Jeremy Long (jeremy.long@owasp.org)
 */
public class IndexIntegrationTest {

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
     * Test of update method, of class Index.
     */
    @Test
    public void testUpdate() throws Exception {
        //deprecated
        //Index instance = new Index();
        //instance.update();
    }

    /**
     * Test of updateNeeded method, of class Index.
     */
    @Test
    public void testUpdateNeeded() throws Exception {
        //deprecated
        //Index instance = new Index();
        //instance.updateNeeded();
        //if an exception is thrown this test fails. However, because it depends on the
        //  order of the tests what this will return I am just testing for the exception.
        //assertTrue(expResult < result);
    }
}
