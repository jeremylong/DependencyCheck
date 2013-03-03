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
package org.owasp.dependencycheck.data.cpe;

import org.owasp.dependencycheck.data.cpe.Index;
import java.io.File;
import java.io.IOException;
import junit.framework.Assert;
import org.apache.lucene.store.Directory;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;


/**
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class IndexTest {

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
     * Test of open method, of class Index.
     */
    @Test
    public void testOpen() {
        Index instance = new Index();
        try {
            instance.open();
        } catch (IOException ex) {
            Assert.fail(ex.getMessage());
        }
        instance.close();
    }

    /**
     * Test of getDirectory method, of class Index.
     * @throws Exception
     */
    @Test
    public void testGetDirectory() throws Exception {
        Index index = new Index();
        Directory result = index.getDirectory();

        String exp = File.separatorChar + "target" + File.separatorChar + "data" + File.separatorChar + "cpe";
        Assert.assertTrue(result.toString().contains(exp));
    }
}
