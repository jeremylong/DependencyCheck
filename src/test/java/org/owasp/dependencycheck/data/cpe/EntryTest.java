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

import org.owasp.dependencycheck.data.cpe.Entry;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Assert;

/**
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class EntryTest {

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
     * Test of setName method, of class Entry.
     * @throws Exception is thrown when an exception occurs.
     */
    @Test
    public void testSetName() throws Exception {
        String name = "cpe:/a:apache:struts:1.1:rc2";

        Entry instance = new Entry();
        instance.parseName(name);

        Assert.assertEquals(name,instance.getName());
        Assert.assertEquals("apache", instance.getVendor());
        Assert.assertEquals("struts", instance.getProduct());
        Assert.assertEquals("1.1", instance.getVersion());
        Assert.assertEquals("rc2", instance.getRevision());
    }
}
