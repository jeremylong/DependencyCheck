/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.codesecure.dependencycheck.data.cpe;

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
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class IndexTest extends BaseIndexTestCase {

    public IndexTest(String testCase) {
        super(testCase);
    }

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
        System.out.println("open");
        Index instance = new Index();
        try {
            instance.open();
        } catch (IOException ex) {
            fail(ex.getMessage());
        }
        instance.close();
    }

    /**
     * Test of getDirectory method, of class Index.
     */
    @Test
    public void testGetDirectory() throws Exception {
        System.out.println("getDirectory");
        Index index = new Index();
        Directory result = index.getDirectory();

        String exp = File.separatorChar + "target" + File.separatorChar + "data" + File.separatorChar + "cpe";
        assertTrue(result.toString().contains(exp));
    }
}
