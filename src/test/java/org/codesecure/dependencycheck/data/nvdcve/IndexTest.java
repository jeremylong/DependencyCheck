/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.codesecure.dependencycheck.data.nvdcve;

import java.io.File;
import org.apache.lucene.store.Directory;
import static org.junit.Assert.assertTrue;
import org.junit.*;

/**
 *
 * @author Jeremy
 */
public class IndexTest extends BaseIndexTestCase {

    public IndexTest(String testName) {
        super(testName);
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
     * Test of getDirectory method, of class Index.
     */
    @Test
    public void testGetDirectory() throws Exception {
        System.out.println("getDirectory");
        Index instance = new Index();
        String exp = File.separatorChar + "target" + File.separatorChar + "data" + File.separatorChar + "cve";
        Directory result = instance.getDirectory();
       
        assertTrue(result.toString().contains(exp));
    }
}
