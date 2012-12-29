/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.codesecure.dependencycheck.data.nvdcve.xml;

import java.io.File;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.lucene.index.CorruptIndexException;
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
public class NvdCveParserTest {

    public NvdCveParserTest() {
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
     * Test of parse method, of class NvdCveParser.
     */
    @Test
    public void testParse() throws InvalidDataException {
        NvdCveParser instance = null;
        try {
            System.out.println("parse");
            File file = new File(this.getClass().getClassLoader().getResource("nvdcve-2.0-2012.xml").getPath());
            instance = new NvdCveParser();
            instance.openIndexWriter();
            instance.parse(file);
        } catch (CorruptIndexException ex) {
            throw new InvalidDataException("corrupt index", ex);
        } catch (IOException ex) {
            throw new InvalidDataException("IO Exception", ex);
        } finally {
            if (instance != null) {
                instance.close();
            }
        }
    }
}
