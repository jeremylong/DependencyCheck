/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.codesecure.dependencycheck.cpe.xml;

import java.io.File;
import junit.framework.TestCase;
import org.codesecure.dependencycheck.data.cpe.xml.Importer;
import org.xml.sax.Attributes;

/**
 *
 * @author jeremy
 */
public class CPEHandlerTest extends TestCase {
    
    public CPEHandlerTest(String testName) {
        super(testName);
    }
    
    @Override
    protected void setUp() throws Exception {
        super.setUp();
    }
    
    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }


    /**
     * Test of all methods within class CPEHandler.
     */
    public void testHandler() throws Exception {
        System.out.println("CPEHandler");
        
        File path = new File(this.getClass().getClassLoader().getResource("official-cpe-dictionary_v2.2.xml").getPath());
        
        
        Importer.importXML(path.getCanonicalPath());
       
    }

    
}
