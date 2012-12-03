/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.codesecure.dependencycheck.data.cpe;

import junit.framework.TestCase;

/**
 *
 * @author Jeremy Long
 */
public class EntryTest extends TestCase {
    
    public EntryTest(String testName) {
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
     * Test of setName method, of class Entry.
     * @throws Exception is thrown when an exception occurs.
     */
    public void testSetName() throws Exception {
        System.out.println("setName");
        String name = "cpe:/a:apache:struts:1.1:rc2";
        
        Entry instance = new Entry();
        instance.parseName(name);
        
        assertEquals(name,instance.getName());
        assertEquals("apache", instance.getVendor());
        assertEquals("struts", instance.getProduct());
        assertEquals("1.1", instance.getVersion());
        assertEquals("rc2", instance.getRevision());
        
    }
}
