/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.codesecure.dependencycheck.data.cpe;

import org.codesecure.dependencycheck.data.BaseIndexTestCase;

/**
 *
 * @author jeremy
 */
public class IndexTestCase  extends BaseIndexTestCase {
    
    public IndexTestCase(String testName) {
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
    
    public void testIgnoreThisClass() throws Exception {
        assertTrue(true);
    }
    
}
