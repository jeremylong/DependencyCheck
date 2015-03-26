/*
 * Copyright 2014 OWASP.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.owasp.dependencycheck.org.apache.tools.ant;

import org.owasp.dependencycheck.org.apache.tools.ant.DirectoryScanner;
import java.io.File;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class DirectoryScannerTest {

    public DirectoryScannerTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    /**
     * Testing the expected use of the directory scanner.
     */
    @Test
    public void testExpectedUse() {
        DirectoryScanner scanner = new DirectoryScanner();
        scanner.setBasedir("./target");
        scanner.setIncludes("/test-classes/**");
        scanner.scan();

        File base = new File("./target");
        for (String t : scanner.getIncludedFiles()) {
            assertTrue(t.startsWith("test-classes"));
            File test = new File(base, t);
            assertTrue(test.exists());
        }
    }

    /**
     * Test of matchPatternStart method, of class DirectoryScanner.
     */
    @Test
    public void testMatchPatternStart_String_String() {
        String pattern = "alpha/be?a/**";
        String str = "alpha/beta/gamma/";
        boolean expResult = true;
        boolean result = DirectoryScanner.matchPatternStart(pattern, str);
        assertEquals(expResult, result);
    }

    /**
     * Test of matchPatternStart method, of class DirectoryScanner.
     */
    @Test
    public void testMatchPatternStart_3args() {
        String pattern = "Alpha/be?a/**";
        String str = "alpha/beta/gamma/";
        boolean isCaseSensitive = true;
        boolean expResult = false;
        boolean result = DirectoryScanner.matchPatternStart(pattern, str, isCaseSensitive);
        assertEquals(expResult, result);

        isCaseSensitive = false;
        expResult = true;
        result = DirectoryScanner.matchPatternStart(pattern, str, isCaseSensitive);
        assertEquals(expResult, result);
    }

    /**
     * Test of matchPath method, of class DirectoryScanner.
     */
    @Test
    public void testMatchPath_String_String() {
        String pattern = "alpha/be?a/**";
        String str = "alpha/beta/gamma/";
        boolean expResult = true;
        boolean result = DirectoryScanner.matchPath(pattern, str);
        assertEquals(expResult, result);
    }
//
//    /**
//     * Test of matchPath method, of class DirectoryScanner.
//     */
//    @Test
//    public void testMatchPath_3args() {
//        System.out.println("matchPath");
//        String pattern = "";
//        String str = "";
//        boolean isCaseSensitive = false;
//        boolean expResult = false;
//        boolean result = DirectoryScanner.matchPath(pattern, str, isCaseSensitive);
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of match method, of class DirectoryScanner.
//     */
//    @Test
//    public void testMatch_String_String() {
//        System.out.println("match");
//        String pattern = "";
//        String str = "";
//        boolean expResult = false;
//        boolean result = DirectoryScanner.match(pattern, str);
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of match method, of class DirectoryScanner.
//     */
//    @Test
//    public void testMatch_3args() {
//        System.out.println("match");
//        String pattern = "";
//        String str = "";
//        boolean isCaseSensitive = false;
//        boolean expResult = false;
//        boolean result = DirectoryScanner.match(pattern, str, isCaseSensitive);
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of getDefaultExcludes method, of class DirectoryScanner.
//     */
//    @Test
//    public void testGetDefaultExcludes() {
//        System.out.println("getDefaultExcludes");
//        String[] expResult = null;
//        String[] result = DirectoryScanner.getDefaultExcludes();
//        assertArrayEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of addDefaultExclude method, of class DirectoryScanner.
//     */
//    @Test
//    public void testAddDefaultExclude() {
//        System.out.println("addDefaultExclude");
//        String s = "";
//        boolean expResult = false;
//        boolean result = DirectoryScanner.addDefaultExclude(s);
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of removeDefaultExclude method, of class DirectoryScanner.
//     */
//    @Test
//    public void testRemoveDefaultExclude() {
//        System.out.println("removeDefaultExclude");
//        String s = "";
//        boolean expResult = false;
//        boolean result = DirectoryScanner.removeDefaultExclude(s);
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of resetDefaultExcludes method, of class DirectoryScanner.
//     */
//    @Test
//    public void testResetDefaultExcludes() {
//        System.out.println("resetDefaultExcludes");
//        DirectoryScanner.resetDefaultExcludes();
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of setBasedir method, of class DirectoryScanner.
//     */
//    @Test
//    public void testSetBasedir_String() {
//        System.out.println("setBasedir");
//        String basedir = "";
//        DirectoryScanner instance = new DirectoryScanner();
//        instance.setBasedir(basedir);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of setBasedir method, of class DirectoryScanner.
//     */
//    @Test
//    public void testSetBasedir_File() {
//        System.out.println("setBasedir");
//        File basedir = null;
//        DirectoryScanner instance = new DirectoryScanner();
//        instance.setBasedir(basedir);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of getBasedir method, of class DirectoryScanner.
//     */
//    @Test
//    public void testGetBasedir() {
//        System.out.println("getBasedir");
//        DirectoryScanner instance = new DirectoryScanner();
//        File expResult = null;
//        File result = instance.getBasedir();
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of isCaseSensitive method, of class DirectoryScanner.
//     */
//    @Test
//    public void testIsCaseSensitive() {
//        System.out.println("isCaseSensitive");
//        DirectoryScanner instance = new DirectoryScanner();
//        boolean expResult = false;
//        boolean result = instance.isCaseSensitive();
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of setCaseSensitive method, of class DirectoryScanner.
//     */
//    @Test
//    public void testSetCaseSensitive() {
//        System.out.println("setCaseSensitive");
//        boolean isCaseSensitive = false;
//        DirectoryScanner instance = new DirectoryScanner();
//        instance.setCaseSensitive(isCaseSensitive);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of setErrorOnMissingDir method, of class DirectoryScanner.
//     */
//    @Test
//    public void testSetErrorOnMissingDir() {
//        System.out.println("setErrorOnMissingDir");
//        boolean errorOnMissingDir = false;
//        DirectoryScanner instance = new DirectoryScanner();
//        instance.setErrorOnMissingDir(errorOnMissingDir);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of isFollowSymlinks method, of class DirectoryScanner.
//     */
//    @Test
//    public void testIsFollowSymlinks() {
//        System.out.println("isFollowSymlinks");
//        DirectoryScanner instance = new DirectoryScanner();
//        boolean expResult = false;
//        boolean result = instance.isFollowSymlinks();
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of setFollowSymlinks method, of class DirectoryScanner.
//     */
//    @Test
//    public void testSetFollowSymlinks() {
//        System.out.println("setFollowSymlinks");
//        boolean followSymlinks = false;
//        DirectoryScanner instance = new DirectoryScanner();
//        instance.setFollowSymlinks(followSymlinks);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of setMaxLevelsOfSymlinks method, of class DirectoryScanner.
//     */
//    @Test
//    public void testSetMaxLevelsOfSymlinks() {
//        System.out.println("setMaxLevelsOfSymlinks");
//        int max = 0;
//        DirectoryScanner instance = new DirectoryScanner();
//        instance.setMaxLevelsOfSymlinks(max);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of setIncludes method, of class DirectoryScanner.
//     */
//    @Test
//    public void testSetIncludes() {
//        System.out.println("setIncludes");
//        String[] includes = null;
//        DirectoryScanner instance = new DirectoryScanner();
//        instance.setIncludes(includes);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of setExcludes method, of class DirectoryScanner.
//     */
//    @Test
//    public void testSetExcludes() {
//        System.out.println("setExcludes");
//        String[] excludes = null;
//        DirectoryScanner instance = new DirectoryScanner();
//        instance.setExcludes(excludes);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of addExcludes method, of class DirectoryScanner.
//     */
//    @Test
//    public void testAddExcludes() {
//        System.out.println("addExcludes");
//        String[] excludes = null;
//        DirectoryScanner instance = new DirectoryScanner();
//        instance.addExcludes(excludes);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of setSelectors method, of class DirectoryScanner.
//     */
//    @Test
//    public void testSetSelectors() {
//        System.out.println("setSelectors");
//        FileSelector[] selectors = null;
//        DirectoryScanner instance = new DirectoryScanner();
//        instance.setSelectors(selectors);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of isEverythingIncluded method, of class DirectoryScanner.
//     */
//    @Test
//    public void testIsEverythingIncluded() {
//        System.out.println("isEverythingIncluded");
//        DirectoryScanner instance = new DirectoryScanner();
//        boolean expResult = false;
//        boolean result = instance.isEverythingIncluded();
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of scan method, of class DirectoryScanner.
//     */
//    @Test
//    public void testScan() {
//        System.out.println("scan");
//        DirectoryScanner instance = new DirectoryScanner();
//        instance.scan();
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of clearResults method, of class DirectoryScanner.
//     */
//    @Test
//    public void testClearResults() {
//        System.out.println("clearResults");
//        DirectoryScanner instance = new DirectoryScanner();
//        instance.clearResults();
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of slowScan method, of class DirectoryScanner.
//     */
//    @Test
//    public void testSlowScan() {
//        System.out.println("slowScan");
//        DirectoryScanner instance = new DirectoryScanner();
//        instance.slowScan();
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of scandir method, of class DirectoryScanner.
//     */
//    @Test
//    public void testScandir() {
//        System.out.println("scandir");
//        File dir = null;
//        String vpath = "";
//        boolean fast = false;
//        DirectoryScanner instance = new DirectoryScanner();
//        instance.scandir(dir, vpath, fast);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of isIncluded method, of class DirectoryScanner.
//     */
//    @Test
//    public void testIsIncluded() {
//        System.out.println("isIncluded");
//        String name = "";
//        DirectoryScanner instance = new DirectoryScanner();
//        boolean expResult = false;
//        boolean result = instance.isIncluded(name);
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of couldHoldIncluded method, of class DirectoryScanner.
//     */
//    @Test
//    public void testCouldHoldIncluded() {
//        System.out.println("couldHoldIncluded");
//        String name = "";
//        DirectoryScanner instance = new DirectoryScanner();
//        boolean expResult = false;
//        boolean result = instance.couldHoldIncluded(name);
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of contentsExcluded method, of class DirectoryScanner.
//     */
//    @Test
//    public void testContentsExcluded() {
//        System.out.println("contentsExcluded");
//        TokenizedPath path = null;
//        DirectoryScanner instance = new DirectoryScanner();
//        boolean expResult = false;
//        boolean result = instance.contentsExcluded(path);
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of isExcluded method, of class DirectoryScanner.
//     */
//    @Test
//    public void testIsExcluded() {
//        System.out.println("isExcluded");
//        String name = "";
//        DirectoryScanner instance = new DirectoryScanner();
//        boolean expResult = false;
//        boolean result = instance.isExcluded(name);
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of isSelected method, of class DirectoryScanner.
//     */
//    @Test
//    public void testIsSelected() {
//        System.out.println("isSelected");
//        String name = "";
//        File file = null;
//        DirectoryScanner instance = new DirectoryScanner();
//        boolean expResult = false;
//        boolean result = instance.isSelected(name, file);
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of getIncludedFiles method, of class DirectoryScanner.
//     */
//    @Test
//    public void testGetIncludedFiles() {
//        System.out.println("getIncludedFiles");
//        DirectoryScanner instance = new DirectoryScanner();
//        String[] expResult = null;
//        String[] result = instance.getIncludedFiles();
//        assertArrayEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of getIncludedFilesCount method, of class DirectoryScanner.
//     */
//    @Test
//    public void testGetIncludedFilesCount() {
//        System.out.println("getIncludedFilesCount");
//        DirectoryScanner instance = new DirectoryScanner();
//        int expResult = 0;
//        int result = instance.getIncludedFilesCount();
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of getNotIncludedFiles method, of class DirectoryScanner.
//     */
//    @Test
//    public void testGetNotIncludedFiles() {
//        System.out.println("getNotIncludedFiles");
//        DirectoryScanner instance = new DirectoryScanner();
//        String[] expResult = null;
//        String[] result = instance.getNotIncludedFiles();
//        assertArrayEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of getExcludedFiles method, of class DirectoryScanner.
//     */
//    @Test
//    public void testGetExcludedFiles() {
//        System.out.println("getExcludedFiles");
//        DirectoryScanner instance = new DirectoryScanner();
//        String[] expResult = null;
//        String[] result = instance.getExcludedFiles();
//        assertArrayEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of getDeselectedFiles method, of class DirectoryScanner.
//     */
//    @Test
//    public void testGetDeselectedFiles() {
//        System.out.println("getDeselectedFiles");
//        DirectoryScanner instance = new DirectoryScanner();
//        String[] expResult = null;
//        String[] result = instance.getDeselectedFiles();
//        assertArrayEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of getIncludedDirectories method, of class DirectoryScanner.
//     */
//    @Test
//    public void testGetIncludedDirectories() {
//        System.out.println("getIncludedDirectories");
//        DirectoryScanner instance = new DirectoryScanner();
//        String[] expResult = null;
//        String[] result = instance.getIncludedDirectories();
//        assertArrayEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of getIncludedDirsCount method, of class DirectoryScanner.
//     */
//    @Test
//    public void testGetIncludedDirsCount() {
//        System.out.println("getIncludedDirsCount");
//        DirectoryScanner instance = new DirectoryScanner();
//        int expResult = 0;
//        int result = instance.getIncludedDirsCount();
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of getNotIncludedDirectories method, of class DirectoryScanner.
//     */
//    @Test
//    public void testGetNotIncludedDirectories() {
//        System.out.println("getNotIncludedDirectories");
//        DirectoryScanner instance = new DirectoryScanner();
//        String[] expResult = null;
//        String[] result = instance.getNotIncludedDirectories();
//        assertArrayEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of getExcludedDirectories method, of class DirectoryScanner.
//     */
//    @Test
//    public void testGetExcludedDirectories() {
//        System.out.println("getExcludedDirectories");
//        DirectoryScanner instance = new DirectoryScanner();
//        String[] expResult = null;
//        String[] result = instance.getExcludedDirectories();
//        assertArrayEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of getDeselectedDirectories method, of class DirectoryScanner.
//     */
//    @Test
//    public void testGetDeselectedDirectories() {
//        System.out.println("getDeselectedDirectories");
//        DirectoryScanner instance = new DirectoryScanner();
//        String[] expResult = null;
//        String[] result = instance.getDeselectedDirectories();
//        assertArrayEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of getNotFollowedSymlinks method, of class DirectoryScanner.
//     */
//    @Test
//    public void testGetNotFollowedSymlinks() {
//        System.out.println("getNotFollowedSymlinks");
//        DirectoryScanner instance = new DirectoryScanner();
//        String[] expResult = null;
//        String[] result = instance.getNotFollowedSymlinks();
//        assertArrayEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of addDefaultExcludes method, of class DirectoryScanner.
//     */
//    @Test
//    public void testAddDefaultExcludes() {
//        System.out.println("addDefaultExcludes");
//        DirectoryScanner instance = new DirectoryScanner();
//        instance.addDefaultExcludes();
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of getResource method, of class DirectoryScanner.
//     */
//    @Test
//    public void testGetResource() {
//        System.out.println("getResource");
//        String name = "";
//        DirectoryScanner instance = new DirectoryScanner();
//        Resource expResult = null;
//        Resource result = instance.getResource(name);
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of getScannedDirs method, of class DirectoryScanner.
//     */
//    @Test
//    public void testGetScannedDirs() {
//        System.out.println("getScannedDirs");
//        DirectoryScanner instance = new DirectoryScanner();
//        Set<String> expResult = null;
//        Set<String> result = instance.getScannedDirs();
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }
//
//    /**
//     * Test of ensureNonPatternSetsReady method, of class DirectoryScanner.
//     */
//    @Test
//    public void testEnsureNonPatternSetsReady() {
//        System.out.println("ensureNonPatternSetsReady");
//        DirectoryScanner instance = new DirectoryScanner();
//        instance.ensureNonPatternSetsReady();
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
//    }

}
