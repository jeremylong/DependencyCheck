/*
 * This file is part of dependency-check-core.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import java.io.File;
import mockit.Mocked;
import mockit.Verifications;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Dependency;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * @author Jeremy Long
 */
public class DependencyBundlingAnalyzerTest extends BaseTest {

    @Mocked
    private Engine engineMock;

    /**
     * Test of getName method, of class DependencyBundlingAnalyzer.
     */
    @Test
    public void testGetName() {
        DependencyBundlingAnalyzer instance = new DependencyBundlingAnalyzer();
        String expResult = "Dependency Bundling Analyzer";
        String result = instance.getName();
        assertEquals(expResult, result);
    }

    /**
     * Test of getAnalysisPhase method, of class DependencyBundlingAnalyzer.
     */
    @Test
    public void testGetAnalysisPhase() {
        DependencyBundlingAnalyzer instance = new DependencyBundlingAnalyzer();
        AnalysisPhase expResult = AnalysisPhase.FINAL;
        AnalysisPhase result = instance.getAnalysisPhase();
        assertEquals(expResult, result);
    }

    /**
     * Test of analyze method, of class DependencyBundlingAnalyzer. The actually
     * passed dependency does not matter. The analyzer only runs once.
     */
    @Test
    public void testAnalyze() throws Exception {
        DependencyBundlingAnalyzer instance = new DependencyBundlingAnalyzer();

        // the actual dependency does not matter
        assertFalse(instance.getAnalyzed());
        instance.analyze(null, engineMock);

        // the second runs basically does nothing
        assertTrue(instance.getAnalyzed());
        instance.analyze(null, engineMock);
        instance.analyze(null, engineMock);
        instance.analyze(null, engineMock);
        assertTrue(instance.getAnalyzed());

        new Verifications() {
            {
                engineMock.getDependencies();
                times = 1;
            }
        };
    }

    /**
     * Test of isCore method, of class DependencyBundlingAnalyzer.
     */
    @Test
    public void testIsCore() {
        Dependency left = new Dependency();
        Dependency right = new Dependency();

        left.setFileName("axis2-kernel-1.4.1.jar");
        right.setFileName("axis2-adb-1.4.1.jar");
        DependencyBundlingAnalyzer instance = new DependencyBundlingAnalyzer();
        boolean expResult = true;
        boolean result = instance.isCore(left, right);
        assertEquals(expResult, result);

        left.setFileName("struts-1.2.7.jar");
        right.setFileName("file.tar.gz\\file.tar\\struts.jar");

        expResult = true;
        result = instance.isCore(left, right);
        assertEquals(expResult, result);
    }

    @Test
    public void testFirstPathIsShortest() {
        DependencyBundlingAnalyzer instance = new DependencyBundlingAnalyzer();

        String left = "./a/c.jar";
        String right = "./d/e/f.jar";
        boolean expResult = true;
        boolean result = instance.firstPathIsShortest(left, right);
        assertEquals(expResult, result);

        left = "./a/b/c.jar";
        right = "./d/e/f.jar";
        expResult = true;
        result = instance.firstPathIsShortest(left, right);
        assertEquals(expResult, result);

        left = "./d/b/c.jar";
        right = "./a/e/f.jar";
        expResult = false;
        result = instance.firstPathIsShortest(left, right);
        assertEquals(expResult, result);

        left = "./a/b/c.jar";
        right = "./d/f.jar";
        expResult = false;
        result = instance.firstPathIsShortest(left, right);
        assertEquals(expResult, result);

        left = "./a/b/c.jar";
        right = "./a/b/c.jar";
        expResult = true;
        result = instance.firstPathIsShortest(left, right);
        assertEquals(expResult, result);
    }

    @Test
    public void testIsShaded() {
        DependencyBundlingAnalyzer instance = new DependencyBundlingAnalyzer();

        Dependency left = null;
        Dependency right = null;

        boolean expResult = false;
        boolean result = instance.isShadedJar(left, right);
        assertEquals(expResult, result);

        left = new Dependency();
        expResult = false;
        result = instance.isShadedJar(left, right);
        assertEquals(expResult, result);

        left = new Dependency(new File("/path/jar.jar"), true);
        expResult = false;
        result = instance.isShadedJar(left, right);
        assertEquals(expResult, result);

        right = new Dependency();
        expResult = false;
        result = instance.isShadedJar(left, right);
        assertEquals(expResult, result);

        right = new Dependency(new File("/path/pom.xml"), true);
        expResult = false;
        result = instance.isShadedJar(left, right);
        assertEquals(expResult, result);

        left.addIdentifier("test", "test", "http://example.com/test");
        expResult = false;
        result = instance.isShadedJar(left, right);
        assertEquals(expResult, result);

        right.addIdentifier("next", "next", "http://example.com/next");
        expResult = false;
        result = instance.isShadedJar(left, right);
        assertEquals(expResult, result);

        left.addIdentifier("next", "next", "http://example.com/next");
        expResult = true;
        result = instance.isShadedJar(left, right);
        assertEquals(expResult, result);

        left = new Dependency(new File("/path/pom.xml"), true);
        left.addIdentifier("test", "test", "http://example.com/test");
        right = new Dependency(new File("/path/jar.jar"), true);
        right.addIdentifier("next", "next", "http://example.com/next");
        expResult = false;
        result = instance.isShadedJar(left, right);
        assertEquals(expResult, result);
        
        right.addIdentifier("test", "test", "http://example.com/test");
        expResult = true;
        result = instance.isShadedJar(left, right);
        assertEquals(expResult, result);
        
        left = new Dependency(new File("/path/other.jar"), true);
        left.addIdentifier("test", "test", "http://example.com/test");
        right = new Dependency(new File("/path/jar.jar"), true);
        right.addIdentifier("next", "next", "http://example.com/next");
        expResult = false;
        result = instance.isShadedJar(left, right);
        assertEquals(expResult, result);
    }
}
