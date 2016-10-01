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
 * Copyright (c) 2016 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck;

import java.io.File;
import org.junit.Test;
import static org.junit.Assert.*;
import org.owasp.dependencycheck.analyzer.JarAnalyzer;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.dependency.Dependency;

/**
 *
 * @author Jeremy Long
 */
public class EngineTest extends BaseDBTestCase {

    /**
     * Test of scanFile method, of class Engine.
     */
    @Test
    public void testScanFile() throws DatabaseException {
        Engine instance = new Engine();
        instance.addFileTypeAnalyzer(new JarAnalyzer());
        File file = BaseTest.getResourceAsFile(this, "dwr.jar");
        Dependency dwr = instance.scanFile(file);
        file = BaseTest.getResourceAsFile(this, "org.mortbay.jmx.jar");
        Dependency jmx = instance.scanFile(file);
        assertEquals(2, instance.getDependencies().size());
        
        file = BaseTest.getResourceAsFile(this, "dwr.jar");
        Dependency secondDwr = instance.scanFile(file);
        
        assertEquals(2, instance.getDependencies().size());
        assertTrue(dwr == secondDwr);
        
    }
}
