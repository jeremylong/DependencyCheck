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
 * Copyright (c) 2021 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import java.io.File;
import java.io.FileFilter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import javax.json.JsonArray;
import javax.json.JsonObject;
import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.collections4.multimap.HashSetValuedHashMap;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nodeaudit.Advisory;
import org.owasp.dependencycheck.data.nodeaudit.NodeAuditSearch;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;

/**
 *
 * @author jeremy long
 */
public class AbstractNpmAnalyzerIT {
    

    /**
     * Test of determineVersionFromMap method, of class AbstractNpmAnalyzer.
     */
    @Test
    public void testDetermineVersionFromMap() {
        String versionRange = ">2.1.1 <5.0.1";
        Collection<String> availableVersions = new ArrayList<>();
        availableVersions.add("2.0.2");
        availableVersions.add("5.0.2");
        availableVersions.add("10.1.0");
        availableVersions.add("8.1.0");
        availableVersions.add("5.1.0");
        availableVersions.add("7.1.0");
        availableVersions.add("3.0.0");
        availableVersions.add("2.0.0");
        AbstractNpmAnalyzer instance = new AbstractNpmAnalyzerImpl();
        String expResult = "3.0.0";
        String result = instance.determineVersionFromMap(versionRange, availableVersions);
        assertEquals(expResult, result);
    }

    public class AbstractNpmAnalyzerImpl extends AbstractNpmAnalyzer {

        @Override
        protected FileFilter getFileFilter() {
            throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        }

        @Override
        protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
            throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        }

        @Override
        protected String getAnalyzerEnabledSettingKey() {
            throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        }

        @Override
        public String getName() {
            throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        }

        @Override
        public AnalysisPhase getAnalysisPhase() {
            throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        }
    }
    
}
