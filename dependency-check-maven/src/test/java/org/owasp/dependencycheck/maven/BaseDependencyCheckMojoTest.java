/*
 * This file is part of dependency-check-maven.
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
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.maven;

import java.io.File;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import mockit.Mock;
import mockit.MockUp;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugin.testing.stubs.ArtifactStub;
import org.apache.maven.project.MavenProject;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class BaseDependencyCheckMojoTest extends BaseTest {

    /**
     * Test of scanArtifacts method, of class BaseDependencyCheckMojo.
     */
    @Test
    public void testScanArtifacts() throws DatabaseException, InvalidSettingException {
        MavenProject project = new MockUp<MavenProject>() {
            @Mock
            public Set<Artifact> getArtifacts() {
                Set<Artifact> artifacts = new HashSet<Artifact>();
                Artifact a = new ArtifactStub();
                try {
                    File file = new File(Test.class.getProtectionDomain().getCodeSource().getLocation().toURI());
                    a.setFile(file);
                    artifacts.add(a);
                } catch (URISyntaxException ex) {
                    Logger.getLogger(BaseDependencyCheckMojoTest.class.getName()).log(Level.SEVERE, null, ex);
                }
                //File file = new File(this.getClass().getClassLoader().getResource("daytrader-ear-2.1.7.ear").getPath());

                return artifacts;
            }
        }.getMockInstance();

        boolean autoUpdate = Settings.getBoolean(Settings.KEYS.AUTO_UPDATE);
        Settings.setBoolean(Settings.KEYS.AUTO_UPDATE, false);
        Engine engine = new Engine(null, null);
        Settings.setBoolean(Settings.KEYS.AUTO_UPDATE, autoUpdate);

        assertTrue(engine.getDependencies().isEmpty());
        BaseDependencyCheckMojoImpl instance = new BaseDependencyCheckMojoImpl();
        instance.scanArtifacts(project, engine);
        assertFalse(engine.getDependencies().isEmpty());
        engine.cleanup();
    }

    public class BaseDependencyCheckMojoImpl extends BaseDependencyCheckMojo {

        @Override
        public void runCheck() throws MojoExecutionException, MojoFailureException {
            throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        }

        @Override
        public String getName(Locale locale) {
            return "test implementation";
        }

        @Override
        public String getDescription(Locale locale) {
            return "test implementation";
        }

        @Override
        public boolean canGenerateReport() {
            throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        }

    }

}
