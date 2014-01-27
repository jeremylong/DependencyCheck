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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

public class NuspecAnalyzerTest {
  private NuspecAnalyzer instance;

  @Before
  public void setUp() {
    instance = new NuspecAnalyzer();
  }

  @Test
  public void testGetAnalyzerName() {
    assertEquals("Nuspec Analyzer", instance.getName());
  }

  @Test
  public void testGetSupportedExtensions() {
    assertTrue(instance.getSupportedExtensions().contains("nuspec"));
    assertFalse(instance.getSupportedExtensions().contains("nupkg"));
  }

  @Test
  public void testSupportsExtension() {
    assertTrue(instance.supportsExtension("nuspec"));
    assertFalse(instance.supportsExtension("nupkg"));
  }

  @Test
  public void testGetAnalysisPhaze() {
    assertEquals(AnalysisPhase.INFORMATION_COLLECTION, instance.getAnalysisPhase());
  }
}

// vim: cc=120:sw=4:ts=4:sts=4
