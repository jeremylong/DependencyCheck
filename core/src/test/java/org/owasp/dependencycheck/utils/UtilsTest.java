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
 * Copyright (c) 2023 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Jeremy Long
 */
public class UtilsTest {

    /**
     * Test of parseUpdate method, of class Utils.
     */
    @Test
    public void testParseUpdate() {

        String runtimeVersion = "1.8.0_252-8u252-b09-1~deb9u1-b09";
        int expResult = 252;
        int result = Utils.parseUpdate(runtimeVersion);
        assertEquals(expResult, result);

        runtimeVersion = "1.8.0_144";
        expResult = 144;
        result = Utils.parseUpdate(runtimeVersion);
        assertEquals(expResult, result);

        runtimeVersion = "11.0.2+9";
        expResult = 2;
        result = Utils.parseUpdate(runtimeVersion);
        assertEquals(expResult, result);

        runtimeVersion = "17.0.8.1";
        expResult = 8;
        result = Utils.parseUpdate(runtimeVersion);
        assertEquals(expResult, result);
    }

}
