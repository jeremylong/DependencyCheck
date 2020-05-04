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
 * Copyright (c) 2018 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nvd.json;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author jeremy long
 */
public class CpeMatchStreamCollectorTest {

    private List<DefNode> nodes;

    @Before
    public void setUp() {
        nodes = new ArrayList<>();
        for (int x = 0; x < 5; x++) {
            DefNode node = new DefNode();
            DefCpeMatch cpe = new DefCpeMatch();
            cpe.setCpe23Uri("cpe:/a:owasp:dependency-check:" + x);
            List<DefCpeMatch> cpes = new ArrayList<>();
            cpes.add(cpe);
            node.setCpeMatch(cpes);
            nodes.add(node);
        }
    }

    /**
     * Test of CpeMatchStreamCollector.
     */
    @Test
    public void testCollector() {
        assertTrue(nodes.stream().collect(CpeMatchStreamCollector.getInstance()).anyMatch((node) -> "cpe:/a:owasp:dependency-check:4".equals(node.getCpe23Uri())));
        List<String> operators = nodes.stream().collect(CpeMatchStreamCollector.getInstance()).map(mapper -> mapper.getCpe23Uri()).collect(Collectors.toList());
        assertEquals(5, operators.size());
    }
}
