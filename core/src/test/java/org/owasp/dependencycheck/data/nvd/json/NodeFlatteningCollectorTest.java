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
public class NodeFlatteningCollectorTest {

    private List<Node> nodes;

    @Before
    public void setUp() {
        nodes = new ArrayList<>();
        Node node = new Node();
        node.setOperator("top");
        nodes.add(node);

        Node parent = node;
        for (int x = 0; x < 5; x++) {
            Node child = new Node();
            child.setOperator("Child " + x);
            List<Node> l = new ArrayList<>(1);
            l.add(child);
            parent.setChildren(l);
            parent = child;
        }
    }

    /**
     * Test of supplier method, of class NodeFlatteningCollector.
     */
    @Test
    public void testCollector() {
        assertFalse(nodes.stream().anyMatch((node) -> "Child 4".equals(node.getOperator())));
        assertTrue(nodes.stream().collect(new NodeFlatteningCollector()).anyMatch((node) -> "Child 4".equals(node.getOperator())));
        List<String> operators = nodes.stream().collect(new NodeFlatteningCollector()).map(mapper -> mapper.getOperator()).collect(Collectors.toList());
        assertEquals(6, operators.size());
    }
}
