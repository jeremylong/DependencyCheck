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
 * Copyright (c) 2022 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.maven;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.maven.shared.dependency.graph.DependencyNode;
import org.apache.maven.shared.dependency.graph.traversal.DependencyNodeVisitor;

/**
 *
 * @author Jeremy Long
 */
public class CollectingRootDependencyGraphVisitor implements DependencyNodeVisitor {

    /**
     * The map of nodes collected by root nodes.
     */
    private final Map<DependencyNode, List<DependencyNode>> nodes = new HashMap<>();
    private DependencyNode root;
    private int depth = 0;

    public CollectingRootDependencyGraphVisitor() {

    }

    @Override
    public boolean visit(DependencyNode node) {
        if (depth == 0) {
            root = node;
            if (!nodes.containsKey(root)) {
                nodes.put(root, new ArrayList<>());
            }
        } else {
            // collect node
            nodes.get(root).add(node);
        }
        depth += 1;
        return true;
    }

    @Override
    public boolean endVisit(DependencyNode node) {
        depth -= 1;
        return true;
    }

    public Map<DependencyNode, List<DependencyNode>> getNodes() {
        return Collections.unmodifiableMap(nodes);
    }

}
