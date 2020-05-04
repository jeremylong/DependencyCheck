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
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.BinaryOperator;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collector;
import java.util.stream.Stream;

import javax.annotation.concurrent.ThreadSafe;

/**
 * Used to flatten a hierarchical list of nodes with children.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public final class NodeFlatteningCollector implements Collector<DefNode, ArrayList<DefNode>, Stream<DefNode>> {

    /**
     * Singleton instance variable.
     */
    private static final NodeFlatteningCollector INSTANCE;

    static {
        INSTANCE = new NodeFlatteningCollector();
    }

    public static NodeFlatteningCollector getInstance() {
        return INSTANCE;
    }

    private NodeFlatteningCollector() {
    }

    /**
     * Flattens the hierarchical list of nodes.
     *
     * @param node the node with children to flatten
     * @return the flattened list of nodes
     */
    private List<DefNode> flatten(DefNode node) {
        final List<DefNode> result = new ArrayList<>();
        result.add(node);
        return flatten(result, node.getChildren());
    }

    /**
     * Flattens the hierarchical list of nodes.
     *
     * @param result the results
     * @param nodes the nodes
     * @return the flattened list of nodes
     */
    private List<DefNode> flatten(List<DefNode> result, List<DefNode> nodes) {
        nodes.forEach(n -> {
            flatten(result, n.getChildren());
            result.add(n);
        });
        return result;
    }

    @Override
    public Supplier<ArrayList<DefNode>> supplier() {
        return ArrayList::new;
    }

    @Override
    public BiConsumer<ArrayList<DefNode>, DefNode> accumulator() {
        return (nodes, n) -> nodes.addAll(flatten(n));
    }

    @Override
    public BinaryOperator<ArrayList<DefNode>> combiner() {
        return (map, other) -> {
            map.addAll(other);
            return map;
        };
    }

    @Override
    public Function<ArrayList<DefNode>, Stream<DefNode>> finisher() {
        return (m) -> m.stream();
    }

    @Override
    public Set<Characteristics> characteristics() {
        return EnumSet.of(Characteristics.UNORDERED);
    }
}
