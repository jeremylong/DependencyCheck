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

/**
 * Used to flatten a hierarchical list of nodes with children.
 *
 * @author Jeremy Long
 */
public class NodeFlatteningCollector implements Collector<Node, ArrayList<Node>, Stream<Node>> {

    /**
     * Flattens the hierarchical list of nodes.
     *
     * @param node the node with children to flatten
     * @return the flattened list of nodes
     */
    private List<Node> flatten(Node node) {
        final List<Node> result = new ArrayList<>();
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
    private List<Node> flatten(List<Node> result, List<Node> nodes) {
        nodes.stream().forEach(n -> {
            flatten(result, n.getChildren());
            result.add(n);
        });
        return result;
    }

    @Override
    public Supplier<ArrayList<Node>> supplier() {
        return ArrayList::new;
    }

    @Override
    public BiConsumer<ArrayList<Node>, Node> accumulator() {
        return (nodes, n) -> nodes.addAll(flatten(n));
    }

    @Override
    public BinaryOperator<ArrayList<Node>> combiner() {
        return (map, other) -> {
            map.addAll(other);
            return map;
        };
    }

    @Override
    public Function<ArrayList<Node>, Stream<Node>> finisher() {
        return (m) -> m.stream();
    }

    @Override
    public Set<Characteristics> characteristics() {
        return EnumSet.of(Characteristics.UNORDERED);
    }
}
