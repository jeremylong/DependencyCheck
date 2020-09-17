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
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.BinaryOperator;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collector;
import java.util.stream.Stream;

import javax.annotation.concurrent.ThreadSafe;

/**
 *
 * @author Jeremy Long
 *
 */
@ThreadSafe
public final class CpeMatchStreamCollector implements Collector<DefNode, ArrayList<DefCpeMatch>, Stream<DefCpeMatch>> {

    /**
     * The singleton instance.
     */
    private static final CpeMatchStreamCollector INSTANCE;

    static {
        INSTANCE = new CpeMatchStreamCollector();
    }

    public static CpeMatchStreamCollector getInstance() {
        return INSTANCE;
    }

    private CpeMatchStreamCollector() {
    }

    @Override
    public Supplier<ArrayList<DefCpeMatch>> supplier() {
        return ArrayList::new;
    }

    @Override
    public BiConsumer<ArrayList<DefCpeMatch>, DefNode> accumulator() {
        return (match, nodes) -> match.addAll(nodes.getCpeMatch());
    }

    @Override
    public BinaryOperator<ArrayList<DefCpeMatch>> combiner() {
        return (map, other) -> {
            map.addAll(other);
            return map;
        };
    }

    @Override
    public Function<ArrayList<DefCpeMatch>, Stream<DefCpeMatch>> finisher() {
        return (m) -> m.stream();
    }

    @Override
    public Set<Characteristics> characteristics() {
        return EnumSet.of(Characteristics.UNORDERED);
    }

}
