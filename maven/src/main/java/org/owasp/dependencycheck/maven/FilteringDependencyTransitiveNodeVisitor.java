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
 * Copyright (c) 2019 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.maven;

import org.apache.maven.shared.dependency.graph.DependencyNode;
import org.apache.maven.shared.dependency.graph.filter.DependencyNodeFilter;
import org.apache.maven.shared.dependency.graph.traversal.DependencyNodeVisitor;

/**
 * A dependency node visitor that filters nodes and their children and delegates
 * to another visitor.
 *
 * @author Nikolas Falco
 * @since 5.0.0
 */
public class FilteringDependencyTransitiveNodeVisitor implements DependencyNodeVisitor {

    /**
     * The dependency node visitor to delegate to.
     */
    private final DependencyNodeVisitor visitor;

    /**
     * The dependency node filter to apply before delegation.
     */
    private final DependencyNodeFilter filter;

    /**
     * Creates a dependency node visitor that delegates nodes that are accepted
     * by the specified filter to the specified visitor.
     *
     * @param visitor the dependency node visitor to delegate to
     * @param filter the dependency node filter to apply before delegation
     */
    public FilteringDependencyTransitiveNodeVisitor(DependencyNodeVisitor visitor, DependencyNodeFilter filter) {
        this.visitor = visitor;
        this.filter = filter;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean visit(DependencyNode node) {
        final boolean visit;

        if (filter.accept(node)) {
            visit = visitor.visit(node);
        } else {
            visit = false;
        }

        return visit;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean endVisit(DependencyNode node) {
        final boolean visit;

        if (filter.accept(node)) {
            visit = visitor.endVisit(node);
        } else {
            visit = true;
        }

        return visit;
    }

    /**
     * Gets the dependency node visitor that this visitor delegates to.
     *
     * @return the dependency node visitor
     */
    public DependencyNodeVisitor getDependencyNodeVisitor() {
        return visitor;
    }

    /**
     * Gets the dependency node filter that this visitor applies before
     * delegation.
     *
     * @return the dependency node filter
     */
    public DependencyNodeFilter getDependencyNodeFilter() {
        return filter;
    }

}
