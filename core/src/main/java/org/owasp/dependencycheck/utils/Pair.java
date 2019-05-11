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
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

import javax.annotation.concurrent.ThreadSafe;

/**
 * A generic pair of elements.
 *
 * @param <L> the type for the left element in the pair
 * @param <R> the type for the right element in the pair
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class Pair<L, R> {

    /**
     * The left element of the pair.
     */
    private L left = null;
    /**
     * The right element of the pair.
     */
    private R right = null;

    /**
     * Constructs a new empty pair.
     */
    public Pair() {
    }

    /**
     * Constructs a new Pair with the given left and right values.
     *
     * @param left the value for the left pair
     * @param right the value for the right pair
     */
    public Pair(L left, R right) {
        this.left = left;
        this.right = right;
    }

    /**
     * Get the value of left.
     *
     * @return the value of left
     */
    public L getLeft() {
        return left;
    }

    /**
     * Set the value of left.
     *
     * @param left new value of left
     */
    public void setLeft(L left) {
        this.left = left;
    }

    /**
     * Get the value of right.
     *
     * @return the value of right
     */
    public R getRight() {
        return right;
    }

    /**
     * Set the value of right.
     *
     * @param right new value of right
     */
    public void setRight(R right) {
        this.right = right;
    }

    /**
     * Generates the hash code using the hash codes from the contained objects.
     *
     * @return the hash code of the Pair
     */
    @Override
    public int hashCode() {
        return new HashCodeBuilder(19, 53)
                .append(left)
                .append(right)
                .toHashCode();
    }

    /**
     * Determines the equality of this and the provided object.
     *
     * @param obj the {@link Object} to check for equality to this
     * @return true if this and the provided {@link Object} are equal; otherwise
     * false
     */
    @Override
    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof Pair)) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        final Pair<?, ?> rhs = (Pair) obj;
        return new EqualsBuilder()
                .append(left, rhs.left)
                .append(right, rhs.right)
                .isEquals();
    }
}
