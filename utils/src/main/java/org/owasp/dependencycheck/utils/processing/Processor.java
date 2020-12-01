/*
 * This file is part of dependency-check-utils.
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
 * Copyright (c) 2020 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils.processing;

/**
 * Abstract class to create, in general, an input stream processor used to
 * evaluate the output of an external process.
 *
 * @author Jeremy Long
 * @param <T> the type of processor
 */
public abstract class Processor<T> implements Runnable, AutoCloseable {

    /**
     * Stores the value.
     */
    private T input;

    /**
     * Creates a new processor.
     */
    public Processor() {
        //empty constructor
    }

    /**
     * Creates a new processor.
     *
     * @param input the input to process
     */
    public Processor(T input) {
        this.input = input;
    }

    /**
     * Sets the input to process.
     *
     * @param input the input to process
     */
    public void setInput(T input) {
        this.input = input;
    }

    /**
     * Retrieves a reference to the input.
     *
     * @return a reference to the input
     */
    protected T getInput() {
        return input;
    }

    /**
     * Adds any non-null exceptions in the `suppress` list to the suppressed
     * exceptions on the main exception `ex`.
     *
     * @param ex the main exception that suppressed exceptions will be added
     * @param suppress one or more exceptions that will be added as suppressed
     */
    protected void addSuppressedExceptions(Throwable ex, Throwable... suppress) {
        for (Throwable e : suppress) {
            if (e != null) {
                ex.addSuppressed(e);
            }
        }
    }
}
