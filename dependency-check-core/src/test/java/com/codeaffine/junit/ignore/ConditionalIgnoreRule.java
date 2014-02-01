/**
 * *****************************************************************************
 * Copyright (c) 2013 Rüdiger Herrmann All rights reserved. This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License v1.0 which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors: Rüdiger Herrmann - initial API and implementation
 *****************************************************************************
 */
package com.codeaffine.junit.ignore;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.junit.Assume;
import org.junit.rules.MethodRule;
import org.junit.runners.model.FrameworkMethod;
import org.junit.runners.model.Statement;

public class ConditionalIgnoreRule implements MethodRule {

    public interface IgnoreCondition {

        boolean isSatisfied();
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.METHOD})
    public @interface ConditionalIgnore {

        Class<? extends IgnoreCondition> condition();
    }

    public Statement apply(Statement base, FrameworkMethod method, Object target) {
        Statement result = base;
        if (hasConditionalIgnoreAnnotation(method)) {
            IgnoreCondition condition = getIgnoreContition(method);
            if (condition.isSatisfied()) {
                result = new IgnoreStatement(condition);
            }
        }
        return result;
    }

    private boolean hasConditionalIgnoreAnnotation(FrameworkMethod method) {
        return method.getAnnotation(ConditionalIgnore.class) != null;
    }

    private IgnoreCondition getIgnoreContition(FrameworkMethod method) {
        ConditionalIgnore annotation = method.getAnnotation(ConditionalIgnore.class);
        return newCondition(annotation);
    }

    private IgnoreCondition newCondition(ConditionalIgnore annotation) {
        try {
            return annotation.condition().newInstance();
        } catch (RuntimeException re) {
            throw re;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static class IgnoreStatement extends Statement {

        private IgnoreCondition condition;

        IgnoreStatement(IgnoreCondition condition) {
            this.condition = condition;
        }

        @Override
        public void evaluate() {
            Assume.assumeTrue("Ignored by " + condition.getClass().getSimpleName(), false);
        }
    }

}
