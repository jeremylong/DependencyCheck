/*
 * This file is part of dependency-check-ant.
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
 * Copyright (c) 2015 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.ant.logging;

import org.apache.tools.ant.Project;
import org.apache.tools.ant.Task;
import org.slf4j.helpers.FormattingTuple;
import org.slf4j.helpers.MarkerIgnoringBase;
import org.slf4j.helpers.MessageFormatter;

/**
 * An instance of {@link org.slf4j.Logger} which simply calls the log method on
 * the delegate Ant task.
 *
 * @author colezlaw
 */
public class AntLoggerAdapter extends MarkerIgnoringBase {

    /**
     * The serial version UID for serialization.
     */
    private static final long serialVersionUID = -8546294566287970709L;
    /**
     * A reference to the Ant task used for logging.
     */
    private transient Task task;

    /**
     * Constructs an Ant Logger Adapter.
     *
     * @param task the Ant Task to use for logging
     */
    public AntLoggerAdapter(Task task) {
        super();
        this.task = task;
    }

    /**
     * Sets the current Ant task to use for logging.
     *
     * @param task the Ant task to use for logging
     */
    public void setTask(Task task) {
        this.task = task;
    }

    @Override
    public boolean isTraceEnabled() {
        // Might be a more efficient way to do this, but Ant doesn't enable or disable
        // various levels globally - it just fires things at registered Listeners.
        return true;
    }

    @Override
    public void trace(String msg) {
        if (task != null) {
            task.log(msg, Project.MSG_VERBOSE);
        }
    }

    @Override
    public void trace(String format, Object arg) {
        if (task != null) {
            final FormattingTuple tp = MessageFormatter.format(format, arg);
            task.log(tp.getMessage(), Project.MSG_VERBOSE);
        }
    }

    @Override
    public void trace(String format, Object arg1, Object arg2) {
        if (task != null) {
            final FormattingTuple tp = MessageFormatter.format(format, arg1, arg2);
            task.log(tp.getMessage(), Project.MSG_VERBOSE);
        }
    }

    @Override
    public void trace(String format, Object... arguments) {
        if (task != null) {
            final FormattingTuple tp = MessageFormatter.format(format, arguments);
            task.log(tp.getMessage(), Project.MSG_VERBOSE);
        }
    }

    @Override
    public void trace(String msg, Throwable t) {
        if (task != null) {
            task.log(msg, t, Project.MSG_VERBOSE);
        }
    }

    @Override
    public boolean isDebugEnabled() {
        return true;
    }

    @Override
    public void debug(String msg) {
        if (task != null) {
            task.log(msg, Project.MSG_DEBUG);
        }
    }

    @Override
    public void debug(String format, Object arg) {
        if (task != null) {
            final FormattingTuple tp = MessageFormatter.format(format, arg);
            task.log(tp.getMessage(), Project.MSG_DEBUG);
        }
    }

    @Override
    public void debug(String format, Object arg1, Object arg2) {
        if (task != null) {
            final FormattingTuple tp = MessageFormatter.format(format, arg1, arg2);
            task.log(tp.getMessage(), Project.MSG_DEBUG);
        }
    }

    @Override
    public void debug(String format, Object... arguments) {
        if (task != null) {
            final FormattingTuple tp = MessageFormatter.format(format, arguments);
            task.log(tp.getMessage(), Project.MSG_DEBUG);
        }
    }

    @Override
    public void debug(String msg, Throwable t) {
        if (task != null) {
            task.log(msg, t, Project.MSG_DEBUG);
        }
    }

    @Override
    public boolean isInfoEnabled() {
        return true;
    }

    @Override
    public void info(String msg) {
        if (task != null) {
            task.log(msg, Project.MSG_INFO);
        }
    }

    @Override
    public void info(String format, Object arg) {
        if (task != null) {
            final FormattingTuple tp = MessageFormatter.format(format, arg);
            task.log(tp.getMessage(), Project.MSG_INFO);
        }
    }

    @Override
    public void info(String format, Object arg1, Object arg2) {
        if (task != null) {
            final FormattingTuple tp = MessageFormatter.format(format, arg1, arg2);
            task.log(tp.getMessage(), Project.MSG_INFO);
        }
    }

    @Override
    public void info(String format, Object... arguments) {
        if (task != null) {
            final FormattingTuple tp = MessageFormatter.format(format, arguments);
            task.log(tp.getMessage(), Project.MSG_INFO);
        }
    }

    @Override
    public void info(String msg, Throwable t) {
        if (task != null) {
            task.log(msg, t, Project.MSG_INFO);
        }
    }

    @Override
    public boolean isWarnEnabled() {
        return true;
    }

    @Override
    public void warn(String msg) {
        if (task != null) {
            task.log(msg, Project.MSG_WARN);
        }
    }

    @Override
    public void warn(String format, Object arg) {
        if (task != null) {
            final FormattingTuple tp = MessageFormatter.format(format, arg);
            task.log(tp.getMessage(), Project.MSG_WARN);
        }
    }

    @Override
    public void warn(String format, Object... arguments) {
        if (task != null) {
            final FormattingTuple tp = MessageFormatter.format(format, arguments);
            task.log(tp.getMessage(), Project.MSG_WARN);
        }
    }

    @Override
    public void warn(String format, Object arg1, Object arg2) {
        if (task != null) {
            final FormattingTuple tp = MessageFormatter.format(format, arg1, arg2);
            task.log(tp.getMessage(), Project.MSG_WARN);
        }
    }

    @Override
    public void warn(String msg, Throwable t) {
        if (task != null) {
            task.log(msg, t, Project.MSG_WARN);
        }
    }

    @Override
    public boolean isErrorEnabled() {
        return true;
    }

    @Override
    public void error(String msg) {
        if (task != null) {
            task.log(msg, Project.MSG_ERR);
        }
    }

    @Override
    public void error(String format, Object arg) {
        if (task != null) {
            final FormattingTuple tp = MessageFormatter.format(format, arg);
            task.log(tp.getMessage(), Project.MSG_ERR);
        }
    }

    @Override
    public void error(String format, Object arg1, Object arg2) {
        if (task != null) {
            final FormattingTuple tp = MessageFormatter.format(format, arg1, arg2);
            task.log(tp.getMessage(), Project.MSG_ERR);
        }
    }

    @Override
    public void error(String format, Object... arguments) {
        if (task != null) {
            final FormattingTuple tp = MessageFormatter.format(format, arguments);
            task.log(tp.getMessage(), Project.MSG_ERR);
        }
    }

    @Override
    public void error(String msg, Throwable t) {
        if (task != null) {
            task.log(msg, t, Project.MSG_ERR);
        }
    }
}
