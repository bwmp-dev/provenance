package dev.provenance.probe;

import java.util.LinkedHashSet;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.config.Property;
import org.apache.logging.log4j.core.impl.ThrowableProxy;

final class Log4jLifecycleExceptionAppender extends AbstractAppender {
  private final LifecycleExceptionHandler handler;
  private final LoggerContext context;
  private final Set<LoggerConfig> loggerConfigurations;

  Log4jLifecycleExceptionAppender(
      LifecycleExceptionHandler handler,
      LoggerContext context,
      Set<LoggerConfig> loggerConfigurations) {
    super("ProvenanceLifecycleExceptions", null, null, true, Property.EMPTY_ARRAY);
    this.handler = handler;
    this.context = context;
    this.loggerConfigurations = loggerConfigurations;
  }

  static Log4jLifecycleExceptionAppender install(LifecycleExceptionHandler handler) {
    LoggerContext context = (LoggerContext) LogManager.getContext(false);
    LinkedHashSet<LoggerConfig> configurations =
        new LinkedHashSet<>(context.getConfiguration().getLoggers().values());
    configurations.add(context.getConfiguration().getRootLogger());
    Log4jLifecycleExceptionAppender appender =
        new Log4jLifecycleExceptionAppender(handler, context, Set.copyOf(configurations));
    appender.start();
    configurations.forEach(configuration -> configuration.addAppender(appender, null, null));
    context.updateLoggers();
    return appender;
  }

  @Override
  public void append(LogEvent event) {
    Throwable thrown = event.getThrown();
    if (thrown == null) {
      ThrowableProxy proxy = event.getThrownProxy();
      if (proxy != null) {
        thrown = proxy.getThrowable();
      }
    }
    handler.publish(thrown);
  }

  @Override
  public void stop() {
    for (LoggerConfig configuration : loggerConfigurations) {
      configuration.removeAppender(getName());
    }
    context.updateLoggers();
    super.stop();
  }
}
