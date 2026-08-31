package dev.provenance.probe;

public interface EventSink extends AutoCloseable {
  void emit(ProbeEvent event);

  @Override
  default void close() {}
}
