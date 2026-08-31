package dev.provenance.probe;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

public final class NdjsonEventSink implements EventSink {
  private final BufferedWriter writer;

  public NdjsonEventSink(Path output) throws IOException {
    Path parent = output.toAbsolutePath().getParent();
    if (parent != null) {
      Files.createDirectories(parent);
    }
    writer =
        Files.newBufferedWriter(
            output,
            StandardCharsets.UTF_8,
            StandardOpenOption.CREATE,
            StandardOpenOption.TRUNCATE_EXISTING,
            StandardOpenOption.WRITE);
  }

  @Override
  public synchronized void emit(ProbeEvent event) {
    try {
      writer.write(Json.event(event));
      writer.newLine();
      writer.flush();
    } catch (IOException exception) {
      throw new IllegalStateException("could not write probe event", exception);
    }
  }

  @Override
  public synchronized void close() {
    try {
      writer.close();
    } catch (IOException exception) {
      throw new IllegalStateException("could not close probe event sink", exception);
    }
  }
}
