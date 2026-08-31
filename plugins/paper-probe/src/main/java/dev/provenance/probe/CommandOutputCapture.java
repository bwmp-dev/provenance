package dev.provenance.probe;

import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.List;

final class CommandOutputCapture {
  private final int maximumBytes;
  private final StringBuilder captured = new StringBuilder();
  private long observedBytes;
  private int capturedBytes;
  private boolean truncated;
  private boolean hasMessage;

  CommandOutputCapture(int maximumBytes) {
    if (maximumBytes < 1) {
      throw new IllegalArgumentException("maximumBytes must be positive");
    }
    this.maximumBytes = maximumBytes;
  }

  void append(String message) {
    String normalized = normalize(message);
    if (hasMessage) {
      appendBounded("\n");
    }
    hasMessage = true;
    appendBounded(normalized);
  }

  String text() {
    return captured.toString();
  }

  List<String> lines() {
    return captured.toString().lines().toList();
  }

  long observedBytes() {
    return observedBytes;
  }

  int capturedBytes() {
    return capturedBytes;
  }

  boolean truncated() {
    return truncated;
  }

  private void appendBounded(String value) {
    byte[] allBytes = value.getBytes(StandardCharsets.UTF_8);
    observedBytes = saturatedAdd(observedBytes, allBytes.length);
    int remaining = maximumBytes - capturedBytes;
    if (remaining <= 0) {
      truncated |= allBytes.length > 0;
      return;
    }
    for (int offset = 0; offset < value.length(); ) {
      int codePoint = value.codePointAt(offset);
      String character = new String(Character.toChars(codePoint));
      int byteCount = character.getBytes(StandardCharsets.UTF_8).length;
      if (byteCount > remaining) {
        truncated = true;
        return;
      }
      captured.append(character);
      capturedBytes += byteCount;
      remaining -= byteCount;
      offset += Character.charCount(codePoint);
    }
  }

  private static long saturatedAdd(long current, int value) {
    return current > Long.MAX_VALUE - value ? Long.MAX_VALUE : current + value;
  }

  private static String normalize(String value) {
    String unicode = Normalizer.normalize(value, Normalizer.Form.NFC);
    StringBuilder normalized = new StringBuilder(unicode.length());
    for (int offset = 0; offset < unicode.length(); ) {
      int codePoint = unicode.codePointAt(offset);
      offset += Character.charCount(codePoint);
      if (codePoint == '\r') {
        if (offset < unicode.length() && unicode.charAt(offset) == '\n') {
          offset++;
        }
        normalized.append('\n');
      } else if (codePoint == '\n' || codePoint == '\t') {
        normalized.appendCodePoint(codePoint);
      } else if (codePoint == '\u00a7' && offset < unicode.length()) {
        int formatCode = unicode.codePointAt(offset);
        if (isLegacyFormatCode(formatCode)) {
          offset += Character.charCount(formatCode);
        } else {
          normalized.appendCodePoint(codePoint);
        }
      } else if (Character.isISOControl(codePoint)) {
        normalized.append('\ufffd');
      } else {
        normalized.appendCodePoint(codePoint);
      }
    }
    return normalized.toString();
  }

  private static boolean isLegacyFormatCode(int codePoint) {
    int lower = Character.toLowerCase(codePoint);
    return (lower >= '0' && lower <= '9')
        || (lower >= 'a' && lower <= 'f')
        || lower == 'k'
        || lower == 'l'
        || lower == 'm'
        || lower == 'n'
        || lower == 'o'
        || lower == 'r'
        || lower == 'x';
  }
}
