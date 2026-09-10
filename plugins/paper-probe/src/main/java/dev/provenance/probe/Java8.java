package dev.provenance.probe;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collector;
import java.util.stream.Collectors;

/** Small immutable collection and bounded I/O helpers for the Java 8 baseline. */
final class Java8 {
  private Java8() {}

  @SafeVarargs
  static <T> List<T> list(T... values) {
    return listCopy(Arrays.asList(values));
  }

  static <T> List<T> listCopy(Collection<? extends T> values) {
    List<T> copy = new ArrayList<>();
    for (T value : values) copy.add(Objects.requireNonNull(value));
    return Collections.unmodifiableList(copy);
  }

  @SafeVarargs
  static <T> Set<T> set(T... values) {
    Set<T> result = setCopy(Arrays.asList(values));
    if (result.size() != values.length) throw new IllegalArgumentException("duplicate set entry");
    return result;
  }

  static <T> Set<T> setCopy(Collection<? extends T> values) {
    return Collections.unmodifiableSet(new LinkedHashSet<>(listCopy(values)));
  }

  static <K, V> Map<K, V> mapCopy(Map<? extends K, ? extends V> values) {
    Map<K, V> copy = new LinkedHashMap<>();
    values.forEach(
        (key, value) -> copy.put(Objects.requireNonNull(key), Objects.requireNonNull(value)));
    return Collections.unmodifiableMap(copy);
  }

  static Map<String, Object> map(Object... pairs) {
    if (pairs.length % 2 != 0) throw new IllegalArgumentException("unpaired map entry");
    Map<String, Object> result = new LinkedHashMap<>();
    for (int index = 0; index < pairs.length; index += 2) {
      String key = (String) Objects.requireNonNull(pairs[index]);
      if (result.put(key, Objects.requireNonNull(pairs[index + 1])) != null)
        throw new IllegalArgumentException("duplicate map entry");
    }
    return Collections.unmodifiableMap(result);
  }

  static <T> Collector<T, ?, List<T>> toList() {
    return Collectors.collectingAndThen(Collectors.toList(), Collections::unmodifiableList);
  }

  static boolean isBlank(String value) {
    return value.codePoints().allMatch(Character::isWhitespace);
  }

  static List<String> lines(String value) {
    List<String> lines = new ArrayList<>();
    int start = 0;
    for (int index = 0; index < value.length(); index++) {
      char current = value.charAt(index);
      if (current == '\r' || current == '\n') {
        lines.add(value.substring(start, index));
        if (current == '\r' && index + 1 < value.length() && value.charAt(index + 1) == '\n')
          index++;
        start = index + 1;
      }
    }
    if (start < value.length()) lines.add(value.substring(start));
    return Collections.unmodifiableList(lines);
  }

  static byte[] readNBytes(InputStream input, int maximum) throws IOException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    byte[] buffer = new byte[Math.min(8192, maximum)];
    while (output.size() < maximum) {
      int count = input.read(buffer, 0, Math.min(buffer.length, maximum - output.size()));
      if (count < 0) break;
      if (count == 0) {
        int value = input.read();
        if (value < 0) break;
        output.write(value);
      } else output.write(buffer, 0, count);
    }
    return output.toByteArray();
  }

  static String hex(byte[] bytes) {
    char[] alphabet = "0123456789abcdef".toCharArray();
    char[] result = new char[bytes.length * 2];
    for (int i = 0; i < bytes.length; i++) {
      result[i * 2] = alphabet[(bytes[i] & 255) >>> 4];
      result[i * 2 + 1] = alphabet[bytes[i] & 15];
    }
    return new String(result);
  }
}
