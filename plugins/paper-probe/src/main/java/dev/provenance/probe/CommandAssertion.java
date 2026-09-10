package dev.provenance.probe;

import com.google.re2j.Matcher;
import com.google.re2j.Pattern;

final class CommandAssertion {
  private final String id;
  private final CommandOutputStream stream;
  private final CommandAssertionOperator operator;
  private final String pattern;
  private final CommandAssertionMatch match;
  private final int minimumOccurrences;
  private final Pattern compiledPattern;

  CommandAssertion(
      String id,
      CommandOutputStream stream,
      CommandAssertionOperator operator,
      String pattern,
      CommandAssertionMatch match,
      int minimumOccurrences,
      Pattern compiledPattern) {

    this.id = id;
    this.stream = stream;
    this.operator = operator;
    this.pattern = pattern;
    this.match = match;
    this.minimumOccurrences = minimumOccurrences;
    this.compiledPattern = compiledPattern;
  }

  public String id() {
    return id;
  }

  public CommandOutputStream stream() {
    return stream;
  }

  public CommandAssertionOperator operator() {
    return operator;
  }

  public String pattern() {
    return pattern;
  }

  public CommandAssertionMatch match() {
    return match;
  }

  public int minimumOccurrences() {
    return minimumOccurrences;
  }

  public Pattern compiledPattern() {
    return compiledPattern;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) return true;
    if (!(other instanceof CommandAssertion)) return false;
    CommandAssertion that = (CommandAssertion) other;
    return java.util.Objects.equals(id, that.id)
        && java.util.Objects.equals(stream, that.stream)
        && java.util.Objects.equals(operator, that.operator)
        && java.util.Objects.equals(pattern, that.pattern)
        && java.util.Objects.equals(match, that.match)
        && java.util.Objects.equals(minimumOccurrences, that.minimumOccurrences)
        && java.util.Objects.equals(compiledPattern, that.compiledPattern);
  }

  @Override
  public int hashCode() {
    return java.util.Objects.hash(
        id, stream, operator, pattern, match, minimumOccurrences, compiledPattern);
  }

  int occurrences(String output) {
    if (operator == CommandAssertionOperator.CONTAINS) {
      int count = 0;
      int offset = 0;
      while (count < 10_000) {
        int matchIndex = output.indexOf(pattern, offset);
        if (matchIndex < 0) {
          return count;
        }
        count++;
        offset = matchIndex + pattern.length();
      }
      return count;
    }

    Matcher matcher = compiledPattern.matcher(output);
    int count = 0;
    while (count < 10_000 && matcher.find()) {
      count++;
    }
    return count;
  }

  boolean passes(int occurrences) {
    return match == CommandAssertionMatch.PRESENT
        ? occurrences >= minimumOccurrences
        : occurrences == 0;
  }
}

enum CommandOutputStream {
  STDOUT,
  STDERR,
  COMBINED
}

enum CommandAssertionOperator {
  CONTAINS,
  REGEX
}

enum CommandAssertionMatch {
  PRESENT,
  ABSENT
}
