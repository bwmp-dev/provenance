package dev.provenance.probe;

import com.google.re2j.Matcher;
import com.google.re2j.Pattern;

record CommandAssertion(
    String id,
    CommandOutputStream stream,
    CommandAssertionOperator operator,
    String pattern,
    CommandAssertionMatch match,
    int minimumOccurrences,
    Pattern compiledPattern) {
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
    return switch (match) {
      case PRESENT -> occurrences >= minimumOccurrences;
      case ABSENT -> occurrences == 0;
    };
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
