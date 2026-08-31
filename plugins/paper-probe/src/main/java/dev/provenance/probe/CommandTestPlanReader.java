package dev.provenance.probe;

import com.google.re2j.Pattern;
import com.google.re2j.PatternSyntaxException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.snakeyaml.engine.v2.api.Load;
import org.snakeyaml.engine.v2.api.LoadSettings;

final class CommandTestPlanReader {
  static final int MAX_PLAN_BYTES = 262_144;
  private static final int MAX_COMMANDS = 100;
  private static final int MAX_ASSERTIONS = 20;
  private static final int MAX_COMMAND_EVENTS = 512;
  private static final Set<String> ROOT_FIELDS =
      Set.of("targetPlugin", "requiredDependencies", "stabilizationMilliseconds", "console");
  private static final Set<String> COMMAND_FIELDS =
      Set.of("id", "command", "timeoutSeconds", "assertions");
  private static final Set<String> ASSERTION_FIELDS =
      Set.of("stream", "operator", "pattern", "match", "minimumOccurrences");

  CommandTestPlan read(Path path) throws IOException, TestPlanException {
    if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
      throw new TestPlanException("test plan must be a regular file");
    }
    long size = Files.size(path);
    if (size > MAX_PLAN_BYTES) {
      throw new TestPlanException("test plan exceeds 262144 bytes");
    }
    return parse(Files.readString(path, StandardCharsets.UTF_8));
  }

  CommandTestPlan parse(String source) throws TestPlanException {
    if (source.getBytes(StandardCharsets.UTF_8).length > MAX_PLAN_BYTES) {
      throw new TestPlanException("test plan exceeds 262144 bytes");
    }
    LoadSettings settings =
        LoadSettings.builder()
            .setLabel("provenance-test-plan.json")
            .setAllowDuplicateKeys(false)
            .setAllowRecursiveKeys(false)
            .setMaxAliasesForCollections(0)
            .setCodePointLimit(MAX_PLAN_BYTES)
            .build();
    final Object loaded;
    try {
      loaded = new Load(settings).loadFromString(source);
    } catch (RuntimeException exception) {
      throw new TestPlanException("test plan is not valid JSON-compatible data", exception);
    }
    Map<?, ?> root = mapping(loaded, "test plan");
    rejectUnknownFields(root, ROOT_FIELDS, "test plan");
    validateOptionalRootFields(root);

    Object consoleValue = root.get("console");
    if (consoleValue == null) {
      return new CommandTestPlan(List.of());
    }
    List<?> commands = list(consoleValue, "console");
    if (commands.size() > MAX_COMMANDS) {
      throw new TestPlanException("console must contain at most 100 commands");
    }
    List<ConsoleCommandTest> result = new ArrayList<>(commands.size());
    Set<String> identifiers = new HashSet<>();
    int commandEvents = 0;
    for (int index = 0; index < commands.size(); index++) {
      ConsoleCommandTest command = parseCommand(commands.get(index), index);
      if (!identifiers.add(command.id())) {
        throw new TestPlanException("console command ids must be unique");
      }
      commandEvents += 6 + command.assertions().size();
      if (commandEvents > MAX_COMMAND_EVENTS) {
        throw new TestPlanException("console commands exceed the 512-event evidence budget");
      }
      result.add(command);
    }
    return new CommandTestPlan(result);
  }

  private static ConsoleCommandTest parseCommand(Object value, int index) throws TestPlanException {
    String path = "console[" + index + "]";
    Map<?, ?> command = mapping(value, path);
    rejectUnknownFields(command, COMMAND_FIELDS, path);
    String id = identifier(requiredString(command, "id", path), path + ".id");
    String rawCommandLine = requiredString(command, "command", path);
    if (rawCommandLine.length() > 500) {
      throw new TestPlanException(path + ".command is invalid");
    }
    String commandLine = rawCommandLine.trim();
    if (commandLine.startsWith("/")) {
      commandLine = commandLine.substring(1);
    }
    if (commandLine.isEmpty()
        || commandLine.indexOf('\r') >= 0
        || commandLine.indexOf('\n') >= 0
        || commandLine.indexOf('\0') >= 0) {
      throw new TestPlanException(path + ".command is invalid");
    }
    long timeoutSeconds = requiredInteger(command, "timeoutSeconds", path, 1, 86_400);
    List<?> assertionValues = list(required(command, "assertions", path), path + ".assertions");
    if (assertionValues.isEmpty() || assertionValues.size() > MAX_ASSERTIONS) {
      throw new TestPlanException(path + ".assertions must contain between 1 and 20 entries");
    }
    List<CommandAssertion> assertions = new ArrayList<>(assertionValues.size());
    for (int assertionIndex = 0; assertionIndex < assertionValues.size(); assertionIndex++) {
      assertions.add(parseAssertion(assertionValues.get(assertionIndex), path, id, assertionIndex));
    }
    return new ConsoleCommandTest(id, commandLine, timeoutSeconds, assertions);
  }

  private static CommandAssertion parseAssertion(
      Object value, String commandPath, String commandId, int index) throws TestPlanException {
    String path = commandPath + ".assertions[" + index + "]";
    Map<?, ?> assertion = mapping(value, path);
    rejectUnknownFields(assertion, ASSERTION_FIELDS, path);
    CommandOutputStream stream =
        enumValue(
            requiredString(assertion, "stream", path),
            path + ".stream",
            CommandOutputStream.class);
    String operatorValue = optionalString(assertion, "operator", "regex", path);
    CommandAssertionOperator operator =
        enumValue(operatorValue, path + ".operator", CommandAssertionOperator.class);
    String pattern = requiredNonEmptyString(assertion, "pattern", path);
    if (pattern.length() > 1_000) {
      throw new TestPlanException(path + ".pattern exceeds 1000 characters");
    }
    CommandAssertionMatch match =
        enumValue(
            requiredString(assertion, "match", path),
            path + ".match",
            CommandAssertionMatch.class);
    int minimumOccurrences = 1;
    if (assertion.containsKey("minimumOccurrences")) {
      minimumOccurrences =
          Math.toIntExact(
              requiredInteger(assertion, "minimumOccurrences", path, 1, 10_000));
    }
    if (match == CommandAssertionMatch.ABSENT && assertion.containsKey("minimumOccurrences")) {
      throw new TestPlanException(path + ".minimumOccurrences is not allowed for absent matches");
    }

    Pattern compiled = null;
    if (operator == CommandAssertionOperator.REGEX) {
      try {
        compiled = Pattern.compile(pattern);
      } catch (PatternSyntaxException exception) {
        throw new TestPlanException(path + ".pattern is not a safe RE2 expression", exception);
      }
    }
    return new CommandAssertion(
        commandId + ":" + (index + 1),
        stream,
        operator,
        pattern,
        match,
        minimumOccurrences,
        compiled);
  }

  private static void validateOptionalRootFields(Map<?, ?> root) throws TestPlanException {
    if (root.containsKey("targetPlugin")) {
      requiredString(root, "targetPlugin", "test plan");
    }
    if (root.containsKey("requiredDependencies")) {
      List<?> dependencies = list(root.get("requiredDependencies"), "requiredDependencies");
      if (dependencies.size() > 64) {
        throw new TestPlanException("requiredDependencies must contain at most 64 entries");
      }
      for (Object dependency : dependencies) {
        if (!(dependency instanceof String string) || string.isBlank() || string.length() > 64) {
          throw new TestPlanException("requiredDependencies entries must be plugin names");
        }
      }
    }
    if (root.containsKey("stabilizationMilliseconds")) {
      requiredInteger(root, "stabilizationMilliseconds", "test plan", 0, 60_000);
    }
  }

  private static Object required(Map<?, ?> mapping, String field, String path)
      throws TestPlanException {
    if (!mapping.containsKey(field) || mapping.get(field) == null) {
      throw new TestPlanException(path + "." + field + " is required");
    }
    return mapping.get(field);
  }

  private static String requiredString(Map<?, ?> mapping, String field, String path)
      throws TestPlanException {
    Object value = required(mapping, field, path);
    if (!(value instanceof String string) || string.isBlank()) {
      throw new TestPlanException(path + "." + field + " must be a non-empty string");
    }
    return string;
  }

  private static String requiredNonEmptyString(Map<?, ?> mapping, String field, String path)
      throws TestPlanException {
    Object value = required(mapping, field, path);
    if (!(value instanceof String string) || string.isEmpty()) {
      throw new TestPlanException(path + "." + field + " must be a non-empty string");
    }
    return string;
  }

  private static String optionalString(
      Map<?, ?> mapping, String field, String fallback, String path) throws TestPlanException {
    if (!mapping.containsKey(field)) {
      return fallback;
    }
    return requiredString(mapping, field, path);
  }

  private static long requiredInteger(
      Map<?, ?> mapping, String field, String path, long minimum, long maximum)
      throws TestPlanException {
    Object value = required(mapping, field, path);
    if (!(value instanceof Number number)) {
      throw new TestPlanException(path + "." + field + " must be an integer");
    }
    long integer = number.longValue();
    if (number.doubleValue() != integer || integer < minimum || integer > maximum) {
      throw new TestPlanException(
          path + "." + field + " must be an integer from " + minimum + " to " + maximum);
    }
    return integer;
  }

  private static String identifier(String value, String path) throws TestPlanException {
    if (!value.matches("[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*") || value.length() > 63) {
      throw new TestPlanException(path + " is not a valid identifier");
    }
    return value;
  }

  private static <E extends Enum<E>> E enumValue(String value, String path, Class<E> type)
      throws TestPlanException {
    try {
      return Enum.valueOf(type, value.toUpperCase(java.util.Locale.ROOT));
    } catch (IllegalArgumentException exception) {
      throw new TestPlanException(path + " has an unsupported value");
    }
  }

  private static Map<?, ?> mapping(Object value, String path) throws TestPlanException {
    if (!(value instanceof Map<?, ?> mapping)) {
      throw new TestPlanException(path + " must be an object");
    }
    for (Object key : mapping.keySet()) {
      if (!(key instanceof String)) {
        throw new TestPlanException(path + " keys must be strings");
      }
    }
    return mapping;
  }

  private static List<?> list(Object value, String path) throws TestPlanException {
    if (!(value instanceof List<?> list)) {
      throw new TestPlanException(path + " must be an array");
    }
    return list;
  }

  private static void rejectUnknownFields(Map<?, ?> value, Set<String> allowed, String path)
      throws TestPlanException {
    for (Object key : value.keySet()) {
      if (!allowed.contains(key)) {
        throw new TestPlanException(path + " contains an unknown field");
      }
    }
  }
}
