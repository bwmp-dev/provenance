package dev.provenance.probe;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import org.junit.jupiter.api.Test;

class LifecycleValidatorTest {
  private final LifecycleValidator validator = new LifecycleValidator();

  @Test
  void independentlyReportsTargetAndEveryRequiredDependency() {
    List<RequirementStatus> statuses =
        validator.evaluate(
            "TargetPlugin",
            List.of("ReadyDependency", "DisabledDependency", "MissingDependency"),
            List.of(
                new PluginSnapshot("targetplugin", true, true),
                new PluginSnapshot("ReadyDependency", true, true),
                new PluginSnapshot("DisabledDependency", true, false)));

    assertEquals(
        new RequirementStatus("TARGET", "TargetPlugin", true, true, true), statuses.get(0));
    assertEquals(
        new RequirementStatus("REQUIRED_DEPENDENCY", "ReadyDependency", true, true, true),
        statuses.get(1));
    assertEquals(
        new RequirementStatus("REQUIRED_DEPENDENCY", "DisabledDependency", true, true, false),
        statuses.get(2));
    assertEquals(
        new RequirementStatus("REQUIRED_DEPENDENCY", "MissingDependency", true, false, false),
        statuses.get(3));
  }

  @Test
  void reportsMissingTargetConfiguration() {
    assertEquals(
        List.of(new RequirementStatus("TARGET", "", false, false, false)),
        validator.evaluate(null, List.of(), List.of()));
  }
}
