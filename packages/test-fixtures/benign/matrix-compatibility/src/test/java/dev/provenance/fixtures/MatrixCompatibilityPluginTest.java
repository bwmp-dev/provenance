package dev.provenance.fixtures;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

final class MatrixCompatibilityPluginTest {
  @Test
  void observationIsBoundedAndPreservesInterruption() {
    MatrixCompatibilityPlugin.observeBeforeClassification(milliseconds -> assertEquals(10_000, milliseconds));
    try {
      assertThrows(IllegalStateException.class, () -> MatrixCompatibilityPlugin.observeBeforeClassification(milliseconds -> { throw new InterruptedException(); }));
      assertTrue(Thread.currentThread().isInterrupted());
    } finally {
      Thread.interrupted();
    }
  }
  @Test
  void frozenMatrixHasTwoDeliberateFailuresAndOnePass() {
    assertThrows(IllegalStateException.class, () -> MatrixCompatibilityPlugin.requireSupportedVersion("1.20.6"));
    assertThrows(IllegalStateException.class, () -> MatrixCompatibilityPlugin.requireSupportedVersion("1.21.4"));
    assertDoesNotThrow(() -> MatrixCompatibilityPlugin.requireSupportedVersion("1.21.8"));
  }

  @Test
  void unknownVersionsCannotSilentlyPass() {
    for (String version : new String[] {null, "", "1.21.80", "1.21.8-R0.1", "1.22"}) {
      assertThrows(IllegalStateException.class, () -> MatrixCompatibilityPlugin.requireSupportedVersion(version));
    }
  }
}
