package dev.provenance.probe;

final class TestPlanException extends Exception {
  TestPlanException(String message) {
    super(message);
  }

  TestPlanException(String message, Throwable cause) {
    super(message, cause);
  }
}
