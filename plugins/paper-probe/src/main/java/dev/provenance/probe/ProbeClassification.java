package dev.provenance.probe;

import java.util.LinkedHashMap;
import java.util.Map;

public enum ProbeClassification {
  PLUGIN_NOT_FOUND("plugin_not_found", "FAILURE_CATEGORY_PLUGIN", "FAILURE_STAGE_PREPARATION"),
  INVALID_METADATA("invalid_metadata", "FAILURE_CATEGORY_PLUGIN", "FAILURE_STAGE_PREPARATION"),
  MISSING_REQUIRED_DEPENDENCY(
      "missing_required_dependency", "FAILURE_CATEGORY_PLUGIN", "FAILURE_STAGE_PREPARATION"),
  FAILED_REQUIRED_DEPENDENCY(
      "failed_required_dependency", "FAILURE_CATEGORY_PLUGIN", "FAILURE_STAGE_STARTUP"),
  ON_LOAD_FAILURE("on_load_failure", "FAILURE_CATEGORY_PLUGIN", "FAILURE_STAGE_STARTUP"),
  ON_ENABLE_FAILURE("on_enable_failure", "FAILURE_CATEGORY_PLUGIN", "FAILURE_STAGE_STARTUP");

  private final String code;
  private final String category;
  private final String stage;

  ProbeClassification(String code, String category, String stage) {
    this.code = code;
    this.category = category;
    this.stage = stage;
  }

  public Map<String, Object> data(Map<String, ?> evidence) {
    LinkedHashMap<String, Object> data = new LinkedHashMap<>();
    data.put("code", code);
    data.put("category", category);
    data.put("stage", stage);
    data.put("retryable", false);
    data.putAll(evidence);
    return data;
  }
}
