package dev.provenance.probe;

public record RequirementStatus(
    String role, String name, boolean configured, boolean loaded, boolean enabled) {}
