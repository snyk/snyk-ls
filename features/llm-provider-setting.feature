Feature: Choose the LLM provider used by autonomous remediation
  A developer can tell the Snyk Remediation Agent which LLM backend to use,
  and optionally point it at a self-hosted endpoint, from the existing Snyk
  configuration dialog. This feature file covers CP-1 only: the setting
  exists, persists, and is reflected back in the dialog. It does not cover
  whether autonomous remediation actually uses the choice (CP-2).

  # maps: IDE-2274-M1, IDE-2274-M2
  Scenario: The chosen provider and endpoint survive reopening the dialog
    Given a running language server
    When a developer saves "ollama" as the LLM provider with custom API endpoint "http://localhost:11434"
    And the developer reopens the Snyk configuration dialog
    Then the configuration dialog shows "ollama" as the selected LLM provider
    And the configuration dialog shows "http://localhost:11434" as the custom API endpoint

  # maps: IDE-2274-M5
  Scenario: A developer who has never chosen a provider sees no forced default
    Given a running language server
    When a developer reopens the Snyk configuration dialog without ever choosing an LLM provider
    Then the configuration dialog shows no LLM provider selected

  # maps: IDE-2274-M4
  Scenario: The configuration dialog never asks for or displays an LLM API key
    Given a running language server
    When a developer reopens the Snyk configuration dialog
    Then the configuration dialog contains no field for an LLM API key
