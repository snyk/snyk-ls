Feature: LLM provider settings for autonomous remediation
  A developer can configure which LLM backend autonomous remediation uses
  via language-server settings (config file, environment, or LSP). Those
  settings persist and are used when an autonomous fix runs, but they are
  deliberately not exposed in the IDE configuration dialog.

  # maps: IDE-2274-M1, IDE-2274-M2
  Scenario: Saved LLM settings are not exposed in the configuration dialog
    Given a running language server
    When a developer saves "ollama" as the LLM provider with custom API endpoint "http://localhost:11434"
    And the developer reopens the Snyk configuration dialog
    Then the configuration dialog does not expose LLM provider settings

  # maps: IDE-2274-M5
  Scenario: The configuration dialog has no LLM provider field
    Given a running language server
    When a developer reopens the Snyk configuration dialog without ever choosing an LLM provider
    Then the configuration dialog does not expose LLM provider settings

  # maps: IDE-2274-M4
  Scenario: The configuration dialog never asks for or displays an LLM API key
    Given a running language server
    When a developer reopens the Snyk configuration dialog
    Then the configuration dialog contains no field for an LLM API key

  # maps: IDE-2274-M1
  Scenario: A chosen LLM provider and model persist via LSP without appearing in the dialog
    Given a running language server
    When a developer saves "ollama" as the LLM provider with model "llama3.1"
    And the developer reopens the Snyk configuration dialog
    Then the configuration dialog does not expose LLM provider settings

  # maps: IDE-2274-CP-2
  Scenario: An autonomous fix run uses the developer's chosen LLM provider and model
    Given a running language server
    When a developer saves "ollama" as the LLM provider with model "llama3.1"
    And the developer asks Snyk to autonomously fix a folder
    Then the fix runs with the developer's chosen LLM provider and model
