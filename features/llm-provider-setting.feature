Feature: LLM provider settings for autonomous remediation
  Ambient Canary uses these settings to choose the LLM backend for
  autonomous remediation. They persist and apply when an autonomous fix
  runs. Ambient Canary supplies them from its own settings. The IDE HTML
  configuration dialog does not render them.

  # maps: IDE-2274-M1, IDE-2274-M2
  Scenario: Saved LLM settings persist via LSP and the dialog does not render them
    Given a running language server
    When a developer saves "ollama" as the LLM provider with custom API endpoint "http://localhost:11434"
    And the developer reopens the Snyk configuration dialog
    Then the language server has persisted the chosen LLM provider and endpoint
    And the configuration dialog does not render Ambient Canary or LLM settings

  # maps: IDE-2274-M5
  Scenario: A developer who has never chosen a provider has no forced default
    Given a running language server
    When a developer reopens the Snyk configuration dialog without ever choosing an LLM provider
    Then the language server has no persisted LLM provider

  # maps: IDE-2274-M4
  Scenario: The configuration dialog never asks for or displays an LLM API key
    Given a running language server
    When a developer reopens the Snyk configuration dialog
    Then the configuration dialog contains no field for an LLM API key

  # maps: IDE-2274-M1
  Scenario: A chosen LLM provider and model persist via LSP and the dialog does not render them
    Given a running language server
    When a developer saves "ollama" as the LLM provider with model "llama3.1"
    And the developer reopens the Snyk configuration dialog
    Then the language server has persisted the chosen LLM provider and model
    And the configuration dialog does not render Ambient Canary or LLM settings

  # maps: IDE-2274-CP-2
  Scenario: An autonomous fix run uses the developer's chosen LLM provider and model
    Given a running language server
    When a developer saves "ollama" as the LLM provider with model "llama3.1"
    And the developer asks Snyk to autonomously fix a folder
    Then the fix runs with the developer's chosen LLM provider and model
