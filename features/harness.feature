Feature: BDD harness
  This feature proves the godog wiring itself: step definitions drive the real
  language server over JSON-RPC, through the same unexported test harness used
  by the plain Go acceptance tests in application/server (setupServer,
  testsupport.JsonRPCRecorder) — not a second, divergent harness.

  # maps: M1
  Scenario: A developer's editor connects to the language server
    Given a running language server
    When the editor sends the initialize request
    Then the server responds with its capabilities

  # maps: M2
  Scenario: A developer overrides Ambient Canary autonomy for one folder
    Given a running language server
    And a workspace folder is open
    Then the folder has no Ambient Canary autonomy override
    When the editor sets the folder's Ambient Canary autonomy to "autonomous_fixes"
    Then the folder's effective Ambient Canary autonomy is "autonomous_fixes"
