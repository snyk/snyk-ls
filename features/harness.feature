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
