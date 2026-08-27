Feature: Delta findings fail open when no baseline exists

  A developer who enables "only show new findings" must never see an empty
  result just because no baseline has been recorded yet. Until a baseline
  exists, every current finding is shown; once a baseline exists, only newly
  introduced findings are shown.

  # maps: IDE-2418-M2
  Scenario: A developer's first scan with delta findings enabled shows every finding
    Given a running language server
    And the editor sends the initialize request
    And delta findings are switched to "New new issues" globally
    When the developer saves a file with a security issue for the first time
    Then the editor is notified of the security issue

  # maps: IDE-2418-M3
  Scenario: A developer pulling diagnostics before a baseline exists sees every finding
    Given a running language server
    And the editor sends the initialize request
    And delta findings are switched to "New new issues" globally
    And the developer has saved a file with a security issue for the first time
    When the editor asks for diagnostics for the whole workspace
    Then the editor is told about the security issue
    When the editor asks for diagnostics for that file
    Then the editor is told about the security issue

  # maps: IDE-2418-M4
  Scenario: A developer opening the issue tree before a baseline exists sees every finding
    Given a running language server
    And the editor sends the initialize request
    And delta findings are switched to "New new issues" globally
    And the developer has saved a file with a security issue for the first time
    When the editor asks for the issue tree view
    Then the issue tree view shows the security issue

  # maps: IDE-2418-M5
  Scenario: A developer with an established baseline only sees newly introduced findings
    Given a running language server
    And the editor sends the initialize request
    And delta findings are switched to "New new issues" globally
    And the developer has an established baseline with one known issue
    When the developer saves a file that introduces a new issue alongside the known one
    Then the editor is notified of only the newly introduced issue

  # maps: IDE-2418-M6
  Scenario: A developer with a baseline for one product but not another sees new findings from both
    Given a running language server
    And the editor sends the initialize request
    And delta findings are switched to "New new issues" globally
    And the developer has an established baseline for "Code" with one known issue
    When the developer saves a file that produces a new "Code" issue and an "Open Source" issue
    Then the editor is notified of both the newly introduced "Code" issue and the "Open Source" issue

  # maps: IDE-2418-M7
  Scenario: Delta findings switched at folder level behave the same as global setting
    Given a running language server
    And the editor sends the initialize request
    And delta findings are switched to "New new issues" at the workspace folder level
    And the developer has saved a file with a security issue for the first time
    When the editor asks for diagnostics for the whole workspace
    Then the editor is told about the security issue
