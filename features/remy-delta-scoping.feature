Feature: Autonomous folder fixes only touch newly introduced findings

  A developer who enables "only show new findings" expects an autonomous fix
  of a folder to work on the findings they were shown, not on every finding
  the folder has ever had. Once a baseline exists, the fix is scoped to the
  net-new findings; until then, it runs on the whole folder.

  # maps: IDE-2592-M1
  Scenario: A folder fix with a baseline is scoped to the newly introduced finding
    Given a running language server
    And the editor sends the initialize request
    And delta findings are switched to "New new issues" globally
    And the developer has an established baseline with one known issue
    And the developer saves a file that introduces a new issue alongside the known one
    When the developer asks Snyk to autonomously fix that workspace folder
    Then the fix runs scoped to only the newly introduced finding

  # maps: IDE-2592-M2
  Scenario: A folder fix with a baseline and nothing newly introduced does not run
    Given a running language server
    And the editor sends the initialize request
    And delta findings are switched to "New new issues" globally
    And the developer has an established baseline with one known issue
    And the developer saves a file that still has only the known issue
    When the developer asks Snyk to autonomously fix that workspace folder
    Then the fix does not run

  # maps: IDE-2592-M3
  Scenario: A folder fix before any baseline exists runs on the whole folder
    Given a running language server
    And the editor sends the initialize request
    And delta findings are switched to "New new issues" globally
    And the developer has a Code issue found by Snyk
    When the developer asks Snyk to autonomously fix that workspace folder
    Then the fix runs on the whole folder
