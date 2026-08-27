Feature: New Issues in repositories containing Windows device filenames

  CON, PRN, AUX, NUL, COM1-9 and LPT1-9 are ordinary filenames on macOS and
  Linux, and a repository is free to contain them. Snyk clones the base branch
  to decide which findings are new. One such file anywhere on the base branch
  stopped that clone completing, so no baseline was ever recorded: findings kept
  appearing under Total while New stayed permanently empty.

  # maps: IDE-2473-M1
  Scenario Outline: A developer sees only the finding they introduced, not the one already on the base branch
    Given a running language server
    And delta findings are switched to "New new issues" globally
    And the developer opens a repository whose base branch carries a file named "<filename>"
    And their feature branch adds a finding the base branch does not have
    When the developer scans the whole repository
    Then the editor is notified of only the newly introduced issue

    Examples:
      | filename |
      | prn.sh   |
      | con.cmd  |
      | aux.bat  |
      | nul.sh   |
      | com1.exe |
      | lpt1.sh  |
      | prn      |

  # maps: IDE-2473-M2
  Scenario: A developer working on a branch with a device-named file in their checkout still sees new findings
    Given a running language server
    And delta findings are switched to "New new issues" globally
    And the developer has a file named "prn.sh" checked out in their working tree
    And their feature branch adds a finding the base branch does not have
    When the developer scans the whole repository
    Then the editor is notified of only the newly introduced issue
