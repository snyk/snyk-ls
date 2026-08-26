Feature: New Issues scanning in repositories containing Windows device file names

  CON, PRN, AUX, NUL, COM1-9 and LPT1-9 are ordinary file names on macOS and
  Linux. Snyk clones the base branch to work out which findings are new, so a
  repository carrying such a name anywhere on its base branch stops producing
  new-issue results at all: findings keep showing under Total and nothing ever
  appears under New.

  The customer hit this with the file checked out in their own working tree.
  The scenario below puts it only on the base branch, which reaches the bug
  through the same code and is additionally a state a Windows developer can be
  in, since git will not check such a file out on Windows.

  # maps: IDE-2473-M1
  Scenario: A developer sees only the finding they introduced, not the one already on the base branch
    Given a running language server that finds one issue in every source file
    And delta findings are switched to "New new issues" globally
    And the developer opens a repository whose base branch carries a file named after a Windows device
    When the developer scans the whole repository
    Then the editor is notified of only the newly introduced issue
