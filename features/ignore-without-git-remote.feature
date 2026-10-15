Feature: Creating an ignore in a folder without a Git remote

  A developer working in a folder that has no Git remote can still set a
  --remote-repo-url override in the editor's Additional parameters setting,
  in the same style the CLI itself accepts. Creating an ignore on a Snyk
  Code issue must use that override and succeed, whether the editor stores
  the parameter as one global string (VS Code) or per folder (IntelliJ).
  Without either a Git remote or the override, Create ignore is disabled
  up front instead of failing after submission.

  # maps: IDE-2526-M1
  Scenario: A developer creates an ignore using a globally configured remote repository URL override
    Given a running language server
    And the editor sends the initialize request
    And a folder that is not a Git repository
    And the developer sets "--remote-repo-url=https://mainframe.example/payroll" as a global additional parameter
    When the developer saves a file with a security issue and creates an ignore
    Then the ignore is filed for repository "https://mainframe.example/payroll"
    And the ignore is filed against the finding the scan produced
    And the issue shows as ignored
    And no error notification is shown to the developer
    And the details offered an enabled button

  # maps: IDE-2526-M1
  Scenario: A developer creates an ignore using a per-folder remote repository URL override
    Given a running language server
    And the editor sends the initialize request
    And a folder that is not a Git repository
    And the developer sets "--remote-repo-url=https://mainframe.example/payroll" as the folder's additional parameter
    When the developer saves a file with a security issue and creates an ignore
    Then the ignore is filed for repository "https://mainframe.example/payroll"
    And the ignore is filed against the finding the scan produced
    And the issue shows as ignored
    And no error notification is shown to the developer
    And the details offered an enabled button

  # maps: IDE-2526-M2
  Scenario: A developer without a Git remote or override sees a disabled Create ignore button
    Given a running language server
    And the editor sends the initialize request
    And a folder that is not a Git repository
    When the developer opens the issue details
    Then Create ignore is disabled with an explanation to add a Git remote or set --remote-repo-url, then rescan
    And no error notification is shown to the developer
