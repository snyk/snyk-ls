Feature: Creating an ignore in a folder without a Git remote

  A developer working in a folder that has no Git remote can still set a
  --remote-repo-url override in the editor's Additional parameters setting,
  in the same style the CLI itself accepts. Creating an ignore on a Snyk
  Code issue must use that override and succeed, whether the parameter is set
  globally or per folder.
  Without either a Git remote or the override, Create ignore is disabled
  up front instead of failing after submission.

  # maps: IDE-2526-M1
  Scenario: A developer creates an ignore using a globally configured remote repository URL override
    Given a running language server
    And the editor sends the initialize request
    And a folder that is not a Git repository
    And the developer sets "--remote-repo-url=https://mainframe.example/payroll" as a global additional parameter
    When the developer saves a file with a security issue
    And the developer creates an ignore for that issue
    Then the ignore is filed for repository "https://mainframe.example/payroll"
    And the ignore is filed against the finding the scan produced
    And the issue shows as ignored
    And no error notification is shown to the developer
    And the issue details offer an enabled "Create ignore" button

  # maps: IDE-2526-M1
  Scenario: A developer creates an ignore using a per-folder remote repository URL override
    Given a running language server
    And the editor sends the initialize request
    And a folder that is not a Git repository
    And the developer sets "--remote-repo-url=https://mainframe.example/payroll" as the folder's additional parameter
    When the developer saves a file with a security issue
    And the developer creates an ignore for that issue
    Then the ignore is filed for repository "https://mainframe.example/payroll"
    And the ignore is filed against the finding the scan produced
    And the issue shows as ignored
    And no error notification is shown to the developer
    And the issue details offer an enabled "Create ignore" button

  # maps: IDE-2526-M2
  Scenario: A developer without a Git remote or override sees a disabled Create ignore button
    Given a running language server
    And the editor sends the initialize request
    And a folder that is not a Git repository
    When the developer opens the issue details
    Then the issue details offer a disabled "Create ignore" button with an explanation to add a Git remote or set --remote-repo-url, then rescan
    And no error notification is shown to the developer

  # maps: IDE-2526-M1
  Scenario: A developer changes the globally configured remote repository URL while creating an ignore
    Given a running language server
    And the editor sends the initialize request
    And a folder that is not a Git repository
    And the developer sets "--remote-repo-url=https://first.example/repos/project" as a global additional parameter
    When the developer saves a file with a security issue
    And the developer sets "--remote-repo-url=https://second.example/project" as a global additional parameter
    And the developer creates an ignore for that issue
    Then the ignore is filed for repository "https://second.example/project"
    And the ignore is filed against the finding the scan produced
    And the issue shows as ignored
    And no error notification is shown to the developer
    And the issue details offer an enabled "Create ignore" button
