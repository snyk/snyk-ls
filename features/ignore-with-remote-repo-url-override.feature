Feature: Creating an ignore in a Git repository with a remote repository URL override

  A --remote-repo-url set in the editor's Additional parameters takes precedence
  over the Git remote of a folder that is a Git repository, so the ignore is filed
  against the repository the developer names instead of the one Git reports.

  # maps: IDE-2526-M1
  Scenario: A developer's remote repository URL override replaces the Git remote of a Git repository
    Given a running language server
    And the editor sends the initialize request
    And a folder that is a Git repository with a remote
    And the developer sets "--remote-repo-url=https://mainframe.example/payroll" as a global additional parameter
    When the developer saves a file with a security issue
    And the developer creates an ignore for that issue
    Then the ignore is filed for repository "https://mainframe.example/payroll"
    And the ignore is filed against the finding the scan produced
    And the issue shows as ignored
    And no error notification is shown to the developer
