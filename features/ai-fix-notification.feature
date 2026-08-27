Feature: Structured Code AI Fix result notification

  A developer running Code AI Fix on an issue needs to know, in the IDE, what
  happened to that fix attempt - which issue it was for, whether it succeeded,
  and which fixes were produced - without the IDE having to scrape an HTML
  panel to find out.

  # maps: IDE-2451-M1
  Scenario: A developer running Code AI Fix on an issue gets a structured fix result notification
    Given a running language server
    And the editor sends the initialize request
    And the developer has a Code issue found by Snyk
    When the developer asks Snyk to fix the issue with AI
    Then the editor receives a structured AI fix result for the issue
