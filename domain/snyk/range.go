package snyk

import "fmt"

type Position struct {
	/**
	 * Line position in a document (zero-based).
	 */
	Line int
	/**
	 * Character offset on a line in a document (zero-based).
	 */
	Character int
}

func (p Position) String() string {
	return fmt.Sprintf("%d:%d", p.Line, p.Character)
}

type Range struct {
	/**
	 * The range's start position.
	 */
	Start Position

	/**
	 * The range's end position.
	 */
	End Position
}

func (r Range) String() string {
	return fmt.Sprintf("%s-%s", r.Start, r.End)
}

func (r Range) Contains(otherRange Range) bool {
	if otherRange.Start.Line < r.Start.Line || otherRange.End.Line < r.Start.Line {
		return false
	}
	if otherRange.Start.Line > r.End.Line || otherRange.End.Line > r.End.Line {
		return false
	}
	if otherRange.Start.Line == r.Start.Line && otherRange.Start.Character < r.Start.Character {
		return false
	}
	if otherRange.End.Line == r.End.Line && otherRange.End.Character > r.End.Character {
		return false
	}
	return true
}

func (r Range) Overlaps(otherRange Range) bool {
	if r.Contains(otherRange) {
		return true
	}
	if otherRange.End.Line < r.Start.Line {
		return false
	}
	if otherRange.Start.Line > r.End.Line {
		return false
	}
	if otherRange.End.Line <= r.Start.Line && otherRange.End.Character < r.End.Character {
		return false
	}
	if otherRange.End.Line <= r.End.Line && otherRange.Start.Character > r.End.Character {
		return false
	}
	return true
}
