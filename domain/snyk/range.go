/*
 * © 2022 Snyk Limited All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

// Contains returns true if the otherRange is contained within the range
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

// Overlaps returns true if the otherRange overlaps with the range
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
