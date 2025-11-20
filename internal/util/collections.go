package util

import (
	"cmp"
	"slices"
)

// ChannelToSlice converts a channel to a slice by reading all values from the channel.
func ChannelToSlice[t any](channel <-chan t) []t {
	slice := make([]t, 0)
	for f := range channel {
		slice = append(slice, f)
	}
	return slice
}

// SlicesEqualIgnoringOrder compares two slices for equality ignoring element order
func SlicesEqualIgnoringOrder[T cmp.Ordered](a, b []T) bool {
	if len(a) != len(b) {
		return false
	}

	// Create sorted copies to avoid modifying originals
	sortedA := make([]T, len(a))
	copy(sortedA, a)
	slices.Sort(sortedA)

	sortedB := make([]T, len(b))
	copy(sortedB, b)
	slices.Sort(sortedB)

	return slices.Equal(sortedA, sortedB)
}
