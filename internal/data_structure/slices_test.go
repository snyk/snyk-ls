/*
 * © 2025 Snyk Limited
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

package data_structure

import (
	"reflect"
	"testing"
)

func TestUnique_EmptySlice(t *testing.T) {
	input := []int{}
	expected := []int{}
	result := Unique(input)

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestUnique_SingleElement(t *testing.T) {
	input := []int{1}
	expected := []int{1}
	result := Unique(input)

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestUnique_AllUniqueElements(t *testing.T) {
	input := []int{1, 2, 3, 4, 5}
	expected := []int{1, 2, 3, 4, 5}
	result := Unique(input)

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestUnique_AllDuplicateElements(t *testing.T) {
	input := []int{1, 1, 1, 1, 1}
	expected := []int{1}
	result := Unique(input)

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestUnique_MixedDuplicates(t *testing.T) {
	input := []int{1, 2, 1, 3, 2, 4, 5, 3}
	expected := []int{1, 2, 3, 4, 5}
	result := Unique(input)

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestUnique_PreservesOrder(t *testing.T) {
	input := []int{5, 3, 1, 3, 2, 5, 4}
	expected := []int{5, 3, 1, 2, 4}
	result := Unique(input)

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v (order should be preserved)", expected, result)
	}
}

func TestUnique_Strings(t *testing.T) {
	input := []string{"apple", "banana", "apple", "cherry", "banana"}
	expected := []string{"apple", "banana", "cherry"}
	result := Unique(input)

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestUnique_EmptyStrings(t *testing.T) {
	input := []string{"", "apple", "", "banana", ""}
	expected := []string{"", "apple", "banana"}
	result := Unique(input)

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestUnique_Float64(t *testing.T) {
	input := []float64{1.1, 2.2, 1.1, 3.3, 2.2}
	expected := []float64{1.1, 2.2, 3.3}
	result := Unique(input)

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestUnique_Bool(t *testing.T) {
	input := []bool{true, false, true, false, true}
	expected := []bool{true, false}
	result := Unique(input)

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestUnique_DoesNotModifyOriginal(t *testing.T) {
	original := []int{1, 2, 1, 3, 2}
	input := make([]int, len(original))
	copy(input, original)

	_ = Unique(input)

	if !reflect.DeepEqual(input, original) {
		t.Errorf("Original slice was modified: expected %v, got %v", original, input)
	}
}

func TestUnique_LargeSlice(t *testing.T) {
	input := make([]int, 10000)
	for i := 0; i < 10000; i++ {
		input[i] = i % 100 // Creates 100 unique values, each repeated 100 times
	}

	result := Unique(input)

	if len(result) != 100 {
		t.Errorf("Expected 100 unique elements, got %d", len(result))
	}

	// Verify all values from 0-99 are present
	seen := make(map[int]bool)
	for _, v := range result {
		seen[v] = true
	}

	for i := 0; i < 100; i++ {
		if !seen[i] {
			t.Errorf("Expected value %d to be present in result", i)
		}
	}
}

func FuzzUnique_Int(f *testing.F) {
	// Add seed corpus
	f.Add([]byte{})
	f.Add([]byte{1})
	f.Add([]byte{1, 2, 3})
	f.Add([]byte{1, 1, 1})
	f.Add([]byte{1, 2, 1, 3, 2})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Convert bytes to int slice
		input := make([]int, len(data))
		for i, b := range data {
			input[i] = int(b)
		}

		result := Unique(input)

		// Property 1: Result length should be <= input length
		if len(result) > len(input) {
			t.Errorf("Result length %d is greater than input length %d", len(result), len(input))
		}

		// Property 2: All elements in result should be unique
		seen := make(map[int]bool)
		for _, v := range result {
			if seen[v] {
				t.Errorf("Duplicate value %d found in result", v)
			}
			seen[v] = true
		}

		// Property 3: All elements in result should exist in input
		inputMap := make(map[int]bool)
		for _, v := range input {
			inputMap[v] = true
		}
		for _, v := range result {
			if !inputMap[v] {
				t.Errorf("Value %d in result but not in input", v)
			}
		}

		// Property 4: All unique elements from input should be in result
		if len(inputMap) != len(result) {
			t.Errorf("Expected %d unique elements, got %d", len(inputMap), len(result))
		}

		// Property 5: Order should be preserved (first occurrence)
		resultIndex := 0
		for _, v := range input {
			if resultIndex < len(result) && result[resultIndex] == v {
				resultIndex++
			}
		}
		if resultIndex != len(result) {
			t.Error("Order of first occurrences not preserved")
		}
	})
}

func FuzzUnique_String(f *testing.F) {
	// Add seed corpus
	f.Add("", ",", "")
	f.Add("a,b,c", ",", "")
	f.Add("x,x,x", ",", "")
	f.Add("foo,bar,foo,baz", ",", "")

	f.Fuzz(func(t *testing.T, input string, sep string, prefix string) {
		// Handle edge cases for separator
		if sep == "" {
			sep = ","
		}

		// Create slice from input
		var slice []string
		if input == "" {
			slice = []string{}
		} else {
			parts := []string{}
			current := ""
			for _, ch := range input {
				if string(ch) == sep {
					parts = append(parts, prefix+current)
					current = ""
				} else {
					current += string(ch)
				}
			}
			parts = append(parts, prefix+current)
			slice = parts
		}

		result := Unique(slice)

		// Property 1: Result length should be <= input length
		if len(result) > len(slice) {
			t.Errorf("Result length %d is greater than input length %d", len(result), len(slice))
		}

		// Property 2: All elements in result should be unique
		seen := make(map[string]bool)
		for _, v := range result {
			if seen[v] {
				t.Errorf("Duplicate value %q found in result", v)
			}
			seen[v] = true
		}

		// Property 3: All elements in result should exist in input
		inputMap := make(map[string]bool)
		for _, v := range slice {
			inputMap[v] = true
		}
		for _, v := range result {
			if !inputMap[v] {
				t.Errorf("Value %q in result but not in input", v)
			}
		}

		// Property 4: All unique elements from input should be in result
		if len(inputMap) != len(result) {
			t.Errorf("Expected %d unique elements, got %d", len(inputMap), len(result))
		}
	})
}

// Filter tests
func TestFilter_EmptySlice(t *testing.T) {
	input := []int{}
	result := Filter(input, func(x int) bool { return x > 0 })
	expected := []int(nil)

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestFilter_AllMatch(t *testing.T) {
	input := []int{1, 2, 3, 4, 5}
	result := Filter(input, func(x int) bool { return x > 0 })
	expected := []int{1, 2, 3, 4, 5}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestFilter_NoneMatch(t *testing.T) {
	input := []int{1, 2, 3, 4, 5}
	result := Filter(input, func(x int) bool { return x > 10 })
	expected := []int(nil)

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestFilter_SomeMatch(t *testing.T) {
	input := []int{1, 2, 3, 4, 5, 6}
	result := Filter(input, func(x int) bool { return x%2 == 0 })
	expected := []int{2, 4, 6}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestFilter_PreservesOrder(t *testing.T) {
	input := []int{5, 1, 8, 3, 9, 2, 6}
	result := Filter(input, func(x int) bool { return x > 5 })
	expected := []int{8, 9, 6}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestFilter_Strings(t *testing.T) {
	input := []string{"apple", "banana", "cherry", "date"}
	result := Filter(input, func(s string) bool { return len(s) > 5 })
	expected := []string{"banana", "cherry"}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestFilter_EmptyStrings(t *testing.T) {
	input := []string{"", "a", "", "b", "c"}
	result := Filter(input, func(s string) bool { return s != "" })
	expected := []string{"a", "b", "c"}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestFilter_DoesNotModifyOriginal(t *testing.T) {
	original := []int{1, 2, 3, 4, 5}
	input := make([]int, len(original))
	copy(input, original)

	_ = Filter(input, func(x int) bool { return x%2 == 0 })

	if !reflect.DeepEqual(input, original) {
		t.Errorf("Original slice was modified: expected %v, got %v", original, input)
	}
}

// Map tests
func TestMap_EmptySlice(t *testing.T) {
	input := []int{}
	result := Map(input, func(x int) int { return x * 2 })
	expected := []int{}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestMap_IntToInt(t *testing.T) {
	input := []int{1, 2, 3, 4, 5}
	result := Map(input, func(x int) int { return x * 2 })
	expected := []int{2, 4, 6, 8, 10}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestMap_IntToString(t *testing.T) {
	input := []int{1, 2, 3}
	result := Map(input, func(x int) string {
		if x == 1 {
			return "one"
		} else if x == 2 {
			return "two"
		}
		return "three"
	})
	expected := []string{"one", "two", "three"}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestMap_StringToInt(t *testing.T) {
	input := []string{"a", "bb", "ccc"}
	result := Map(input, func(s string) int { return len(s) })
	expected := []int{1, 2, 3}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestMap_PreservesOrder(t *testing.T) {
	input := []int{5, 3, 1, 4, 2}
	result := Map(input, func(x int) int { return x * x })
	expected := []int{25, 9, 1, 16, 4}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestMap_PreservesLength(t *testing.T) {
	input := []int{1, 2, 3, 4, 5}
	result := Map(input, func(x int) string { return "x" })

	if len(result) != len(input) {
		t.Errorf("Expected length %d, got %d", len(input), len(result))
	}
}

func TestMap_DoesNotModifyOriginal(t *testing.T) {
	original := []int{1, 2, 3, 4, 5}
	input := make([]int, len(original))
	copy(input, original)

	_ = Map(input, func(x int) int { return x * 2 })

	if !reflect.DeepEqual(input, original) {
		t.Errorf("Original slice was modified: expected %v, got %v", original, input)
	}
}

func TestMap_ComplexTransformation(t *testing.T) {
	type Person struct {
		Name string
		Age  int
	}
	input := []Person{
		{Name: "Alice", Age: 30},
		{Name: "Bob", Age: 25},
		{Name: "Charlie", Age: 35},
	}
	result := Map(input, func(p Person) string { return p.Name })
	expected := []string{"Alice", "Bob", "Charlie"}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

// Fuzz tests for Filter
func FuzzFilter_Int(f *testing.F) {
	// Add seed corpus
	f.Add([]byte{}, byte(5))
	f.Add([]byte{1, 2, 3}, byte(2))
	f.Add([]byte{10, 20, 30}, byte(15))

	f.Fuzz(func(t *testing.T, data []byte, threshold byte) {
		// Convert bytes to int slice
		input := make([]int, len(data))
		for i, b := range data {
			input[i] = int(b)
		}

		thresholdInt := int(threshold)
		result := Filter(input, func(x int) bool { return x > thresholdInt })

		// Property 1: Result length should be <= input length
		if len(result) > len(input) {
			t.Errorf("Result length %d is greater than input length %d", len(result), len(input))
		}

		// Property 2: All elements in result should match the predicate
		for _, v := range result {
			if v <= thresholdInt {
				t.Errorf("Value %d in result does not match predicate (> %d)", v, thresholdInt)
			}
		}

		// Property 3: All elements in result should exist in input
		inputMap := make(map[int]int) // value -> count
		for _, v := range input {
			inputMap[v]++
		}
		resultMap := make(map[int]int)
		for _, v := range result {
			resultMap[v]++
		}
		for v, count := range resultMap {
			if inputMap[v] < count {
				t.Errorf("Value %d appears %d times in result but only %d times in input", v, count, inputMap[v])
			}
		}

		// Property 4: Order should be preserved
		resultIndex := 0
		for _, v := range input {
			if resultIndex < len(result) && result[resultIndex] == v {
				resultIndex++
			}
		}
		if resultIndex != len(result) {
			t.Error("Order not preserved")
		}
	})
}

func FuzzFilter_String(f *testing.F) {
	// Add seed corpus
	f.Add("", ",", 5)
	f.Add("a,bb,ccc,dddd", ",", 2)
	f.Add("short,verylongstring,mid", ",", 10)

	f.Fuzz(func(t *testing.T, input string, sep string, minLen int) {
		// Handle edge cases
		if sep == "" {
			sep = ","
		}
		if minLen < 0 {
			minLen = 0
		}

		// Create slice from input
		var slice []string
		if input == "" {
			slice = []string{}
		} else {
			parts := []string{}
			current := ""
			for _, ch := range input {
				if string(ch) == sep {
					parts = append(parts, current)
					current = ""
				} else {
					current += string(ch)
				}
			}
			parts = append(parts, current)
			slice = parts
		}

		result := Filter(slice, func(s string) bool { return len(s) >= minLen })

		// Property 1: Result length should be <= input length
		if len(result) > len(slice) {
			t.Errorf("Result length %d is greater than input length %d", len(result), len(slice))
		}

		// Property 2: All elements in result should match the predicate
		for _, v := range result {
			if len(v) < minLen {
				t.Errorf("String %q in result does not match predicate (len >= %d)", v, minLen)
			}
		}

		// Property 3: All elements in result should exist in input
		for _, v := range result {
			found := false
			for _, iv := range slice {
				if v == iv {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Value %q in result but not in input", v)
			}
		}
	})
}

// Fuzz tests for Map
func FuzzMap_IntToInt(f *testing.F) {
	// Add seed corpus
	f.Add([]byte{}, byte(2))
	f.Add([]byte{1, 2, 3}, byte(3))
	f.Add([]byte{10, 20, 30}, byte(1))

	f.Fuzz(func(t *testing.T, data []byte, multiplier byte) {
		// Convert bytes to int slice
		input := make([]int, len(data))
		for i, b := range data {
			input[i] = int(b)
		}

		mult := int(multiplier)
		if mult == 0 {
			mult = 1 // Avoid multiplication by zero for testing
		}

		result := Map(input, func(x int) int { return x * mult })

		// Property 1: Result length should equal input length
		if len(result) != len(input) {
			t.Errorf("Result length %d does not equal input length %d", len(result), len(input))
		}

		// Property 2: Each element should be transformed correctly
		for i, v := range input {
			expected := v * mult
			if result[i] != expected {
				t.Errorf("At index %d: expected %d, got %d", i, expected, result[i])
			}
		}

		// Property 3: Order should be preserved
		for i := range input {
			if input[i]*mult != result[i] {
				t.Error("Order or transformation not correct")
			}
		}
	})
}

func FuzzMap_StringToInt(f *testing.F) {
	// Add seed corpus
	f.Add("", ",")
	f.Add("a,bb,ccc", ",")
	f.Add("hello,world", ",")

	f.Fuzz(func(t *testing.T, input string, sep string) {
		// Handle edge cases
		if sep == "" {
			sep = ","
		}

		// Create slice from input
		var slice []string
		if input == "" {
			slice = []string{}
		} else {
			parts := []string{}
			current := ""
			for _, ch := range input {
				if string(ch) == sep {
					parts = append(parts, current)
					current = ""
				} else {
					current += string(ch)
				}
			}
			parts = append(parts, current)
			slice = parts
		}

		result := Map(slice, func(s string) int { return len(s) })

		// Property 1: Result length should equal input length
		if len(result) != len(slice) {
			t.Errorf("Result length %d does not equal input length %d", len(result), len(slice))
		}

		// Property 2: Each element should be transformed correctly
		for i, s := range slice {
			expected := len(s)
			if result[i] != expected {
				t.Errorf("At index %d: expected %d (len of %q), got %d", i, expected, s, result[i])
			}
		}
	})
}
