package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
)

type testEvent struct {
	Action  string  `json:"Action"`
	Package string  `json:"Package"`
	Test    string  `json:"Test"`
	Elapsed float64 `json:"Elapsed"`
}

type timingEntry struct {
	Package string
	Test    string
	Elapsed float64
}

const maxGoTestJSONLineBytes = 1024 * 1024

func main() {
	inputPath := flag.String("input", "", "path to go test -json output")
	outputPath := flag.String("output", "", "optional path for the timing summary")
	top := flag.Int("top", 20, "number of slow tests to include")
	flag.Parse()

	if *inputPath == "" {
		_, _ = fmt.Fprintln(os.Stderr, "-input is required")
		os.Exit(2)
	}

	input, err := os.Open(*inputPath)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "open input: %v\n", err)
		os.Exit(1)
	}
	defer input.Close()

	summary, err := summarizeGoTestJSON(input, *top)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "summarize: %v\n", err)
		os.Exit(1)
	}

	if *outputPath == "" {
		_, _ = io.WriteString(os.Stdout, summary)
		return
	}

	if err := os.WriteFile(*outputPath, []byte(summary), 0o600); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "write output: %v\n", err)
		os.Exit(1)
	}
}

func summarizeGoTestJSON(input io.Reader, top int) (string, error) {
	if top < 0 {
		top = 0
	}

	packageDurations, tests, err := parseGoTestJSON(input)
	if err != nil {
		return "", err
	}

	packages := make([]timingEntry, 0, len(packageDurations))
	for pkg, elapsed := range packageDurations {
		packages = append(packages, timingEntry{Package: pkg, Elapsed: elapsed})
	}
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Elapsed == packages[j].Elapsed {
			return packages[i].Package < packages[j].Package
		}
		return packages[i].Elapsed > packages[j].Elapsed
	})
	sort.Slice(tests, func(i, j int) bool {
		if tests[i].Elapsed == tests[j].Elapsed {
			if tests[i].Package == tests[j].Package {
				return tests[i].Test < tests[j].Test
			}
			return tests[i].Package < tests[j].Package
		}
		return tests[i].Elapsed > tests[j].Elapsed
	})

	var output bytes.Buffer
	output.WriteString("Package durations\n")
	for _, entry := range packages {
		_, _ = fmt.Fprintf(&output, "%s %.3fs\n", entry.Package, entry.Elapsed)
	}

	output.WriteString("\nSlowest tests\n")
	if top > len(tests) {
		top = len(tests)
	}
	for _, entry := range tests[:top] {
		_, _ = fmt.Fprintf(&output, "%s %s %.3fs\n", entry.Package, entry.Test, entry.Elapsed)
	}

	return output.String(), nil
}

func parseGoTestJSON(input io.Reader) (map[string]float64, []timingEntry, error) {
	packageDurations := map[string]float64{}
	var tests []timingEntry

	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), maxGoTestJSONLineBytes)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}

		var event testEvent
		if err := json.Unmarshal(line, &event); err != nil {
			return nil, nil, err
		}
		if event.Action != "pass" || event.Elapsed <= 0 {
			continue
		}
		if event.Test == "" {
			packageDurations[event.Package] = event.Elapsed
			continue
		}
		tests = append(tests, timingEntry{
			Package: event.Package,
			Test:    event.Test,
			Elapsed: event.Elapsed,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}

	return packageDurations, tests, nil
}
