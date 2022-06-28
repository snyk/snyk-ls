package snyk

type ScanResultProcessor = func(issues []Issue)

func NoopResultProcessor(_ []Issue) {}
