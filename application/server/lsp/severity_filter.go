package lsp

// TODO: this belongs to Snyk domain but has to live here until there's no dependency on lsp from the domain layer.

func NewSeverityFilter(critical bool, high bool, medium bool, low bool) SeverityFilter {
	return SeverityFilter{
		Critical: critical,
		High:     high,
		Medium:   medium,
		Low:      low,
	}
}

func DefaultSeverityFilter() SeverityFilter {
	return SeverityFilter{
		Critical: true,
		High:     true,
		Medium:   true,
		Low:      true,
	}
}
