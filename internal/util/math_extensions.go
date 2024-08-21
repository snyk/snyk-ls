package util

type ordered interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~float32 | ~float64
}

func Max[T ordered](values ...T) T {
	m := values[0]
	for _, v := range values {
		if v > m {
			m = v
		}
	}

	return m
}

func Min[T ordered](values ...T) T {
	m := values[0]
	for _, v := range values {
		if v < m {
			m = v
		}
	}

	return m
}
