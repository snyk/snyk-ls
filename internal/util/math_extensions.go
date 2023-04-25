package util

type ordered interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~float32 | ~float64
}

func Max[T ordered](values ...T) T {
	max := values[0]
	for _, v := range values {
		if v > max {
			max = v
		}
	}

	return max
}

func Min[T ordered](values ...T) T {
	min := values[0]
	for _, v := range values {
		if v < min {
			min = v
		}
	}

	return min
}
