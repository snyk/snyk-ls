package util

// channelToSlice converts a channel to a slice by reading all values from the channel.
func ChannelToSlice[t any](channel <-chan t) []t {
	slice := make([]t, 0)
	for f := range channel {
		slice = append(slice, f)
	}
	return slice
}
