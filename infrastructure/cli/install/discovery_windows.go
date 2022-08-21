package install

func (r *Release) downloadURL() string {
	return r.Assets.Windows.URL
}

func (r *Release) checksumURL() string {
	return r.Assets.Windows.ChecksumURL
}

func (r *Release) checksumInfo() string {
	return r.Assets.Windows.ChecksumInfo
}
