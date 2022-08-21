package install

func (r *Release) downloadURL() string {
	return r.Assets.MacOS.URL
}

func (r *Release) checksumURL() string {
	return r.Assets.MacOS.ChecksumURL
}

func (r *Release) checksumInfo() string {
	return r.Assets.MacOS.ChecksumInfo
}
