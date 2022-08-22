package install

func (r *Release) downloadURL() string {
	return r.Assets.LinuxARM64.URL
}

func (r *Release) checksumURL() string {
	return r.Assets.LinuxARM64.ChecksumURL
}

func (r *Release) checksumInfo() string {
	return r.Assets.LinuxARM64.ChecksumInfo
}
