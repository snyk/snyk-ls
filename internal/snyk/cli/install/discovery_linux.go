package install

const executableName = "snyk-linux"

func (r *Release) downloadURL() string {
	return r.Assets.Linux.URL
}

func (r *Release) checksumURL() string {
	return r.Assets.Linux.ChecksumURL
}

func (r *Release) checksumInfo() string {
	return r.Assets.Linux.ChecksumInfo
}
