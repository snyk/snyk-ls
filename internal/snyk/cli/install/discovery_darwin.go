package install

const executableName = "snyk-macos"

func (r *Release) downloadURL() string {
	return r.Assets.MacOS.URL
}

func (r *Release) checksumURL() string {
	return r.Assets.MacOS.ChecksumURL
}
