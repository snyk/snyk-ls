package install

const executableName = "snyk-linux-arm64"

func (r *Release) downloadURL() string {
	return r.Assets.LinuxARM64.URL
}

func (r *Release) checksumURL() string {
	return r.Assets.LinuxARM64.ChecksumURL
}
