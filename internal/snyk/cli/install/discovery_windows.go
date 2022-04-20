package install

const executableName = "snyk-win.exe"

func (r *Release) downloadURL() string {
	return r.Assets.Windows.URL
}

func (r *Release) checksumURL() string {
	return r.Assets.Windows.ChecksumURL
}
