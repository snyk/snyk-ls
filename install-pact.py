#!/usr/bin/env python
import os
import platform
import tarfile

import requests


def download_and_extract(url, destination):
	response = requests.get(url, stream=True)
	response.raise_for_status()

	os.makedirs(os.path.dirname(destination), exist_ok=True)

	with open(destination, 'wb') as f:
		for chunk in response.iter_content(chunk_size=8192):
			if chunk:
				f.write(chunk)

	# Extract the contents of the downloaded tar.gz archive to the pact_dir
	with tarfile.open(destination, 'r:gz') as tar:
		tar.extractall(path=os.path.dirname(destination))


def main():
	script_dir = os.path.dirname(os.path.realpath(__file__))
	pact_dir = os.path.join(script_dir, ".bin", "pact")

	is_installed = os.path.isdir(pact_dir)
	if not is_installed:
		print("--- 🛠 Installing Pact CLI dependencies")
		os_name = platform.system().lower()
		arch = platform.machine()

		if os_name == "linux" and arch == "x86_64":
			os_name = "linux-x86_64"
		elif os_name == "darwin" and arch == "x86_64":
			os_name = "osx-x86_64"
		elif os_name == "darwin" and arch == "arm64":
			os_name = "osx-arm64"
		else:
			print("Sorry, you'll need to install the pact-ruby-standalone manually.")
			exit(1)

		tag_url = "https://github.com/pact-foundation/pact-ruby-standalone/releases/latest"
		response = requests.head(tag_url, allow_redirects=True)
		response.raise_for_status()
		tag = response.url.split("/")[-1]
		filename = f"pact-{tag[1:]}-{os_name}.tar.gz"
		download_url = f"https://github.com/pact-foundation/pact-ruby-standalone/releases/download/{tag}/{filename}"
		download_and_extract(download_url, os.path.join(script_dir, ".bin", filename))
	else:
		print("--- 🛠 Pact CLI already installed; skipping download")

	print("--- 🛠 Creating symlinks for Pact CLI")
	os.makedirs("/usr/local/bin", exist_ok=True)

	binaries = [
		"pact", "pact-broker", "pact-message", "pact-mock-service",
		"pact-plugin-cli", "pact-provider-verifier", "pact-publish",
		"pact-stub-service", "pactflow"
	]

	for binary in binaries:
		source_path = os.path.join(script_dir, '.bin', 'pact', 'bin', binary)
		dest_path = os.path.join("/usr/local/bin", binary)
		try:
			os.symlink(source_path, dest_path)
			print(f"Created symlink for {binary} at {dest_path}")
		except OSError:
			if not os.path.exists(dest_path) or not os.path.islink(dest_path):
				print(f"Cannot create symlink for {binary}. Please check {dest_path}")

	print("--- 🛠 Pact CLI installed")


if __name__ == "__main__":
	main()
