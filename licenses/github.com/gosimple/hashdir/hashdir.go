package hashdir

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Make generate hash of all files and they paths for specified directory.
func Make(dir string, hashType string) (string, error) {
	var endHash string

	bigErr := filepath.Walk(dir,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			endHash, err = hashData(endHash, hashType)
			if err != nil {
				return err
			}

			if !info.IsDir() {
				pathHash, err := hashData(path, hashType)
				if err != nil {
					return err
				}
				fileHash, err := hashFile(path, hashType)
				if err != nil {
					return err
				}
				// log.Println(path, fileHash, info.ModTime())
				endHash = endHash + pathHash + fileHash
			}
			return nil
		})

	if bigErr != nil {
		return "", bigErr
	}
	endHash, err := hashData(endHash, hashType)
	if err != nil {
		return "", err
	}
	return endHash, err
}

func selectHash(hashType string) (hash.Hash, error) {
	switch strings.ToLower(hashType) {
	case "md5":
		return md5.New(), nil
	case "sha1":
		return sha1.New(), nil
	case "sha256":
		return sha256.New(), nil
	case "sha512":
		return sha512.New(), nil
	}
	return nil, errors.New("Unknown hash: " + hashType)
}

func hashData(data string, hashType string) (string, error) {
	h, err := selectHash(hashType)
	if err != nil {
		return "", err
	}

	_, err = h.Write([]byte(data))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func hashFile(path string, hashType string) (string, error) {
	// Handle hashing big files.
	// Source: https://stackoverflow.com/q/60328216/1722542

	f, err := os.Open(path)
	if err != nil {
		return "", err
	}

	defer func() {
		_ = f.Close()
	}()

	buf := make([]byte, 1024*1024)
	h, err := selectHash(hashType)
	if err != nil {
		return "", err
	}

	for {
		bytesRead, err := f.Read(buf)
		if err != nil {
			if err != io.EOF {
				return "", err
			}
			_, err = h.Write(buf[:bytesRead])
			if err != nil {
				return "", err
			}
			break
		}
		_, err = h.Write(buf[:bytesRead])
		if err != nil {
			return "", err
		}
	}

	fileHash := hex.EncodeToString(h.Sum(nil))
	return fileHash, nil
}
