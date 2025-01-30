package hashdir

import "testing"

func TestMake(t *testing.T) {
	type args struct {
		root     string
		hashType string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			"Test making MD5 hash",
			args{
				"./assets/",
				"md5",
			},
			"2d03afa7a1d8e7de98ce8a56660f86ff",
			false,
		},
		{
			"Test making SHA1 hash",
			args{
				"./assets/",
				"SHA1",
			},
			"6049fcf8e09f83a28d769f8493b2af35a0824886",
			false,
		},
		{
			"Test making SHA256 hash",
			args{
				"./assets/",
				"sha256",
			},
			"a7da71b33ec7ce8179b6d47cab465e0b51e581de8086c9e3d7f4e71ee36a39fd",
			false,
		},
		{
			"Test making SHA512 hash",
			args{
				"./assets/",
				"SHA512",
			},
			"5427e699678230eb1a813691d1e7925e5549ad1541bf3e380e7a8267d13fad331873ccb90ebba10f54713653b0fdd82d14532ff956e17519e557790e8c477dcf",
			false,
		},
		{
			"Test making with wrong hash name",
			args{
				"./assets/",
				"unknownHash",
			},
			"",
			true,
		},
		{
			"Test non existing folder",
			args{
				"./someDir/",
				"md5",
			},
			"",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Make(tt.args.root, tt.args.hashType)
			if (err != nil) != tt.wantErr {
				t.Errorf("Make() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Make() = %v, want %v", got, tt.want)
			}
		})
	}
}
