// Copyright 2020 by Dobrosław Żybort. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/*
Package hashdir generate hash of all files and they paths for specified
directory.

Example:

	package main

	import (
		"fmt"

		"github.com/gosimple/hashdir"
	)

	func main() {
		dirHash, err := hashdir.Make("./someDir/", "md5")
		fmt.Println(dirHash)
	}

Requests or bugs?

https://github.com/gosimple/hashdir/issues
*/
package hashdir
