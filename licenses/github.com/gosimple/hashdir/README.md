# hashdir

[![Go Reference](https://pkg.go.dev/badge/github.com/gosimple/hashdir.svg)](https://pkg.go.dev/github.com/gosimple/hashdir)
[![Tests](https://github.com/gosimple/hashdir/actions/workflows/tests.yml/badge.svg)](https://github.com/gosimple/hashdir/actions/workflows/tests.yml)

Generate hash of all files and they paths for specified directory.

```go
package main

import (
	"fmt"

	"github.com/gosimple/hashdir"
)

func main() {
	dirHash, err := hashdir.Make("./someDir/", "md5")
	fmt.Println(dirHash)
}
```

Supported hashes:

* md5
* sha1
* sha256
* sha512

### Requests or bugs?

<https://github.com/gosimple/hashdir/issues>

## Installation

```sh
go get -u github.com/gosimple/hashdir
```

## License

The source files are distributed under the
[Mozilla Public License, version 2.0](http://mozilla.org/MPL/2.0/),
unless otherwise noted.
Please read the [FAQ](http://www.mozilla.org/MPL/2.0/FAQ.html)
if you have further questions regarding the license.
