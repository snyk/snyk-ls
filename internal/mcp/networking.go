/*
 * © 2025 Snyk Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package mcp

import (
	"fmt"
	"net"
	"net/url"
)

const (
	DefaultPort = 7695
	DefaultHost = "127.0.0.1"
)

func isPortInUse(u *url.URL) bool {
	address := u.Host
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return true
	}
	listener.Close()
	return false
}

func determineFreePort() int {
	port := DefaultPort
	for range 1000 {
		u, err := url.Parse(fmt.Sprintf("http://%s:%d", DefaultHost, port))
		if err != nil {
			// this should not ever happen. so if it does, we panic
			panic(err)
		}
		inUse := isPortInUse(u)
		if !inUse {
			break
		}
		port++
	}
	return port
}
