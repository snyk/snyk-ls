/*
 * © 2026 Snyk Limited
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

package backend

import (
	"os"
	"path/filepath"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Wire format version embedded in the on-disk filename. Bump when the JSON shape
// or bucket layout changes so a new file is used (see OpenBoltDBForCacheDir).
const issueCacheBoltWireVersion = "v1"

var (
	boltMu       sync.Mutex
	boltDBByPath = map[string]*bolt.DB{}
)

// OpenBoltDBForCacheDir returns a process-wide shared handle to the issue-cache
// bbolt file under the Snyk cache directory. The same absolute path always
// resolves to the same *bolt.DB (second open of the same file would fail).
func OpenBoltDBForCacheDir(cacheDir string) (*bolt.DB, error) {
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return nil, err
	}
	abs := filepath.Join(cacheDir, "issuecache."+issueCacheBoltWireVersion+".bolt")
	abs, err := filepath.Abs(abs)
	if err != nil {
		return nil, err
	}

	boltMu.Lock()
	defer boltMu.Unlock()
	if db, ok := boltDBByPath[abs]; ok {
		return db, nil
	}

	db, err := bolt.Open(abs, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	boltDBByPath[abs] = db
	return db, nil
}

// CloseBoltDBForTesting closes and forgets the DB for the given cache dir. Only
// for tests that need a clean slate; production never closes until exit.
func CloseBoltDBForTesting(cacheDir string) error {
	abs := filepath.Join(cacheDir, "issuecache."+issueCacheBoltWireVersion+".bolt")
	abs, err := filepath.Abs(abs)
	if err != nil {
		return err
	}
	boltMu.Lock()
	defer boltMu.Unlock()
	db, ok := boltDBByPath[abs]
	if !ok {
		return nil
	}
	delete(boltDBByPath, abs)
	return db.Close()
}
