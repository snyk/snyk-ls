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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	bolt "go.etcd.io/bbolt"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

const boltRootBucket = "ic"

// BoltBackend stores rich issue payloads per file path under a product-specific
// sub-bucket. Keys are sha256(filePath); values are JSON arrays of *snyk.Issue
// (same wire shape as GitPersistenceProvider snapshots, CodeActions omitted).
type BoltBackend struct {
	db      *bolt.DB
	prodSeg []byte
}

var _ StorageBackend = (*BoltBackend)(nil)

// NewBoltBackend constructs a backend that reads/writes under root bucket
// "ic"/<product codename>. The db handle is typically shared across products
// via OpenBoltDBForCacheDir.
func NewBoltBackend(db *bolt.DB, p product.Product) *BoltBackend {
	name := p.ToProductCodename()
	if name == "" {
		name = "unknown"
	}
	return &BoltBackend{db: db, prodSeg: []byte(name)}
}

func (b *BoltBackend) RemoveExpired() {
	// Disk backend has no TTL in v1; imcache RemoveExpired is a no-op equivalent.
}

func (b *BoltBackend) Get(path types.FilePath) ([]types.Issue, bool) {
	key := pathKey(path)
	var out []types.Issue
	var found bool
	_ = b.db.View(func(tx *bolt.Tx) error {
		pb, err := b.productBucket(tx)
		if err != nil || pb == nil {
			return nil
		}
		v := pb.Get(key)
		if v == nil {
			return nil
		}
		issues, err := unmarshalIssues(v)
		if err != nil {
			return err
		}
		out = issues
		found = true
		return nil
	})
	return out, found
}

func (b *BoltBackend) Set(path types.FilePath, issues []types.Issue) {
	key := pathKey(path)
	data, err := json.Marshal(issues)
	if err != nil {
		return
	}
	_ = b.db.Update(func(tx *bolt.Tx) error {
		pb, err := b.ensureProductBucket(tx)
		if err != nil {
			return err
		}
		return pb.Put(key, data)
	})
}

func (b *BoltBackend) GetAll() snyk.IssuesByFile {
	out := make(snyk.IssuesByFile)
	_ = b.db.View(func(tx *bolt.Tx) error {
		pb, err := b.productBucket(tx)
		if err != nil || pb == nil {
			return nil
		}
		c := pb.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			issues, err := unmarshalIssues(v)
			if err != nil {
				return err
			}
			if len(issues) == 0 {
				continue
			}
			fp := issues[0].GetAffectedFilePath()
			out[fp] = issues
		}
		return nil
	})
	return out
}

func (b *BoltBackend) Remove(path types.FilePath) {
	key := pathKey(path)
	_ = b.db.Update(func(tx *bolt.Tx) error {
		pb, err := b.productBucket(tx)
		if err != nil || pb == nil {
			return nil
		}
		return pb.Delete(key)
	})
}

func (b *BoltBackend) ForEachPath(fn func(path types.FilePath) bool) {
	_ = b.db.View(func(tx *bolt.Tx) error {
		pb, err := b.productBucket(tx)
		if err != nil || pb == nil {
			return nil
		}
		c := pb.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			issues, err := unmarshalIssues(v)
			if err != nil {
				return err
			}
			if len(issues) == 0 {
				continue
			}
			if !fn(issues[0].GetAffectedFilePath()) {
				break
			}
		}
		return nil
	})
}

func (b *BoltBackend) Close() error {
	// Shared DB; do not close here.
	return nil
}

func (b *BoltBackend) productBucket(tx *bolt.Tx) (*bolt.Bucket, error) {
	root := tx.Bucket([]byte(boltRootBucket))
	if root == nil {
		return nil, nil
	}
	return root.Bucket(b.prodSeg), nil
}

func (b *BoltBackend) ensureProductBucket(tx *bolt.Tx) (*bolt.Bucket, error) {
	root, err := tx.CreateBucketIfNotExists([]byte(boltRootBucket))
	if err != nil {
		return nil, err
	}
	return root.CreateBucketIfNotExists(b.prodSeg)
}

func pathKey(path types.FilePath) []byte {
	sum := sha256.Sum256([]byte(path))
	dst := make([]byte, hex.EncodedLen(len(sum)))
	hex.Encode(dst, sum[:])
	return dst
}

func unmarshalIssues(data []byte) ([]types.Issue, error) {
	var decoded []*snyk.Issue
	if err := json.Unmarshal(data, &decoded); err != nil {
		return nil, err
	}
	out := make([]types.Issue, len(decoded))
	for i, x := range decoded {
		out[i] = x
	}
	return out, nil
}
