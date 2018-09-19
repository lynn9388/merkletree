/*
 * Copyright © 2018 Lynn <lynn9388@gmail.com>
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

package merkletree

import (
	"testing"
)

var tests = [][]byte{[]byte("http"), []byte("www"), []byte("lynn"), []byte("9388"), []byte("com")}

func TestNewMerkleTree(t *testing.T) {
	mt := NewMerkleTree(tests...)
	t.Log("\n" + mt.PrettyString(7, 2))
}

func TestMerkleTree_GetProof(t *testing.T) {
	mt := NewMerkleTree(tests[2])
	proof, err := mt.GetProof(tests[0])
	if err == nil || proof != nil || VerifyProof(tests[0], proof, mt.Root.Hash) == true {
		t.Error("failed in case 0")
	}
	proof, err = mt.GetProof(tests[2])
	if err != nil || proof != nil || VerifyProof(tests[2], proof, mt.Root.Hash) == false {
		t.Error("failed in case 1")
	}

	mt = NewMerkleTree(tests...)
	proof, err = mt.GetProof(tests[0])
	if err != nil || proof == nil || VerifyProof(tests[0], proof, mt.Root.Hash) == false {
		t.Error("failed in case 2")
	}
	proof, err = mt.GetProof(tests[2])
	if err != nil || proof == nil || VerifyProof(tests[2], proof, mt.Root.Hash) == false {
		t.Error("failed in case 3")
	}
}
