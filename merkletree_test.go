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
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func ExampleNewMerkleTree() {
	tests := [][]byte{[]byte("http"), []byte("www"), []byte("lynn"), []byte("9388"), []byte("com")}
	mt := NewMerkleTree(tests...)

	fmt.Println("Merkle Tree:\n" + mt.PrettyString(6, 2))
	// Output:
	// Merkle Tree:
	//                 cf5744
	//                   / \
	//                  /   \
	//                 /     \
	//             1b5c1e  71b4f3
	//               / \
	//              /   \
	//             /     \
	//            /       \
	//           /         \
	//          /           \
	//         /             \
	//     4b2099          19ec96
	//       / \             / \
	//      /   \           /   \
	//     /     \         /     \
	// e0603c  7c2ecd  1502fe  6d86b7
}

func ExampleMerkleTree_GetProof() {
	tests := [][]byte{[]byte("http"), []byte("www"), []byte("lynn"), []byte("9388"), []byte("com")}
	mt := NewMerkleTree(tests...)
	proof, _ := mt.GetProof(tests[3])

	prettyTree := mt.PrettyString(6, 2)
	for i, p := range proof {
		hash := hex.EncodeToString(p.Hash)[:6]
		prettyTree = strings.Replace(prettyTree, hash, fmt.Sprintf("%v-%v", i, hash[:4]), 1)
	}
	fmt.Println("Proof Path:\n" + prettyTree)
	// Output:
	// Proof Path:
	//                 cf5744
	//                   / \
	//                  /   \
	//                 /     \
	//             1b5c1e  2-71b4
	//               / \
	//              /   \
	//             /     \
	//            /       \
	//           /         \
	//          /           \
	//         /             \
	//     1-4b20          19ec96
	//       / \             / \
	//      /   \           /   \
	//     /     \         /     \
	// e0603c  7c2ecd  0-1502  6d86b7
}

func TestIsProofValid(t *testing.T) {
	tests := [][]byte{[]byte("http"), []byte("www"), []byte("lynn"), []byte("9388"), []byte("com")}
	mt := NewMerkleTree(tests[2])
	proof, err := mt.GetProof(tests[0])
	if err == nil || proof != nil || IsProofValid(tests[0], proof, mt.Root.Hash) == true {
		t.Error("failed in case 0")
	}
	proof, err = mt.GetProof(tests[2])
	if err != nil || proof != nil || IsProofValid(tests[2], proof, mt.Root.Hash) == false {
		t.Error("failed in case 1")
	}

	mt = NewMerkleTree(tests...)
	proof, err = mt.GetProof(tests[0])
	if err != nil || proof == nil || IsProofValid(tests[0], proof, mt.Root.Hash) == false {
		t.Error("failed in case 2")
	}
	proof, err = mt.GetProof(tests[2])
	if err != nil || proof == nil || IsProofValid(tests[2], proof, mt.Root.Hash) == false {
		t.Error("failed in case 3")
	}
}
