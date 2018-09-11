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

// Package merkletree implements a Merkle tree which is capable of storing
// arbitrary content.
package merkletree

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
)

// Data is arbitrary content stored in Merkle tree
type Data interface {
	toByte() []byte
}

// MerkleNode is a node in the tree. It stores pointers to its immediate
// relationships and a hash.
type MerkleNode struct {
	Left  *MerkleNode
	Right *MerkleNode
	Hash  string
}

// MerkleTree is the container for the tree. It stores a pointer to the
// root of the tree.
type MerkleTree struct {
	Root *MerkleNode
}

// newMerkleNode creates a new node.
func newMerkleNode(left *MerkleNode, right *MerkleNode, data []byte) *MerkleNode {
	var hash [32]byte

	if left == nil && right == nil {
		hash = sha256.Sum256(data)
	} else {
		hash = sha256.Sum256([]byte(left.Hash + right.Hash))
	}

	return &MerkleNode{Left: left, Right: right, Hash: hex.EncodeToString(hash[:])}
}

// NewMerkleTree builds a new Merkle tree using the data.
func NewMerkleTree(data []Data) *MerkleTree {
	var nodes []*MerkleNode

	for _, datum := range data {
		nodes = append(nodes, newMerkleNode(nil, nil, datum.toByte()))
	}

	for len(nodes) != 1 {
		var parents []*MerkleNode

		if len(nodes)%2 != 0 {
			nodes = append(nodes, nodes[len(nodes)-1])
		}

		for i := 0; i <= len(nodes)/2; i += 2 {
			node := newMerkleNode(nodes[i], nodes[i+1], []byte(nodes[i].Hash+nodes[i+1].Hash))
			parents = append(parents, node)
		}

		nodes = parents
	}

	return &MerkleTree{Root: nodes[0]}
}

// prettyString returns a format string to present the Merkle tree.
func (mt *MerkleTree) prettyString() string {
	var buf bytes.Buffer
	nodes := []*MerkleNode{mt.Root}

	var children []*MerkleNode
	for i := 0; i < len(nodes); i++ {
		n := nodes[i]

		if n.Left != nil {
			children = append(children, n.Left)
		}
		if n.Right != nil {
			children = append(children, n.Right)
		}

		buf.WriteString(n.Hash[:3] + "..." + n.Hash[len(n.Hash)-3:])
		buf.WriteByte(' ')

		if i == len(nodes)-1 {
			buf.WriteByte('\n')
			nodes = append(nodes, children...)
			children = children[:0]
		}
	}
	return buf.String()

}
