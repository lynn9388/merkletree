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
	"errors"
)

const (
	left = iota
	right
)

// MerkleNode is a node in the tree. It stores pointers to its immediate
// relationships and a hash.
type MerkleNode struct {
	Parent *MerkleNode
	Left   *MerkleNode
	Right  *MerkleNode
	Hash   string
}

// MerkleTree is the container for the tree. It stores a pointer to the
// root of the tree.
type MerkleTree struct {
	Root *MerkleNode
}

// Proof is a item in data's proof path.
type Proof struct {
	hash  string
	order int
}

// hash returns the hash value in hexadecimal of the data.
func hash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// newMerkleNode creates a new node.
func newMerkleNode(left *MerkleNode, right *MerkleNode, data []byte) *MerkleNode {
	var h string

	if left == nil && right == nil {
		h = hash(data)
	} else {
		h = hash([]byte(left.Hash + right.Hash))
	}

	node := MerkleNode{Left: left, Right: right, Hash: h}
	if left != nil {
		left.Parent = &node
	}
	if right != nil {
		right.Parent = &node
	}

	return &node
}

// NewMerkleTree builds a new Merkle tree using the data.
func NewMerkleTree(data ...Data) *MerkleTree {
	var nodes []*MerkleNode

	for _, datum := range data {
		nodes = append(nodes, newMerkleNode(nil, nil, datum.ToByte()))
	}

	for len(nodes) != 1 {
		var parents []*MerkleNode

		for i := 0; i+1 < len(nodes); i += 2 {
			node := newMerkleNode(nodes[i], nodes[i+1], []byte(nodes[i].Hash+nodes[i+1].Hash))
			parents = append(parents, node)
		}

		if len(nodes)%2 != 0 {
			parents = append(parents, nodes[len(nodes)-1])
		}

		nodes = parents
	}

	return &MerkleTree{Root: nodes[0]}
}

// findNode finds the leaf node with the same hash value.
func (mn *MerkleNode) findNode(hash string) *MerkleNode {
	if mn == nil {
		return nil
	}

	if mn.Left == nil && mn.Right == nil && mn.Hash == hash {
		return mn
	}

	node := mn.Left.findNode(hash)
	if node == nil {
		node = mn.Right.findNode(hash)
	}
	return node
}

// GetProof returns a proof list for the data. The proof list is a verify
// path which proofs the hash value of the data belongs to a leaf node.
func (mt *MerkleTree) GetProof(data Data) ([]Proof, error) {
	var ps []Proof

	node := mt.Root.findNode(hash(data.ToByte()))
	if node == nil {
		return nil, errors.New("failed to find leaf node")
	}

	for node.Hash != mt.Root.Hash {
		if node.Parent.Left == node {
			ps = append(ps, Proof{hash: node.Parent.Right.Hash, order: right})
		} else {
			ps = append(ps, Proof{hash: node.Parent.Left.Hash, order: left})
		}

		node = node.Parent
	}

	return ps, nil
}

// VerifyProof verifies if a proof is valid.
func VerifyProof(data Data, ps []Proof, root string) bool {
	h := hash(data.ToByte())

	for _, p := range ps {
		if p.order == left {
			h = hash([]byte(p.hash + h))
		} else if p.order == right {
			h = hash([]byte(h + p.hash))
		}
	}

	return h == root
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
