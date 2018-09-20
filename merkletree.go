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
	"strings"
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
	Hash  string
	Order int
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
func NewMerkleTree(data ...[]byte) *MerkleTree {
	var nodes []*MerkleNode

	for _, datum := range data {
		nodes = append(nodes, newMerkleNode(nil, nil, datum))
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
func (mt *MerkleTree) GetProof(data []byte) ([]Proof, error) {
	var ps []Proof

	node := mt.Root.findNode(hash(data))
	if node == nil {
		return nil, errors.New("failed to find leaf node")
	}

	for node.Hash != mt.Root.Hash {
		if node.Parent.Left == node {
			ps = append(ps, Proof{Hash: node.Parent.Right.Hash, Order: right})
		} else {
			ps = append(ps, Proof{Hash: node.Parent.Left.Hash, Order: left})
		}

		node = node.Parent
	}

	return ps, nil
}

// VerifyProof verifies if a proof is valid.
func VerifyProof(data []byte, ps []Proof, root string) bool {
	h := hash(data)

	for _, p := range ps {
		if p.Order == left {
			h = hash([]byte(p.Hash + h))
		} else if p.Order == right {
			h = hash([]byte(h + p.Hash))
		}
	}

	return h == root
}

// PrettyString returns a format string to present the Merkle tree.
// hashWidth is the leading number of hash, leafGap is the gap between
// leaves.
func (mt *MerkleTree) PrettyString(hashWidth int, leafGap int) string {
	nodes := [][]*MerkleNode{{mt.Root}}

	for i := 0; i < len(nodes); i++ {
		var ns []*MerkleNode
		for j := 0; j < len(nodes[i]); j++ {
			node := nodes[i][j]
			if node.Left != nil {
				ns = append(ns, node.Left)
			}
			if node.Right != nil {
				ns = append(ns, node.Right)
			}
		}
		if len(ns) > 0 {
			nodes = append(nodes, ns)
		}
	}

	x := hashWidth
	y := leafGap
	height := len(nodes)
	spaces := make([][]int, height)
	for i := height - 1; i >= 0; i-- {
		for j := 0; j < len(nodes[i]); j++ {
			if nodes[i][j].Left == nil && nodes[i][j].Right == nil {
				if i == height-1 && j == 0 {
					spaces[i] = append(spaces[i], 0)
				} else {
					spaces[i] = append(spaces[i], spaces[i][j-1]+x+y)
				}
			} else {
				spaces[i] = append(spaces[i], (spaces[i+1][2*j]+spaces[i+1][2*j+1])/2)
			}
		}
	}

	var buff bytes.Buffer
	for i, level := range nodes {
		for j, node := range level {
			n := spaces[i][j]
			if j > 0 {
				n -= spaces[i][j-1] + x
			}
			buff.WriteString(strings.Repeat(" ", n))
			buff.WriteString(node.Hash[:x])
		}
		buff.WriteString("\n")

		if level[0].Left != nil && level[0].Right != nil {
			lineGap := spaces[i][0] - spaces[i+1][0] - 1
			nodeGap := (spaces[i+1][1] - spaces[i+1][0] - 2*lineGap) / 2
			lines := make([]string, lineGap)
			for i := 0; i < lineGap; i++ {
				lines[i] = strings.Repeat(" ", lineGap-i-1) + "/" +
					strings.Repeat(" ", 2*i+nodeGap) + "\\" +
					strings.Repeat(" ", lineGap-i-1)
			}

			for m, node := range nodes[i] {
				if m != 0 && node.Left != nil && node.Right != nil {
					for n, line := range lines {
						lines[n] = line + strings.Repeat(" ", spaces[i][m]-spaces[i][m-1]-len(line)) + line
					}
				}
			}

			for _, line := range lines {
				buff.WriteString(strings.Repeat(" ", spaces[i+1][0]+x/2+1) + strings.TrimRight(line, " ") + "\n")
			}
		}
	}
	return strings.TrimRight(buff.String(), "\n")
}
