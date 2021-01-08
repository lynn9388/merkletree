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

// Package binary implements a binary Merkle hash tree.
package binary

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"strings"
)

const (
	left = iota
	right
)

// MerkleTree is a binary tree with hash values.
type MerkleTree struct {
	Parent *MerkleTree
	Left   *MerkleTree
	Right  *MerkleTree
	Hash   []byte
}

// AuditPath is the shortest list of additional nodes in the Merkle tree
// required to compute the root hash for that tree.
type AuditPath struct {
	Path  [][]byte
	Order []int
}

func hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func hashString(hash []byte) string {
	return hex.EncodeToString(hash)
}

// New builds a new Merkle hash tree using the data. If the date is empty
// then the hash value of the root node is the hash of an empty string.
func New(data ...[]byte) *MerkleTree {
	n := len(data)
	if n == 0 {
		return &MerkleTree{Hash: hash([]byte{})}
	}
	var subTree func([][]byte) *MerkleTree
	subTree = func(data [][]byte) *MerkleTree {
		n := len(data)

		// leaf node
		if n == 1 {
			return &MerkleTree{Hash: hash(data[0])}
		}

		parent := &MerkleTree{}
		k := int(math.Exp2(math.Ceil(math.Log2(float64(n)) - 1)))

		left := subTree(data[0:k])
		right := subTree(data[k:n])
		left.Parent = parent
		right.Parent = parent

		parent.Left = left
		parent.Right = right
		parent.Hash = hash(append(left.Hash, right.Hash...))

		return parent
	}
	return subTree(data)
}

// findleaf finds the leaf node with the same hash value. If not find then
// nil will be returned.
func (mt *MerkleTree) findLeaf(hash []byte) *MerkleTree {
	if mt == nil {
		return nil
	}

	if mt.Left == nil && mt.Right == nil && bytes.Equal(mt.Hash, hash) {
		return mt
	}

	leaf := mt.Left.findLeaf(hash)
	if leaf == nil {
		leaf = mt.Right.findLeaf(hash)
	}
	return leaf
}

// GetAuditPath returns a Merkle audit path for a leaf node. The audit path
// proofs the hash value of the data belongs to a leaf node.
func (mt *MerkleTree) GetAuditPath(data []byte) (*AuditPath, error) {
	node := mt.findLeaf(hash(data))
	if node == nil {
		return nil, errors.New("failed to find leaf node")
	}

	ap := &AuditPath{}
	for !bytes.Equal(node.Hash, mt.Hash) {
		if node.Parent.Left == node {
			ap.Path = append(ap.Path, node.Parent.Right.Hash)
			ap.Order = append(ap.Order, right)
		} else {
			ap.Path = append(ap.Path, node.Parent.Left.Hash)
			ap.Order = append(ap.Order, left)
		}
		node = node.Parent
	}
	return ap, nil
}

// IsValid checks if an audit path is valid (the data's hash is a leaf of
// the Merkle hash tree).
func (ap *AuditPath) IsValid(data []byte, rootHash []byte) bool {
	if ap == nil {
		return false
	}

	h := hash(data)
	for i, p := range ap.Path {
		if ap.Order[i] == left {
			h = hash(append(p, h...))
		} else {
			h = hash(append(h, p...))
		}
	}
	return bytes.Equal(rootHash, h)
}

// Pretty returns a format string slice for Merkle hash tree as ASCII text.
// nodeWidth is the leading number of hash value.
func (mt *MerkleTree) Pretty(nodeWidth int) []string {
	if mt == nil || nodeWidth < 1 {
		return []string{}
	}

	leftBranchNum := 0 // number of leftmost branches
	for leftRoot := mt.Left; leftRoot != nil; leftRoot = leftRoot.Left {
		leftBranchNum++
	}

	/*
	 *                   *             **            ***            ****
	 *                  / \           / \            / \            / \
	 *                 *   *         /   \          /   \          /   \
	 *                              **   **       ***   ***       /     \
	 *                                                          ****   ****
	 *
	 * nodeWidth =       1             2              3              4
	 *    offset =       1             1              2              2
	 *  branches = {1,3,7,15...} {2,4,9,19...} {2,5,11,23...} {3,6,13,27...}
	 */
	offset := int(math.Ceil(float64(nodeWidth) / 2))
	branches := make([]int, leftBranchNum) // branch lengths at different heights
	length := nodeWidth/2 + 1
	for i := range branches {
		if i == 0 {
			branches[i] = length
			continue
		}
		branches[i] = length + i + offset
		length += branches[i]
	}

	/*
	 *                                        treeHeight = 1   2   3   4
	 *
	 * nodeWidth = 1               -->   canvasMaxHeight = 1   3   7   15
	 *  branches = {1,3,7,15...}          canvasMaxWidth = 1   5   13  29
	 *
	 * nodewidth = 2               -->   canvasMaxHeight = 1   4   9   19
	 *  branches = {2,4,9,19...}          canvasMaxWidth = 2   7   17  37
	 *
	 * nodeWidth = 3               -->   canvasMaxHeight = 1   4   10  22
	 *  branches = {2,5,11,23...}         canvasMaxWidth = 3   9   21  45
	 *
	 * nodeWidth = 4               -->   canvasMaxHeight = 1   5   12  26
	 *  branches = {3,6,13,27...}         canvasMaxWidth = 4   11  25  53
	 */
	canvasMaxHeight := 1
	canvasMaxWidth := nodeWidth
	for i, b := range branches {
		if i == 0 {
			canvasMaxWidth = offset*2 - 1
		}
		canvasMaxHeight += b + 1
		canvasMaxWidth += (b + 1) * 2
	}
	canvas := make([][]byte, canvasMaxHeight)
	for i := range canvas {
		canvas[i] = make([]byte, canvasMaxWidth)
		for j := range canvas[i] {
			canvas[i][j] = ' '
		}
	}

	// limit the scope of the canvas
	maxX := 0
	minY := canvasMaxWidth - 1
	maxY := 0

	var draw func(*MerkleTree, int, int)
	draw = func(mt *MerkleTree, x int, y int) {
		copy(canvas[x][y:y+nodeWidth], hashString(mt.Hash)[0:nodeWidth])
		if mt.Parent != nil {
			if mt == mt.Parent.Left {
				if x > maxX {
					maxX = x
				}
				if y < minY {
					minY = y
				}
			} else {
				if y+nodeWidth-1 > maxY {
					maxY = y + nodeWidth - 1
				}
			}
		}

		if mt.Left == nil {
			return
		}

		rightBranchNum := 0
		for childRoot := mt.Right; childRoot.Left != nil; childRoot = childRoot.Left {
			rightBranchNum++
		}
		length := branches[rightBranchNum]

		/*
		 *            ****
		 *            / \
		 *           /   \
		 *          /     \
		 *         /       \
		 *        /         \
		 *       /           \
		 *     ****         ****
		 *     / \           / \
		 *    /   \         /   \
		 *   /     \       /     \
		 * ****   ****   ****   ****
		 */
		lx := x + 1
		ly := y + offset - 2
		if mt.Parent != nil && mt == mt.Parent.Right {
			ly += (nodeWidth + 1) % 2
		}
		for lx <= x+length {
			canvas[lx][ly] = '/'
			lx++
			ly--
		}
		draw(mt.Left, lx, ly-offset+1)

		rx := x + 1
		ry := y + offset
		if mt.Parent != nil && mt == mt.Parent.Right {
			ry += (nodeWidth + 1) % 2
		}
		for rx <= x+length {
			canvas[rx][ry] = '\\'
			rx++
			ry++
		}
		draw(mt.Right, rx, ry-int(math.Ceil(float64(nodeWidth-1)/2)))
	}
	draw(mt, 0, len(canvas[0])/2-offset+1)

	canvas = canvas[:maxX+1]
	for i := range canvas {
		canvas[i] = canvas[i][minY : maxY+1]
	}

	canvasStrinng := make([]string, len(canvas))
	for i, c := range canvas {
		canvasStrinng[i] = strings.TrimRight(string(c), " ")
	}
	return canvasStrinng
}

// PrettyString returns a format string for Merkle hash tree as ASCII text.
// nodeWidth is the leading number of hash value.
func (mt *MerkleTree) PrettyString(nodeWidth int) string {
	return strings.Join(mt.Pretty(nodeWidth), "\n")
}
