# Merkle Tree

[![Build Status](https://travis-ci.com/lynn9388/merkletree.svg?branch=master)](https://travis-ci.com/lynn9388/merkletree)
[![Go Report Card](https://goreportcard.com/badge/github.com/lynn9388/merkletree)](https://goreportcard.com/report/github.com/lynn9388/merkletree)
[![Go Reference](https://pkg.go.dev/badge/github.com/lynn9388/merkletree.svg)](https://pkg.go.dev/github.com/lynn9388/merkletree)

This module provides the following Merkle Hash Trees (MHT):

- Binary Merkle Hash Tree

## Example Usage

### Binary Merkle Hash Tree

You can run the following code in the [Playground](https://play.golang.org/p/zGOWqyexwNN).

```go
package main

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/lynn9388/merkletree/binary"
)

func main() {
	// create a new binary Merkle hash tree with some data
	mt := binary.New([]byte("a"), []byte("b"), []byte("c"), []byte("d"), []byte("e"), []byte("f"), []byte("g"))

	// print the tree
	prettyTree := mt.PrettyString(4)
	fmt.Printf("Merkle Hash Tree:\n%v\n\n", prettyTree)

	// get the audit path for data
	ap, _ := mt.GetAuditPath([]byte("c"))

	// print the audit path
	for i, v := range ap.Path {
		hashString := hex.EncodeToString(v)[:4]
		prettyTree = strings.Replace(prettyTree, hashString, fmt.Sprintf("%v-%v", i, hashString[:2]), 1)
	}
	fmt.Printf("Audit Path:\n%v\n", prettyTree)

	// verify the audit path
	if ap.IsValid([]byte("c"), mt.Hash) == false {
		fmt.Println("failed to verify")
	}
}
```

Result:

```
Merkle Hash Tree:
                         e2a8
                         / \
                        /   \
                       /     \
                      /       \
                     /         \
                    /           \
                   /             \
                  /               \
                 /                 \
                /                   \
               /                     \
              /                       \
             /                         \
           14ed                       7bd2
           / \                         / \
          /   \                       /   \
         /     \                     /     \
        /       \                  04fa   cd0a
       /         \                 / \
      /           \               /   \
    e5a0         bffe            /     \
    / \           / \          3f79   252f
   /   \         /   \
  /     \       /     \
ca97   3e23   2e7d   18ac

Audit Path:
                         e2a8
                         / \
                        /   \
                       /     \
                      /       \
                     /         \
                    /           \
                   /             \
                  /               \
                 /                 \
                /                   \
               /                     \
              /                       \
             /                         \
           14ed                       2-7b
           / \                         / \
          /   \                       /   \
         /     \                     /     \
        /       \                  04fa   cd0a
       /         \                 / \
      /           \               /   \
    1-e5         bffe            /     \
    / \           / \          3f79   252f
   /   \         /   \
  /     \       /     \
ca97   3e23   2e7d   0-18
``
