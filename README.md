# Merkle Tree

[![GoDoc](https://godoc.org/github.com/lynn9388/merkletree?status.svg)](https://godoc.org/github.com/lynn9388/merkletree)
[![Build Status](https://travis-ci.com/lynn9388/merkletree.svg?branch=master)](https://travis-ci.com/lynn9388/merkletree)

A simple Merkle tree implementation.

## Install

Fist, use `go get` to install the latest version of the library:

```sh
go get -u github.com/lynn9388/merkletree
```

Next, include this package in your application:

```go
import "github.com/lynn9388/merkletree"
```

## Example

1. Create a new Merkle tree and print it with [PrettyString](https://godoc.org/github.com/lynn9388/merkletree#MerkleTree.PrettyString):

    ```go
    tests := [][]byte{[]byte("http"), []byte("www"), []byte("lynn"), []byte("9388"), []byte("com")}
	mt := NewMerkleTree(tests...)
	prettyTree := mt.PrettyString(6, 2)
	fmt.Println("Merkle Tree:\n" + prettyTree)

	proofs, _ := mt.GetProof(tests[3])
	for i, proof := range proofs {
		hash := proof.Hash[:5]
		prettyTree = strings.Replace(prettyTree, hash, fmt.Sprintf("%v-%v", i, hash), 1)
	}
	fmt.Println("Proof Path:\n" + prettyTree)
    ```

    Output:

    ```text
    Merkle Tree:
                    fda22a
                      / \
                     /   \
                    /     \
                fdc64a  71b4f3
                  / \
                 /   \
                /     \
               /       \
              /         \
             /           \
            /             \
        eea865          a02c46
          / \             / \
         /   \           /   \
        /     \         /     \
    e0603c  7c2ecd  1502fe  6d86b7
    Proof Path:
                    fda22a
                      / \
                     /   \
                    /     \
                fdc64a  2-71b4f3
                  / \
                 /   \
                /     \
               /       \
              /         \
             /           \
            /             \
        1-eea865          a02c46
          / \             / \
         /   \           /   \
        /     \         /     \
    e0603c  7c2ecd  0-1502fe  6d86b7
    ```

2. Verify the hash of data is in the Merkle tree with [GetProof](https://godoc.org/github.com/lynn9388/merkletree#MerkleTree.GetProof) and [VerifyProof](https://godoc.org/github.com/lynn9388/merkletree#VerifyProof):

    ```go
    proof, err := mt.GetProof(tests[2])
    if err != nill {
       log.Error(err)
    }
    if VerifyProof(tests[2], proof, mt.Root.Hash) == false {
        log.Error("failed to verify")
    }
    ```
