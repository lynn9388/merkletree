# Merkle Tree

[![GoDoc](https://godoc.org/github.com/lynn9388/merkletree?status.svg)](https://godoc.org/github.com/lynn9388/merkletree)
[![Go Report Card](https://goreportcard.com/badge/github.com/lynn9388/merkletree)](https://goreportcard.com/report/github.com/lynn9388/merkletree)
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

## Usage

1. Create a new Merkle tree and print it with [PrettyString](https://godoc.org/github.com/lynn9388/merkletree#MerkleTree.PrettyString):

    ```go
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
    ```

1. Get a proof of hash of data is in the Merkle tree with [GetProof](https://godoc.org/github.com/lynn9388/merkletree#MerkleTree.GetProof):

    ```go
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
    ```

1. Verify the proofs with [IsProofValid](https://godoc.org/github.com/lynn9388/merkletree#IsProofValid):

    ```go
    if IsProofValid(tests[2], proof, mt.Root.Hash) == false {
        fmt.Println("failed to verify")
    }
    ```
