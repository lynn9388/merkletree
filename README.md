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
    fmt.Print(mt.PrettyString(5, 2))
    ```

    Output:

    ```text
                 fda22
                   /\
                  /  \
                 /    \
              fdc64  71b4f
                /\
               /  \
              /    \
             /      \
            /        \
           /          \
          /            \
       eea86         a02c4
         /\            /\
        /  \          /  \
       /    \        /    \
    e0603  7c2ec  1502f  6d86b
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
