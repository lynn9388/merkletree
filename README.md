# Merkle Tree

[![GoDoc](https://godoc.org/github.com/lynn9388/merkletree?status.svg)](https://godoc.org/github.com/lynn9388/merkletree)
[![Build Status](https://travis-ci.com/lynn9388/merkletree.svg?branch=master)](https://travis-ci.com/lynn9388/merkletree)

A simple Merkle tree implementation.

## Install

Fist, use `go get` to install the latest version of the library:

```sh
go get -u github.com/lynn9388/merkletree
```

Next, include SupSub in your application:

```go
import "github.com/lynn9388/merkletree"
```

## Example

1. Create a new Merkle tree (The data type could be changed to any implementation of `Data`)

    ```go
    tests := []Data{StringData("lynn"), StringData("9388"), StringData("lynn9388")}
    mt := NewMerkleTree(tests...)
    ```

    The code above will create a new Merkle tree like this:

    ```text
                e46...538
                   / \
                  /   \
                 /     \
                /       \
               /         \
          a02...74d   e20...0a4
             / \
            /   \
           /     \
          /       \
         /         \
    150...cea   6d8...df4
    ```

1. Verify the data

    ```go
    proof, err := mt.GetVerifyProof(tests[2])
    if err != nill {
       log.Error(err)
    }
    if VerifyProof(tests[2], proof, mt.Root.Hash) == false {
        log.Error("failed to verify")
    }
    ```
