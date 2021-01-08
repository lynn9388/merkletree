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

// Package binary implements a binary Merkle Hash Tree.
package binary

import (
	"reflect"
	"testing"
)

func TestNew1(t *testing.T) {
	type args struct {
		data [][]byte
	}
	tests := []struct {
		name string
		args args
		want *MerkleTree
	}{
		{name: "empty0", want: &MerkleTree{Hash: hash([]byte{})}},
		{"empty1", args{}, &MerkleTree{Hash: hash([]byte{})}},
		{"empty2", args{[][]byte{[]byte("")}}, &MerkleTree{Hash: hash([]byte{})}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := New(tt.args.data...); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNew2(t *testing.T) {
	aHash := hash([]byte("a"))
	bHash := hash([]byte("b"))
	cHash := hash([]byte("c"))
	dHash := hash([]byte("d"))
	abHash := hash(append(aHash, bHash...))
	cdHash := hash(append(cHash, dHash...))
	abcHash := hash(append(abHash, cHash...))
	abcdHash := hash(append(abHash, cdHash...))

	type args struct {
		data [][]byte
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{"a", args{[][]byte{[]byte("a")}}, aHash},
		{"ab", args{[][]byte{[]byte("a"), []byte("b")}}, abHash},
		{"abc", args{[][]byte{[]byte("a"), []byte("b"), []byte("c")}}, abcHash},
		{"abcd", args{[][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d")}}, abcdHash},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := New(tt.args.data...).Hash; !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New().Hash = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMerkleTree_GetAuditPath(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		mt      *MerkleTree
		args    args
		want    *AuditPath
		wantErr bool
	}{
		{"a_b", New([]byte("a")), args{[]byte("b")}, nil, true},
		{"a_a", New([]byte("a")), args{[]byte("a")}, &AuditPath{}, false},
		{"ab_c", New([]byte("a"), []byte("b")), args{[]byte("c")}, nil, true},
		{"ab_a", New([]byte("a"), []byte("b")), args{[]byte("a")}, &AuditPath{[][]byte{hash([]byte("b"))}, []int{right}}, false},
		{"ab_b", New([]byte("a"), []byte("b")), args{[]byte("b")}, &AuditPath{[][]byte{hash([]byte("a"))}, []int{left}}, false},
		{"abc_b", New([]byte("a"), []byte("b"), []byte("c")), args{[]byte("b")}, &AuditPath{[][]byte{hash([]byte("a")), hash([]byte("c"))}, []int{left, right}}, false},
		{"abc_c", New([]byte("a"), []byte("b"), []byte("c")), args{[]byte("c")}, &AuditPath{[][]byte{hash(append(hash([]byte("a")), hash([]byte("b"))...))}, []int{left}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.mt.GetAuditPath(tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("MerkleTree.GetAuditPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MerkleTree.GetAuditPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuditPath_IsValid(t *testing.T) {
	type args struct {
		data     []byte
		rootHash []byte
	}
	tests := []struct {
		name string
		ap   *AuditPath
		args args
		want bool
	}{
		{"a_b", nil, args{[]byte("b"), New([]byte("a")).Hash}, false},
		{"a_a", &AuditPath{}, args{[]byte("a"), New([]byte("a")).Hash}, true},
		{"ab_c", nil, args{[]byte("c"), New([]byte("a"), []byte("b")).Hash}, false},
		{"ab_a", &AuditPath{[][]byte{hash([]byte("b"))}, []int{right}}, args{[]byte("a"), New([]byte("a"), []byte("b")).Hash}, true},
		{"ab_b", &AuditPath{[][]byte{hash([]byte("a"))}, []int{left}}, args{[]byte("b"), New([]byte("a"), []byte("b")).Hash}, true},
		{"abc_b", &AuditPath{[][]byte{hash([]byte("a")), hash([]byte("c"))}, []int{left, right}}, args{[]byte("b"), New([]byte("a"), []byte("b"), []byte("c")).Hash}, true},
		{"abc_c", &AuditPath{[][]byte{hash(append(hash([]byte("a")), hash([]byte("b"))...))}, []int{left}}, args{[]byte("c"), New([]byte("a"), []byte("b"), []byte("c")).Hash}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ap.IsValid(tt.args.data, tt.args.rootHash); got != tt.want {
				t.Errorf("AuditPath.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMerkleTree_Pretty(t *testing.T) {
	aHash := hash([]byte("a"))
	bHash := hash([]byte("b"))
	cHash := hash([]byte("c"))
	dHash := hash([]byte("d"))
	eHash := hash([]byte("e"))
	fHash := hash([]byte("f"))
	gHash := hash([]byte("g"))
	abHash := hash(append(aHash, bHash...))
	cdHash := hash(append(cHash, dHash...))
	efHash := hash(append(eHash, fHash...))
	abcHash := hash(append(abHash, cHash...))
	efgHash := hash(append(efHash, gHash...))
	abcdHash := hash(append(abHash, cdHash...))
	abcdefgHash := hash(append(abcdHash, efgHash...))

	type args struct {
		nodeWidth int
	}
	tests := []struct {
		name string
		mt   *MerkleTree
		args args
		want []string
	}{
		{"nil", nil, args{1}, []string{}},
		{"a_0", New([]byte("a")), args{0}, []string{}},
		{"a_1", New([]byte("a")), args{1}, []string{hashString(aHash)[:1]}},
		{
			"ab_2", New([]byte("a"), []byte("b")), args{2},
			[]string{
				"   " + hashString(abHash)[:2],
				"  / \\",
				" /   \\",
				hashString(aHash)[:2] + "   " + hashString(bHash)[:2],
			},
		},
		{
			"abc_3", New([]byte("a"), []byte("b"), []byte("c")), args{3},
			[]string{
				"      " + hashString(abcHash)[:3],
				"      / \\",
				"     /   \\",
				"   " + hashString(abHash)[:3] + "   " + hashString(cHash)[:3],
				"   / \\",
				"  /   \\",
				hashString(aHash)[:3] + "   " + hashString(bHash)[:3],
			},
		},
		{
			"abcd_4", New([]byte("a"), []byte("b"), []byte("c"), []byte("d")), args{4},
			[]string{
				"           " + hashString(abcdHash)[:4],
				"           / \\",
				"          /   \\",
				"         /     \\",
				"        /       \\",
				"       /         \\",
				"      /           \\",
				"    " + hashString(abHash)[:4] + "         " + hashString(cdHash)[:4],
				"    / \\           / \\",
				"   /   \\         /   \\",
				"  /     \\       /     \\",
				hashString(aHash)[:4] + "   " + hashString(bHash)[:4] + "   " + hashString(cHash)[:4] + "   " + hashString(dHash)[:4],
			},
		},
		{
			"abcdefg_2", New([]byte("a"), []byte("b"), []byte("c"), []byte("d"), []byte("e"), []byte("f"), []byte("g")), args{2},
			[]string{
				"                  " + hashString(abcdefgHash)[:2],
				"                 / \\",
				"                /   \\",
				"               /     \\",
				"              /       \\",
				"             /         \\",
				"            /           \\",
				"           /             \\",
				"          /               \\",
				"         /                 \\",
				"        " + hashString(abcdHash)[:2] + "                 " + hashString(efgHash)[:2],
				"       / \\                 / \\",
				"      /   \\               /   \\",
				"     /     \\             " + hashString(efHash)[:2] + "   " + hashString(gHash)[:2],
				"    /       \\           / \\",
				"   " + hashString(abHash)[:2] + "       " + hashString(cdHash)[:2] + "         /   \\",
				"  / \\       / \\       " + hashString(eHash)[:2] + "   " + hashString(fHash)[:2],
				" /   \\     /   \\",
				hashString(aHash)[:2] + "   " + hashString(bHash)[:2] + "   " + hashString(cHash)[:2] + "   " + hashString(dHash)[:2],
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.mt.Pretty(tt.args.nodeWidth); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MerkleTree.Pretty() = %v, want %v", got, tt.want)
			}
		})
	}
}
