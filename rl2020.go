package rl2020

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	maxBitSetSize                = 128 // max size is 128kb
	minBitSetSize                = 16  // minimum bit set size
	TypeRevocationList2020       = "RevocationList2020"
	TypeRevocationList2020Status = "RevocationList2020status"
	Revoke                       = true
	Reset                        = false
)

// CredentialStatus represent the status block of a credential issued using the RevocationList2020
// as a revocation method. See https://w3c-ccg.github.io/vc-status-rl-2020/#revocationlist2020status
type CredentialStatus struct {
	ID                       string `json:"id"`
	Type                     string `json:"type"`
	RevocationListIndex      int    `json:"revocationListIndex"`
	RevocationListCredential string `json:"revocationListCredential"`
}

// NewCredentialStatus creates a new CredentialStatus
func NewCredentialStatus(rlCredential string, rlIndex int) CredentialStatus {
	return CredentialStatus{
		ID:                       fmt.Sprint(rlCredential, "/", rlIndex),
		Type:                     TypeRevocationList2020Status,
		RevocationListCredential: rlCredential,
		RevocationListIndex:      rlIndex,
	}
}

// RevocationList2020 represent the credential subject of a RevocationList2020 credential as
// defined in https://w3c-ccg.github.io/vc-status-rl-2020/
type RevocationList2020 struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	EncodedList string `json:"encodedList"`
	bitSet      bitSet `json:"-"`
}

// NewRevocationList creates a new revocation lists of the specified size
func NewRevocationList(id string, kbSize int) (rl RevocationList2020, err error) {
	if kbSize > maxBitSetSize || kbSize < minBitSetSize {
		err = fmt.Errorf("size must be between %d and %d, got %d", minBitSetSize, maxBitSetSize, kbSize)
		return
	}
	bs := newBitSet(kbSize)
	ebs, err := pack(bs)
	if err != nil {
		return
	}
	rl = RevocationList2020{
		ID:          id,
		Type:        TypeRevocationList2020,
		EncodedList: ebs,
		bitSet:      bs,
	}
	return
}

// NewRevocationListFromJSON parse
func NewRevocationListFromJSON(data []byte) (rl RevocationList2020, err error) {
	if err = json.Unmarshal(data, &rl); err != nil {
		return
	}
	if strings.TrimSpace(rl.ID) == "" {
		err = fmt.Errorf("revocation list has no ID")
		return
	}
	if rl.Type != TypeRevocationList2020 {
		err = fmt.Errorf("unsupported type %v, expected %v", rl.Type, TypeRevocationList2020)
		return
	}
	// decode the revocation list to a bit set
	if rl.bitSet, err = unpack(rl.EncodedList); err != nil {
		return
	}
	// check the bitset size
	if rl.Size() > maxBitSetSize || rl.Size() < minBitSetSize {
		err = fmt.Errorf("size must be between %d and %d, got %d", minBitSetSize, maxBitSetSize, rl.Size())
		return
	}
	return
}

// Capacity returns the number of credentials that can be handled by this revocation list
func (rl RevocationList2020) Capacity() int {
	return rl.bitSet.len()
}

// Size returns the size in KB of the revocation list
func (rl RevocationList2020) Size() int {
	return rl.bitSet.size()
}

func (rl *RevocationList2020) Update(action bool, indexes ...int) (err error) {
	for _, i := range indexes {
		if i < 0 || i >= rl.Capacity() {
			err = fmt.Errorf("credential index out of range 0-%d: %v", rl.Capacity(), i)
			return
		}
	}
	for _, ci := range indexes {
		rl.bitSet.setBit(ci, action)
	}
	rl.EncodedList, err = pack(rl.bitSet)
	return
}

func (rl *RevocationList2020) Revoke(credentials ...int) (err error) {
	return rl.Update(Revoke, credentials...)
}

func (rl *RevocationList2020) Reset(credentials ...int) (err error) {
	return rl.Update(Reset, credentials...)
}

func (rl RevocationList2020) IsRevoked(status CredentialStatus) (isIt bool, err error) {
	if status.Type != TypeRevocationList2020Status {
		err = fmt.Errorf("unsupported type %v, expected %v", rl.Type, TypeRevocationList2020Status)
		return
	}
	if status.RevocationListCredential != rl.ID {
		err = fmt.Errorf("wrong revocation list, expected %v, got %v", rl.ID, status.RevocationListCredential)
		return
	}
	if status.RevocationListIndex < 0 || status.RevocationListIndex >= rl.Capacity() {
		err = fmt.Errorf("credential index out of range 0-%d: %v", rl.Capacity(), status.RevocationListCredential)
		return
	}

	isIt = rl.bitSet.getBit(status.RevocationListIndex)
	return
}

type bitSet []uint8

func newBitSet(kbSize int) (bs bitSet) {
	return make([]uint8, kbSize*1024)
}

func (bs bitSet) getBit(index int) bool {
	pos := index / 8
	j := index % 8
	return (bs[pos] & (uint8(1) << j)) != 0
}
func (bs bitSet) setBit(index int, value bool) {
	pos := index / 8
	j := uint(index % 8)
	if value {
		bs[pos] |= uint8(1) << j
	} else {
		bs[pos] &= ^(uint8(1) << j)
	}
}

func (bs bitSet) len() int {
	return 8 * len(bs)
}

// size returns the size of the bitset int kb
func (bs bitSet) size() int {
	return len(bs) / 1024
}

func pack(set bitSet) (s string, err error) {
	var bb bytes.Buffer
	// fist compress the data
	w := zlib.NewWriter(&bb)
	if _, err = w.Write(set); err != nil {
		return
	}
	if err = w.Close(); err != nil {
		return
	}
	// reset the buffer
	zData := bb.Bytes()
	bb.Reset()
	// encode to base64
	bw := base64.NewEncoder(base64.StdEncoding, &bb)
	defer bw.Close()
	if _, err = bw.Write(zData); err != nil {
		return
	}
	//
	s = bb.String()
	return
}

func unpack(s string) (bs bitSet, err error) {
	var bb bytes.Buffer
	if _, err = bb.WriteString(s); err != nil {
		return
	}
	bw := base64.NewDecoder(base64.StdEncoding, &bb)
	// decode to bytes
	var zbs []byte
	bw.Read(zbs)
	// reset the byte buffer and write the decoded bytes
	bb.Reset()
	if _, err = bb.Write(zbs); err != nil {
		return
	}
	// pass the buffer to the zlib reader
	r, err := zlib.NewReader(&bb)
	if err != nil {
		return
	}
	defer r.Close()
	if _, err = r.Read(bs); err != nil {
		return
	}
	return
}
