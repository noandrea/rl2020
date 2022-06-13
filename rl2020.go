package rl2020

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const (
	maxBitSetSize                    = 128 // max size is 128kb
	minBitSetSize                    = 16  // minimum bit set size
	TypeRevocationList2020           = "RevocationList2020"
	TypeRevocationList2020Credential = "RevocationList2020Credential"
	TypeRevocationList2020Status     = "RevocationList2020status"
	Revoke                           = true
	Reset                            = false
)

// CredentialStatus represent the status block of a credential issued using the RevocationList2020
// as a revocation method. See https://w3c-ccg.github.io/vc-status-rl-2020/#revocationlist2020status
type CredentialStatus interface {
	// Coordinates returns the credential list ID to check for revocation,
	// and the index within the list
	Coordinates() (string, int)
	// TypeDef returns the ID and the Type of the credential status itself
	TypeDef() (string, string)
}

// CredentialStatusJSON implements the CredentialStatus interface serializable to JSON
// according to the W3C draft proposal
type CredentialStatusJSON struct {
	ID                       string `json:"id"`
	Type                     string `json:"type"`
	RevocationListIndex      int    `json:"revocationListIndex"`
	RevocationListCredential string `json:"revocationListCredential"`
}

// Coordinates retun the revocation list id and credential index within the list
func (cs CredentialStatusJSON) Coordinates() (string, int) {
	return cs.RevocationListCredential, cs.RevocationListIndex
}

// TypeDef returns the credential status ID and type for correctness check
func (cs CredentialStatusJSON) TypeDef() (string, string) {
	return cs.ID, cs.Type
}

// NewCredentialStatus creates a new CredentialStatus
func NewCredentialStatus(rlCredential string, rlIndex int) CredentialStatus {
	return CredentialStatusJSON{
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

// Update - set a list of credential indexes either to revoked (action to true) or reset (action to false)
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

// BitSet return the bitset associated with the revocation list
func (rl RevocationList2020) BitSet() []byte {
	return rl.bitSet
}

// Revoke revoke a credential by it's index, that is, set the corresponding bit to 1
func (rl *RevocationList2020) Revoke(credentials ...int) (err error) {
	return rl.Update(Revoke, credentials...)
}

// Reset reset a credential status by it's index, that is, set the corresponding bit to 0
func (rl *RevocationList2020) Reset(credentials ...int) (err error) {
	return rl.Update(Reset, credentials...)
}

// IsRevoked check the value for CredentialStatus in the list. Check if the corresponding
// bit is set (1) or not (0)
func (rl RevocationList2020) IsRevoked(status CredentialStatus) (isIt bool, err error) {
	csID, csType := status.TypeDef()
	if strings.TrimSpace(csID) == "" {
		err = fmt.Errorf("credential status ID is empty")
		return
	}
	if csType != TypeRevocationList2020Status {
		err = fmt.Errorf("unsupported type %v, expected %v", rl.Type, TypeRevocationList2020Status)
		return
	}
	// check corordinates
	list, index := status.Coordinates()
	if list != rl.ID {
		err = fmt.Errorf("wrong revocation list, expected %v, got %v", rl.ID, list)
		return
	}
	if index < 0 || index >= rl.Capacity() {
		err = fmt.Errorf("credential index out of range 0-%d: %v", rl.Capacity(), list)
		return
	}

	isIt = rl.bitSet.getBit(index)
	return
}

// GetBytes returns the json serialized revocation list
func (rl RevocationList2020) GetBytes() ([]byte, error) {
	return json.Marshal(rl)
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
	// encode to base64
	s = base64.StdEncoding.EncodeToString(bb.Bytes())
	return
}

func unpack(s string) (bs bitSet, err error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return
	}
	// pass the buffer to the zlib reader
	zr, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return
	}
	if err = zr.Close(); err != nil {
		return
	}
	return io.ReadAll(zr)
}
