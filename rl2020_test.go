package rl2020

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewRevocationList(t *testing.T) {
	type args struct {
		id     string
		kbSize int
	}
	tests := []struct {
		name    string
		args    args
		wantRl  func() *RevocationList2020
		wantErr error
	}{
		{
			"PASS: can generate",
			args{
				id:     "test-1",
				kbSize: 16,
			},
			func() *RevocationList2020 {
				return &RevocationList2020{
					"test-1",
					TypeRevocationList2020,
					"eJzswDEBAAAAwiD7pzbGHhgAAAAAAAAAAAAAAAAAAACQewAAAP//QAAA",
					make([]byte, 16384),
				}
			},
			nil,
		},
		{
			"FAIL: size too small",
			args{
				id:     "test-1",
				kbSize: 1,
			},
			func() *RevocationList2020 {
				return nil
			},
			fmt.Errorf("size must be between %d and %d, got %d", minBitSetSize, maxBitSetSize, 1),
		},
		{
			"FAIL: size too big",
			args{
				id:     "test-1",
				kbSize: 129,
			},
			func() *RevocationList2020 {
				return nil
			},
			fmt.Errorf("size must be between %d and %d, got %d", minBitSetSize, maxBitSetSize, 129),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRl, err := NewRevocationList(tt.args.id, tt.args.kbSize)
			if tt.wantErr == nil {
				assert.NoError(t, err)
				assert.Equal(t, *tt.wantRl(), gotRl)
			} else {
				assert.Error(t, err)
				assert.Equal(t, tt.wantErr.Error(), err.Error())
			}
		})
	}
}

func TestRevocationList2020_Update(t *testing.T) {

	cs := func(idx int, cred string) CredentialStatus {
		return CredentialStatus{
			ID:                       fmt.Sprint(cred, "/", idx),
			Type:                     TypeRevocationList2020Status,
			RevocationListIndex:      idx,
			RevocationListCredential: cred,
		}
	}

	type args struct {
		revoke []int
		reset  []int
	}
	tests := []struct {
		name     string
		rlFn     func() RevocationList2020
		args     args
		expected map[CredentialStatus]bool
		wantErr  error
	}{
		{
			"PASS: revocations",
			func() RevocationList2020 {
				rl, _ := NewRevocationList("c0", 16)
				return rl
			},
			args{
				[]int{10, 1231, 1, 31312},
				[]int{10, 54312, 12313, 122311},
			},
			map[CredentialStatus]bool{
				cs(10, "c0"):     false,
				cs(1, "c0"):      true,
				cs(2, "c0"):      false,
				cs(1231, "c0"):   true,
				cs(31312, "c0"):  true,
				cs(54312, "c0"):  false,
				cs(12313, "c0"):  false,
				cs(122311, "c0"): false,
			},
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rl := tt.rlFn()
			// revocation
			if err := rl.Revoke(tt.args.revoke...); tt.wantErr == nil {
				assert.NoError(t, err)
			} else {
				assert.Equal(t, tt.wantErr.Error(), err.Error())
			}
			// resets
			if err := rl.Reset(tt.args.reset...); tt.wantErr == nil {
				assert.NoError(t, err)
			} else {
				assert.Equal(t, tt.wantErr.Error(), err.Error())
			}
			// verification
			for cs, status := range tt.expected {
				if isIt, err := rl.IsRevoked(cs); tt.wantErr == nil {
					assert.NoError(t, err)
					assert.Equal(t, status, isIt)
				} else {
					assert.Equal(t, tt.wantErr.Error(), err.Error())
				}
			}
		})
	}
}
