package sapling

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/gtank/jubjub"
)

type noteTest struct {
	Ovk           []byte // 32
	Ivk           []byte // 32
	Default_d     []byte // 11
	Default_pk_d  []byte // 32
	V             uint64
	Rcm           []byte // 32
	Memo          []byte // 512
	Cv            []byte // 32
	Cmu           []byte // 32
	Esk           []byte // 32
	Epk           []byte // 32
	Shared_secret []byte // 32
	K_enc         []byte // 32
	P_enc         []byte // 564
	C_enc         []byte // 580
	Ock           []byte // 32
	Op            []byte // 64
	C_out         []byte // 80
}

func TestSaplingNoteDecryption(t *testing.T) {
	testdata, err := ioutil.ReadFile("testdata/sapling_note_encryption.json")
	if err != nil {
		t.Fatal("couldn't load sapling tests")
	}

	var table []noteTest
	err = json.Unmarshal(testdata, &table)
	if err != nil {
		t.Skip("couldn't parse sapling tests")
	}

	jj := jubjub.Curve()

	for i, tt := range table {
		ivk, err := jj.ScalarFromBytes(tt.Ivk)
		if err != nil {
			t.Fatalf("Failed to parse `ivk` %d: %v", i, err)
		}

		epk, err := jj.Decompress(tt.Epk)
		if err != nil {
			t.Errorf("Failed to decompress `epk` %d: %v", i, err)
		}

		cmu := jj.FeFromBytes(tt.Cmu) // TODO must check this for consistency

		n, err := DecryptNote(ivk, epk, cmu, tt.C_enc)
		if err != nil {
			t.Fatalf("Failed to decrypt note %d: %v", i, err)
		}

		assertEq := func(x, y interface{}, err string) {
			if reflect.TypeOf(x) != reflect.TypeOf(y) {
				t.Fatalf("assertEq type mismatch: %s", err)
			}

			switch x.(type) {
			case []byte:
				if bytes.Equal(x.([]byte), y.([]byte)) {
					return
				}
			}

			if x == y {
				return
			}

			t.Fatalf("assertEq failed: %s", err)
		}

		assertEq(n.value, tt.V, "note value mismatch")
		assertEq(n.memo, tt.Memo, "memo mismatch")
		assertEq(n.rcm.ToBytes(), tt.Rcm, "rcm mismatch")
		assertEq(n.recipient.pk_d.Compress(), tt.Default_pk_d, "recipient pk_d mismatch")
	}
}
