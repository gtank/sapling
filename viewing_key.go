package sapling

import (
	"errors"

	"github.com/gtank/blake2/blake2s"
	"github.com/gtank/bytecrypto"
	"github.com/gtank/zech32"
)

var (
	ErrKeyType = errors.New("not a sapling viewing key")
)

// This is the format zcashd exports viewing keys in
type saplingExtendedFullViewingKey struct {
	depth        uint8      `json:"depth"`
	parentFVKTag uint32     `json:"parent_fvk_tag"`
	childIndex   uint32     `json:"child_index"`
	chaincode    []byte     `json:"chaincode"`
	vk           ViewingKey `json:"full_viewing_key"`
	dk           []byte     `json:"dk"`
}

// ViewingKey is a Sapling full viewing key, stored in raw bytes.
type ViewingKey struct {
	ak  []byte `json:"ak"`
	nk  []byte `json:"nk"`
	ovk []byte `json:"ovk"`
	ivk []byte `json:"ivk,omitempty"`
}

const SaplingExtendedFullViewingKeyLength = 169

// Ivk derives the incoming viewing key and returns a new copy.
func (vk *ViewingKey) Ivk() []byte {
	return deriveIVK(vk.ak, vk.nk)
}

// Ovk returns a new copy of the outgoing view key.
func (vk *ViewingKey) Ovk() []byte {
	out := make([]byte, len(vk.ovk))
	copy(out, vk.ovk)
	return out
}

func deriveIVK(ak, nk []byte) []byte {
	blake, err := blake2s.NewDigest(nil, nil, ZcashIVKPersonality, 32)
	if err != nil {
		panic("couldn't initialize blake2s!")
	}

	blake.Write(ak)
	blake.Write(nk)

	ivk := blake.Sum(nil)

	// Zero the top five bits so ivk can be interpreted as a Jubjub scalar
	ivk[31] &= 0b0000_0111

	return ivk
}

// NewViewingKey decodes a bech32-encoded full viewing key of the type zcashd exports.
func NewViewingKey(encoded string) (*ViewingKey, error) {
	hrp, decoded, err := zech32.Decode(encoded)
	if err != nil {
		return nil, err
	}

	if hrp != "zxviews" {
		return nil, ErrKeyType
	}

	data, err := zech32.ConvertBits(decoded, 5, 8, false)
	if err != nil {
		return nil, err
	}

	evk := &saplingExtendedFullViewingKey{}
	err = evk.UnmarshalBinary(data)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (evk *saplingExtendedFullViewingKey) UnmarshalBinary(data []byte) error {
	if len(data) != SaplingExtendedFullViewingKeyLength {
		return errors.New("data is wrong size for EFVK")
	}

	in := bytecrypto.String(data)

	if !in.ReadUint8(&evk.depth) {
		return errors.New("could not read depth byte")
	}

	if !in.ReadUint32(&evk.parentFVKTag) {
		return errors.New("could not read parent FVK tag")
	}

	if !in.ReadUint32(&evk.childIndex) {
		return errors.New("could not read child index")
	}

	if !in.ReadBytes(&evk.chaincode, 32) {
		return errors.New("could not read chaincode")
	}

	vk := &ViewingKey{}

	if !in.ReadBytes(&vk.ak, 32) {
		return errors.New("could not read ak")
	}

	if !in.ReadBytes(&vk.nk, 32) {
		return errors.New("could not read ak")
	}

	if !in.ReadBytes(&vk.ovk, 32) {
		return errors.New("could not read ovk")
	}

	evk.vk = *vk

	if !in.ReadBytes(&evk.dk, 32) {
		return errors.New("could not read dk")
	}

	if !in.Empty() {
		return errors.New("leftover bytes in efvk")
	}

	return nil
}
