package sapling

import (
	"github.com/gtank/jubjub"
	"github.com/gtank/sapling/grouphash"
)

// findBasepoint returns the diversified basepoint `g_d` for the given diversifier or an invalid point error.
func findBasepoint(d []byte) (*jubjub.Point, error) {
	// TODO: Fix API. This cannot ever return an error.
	gh, _ := grouphash.NewGroupHasher(ZcashDiversifyPersonality)
	return gh.Hash(d)
}

type PaymentAddress struct {
	d    []byte
	g_d  *jubjub.Point
	pk_d *jubjub.Point
}

// NewPaymentAddress returns the PaymentAddress for this incoming viewing key and diversifier.
func NewPaymentAddress(d []byte, ivk *jubjub.Scalar) (*PaymentAddress, error) {
	g_d, err := findBasepoint(d)
	if err != nil {
		// grouphash.ErrFailed
		return nil, err
	}

	pk_d, err := _jj.ScalarMult(ivk, g_d)
	if err != nil {
		// jubjub.ErrInvalidPoint
		return nil, err
	}

	return &PaymentAddress{
		d:    d,
		g_d:  g_d,
		pk_d: pk_d,
	}, nil
}
