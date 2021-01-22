package grouphash

import (
	"fmt"

	"github.com/gtank/blake2/blake2s"
	"github.com/gtank/jubjub"
)

var (
	ErrContinue = fmt.Errorf("invalid point, keep looking")
	ErrFailed   = fmt.Errorf("FindGroupHash could not find a valid point")
)

var (
	urs = []byte("096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0")
)

type GroupHasher struct {
	curve *jubjub.Jubjub

	domain []byte
}

func NewGroupHasher(domain []byte) (*GroupHasher, error) {
	j := jubjub.Curve()

	return &GroupHasher{
		curve:  j,
		domain: domain,
	}, nil
}

func reverse(numbers []byte) {
	for i, j := 0, len(numbers)-1; i < j; i, j = i+1, j-1 {
		numbers[i], numbers[j] = numbers[j], numbers[i]
	}
}

func (hasher *GroupHasher) FindGroupHash(msg []byte) (*jubjub.Point, error) {
	for i := uint8(0); i <= 255; i++ {
		msgWithIndex := append(msg, i)
		//fmt.Printf("msg: %x\n", msgWithIndex)
		p, err := hasher.Hash(msgWithIndex)
		//fmt.Printf("p: %v\n", p)
		if err == ErrContinue {
			continue
		}
		return p, nil
	}
	return nil, ErrFailed
}

func (hasher *GroupHasher) Hash(msg []byte) (*jubjub.Point, error) {
	blake, err := blake2s.NewDigest(nil, nil, hasher.domain, 32)
	if err != nil {
		return nil, err
	}
	_, err = blake.Write(urs)
	if err != nil {
		return nil, err
	}

	_, err = blake.Write(msg)
	if err != nil {
		return nil, err
	}

	blakeHashBytes := blake.Sum(nil)

	p, err := hasher.curve.Decompress(blakeHashBytes)
	if err != nil {
		return nil, err
	}

	p = p.MulByCofactor()
	if !p.IsOnCurve() || p.IsIdentity() {
		return nil, ErrContinue
	}

	return p, nil
}
