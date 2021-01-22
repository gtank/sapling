package sapling

import (
	"encoding/binary"
	"errors"

	"github.com/gtank/blake2/blake2b"
	"github.com/gtank/bytecrypto"
	"github.com/gtank/jubjub"
	"golang.org/x/crypto/chacha20poly1305"
)

// Note is a decrypted Sapling note
type Note struct {
	// At the moment (Canopy/ZIP212) this indicates expected rcm/rseed semantics.
	// If version == 0x01, `rseed` is actually `rcm`, a Jubjub scalar.
	// If version == 0x02, `rseed` is bytes used to derive `rcm` and `esk`.
	version NoteVersion `json:"-"`

	// The value of the note
	value uint64 `json:"value"`

	// The note's recipient
	recipient *PaymentAddress `json:"recipient"`

	// The intepretation and presence of rcm/rseed depends on the age of the note.
	// Prior to ZIP 212 it was a Jubjub scalar used directly as the randomness
	// `rcm` for the note commitment. After ZIP 212 it is a 32-byte seed used
	// to derive both the note commitment randomness and the ephemeral
	// secret key `esk`.

	rcm   *jubjub.Scalar `json:"-"`
	rseed []byte         `json:"-"`

	// The note's memo field
	memo []byte `json:"memo"`
}

// NoteVersion indicates what type of Sapling note plaintext we're expecting
type NoteVersion byte

const (
	// BeforeZIP212 is the NoteVersion from before Canopy activates
	BeforeZIP212 NoteVersion = 0x01
	// AfterZIP212 is the NoteVersion from after Canopy activates
	AfterZIP212 NoteVersion = 0x02
)

type OutputDescription struct {
	cv            []byte // 32
	cmu           []byte // 32
	epk           []byte // 32
	encCiphertext []byte // 580
	outCiphertext []byte // 80
	zkp           []byte // 192
}

const OutputDescriptionLength = 948

// UnmarshalBinary unpacks an OutputDescription struct to its constituent
// elements but does no further interpretation.
func (od *OutputDescription) UnmarshalBinary(data []byte) error {
	if len(data) != OutputDescriptionLength {
		return errors.New("data is wrong size to be output description")
	}

	in := bytecrypto.String(data)

	if !in.ReadBytes(&od.cv, 32) {
		return errors.New("couldn't read cv")
	}

	if !in.ReadBytes(&od.cmu, 32) {
		return errors.New("couldn't read cmu")
	}

	if !in.ReadBytes(&od.epk, 32) {
		return errors.New("couldn't read epk")
	}

	if !in.ReadBytes(&od.encCiphertext, 580) {
		return errors.New("couldn't read the encrypted note ciphertext")
	}

	if !in.ReadBytes(&od.outCiphertext, 80) {
		return errors.New("couldn't read the output ciphertext")
	}

	if !in.ReadBytes(&od.zkp, 192) {
		return errors.New("couldn't read the proof")
	}

	if !in.Empty() {
		return errors.New("leftover bytes in output description")
	}

	return nil
}

func DecryptNote(ivk *jubjub.Scalar, epk *jubjub.Point, cmu *jubjub.FieldElement, ciphertext []byte) (*Note, error) {
	sharedSecret := saplingKeyAgreement(ivk, epk)
	key := saplingKDF(sharedSecret, epk)

	nonce := make([]byte, 12) // 96 bits of zero
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	note := &Note{
		version: NoteVersion(plaintext[0]),
	}

	// The diversifier
	d := make([]byte, 11)
	copy(d, plaintext[1:12])

	note.recipient, err = NewPaymentAddress(d, ivk)
	if err != nil {
		return nil, err
	}

	// The value of the note
	note.value = binary.LittleEndian.Uint64(plaintext[12:20])

	switch note.version {
	case BeforeZIP212:
		note.rcm, err = _jj.ScalarFromBytes(plaintext[20:52])
		if err != nil && err != jubjub.ErrScalarOutOfRange {
			// TODO: the Scalar type allows the group order to be represented w/o error,
			// but Spec says rcm >= r_{J} should fail. Change Scalar or add check here?
			return nil, errors.New("received non-canonical rcm repr")
		}
	case AfterZIP212:
		note.rseed = make([]byte, 32)
		copy(note.rseed, plaintext[20:52])

		note.rcm, _ = _jj.ScalarFromBytes(prfExpand(note.rseed, prfExpandRcm))

		esk, _ := _jj.ScalarFromBytes(prfExpand(note.rseed, prfExpandEsk))
		computedEPK, _ := _jj.ScalarMult(esk, note.recipient.g_d)

		if !computedEPK.Equals(epk) {
			return nil, errors.New("computed epk didn't match supplied epk")
		}
	default:
		return nil, errors.New("received a non-standard note plaintext")
	}

	note.memo = make([]byte, 512)
	copy(note.memo, plaintext[52:512])

	// TODO compare computed cmu to supplied cmu

	return note, nil
}

func saplingKeyAgreement(s *jubjub.Scalar, P *jubjub.Point) *jubjub.Point {
	p, err := _jj.ScalarMult(s, P)
	if err != nil {
		// TODO handle better
		panic("Tried to do key agreement with an off-curve point!")
	}

	return p.MulByCofactor()
}

func saplingKDF(secret, epk *jubjub.Point) []byte {
	digest, err := blake2b.NewDigest(nil, nil, ZcashSaplingKDFPersonality, 32)
	if err != nil {
		panic("Couldn't construct KDF^{Sapling}")
	}
	digest.Write(secret.Compress())
	digest.Write(epk.Compress())
	return digest.Sum(nil)
}

type prfExpandPurpose []byte

var (
	prfExpandRcm = []byte{0x04}
	prfExpandEsk = []byte{0x05}
)

func prfExpand(seed []byte, purpose prfExpandPurpose) []byte {
	digest, err := blake2b.NewDigest(nil, nil, ZcashPRFExpandPersonality, 64)
	if err != nil {
		panic("Couldn't construct PRF^{Expand}")
	}
	digest.Write(seed)
	digest.Write(purpose)
	return digest.Sum(nil)
}
