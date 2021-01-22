package sapling

import "github.com/gtank/jubjub"

var (
	ZcashIVKPersonality        = []byte{'Z', 'c', 'a', 's', 'h', 'i', 'v', 'k'}
	ZcashDiversifyPersonality  = []byte{'Z', 'c', 'a', 's', 'h', '_', 'g', 'd'}
	ZcashSaplingKDFPersonality = []byte("Zcash_SaplingKDF")
	ZcashPRFExpandPersonality  = []byte("Zcash_ExpandSeed")

	// TODO: I hate that this is a global, but init is expensive until better implementation.
	_jj *jubjub.Jubjub
)

func init() {
	_jj = jubjub.Curve()
}
