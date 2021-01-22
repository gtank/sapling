package sapling

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/gtank/jubjub"
)

var keys = map[string]string{
	"pubkey":  "zs1u57078s4klas8m2aszn8uzgdrsd3yl2x7v5s7hzm3ypzckcf7a3ux2pqj00vsk94nxy7gy72498",
	"viewkey": "zxviews1qd2akd49qqqqpq8qk0nys3ypxvk7kvqk4072tmcqawpu2y53h957apqj0w5t0495uztm5uper74hqk6tl8ehtgq3yflnxy70yql0y6skeuegyuam39a62wxwk2dvya9fnjvpcclkxuxdf8s88lumz5xfzwpp0dkl5s2vmqq2rhjgyeyxj2aea0v3n7l6vtr6y7z3q3r22dafkxjnchst3ckwfzqly8kjhdqq37hlsq0qmevkfgpcyktfentzcmm37sekpvhamd9gfkseqhqpu",
}

var ivkTable = []struct {
	ak, nk, ivk string
}{
	// From https://github.com/zcash-hackworks/zcash-test-vectors/blob/master/sapling_zip32.py
	{
		ak:  "93442e5feffbff16e7217202dc7306729ffffe85af5683bce2642e3eeb5d3871",
		nk:  "dce8e7edece04b8950417f85ba57691b783c45b1a27422db1693dceb67b10106",
		ivk: "4847a130e799d3dbea36a1c16467d621fb2d80e30b3b1d1a426893415dad6601",
	},
	{
		ak:  "dc14b514d3a92594c21925af2f7765a547b30e73fa7b700ea1bff2e5efaaa88b",
		nk:  "6152eb7fdb252779ddcb95d217ea4b6fd34036e9adadb3b5c9cbeceb41ba452a",
		ivk: "155a8ee205d3872d12f8a3e639914633c23cde1f30ed5051e52130b1d0104c06",
	},
	{
		ak:  "a6c5925a0f85fa4f1e405e3a4970d0c4a4b4814438f4e9d4520e20f7fdcf3841",
		nk:  "304e305916216beb7b654d8aae50ecd188fcb384bc36c00c664f307725e2ee11",
		ivk: "a2a13c1e38b45984445803e430a683c90bb2e14d4c8692ff253a6484dd9bb504",
	},

	{
		ak:  "b185c57b509c2536c4f2d326d766c8fab25447de5375a9328d649ddabd97a6a3",
		nk:  "db88049e02d207568afc42e07db2abed500b2701c01bbff36399764b81c0664f",
		ivk: "b0a5f337232f2c3dac70c2a410fa561fc45d8cc59cda246d31c8b1715a57d900",
	},
}

func TestParseExportedViewingKey(t *testing.T) {
	_, err := NewViewingKey(keys["viewkey"])
	if err != nil {
		t.Errorf("Error decoding viewing key: %v\n", err)
	}
}

func TestDeriveIVK(t *testing.T) {
	for i, tt := range ivkTable {
		ak, _ := hex.DecodeString(tt.ak)
		nk, _ := hex.DecodeString(tt.nk)
		ivk, _ := hex.DecodeString(tt.ivk)

		result := deriveIVK(ak, nk)
		if result == nil {
			t.Error("Failed constructing blake2s instance")
		}

		if !bytes.Equal(ivk, result) {
			t.Errorf("Incorrect result for test %d", i)
		}
	}
}

var pkdTable = []struct {
	ivk, defaultD, defaultPkD string
}{
	// From https://github.com/zcash-hackworks/zcash-test-vectors/blob/master/sapling_note_encryption.py
	{
		ivk:        "b70b7cd0ed03cbdfd7ada9502ee245b13e569d54a5719d2daa0f5f1451479204",
		defaultD:   "f19d9b797e39f337445839",
		defaultPkD: "db4cd2b0aac4f7eb8ca131f16567c445a9555126d3c29f14e3d776e841ae7415",
	},
	{
		ivk:        "c518384466b26988b5109067418d192d9d6bd0d9232205d77418c240fc68a406",
		defaultD:   "aef180f6e34e354b888f81",
		defaultPkD: "a6b13ea336ddb7a67bb09a0e68e9d3cfb39210831ea3a296ba09a922060fd38b",
	},
	{
		ivk:        "471c24a3dc8730e75036c0a95f3e2f7dd1be6fb93ad29592203def3041954505",
		defaultD:   "7599f0bf9b57cd2dc299b6",
		defaultPkD: "66141739514b28f05def8a18eeee5eed4d44c6225c3c65d88dd9907708012f5a",
	},
	{
		ivk:        "636aa964bfc23ce4b1fcf7dfc99179ddc406ff55400c9295acfc14f031c72600",
		defaultD:   "1b81614f1dadea0f8d0a58",
		defaultPkD: "25eb55fccf761fc64e85a588efe6ead7832fb1f0f7a83165895bdff942925f5c",
	},
	{
		ivk:        "67fa2bf7c67d4658243c317c0cb41fd32064dfd3709fe0dcb724f14bb01a1d04",
		defaultD:   "fcfb68a40d4bc6a04b09c4",
		defaultPkD: "8b2a337f03622c24ff381d4c546f6977f90522e92fde44c9d1bb099714b9db2b",
	},
	{
		ivk:        "ea3f1d80e4307ca73b9f37801f91fba810cc41d279fc29f564235654a2178e03",
		defaultD:   "eb519882ad1e5cc654cd59",
		defaultPkD: "6b27daccb5a8207f532d10ca238f9786648a11b5966e51a2f7d89e15d29b8fdf",
	},
	{
		ivk:        "b5c5894943956933c0e5c12d311fc12cba58354b5c389edc03da55084f74c205",
		defaultD:   "bebb0fb46b8aaff89040f6",
		defaultPkD: "d11da01f0b43bdd5288d32385b8771d223493c69802544043f77cf1d71c1cb8c",
	},
	{
		ivk:        "8716c82880e13683e1bb059dd06c80c90134a96d5afca8aac2bbf68bb05f8402",
		defaultD:   "ad6e2e185a3100e3a6a8b3",
		defaultPkD: "32cb2806b882f1368b0d4a898f72c4c8f728132cc12456946e7f4cb0fb058da9",
	},
	{
		ivk:        "99c9b4b84f4b4e350f787d1cf7051d50ecc34b1a5b20d2d2139b4af1f160e001",
		defaultD:   "21c90e1c658b3efe86af58",
		defaultPkD: "9e64174b4ab981405c323b5e12475945a46d4fedf8060828041cd20e62fd2cef",
	},
	{
		ivk:        "db95ea8bd9f93d41b5ab2bebc91a38edd527083e2a6ef9f3c29702d5ff89ed00",
		defaultD:   "233c4ab886a55e3ba374c0",
		defaultPkD: "b68e9ee0c0678d7b3036931c831a25255f7ee487385a30316e15f6482b874fda",
	},
}

func TestDerivePaymentAddress(t *testing.T) {
	curve := jubjub.Curve()

	for i, tt := range pkdTable {
		ivk, _ := hex.DecodeString(tt.ivk)
		d, _ := hex.DecodeString(tt.defaultD)
		pkd, _ := hex.DecodeString(tt.defaultPkD)

		scalarIVK, _ := curve.ScalarFromBytes(ivk)
		pa, err := NewPaymentAddress(d, scalarIVK)
		if err != nil {
			t.Error(err)
			continue
		}

		compressed, _ := pa.pk_d.MarshalBinary()
		if !bytes.Equal(pkd, compressed) {
			t.Errorf("Incorrect result for test %d:\nWant: %x\nHave: %x", i, pkd, compressed)
		}
	}
}
