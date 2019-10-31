//Author: xingchang@fusion.org
package lib 

import (
	"github.com/fusion/go-fusion/internal/common/math/random"
	"github.com/fusion/go-fusion/crypto/sha3"
	"math/big"
)

type Commitment struct {
	C *big.Int
	D []*big.Int
}

//var commitment = new(Commitment)

func (commitment *Commitment) Commit(secrets ...*big.Int) *Commitment {
	// Generate the random num
	rnd := random.GetRandomInt(256)

	// First, hash with the keccak256
	keccak256 := sha3.NewKeccak256()

	keccak256.Write(rnd.Bytes())

	for _, secret := range secrets {
		keccak256.Write(secret.Bytes())
	}

	digestKeccak256 := keccak256.Sum(nil)

	//second, hash with the SHA3-256
	sha3256 := sha3.New256()

	sha3256.Write(digestKeccak256)

	digest := sha3256.Sum(nil)

	// convert the hash ([]byte) to big.Int
	digestBigInt := new(big.Int).SetBytes(digest)

	D := []*big.Int{rnd}
	D = append(D, secrets...)

	commitment.C = digestBigInt
	commitment.D = D

	return commitment
}

func (commitment *Commitment) Verify() bool {
	C := commitment.C
	D := commitment.D

	keccak256 := sha3.NewKeccak256()
	for _, secret := range D {
		keccak256.Write(secret.Bytes())
	}
	digestKeccak256 := keccak256.Sum(nil)

	sha3256 := sha3.New256()
	sha3256.Write(digestKeccak256)
	computeDigest := sha3256.Sum(nil)

	computeDigestBigInt := new(big.Int).SetBytes(computeDigest)

	if computeDigestBigInt.Cmp(C) == 0 {
		return true
	} else {
		return false
	}
}

func (commitment *Commitment) DeCommit() (bool, []*big.Int) {
	if commitment.Verify() {
		return true, commitment.D[1:]
	} else {
		return false, nil
	}

}
