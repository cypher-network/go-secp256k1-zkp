// Copyright 2021 Matthew Hellyer. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found in
// the LICENSE file.

package secp256k1

// #include <stdlib.h>
// #include "./secp256k1-zkp/include/secp256k1_commitment.h"
import "C"

import (
	"errors"
	"unsafe"
)

const (
	BlindLength				int = 32
	CommitmentSize			int = 33
	CommitmentInternalSize	int = 64
	BlindKeySizeError    	string = "Blind key must be exactly 32 bytes"
	BlindKeyParseError    	string = "Unable to parse this blind key"
)

// PedersenCommitment
/** Opaque data structure that stores a Pedersen commitment
 *
 *  The exact representation of data inside is implementation defined and not
 *  guaranteed to be portable between different platforms or versions. It is
 *  however guaranteed to be 64 bytes in size, and can be safely copied/moved.
 *  If you need to convert to a format suitable for storage, transmission, or
 *  comparison, use secp256k1_pedersen_commitment_serialize and
 *  secp256k1_pedersen_commitment_parse.
 */
type PedersenCommitment struct {
	pc *C.secp256k1_pedersen_commitment
}

/// Generator point G
///
/// Used as generator point for the blinding factor in Pedersen Commitments.
/// Definition: Standard generator point of secp256k1
/// (as defined in http://www.secg.org/sec2-v2.pdf)
///
/// Format: x- and y- coordinate, without compressed/uncompressed prefix byte
var generatorG = [64]byte {
	0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
	0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
	0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
	0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
	0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65,
	0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8,
	0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19,
	0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8,
}

/// Generator point H
///
/// Used as generator point for the value in Pedersen Commitments.
/// Created as NUMS (nothing-up-my-sleeve) curve point from SHA256 hash of G.
/// Details: Calculate sha256 of uncompressed serialization format of G, treat the
/// result as x-coordinate, find the first point on  curve with this x-coordinate
/// (which happens to exist on the curve)
///
/// Example in SageMath:
/// --------------------
/// sage: import hashlib
///
/// sage: # finite field of secp256k1:
/// sage: F = FiniteField (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
/// sage: # Elliptic Curve defined by y^2 = x^3 + 0x + 7 over finite field F ( = secp256k1)
/// sage: secp256k1 = EllipticCurve ([F (0), F (7)])
///
/// sage: # hash of generator point G in uncompressed form:
/// sage: hash_of_g =  hashlib.sha256('0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'.decode('hex'))
/// sage: hash_of_g_as_int = Integer(int(hash_of_g.hexdigest(),16))
///
/// sage: # get the first point on the curve (if any exists) from given x-coordinate:
/// sage: POINT_H = secp256k1.lift_x(hash_of_g_as_int)
///
/// sage: # output x- and y-coordinates of the point in hexadecimal:
/// sage: '%x %x'%POINT_H.xy()
///
/// sage Result: '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0 31d3c6863973926e049e637cb1b5f40a36dac28af1766968c30c2313f3a38904'
///
/// Format: x- and y- coordinate, without compressed/uncompressed prefix byte
var generatorH = [64]byte {
	0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54,
	0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
	0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5,
	0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
	0x31, 0xd3, 0xc6, 0x86, 0x39, 0x73, 0x92, 0x6e,
	0x04, 0x9e, 0x63, 0x7c, 0xb1, 0xb5, 0xf4, 0x0a,
	0x36, 0xda, 0xc2, 0x8a, 0xf1, 0x76, 0x69, 0x68,
	0xc3, 0x0c, 0x23, 0x13, 0xf3, 0xa3, 0x89, 0x0,
}

/// Generator point J
///
/// Used as generator point in Switch Commitments.
/// Created as NUMS (nothing-up-my-sleeve) curve point from double-SHA256 hash of G.
/// Details: Calculate sha256 of sha256 of uncompressed serialization format of G, treat
/// the result as x-coordinate, find the first point on curve with this x-coordinate
/// (which happens to exist on the curve)
///
/// Example in SageMath:
/// --------------------
/// sage: import hashlib
///
/// sage: # finite field of secp256k1:
/// sage: F = FiniteField (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
/// sage: # Elliptic Curve defined by y^2 = x^3 + 0x + 7 over finite field F ( = secp256k1)
/// sage: secp256k1 = EllipticCurve ([F (0), F (7)])
///
/// sage: # hash of generator point G in uncompressed form:
/// sage: hash_of_g =  hashlib.sha256('0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'.decode('hex'))
///
/// sage: # double hash of generator point G:
/// sage: double_hash_of_g = hashlib.sha256(hash_of_g.hexdigest().decode('hex'))
/// sage: # treat as Integer
/// sage: double_hash_as_int = Integer(int(double_hash_of_g.hexdigest(),16))
///
/// sage: # get the first point on the curve (if any exists) from given x-coordinate:
/// sage: POINT_J = secp256k1.lift_x(double_hash_as_int)
///
/// sage: # output x- and y-coordinates of the point in hexadecimal:
/// sage: '%x %x'%POINT_J.xy()
///
/// sage Result: 'b860f56795fc03f3c21685383d1b5a2f2954f49b7e398b8d2a0193933621155f a43f09d32caa8f53423f427403a56a3165a5a69a74cf56fc5901a2dca6c5c43a'
///
/// Format:
/// raw x- and y- coordinate, without compressed/uncompressed prefix byte
/// in REVERSED byte order (indicated by the suffix "_RAW")!
///
/// This is different from G and H as in the underlying secp256k1 library, J is
/// declared as "secp256k1_pubkey" while G and H are declared as "secp256k1_generator"
/// which seem to be represented and parsed differently (see "secp256k1_ec_pubkey_parse" vs
/// "secp256k1_generator_parse" in https://github.com/mimblewimble/secp256k1-zkp/).
var generatorPubJRaw = [64]byte {
	0x5f, 0x15, 0x21, 0x36, 0x93, 0x93, 0x01, 0x2a,
	0x8d, 0x8b, 0x39, 0x7e, 0x9b, 0xf4, 0x54, 0x29,
	0x2f, 0x5a, 0x1b, 0x3d, 0x38, 0x85, 0x16, 0xc2,
	0xf3, 0x03, 0xfc, 0x95, 0x67, 0xf5, 0x60, 0xb8,
	0x3a, 0xc4, 0xc5, 0xa6, 0xdc, 0xa2, 0x01, 0x59,
	0xfc, 0x56, 0xcf, 0x74, 0x9a, 0xa6, 0xa5, 0x65,
	0x31, 0x6a, 0xa5, 0x03, 0x74, 0x42, 0x3f, 0x42,
	0x53, 0x8f, 0xaa, 0x2c, 0xd3, 0x09, 0x3f, 0xa4,
}

// Commit
/** Generate a Pedersen commitment.
 *  Returns 1: Commitment successfully created.
 *          0: Error. The blinding factor is larger than the group order
 *             (probability for random 32 byte number < 2^-127) or results in the
 *             point at infinity. Retry with a different factor.
 *  In:     ctx:        pointer to a context object (cannot be NULL)
 *          blind:      pointer to a 32-byte blinding factor (cannot be NULL)
 *          value:      unsigned 64-bit integer value to commit to.
 *          value_gen:  value generator 'h'
 *          blind_gen:  blinding factor generator 'g'
 *  Out:    commit:     pointer to the commitment (cannot be NULL)
 *
 *  Blinding factors can be generated and verified in the same way as secp256k1 private keys for ECDSA.
 */
func Commit(ctx *Context, value uint64, blind32 [32]byte) (int, []byte, error)  {
	if len(blind32) != BlindLength {
		return 0, nil, errors.New(BlindKeySizeError)
	}

	var commit64 = make([]byte, CommitmentInternalSize)
	commit64Ptr := (*C.secp256k1_pedersen_commitment)(unsafe.Pointer(&commit64[0]))
	blind32Ptr := (*C.uchar)(unsafe.Pointer(&blind32[0]))
	generator64HPtr := (*C.secp256k1_generator)(unsafe.Pointer(&generatorH[0]))
	generator64GPtr := (*C.secp256k1_generator)(unsafe.Pointer(&generatorG[0]))

	result := int(C.secp256k1_pedersen_commit(ctx.ctx, commit64Ptr, blind32Ptr, C.uint64_t(value), generator64HPtr, generator64GPtr))
	if result != 1 {
		return result, nil, errors.New(BlindKeyParseError)
	}

	return result, commit64, nil
}