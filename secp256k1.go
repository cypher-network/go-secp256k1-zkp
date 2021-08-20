// Copyright 2021 Matthew Hellyer. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found in
// the LICENSE file.

// Package secp256k1 wraps secp256k1-zkp C library.
package secp256k1

/*
#cgo LDFLAGS: -L secp256k1
#cgo CFLAGS: -I./secp256k1-zkp/include
#include <secp256k1.h>
*/
import "C"

import (
	"crypto"
	"errors"
	"io"
	"unsafe"
)

const (
	ContextVerify 	= 		uint(C.SECP256K1_CONTEXT_VERIFY)
	ContextSign   	= 		uint(C.SECP256K1_CONTEXT_SIGN)
	EcCompressed   	= 		uint(C.SECP256K1_EC_COMPRESSED)
	EcUncompressed 	= 		uint(C.SECP256K1_EC_UNCOMPRESSED)
	CompressedLength   		int = 33
	UncompressedLength 		int = 65
	PrivateKeyLength   		int = 32
	PrivateKeyNullError 	string = "Private key cannot be null"
	PrivateKeyInvalidError 	string = "Invalid private key"
	PublicKeyCreateError   	string = "Unable to produce public key"
	PrivateKeySizeError    	string = "Private key must be exactly 32 bytes"
	PublicKeySizeError     	string = "Public key must be 33 or 65 bytes"
	PublicKeyParseError    	string = "Unable to parse this public key"
)

// Context
/** Opaque data structure that holds context information (precomputed tables etc.).
 *
 *  The purpose of context structures is to cache large precomputed data tables
 *  that are expensive to construct, and also to maintain the randomization data
 *  for blinding.
 *
 *  Do not create a new context object for each operation, as construction is
 *  far slower than all other API calls (~100 times slower than an ECDSA
 *  verification).
 *
 *  A constructed context can safely be used from multiple threads
 *  simultaneously, but API calls that take a non-const pointer to a context
 *  need exclusive access to it. In particular this is the case for
 *  secp256k1_context_destroy, secp256k1_context_preallocated_destroy,
 *  and secp256k1_context_randomize.
 *
 *  Regarding randomization, either do it once at creation time (in which case
 *  you do not need any locking for the other calls), or use a read-write lock.
 */
type Context struct {
	ctx *C.secp256k1_context
}

// PublicKey
/** Opaque data structure that holds a parsed and valid public key.
 *
 *  The exact representation of data inside is implementation defined and not
 *  guaranteed to be portable between different platforms or versions. It is
 *  however guaranteed to be 64 bytes in size, and can be safely copied/moved.
 *  If you need to convert to a format suitable for storage, transmission, or
 *  comparison, use secp256k1_ec_pubkey_serialize and secp256k1_ec_pubkey_parse.
 */
type PublicKey struct {
	pk *C.secp256k1_pubkey
}

var _ crypto.PrivateKey = PrivKey{}

// PrivKey implements PrivKey.
type PrivKey []byte


func newContext() *Context {
	return &Context{
		ctx: &C.secp256k1_context{},
	}
}

func newPublicKey() *PublicKey {
	return &PublicKey{
		pk: &C.secp256k1_pubkey{},
	}
}

// ContextCreate
/** Create a secp256k1 context object (in dynamically allocated memory).
 *
 *  This function uses malloc to allocate memory. It is guaranteed that malloc is
 *  called at most once for every call of this function. If you need to avoid dynamic
 *  memory allocation entirely, see the functions in secp256k1_preallocated.h.
 *
 *  Returns: a newly created context object.
 *  In:      flags: which parts of the context to initialize.
 *
 *  See also secp256k1_context_randomize.
 */
func ContextCreate(flags uint) (*Context, error) {
	context := newContext()
	context.ctx = C.secp256k1_context_create(C.uint(flags))
	return context, nil
}

// ContextClone
/** Copy a secp256k1 context object (into dynamically allocated memory).
 *
 *  This function uses malloc to allocate memory. It is guaranteed that malloc is
 *  called at most once for every call of this function. If you need to avoid dynamic
 *  memory allocation entirely, see the functions in secp256k1_preallocated.h.
 *
 *  Returns: a newly created context object.
 *  Args:    ctx: an existing context to copy (cannot be NULL)
 */
func ContextClone(ctx *Context) (*Context, error) {
	other := newContext()
	other.ctx = C.secp256k1_context_clone(ctx.ctx)
	return other, nil
}

// ContextDestroy
/** Destroy a secp256k1 context object (created in dynamically allocated memory).
 *
 *  The context pointer may not be used afterwards.
 *
 *  The context to destroy must have been created using secp256k1_context_create
 *  or secp256k1_context_clone. If the context has instead been created using
 *  secp256k1_context_preallocated_create or secp256k1_context_preallocated_clone, the
 *  behaviour is undefined. In that case, secp256k1_context_preallocated_destroy must
 *  be used instead.
 *
 *  Args:   ctx: an existing context to destroy, constructed using
 *               secp256k1_context_create or secp256k1_context_clone
 */
func ContextDestroy(ctx *Context) {
	C.secp256k1_context_destroy(ctx.ctx)
}

// ContextRandomize
/** Updates the context randomization to protect against side-channel leakage.
 *  Returns: 1: randomization successfully updated
 *           0: error
 *  Args:    ctx:       pointer to a context object (cannot be NULL)
 *  In:      seed32:    pointer to a 32-byte random seed (NULL resets to initial state)
 *
 * While secp256k1 code is written to be constant-time no matter what secret
 * values are, it's possible that a future compiler may output code which isn't,
 * and also that the CPU may not emit the same radio frequencies or draw the same
 * amount power for all values.
 *
 * This function provides a seed which is combined into the blinding value: that
 * blinding value is added before each multiplication (and removed afterwards) so
 * that it does not affect function results, but shields against attacks which
 * rely on any input-dependent behaviour.
 *
 * This function has currently an effect only on contexts initialized for signing
 * because randomization is currently used only for signing. However, this is not
 * guaranteed and may change in the future. It is safe to call this function on
 * contexts not initialized for signing; then it will have no effect and return 1.
 *
 * You should call this after secp256k1_context_create or
 * secp256k1_context_clone (and secp256k1_context_preallocated_create or
 * secp256k1_context_clone, resp.), and you may call this repeatedly afterwards.
 */
func ContextRandomize(ctx *Context, seed32 [32]byte) int {
	return int(C.secp256k1_context_randomize(ctx.ctx, cBuf(seed32[:])))
}

// PubkeyParse
/** Parse a variable-length public key into the pubkey object.
 *
 *  Returns: 1 if the public key was fully valid.
 *           0 if the public key could not be parsed or is invalid.
 *  Args: ctx:      a secp256k1 context object.
 *  Out:  pubkey:   pointer to a pubkey object. If 1 is returned, it is set to a
 *                  parsed version of input. If not, its value is undefined.
 *  In:   input:    pointer to a serialized public key
 *        inputlen: length of the array pointed to by input
 *
 *  This function supports parsing compressed (33 bytes, header byte 0x02 or
 *  0x03), uncompressed (65 bytes, header byte 0x04), or hybrid (65 bytes, header
 *  byte 0x06 or 0x07) format public keys.
 */
func PubkeyParse(ctx *Context, publicKey []byte) (int, *PublicKey, error) {
	l := len(publicKey)
	if l < 1 {
		return 0, nil, errors.New(PublicKeySizeError)
	}

	pk := newPublicKey()
	result := int(C.secp256k1_ec_pubkey_parse(ctx.ctx, pk.pk, cBuf(publicKey), C.size_t(l)))
	if result != 1 {
		return result, nil, errors.New(PublicKeyParseError)
	}
	return result, pk, nil
}

// PubkeySerialize
/** Serialize a pubkey object into a serialized byte sequence.
 *
 *  Returns: 1 always.
 *  Args:   ctx:        a secp256k1 context object.
 *  Out:    output:     a pointer to a 65-byte (if compressed==0) or 33-byte (if
 *                      compressed==1) byte array to place the serialized key
 *                      in.
 *  In/Out: outputlen:  a pointer to an integer which is initially set to the
 *                      size of output, and is overwritten with the written
 *                      size.
 *  In:     pubkey:     a pointer to a secp256k1_pubkey containing an
 *                      initialized public key.
 *          flags:      SECP256K1_EC_COMPRESSED if serialization should be in
 *                      compressed format, otherwise SECP256K1_EC_UNCOMPRESSED.
 */
func PubkeySerialize(ctx *Context, publicKey *PublicKey, flags uint) (int, []byte, error) {
	var size int
	if flags == EcCompressed {
		size = CompressedLength
	} else {
		size = UncompressedLength
	}

	output := make([]C.uchar, size)
	outputLen := C.size_t(size)
	result := int(C.secp256k1_ec_pubkey_serialize(ctx.ctx, &output[0], &outputLen, publicKey.pk, C.uint(flags)))
	return result, goBytes(output, C.int(outputLen)), nil
}

// PubkeyCreate
/** Compute the public key for a secret key.
 *
 *  Returns: 1: secret was valid, public key stores
 *           0: secret was invalid, try again
 *  Args:   ctx:        pointer to a context object, initialized for signing (cannot be NULL)
 *  Out:    pubkey:     pointer to the created public key (cannot be NULL)
 *  In:     seckey:     pointer to a 32-byte private key (cannot be NULL)
 */
func PubkeyCreate(ctx *Context, seckey []byte) (int, *PublicKey, error) {
	if len(seckey) != PrivateKeyLength {
		return 0, nil, errors.New(PrivateKeySizeError)
	}

	pk := newPublicKey()
	result := int(C.secp256k1_ec_pubkey_create(ctx.ctx, pk.pk, cBuf(seckey[:])))
	if result != 1 {
		return result, nil, errors.New(PublicKeyCreateError)
	}
	return result, pk, nil
}

// GenPrivKey generates a new secp256k1 private key using the provided reader.
func GenPrivKey(ctx *Context, rand io.Reader) PrivKey {
	var privKeyBytes [PrivateKeyLength]byte
	for {
		privKeyBytes = [PrivateKeyLength]byte{}
		_, err := io.ReadFull(rand, privKeyBytes[:])
		if err != nil {
			panic(err)
		}

		isValid, _ := SeckeyVerify(ctx.ctx, privKeyBytes[:])
		if isValid == 1 {
			break
		}
	}

	return privKeyBytes[:]
}

// SeckeyVerify
/** Verify an ECDSA secret key.
 *
 *  Returns: 1: secret key is valid
 *           0: secret key is invalid
 *  Args:    ctx: pointer to a context object (cannot be NULL)
 *  In:      seckey: pointer to a 32-byte secret key (cannot be NULL)
 */
func SeckeyVerify(ctx *Context, seckey []byte) (int, error) {
	if len(seckey) < 1 {
		return 0, errors.New(PrivateKeyNullError)
	}
	result := int(C.secp256k1_ec_seckey_verify(ctx.ctx, cBuf(seckey[:])))
	if result != 1 {
		return result, errors.New(PrivateKeyInvalidError)
	}
	return result, nil
}

func cBuf(goSlice []byte) *C.uchar {
	return (*C.uchar)(unsafe.Pointer(&goSlice[0]))
}

func goBytes(cSlice []C.uchar, size C.int) []byte {
	return C.GoBytes(unsafe.Pointer(&cSlice[0]), size)
}