// Copyright 2021 Matthew Hellyer. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be found in
// the LICENSE file.

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
 static secp256k1_context* secp256k1_context_create_sign_verify() {
 	return secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
 }