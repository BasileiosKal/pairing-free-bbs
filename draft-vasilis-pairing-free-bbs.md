%%%
title = "Pairing Free BBS Signatures"
abbrev = "Pairing Free BBS "
ipr= "trust200902"
area = "Internet"
workgroup = "CFRG"

[seriesInfo]
name = "Internet-Draft"
value = "draft-vasilis-pairing-free-bbs-latest"
status = "informational"

[[author]]
initials = "V."
surname = "Kalos"
fullname = "Vasilis Kalos"
#role = "editor"
organization = "MATTR"
  [author.address]
  email = "vasilis.kalos@mattr.global"

%%%

.# Abstract

The BBS Signatures scheme defined in [@!I-D.irtf-cfrg-bbs-signatures], describes a pairing-based, multi-message digital signature, that supports selectively disclosing the messages through unlinkable presentations, build using zero-knowledge proofs. This document describes 2 additional deployments of the BBS Signatures scheme, providing tradeoffs between signature and key size, to decreased need for pairing operations, providing that way verification efficiency and increased hardware support. To do so, it defines an extended signature generation and altered signature verification procedures, that use slightly larger keys and signatures, but avoid the need for pairing operations (during signature verification). It then uses those procedures to build two different deployment models. The first, allows for publicly verifiable BBS proofs, in which case, there is a need for 2 pairing operations during the BBS proof verification. In the second deployment model, BBS proofs are privately verifiable, which allows completely avoiding the need for pairings and pairing-friendly curves.

{mainmatter}

# Introduction

BBS Signatures, originally described in the academic work by Dan Boneh, Xavier Boyen, and Hovav Shacham [@BBS04], is a signature scheme able to sign multiple messages at once, allowing for selectively disclosing those message while not revealing the signature it self. It does so by creating unlinkable, zero-knowledge proofs-of-knowledge of a signature value on the disclosed set of messages.

The scheme has had various works analyzing its security and improving its efficiency. The BBS scheme described in [@!I-D.irtf-cfrg-bbs-signatures] is based on the academic work [@CDL16], using the latest performance improvements from [@TZ23]. Those works, making use of pairing operations, achieve minimum key and signature sizes, while keeping key management complexity to a minimum. For a lot of use cases however, especially those requiring hardware support, the pairing operation are not viable. For example, a lot of the hardware security modulus do not have the necessary capabilities to compute the required pairings, or execute some curve operations taking place on the pairing-friendly curves.

To that end, this document, based on [@BBDT16], extends the BBS signature and public keys defined in the BBS document, making it possible to validate a BBS signature without using any pairings. This would allow the signature verification operation to happen inside secure hardware, which in turn means that the signature does not have to move to the less secure application layer, endangering the user's security and privacy.

Using the described functions for signature generation and verification, this document then describes two deployment models; one for publicly and one for privately verifiable BBS proofs. The two deployments differ in public key size and the BBS proof verification operation. The publicly verifiable BBS deployment uses slightly larger public keys and proof verification works the same as the `ProofVerify` procedure defined in [@!I-D.irtf-cfrg-bbs-signatures], making use of pairing operations. In contrast, the privately verifiable deployment uses an alterative proof verification operation that requires knowledge of the Signer's secret key. This deployment configuration, completely avoids the need for pairing operations. This means that the privately verifiable BBS deployment is not constrained on using just pairing-friendly curves and can make use of a wider range of elliptic curves, like P-256.

## Terminology

The following terminology is used throughout this document:

SK
: The secret key for the signature scheme.

PK
: The public key for the signature scheme.

L
: The total number of signed messages.

R
: The number of message indexes that are disclosed (revealed) in a proof-of-knowledge of a signature.

U
: The number of message indexes that are undisclosed in a proof-of-knowledge of a signature.

scalar
: An integer between 0 and r-1, where r is the prime order of the selected groups, defined by each ciphersuite (see also [Notation](#notation)).

generator
: A valid point on the selected subgroup of the curve being used that is employed to commit a value.

signature
: The digital signature output.

nonce
: A cryptographic nonce

presentation\_header (ph)
: A payload generated and bound to the context of a specific spk.

dst
: The domain separation tag.

I2OSP
: An operation that transforms a non-negative integer into an octet string, defined in Section 4 of [@!RFC8017]. Note, the output of this operation is in big-endian order.

OS2IP
: An operation that transforms a octet string into an non-negative integer, defined in Section 4 of [@!RFC8017]. Note, the input of this operation must be in big-endian order.

INVALID, ABORT
: Error indicators. INVALID refers to an error encountered during the Deserialization or Procedure steps of an operation. An INVALID value can be returned by a subroutine and handled by the calling operation. ABORT indicates that one or more of the initial constraints defined by the operation are not met. In that case, the operation will stop execution. An operation calling a subroutine that aborted must also immediately abort.

## Notation

The following notation and primitives are used:

a || b
: Denotes the concatenation of octet strings a and b.

X\[a..b\]
: Denotes a slice of the array `X` containing all elements from and including the value at index `a` until and including the value at index `b`. Note when this syntax is applied to an octet string, each element in the array `X` is assumed to be a single byte.

range(a, b)
: For integers a and b, with a <= b, denotes the ascending ordered list of all integers between a and b inclusive (i.e., the integers "i" such that a <= i <= b).

length(input)
: Takes as input either an array or an octet string. If the input is an array, returns the number of elements of the array. If the input is an octet string, returns the number of bytes of the inputted octet string.

Terms specific to pairing-friendly elliptic curves that are relevant to this document are restated below, originally defined in [@!I-D.irtf-cfrg-pairing-friendly-curves].

E1, E2
: elliptic curve groups defined over finite fields. This document assumes that E1 has a more compact representation than E2, i.e., because E1 is defined over a smaller field than E2. For a pairing-friendly curve, this document denotes operations in E1 and E2 in additive notation, i.e., P + Q denotes point addition and x \* P denotes scalar multiplication.

G1, G2
: subgroups of E1 and E2 (respectively) having prime order r.

GT
: a subgroup, of prime order r, of the multiplicative group of a field extension.

e
: G1 x G2 -> GT: a non-degenerate bilinear map.

r
: The prime order of the G1 and G2 subgroups.

BP1, BP2
: base (constant) points on the G1 and G2 subgroups respectively.

Identity\_G1, Identity\_G2, Identity\_GT
: The identity element for the G1, G2, and GT subgroups respectively.

hash\_to\_curve\_g1(ostr, dst) -> P
: A cryptographic hash function that takes an arbitrary octet string as input and returns a point in G1, using the hash\_to\_curve operation defined in [@!I-D.irtf-cfrg-hash-to-curve] and the inputted dst as the domain separation tag for that operation (more specifically, the inputted dst will become the DST parameter for the hash\_to\_field operation, called by hash\_to\_curve).

point\_to\_octets\_g1(P) -> ostr, point\_to\_octets\_g2(P) -> ostr
: returns the canonical representation of the point P for the respective subgroup as an octet string. This operation is also known as serialization.

octets\_to\_point\_g1(ostr) -> P, octets\_to\_point\_g2(ostr) -> P
: returns the point P for the respective subgroup corresponding to the canonical representation ostr, or INVALID if ostr is not a valid output of the respective point\_to\_octets_g\* function. This operation is also known as deserialization.

subgroup\_check(P) -> VALID or INVALID
: returns VALID when the point P is an element of the subgroup of order r, and INVALID otherwise. This function can always be implemented by checking that r \* P is equal to the identity element. In some cases, faster checks may also exist, e.g., [@Bowe19].


## Document Organization

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Considerations

## Deployments and Ciphersuites

This document describes 2 different deployments of BBS Signatures, one for publicly and one for privately verifiable BBS proofs. The 2 deployments differ on the public keys size (see (#public-keys)), the BBS proof verification operation and the curves they can use as the underlying primitive. More specifically, the publicly verifiable BBS proofs deployment, requires pairing operations during proof verification, and as such, it can only be used with pairing-friendly curves, like the ones defined in [@!I-D.irtf-cfrg-pairing-friendly-curves]. On the other hand, the privately verifiable BBS proofs deployment, does not use any pairings and can be defined over any suitable elliptic curve (TODO: define "suitable"). As such, each ciphersuite (which defines the curve used), will support only one deployment.

## Public Keys

Depending on the deployment used (i.e., either for publicly or privately verifiable BBS proofs), the Signer's public key will be different. More specifically, in the publicly verifiable BBS proofs deployment, the Signer's public key will consist of 2 points, one in G1 and one in G2 (note that the publicly verifiable BBS proofs deployment requires pairing-friendly curves with the G1 and G2 subgroups, see (#notation)). The encoding of the public key in that case will be the concatenation of the encodings of the 2 points, i.e., `encoded_point_of_g1 || encoded_point_of_g2`. The purpose of the 2 points is different. The point of G1 is used to verify the extended BBS signature (using the alternative, pairing-free signature verification operation described by this document in (#pairing-free-signature-verification)). The point of G2 is used to verify the BBS proof. To avoid misuse, this document treats those 2 points as 1 public key, meaning that both signature and proof verification require knowledge of both points. On the other hand, in the privately verifiable BBS proofs deployment, the Signer's public key will comprise from just a point of G1, used by the Prover to validate the received BBS signature.

# Scheme Definition

This section defines the extended signature generation and alternative, pairing-free, signature verification operations. It also describes the proper use of the proof generation operation defined in [Section 3.4.3](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-03.html#name-proof-generation-proofgen) of [@!I-D.irtf-cfrg-bbs-signatures], as to work with the extended signature defined by this document.

Note that the public key calculation operation is described as part of each specific deployment, defined in (#deployments) (see (#public-keys)). As such, the size of the public key is deployment dependant, hence, ciphersuite specific (see (#deployments-and-ciphersuites)). Each of the operations MUST check that the received public key (PK), has a length consistent with the specific deployment and ciphersuite.

This section uses the following operations defined in [@!I-D.irtf-cfrg-bbs-signatures]:
- `hash_to_scalar` is defined in [Section 4.4](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-03.html#name-hash-to-scalar).
- `serialize` is defined in [Section 4.7.1](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-03.html#name-serialize).
- `Sign` is defined in [Section 3.4.1](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-03.html#name-signature-generation-sign).
- `ProofGen` is defined in [Section 3.4.3](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-03.html#name-proof-generation-proofgen).

## Signature Generation

The `ExtendedSign` operation returns a BBS signature from a secret key (SK) and a public key (PK), over a header and a set of messages. It extends the `Sign` operation defined in [Section 3.4.1](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-03.html#name-signature-generation-sign) of [@!I-D.irtf-cfrg-bbs-signatures], with 2 additional scalar values, allowing for signature verification without pairings.

```
signature = ExtendedSign(SK, PK, header, messages)

Inputs:

- SK (REQUIRED), a non negative integer mod r outputted by the KeyGen
                 operation.
- PK (REQUIRED), an octet string representing the encoded public key of
                 the Signer corresponding to the above SK.
- header (OPTIONAL), an octet string containing context and application
                     specific information. If not supplied, it defaults
                     to an empty string.
- messages (OPTIONAL), a vector of octet strings. If not supplied, it
                       defaults to the empty array "()".

Parameters:

- pubkey_size, an integer representing the size of the public key octet
               representation, defined by the ciphersuite.

Procedure:

1.  if length(PK) != pubkey_size, return INVALID
2.  sig = Sign(SK, PK, header, messages)
3.  if sig is INVALID, return INVALID
4.  (A, e) = octets_to_signature(sig)

5.  sk~ = hash_to_scalar(serialize(SK, e))
6.  PK_1_bar = P1 * sk~
7.  A_bar = A * sk~

8.  c = hash_to_scalar(serialize(PK_1_bar, A_bar, A, e, messages,
                                                          header, PK))

9.  sk^ = sk~ + SK * c
10. return extended_signature_to_octets(A, e, sk^, c)
```

## Pairing Free Signature Verification

This operation checks that a signature is valid for a given header and vector of messages against a supplied public key (PK). The set of messages MUST be supplied in this operation in the same order they were supplied to `ExtendedSign` as defined in (#signature-generation) when creating the signature. Note that this is an alternative operation than the Verify operation defined in [@!I-D.irtf-cfrg-bbs-signatures].

```
result = AlternativeVerify(signature, PK, header, messages)

Inputs:

- signature (REQUIRED), an octet string of the form outputted by the
                        Sign operation.
- PK (REQUIRED), an octet string representing the encoded public key of
                 the Signer.
- header (OPTIONAL), an octet string containing context and application
                     specific information. If not supplied, it defaults
                     to an empty string.
- messages (OPTIONAL), a vector of scalars. If not supplied, it defaults
                       to the empty array "()".

Parameters:

- P1, fixed point of G1, defined by the ciphersuite.
- create_generators, an operation that returns a number of generator
                     points, defined by the ciphersuite.
- pubkey_size, an integer representing the size of the public key octet
               representation, defined by the ciphersuite.

Definitions:

- L, is the non-negative integer representing the number of signed
     messages.

Outputs:

- result, either VALID or INVALID.

Deserialization:

1.  signature_result = octets_to_extended_signature(signature)
2.  if signature_result is INVALID, return INVALID
3.  (A, e, sk^, c) = signature_result

4.  if length(PK) != pubkey_size, return INVALID
4.  PublicKeys = deserialize_public_keys(PK)
5.  if PublicKeys is INVALID, return INVALID
6.  if length(public_keys) is not 1 or 2, return INVALID

7.  PK_1 = PublicKeys[0]
8.  W = octets_to_pubkey_g1(PK_1)
9.  if W is INVALID, return INVALID

10.  L = length(messages)
11. (msg_1, ..., msg_L) = messages

Procedure:

1.  (Q_1, H_1, ..., H_L) = create_generators(L+1, PK, header)
2.  domain = calculate_domain(PK, Q_1, (H_1, ..., H_L), header)
3.  if domain is INVALID, return INVALID
4.  B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L

5.  if e(A, W + P2 * e) * e(B, -P2) != Identity_GT, return INVALID

6.  PK_1_bar = P1 * sk^ + W * (-c)
7.  D = B + A * (-e)
8.  A_bar = A * sk^ + D * (-c)

9.  cv = hash_to_scalar(serialize(PK_1_bar, A_bar, A, e, messages,
                                                         header, PK))

10. if c != cv, return INVALID
11. return VALID
```

## Proof Generation

This operation creates BBS proof, which is a zero-knowledge, proof-of-knowledge, of a BBS signature, while optionally disclosing any subset of the signed messages. Validating the proof guarantees authenticity and integrity of the header and disclosed messages, as well as knowledge of a valid BBS signature.

Other than the Signer's public key (PK), the BBS signature, the header and the messages, the operation also accepts a presentation header value, that will be bound the the resulting proof. To indicate which of the messages should be disclosed, the operation accepts a list of integers in ascending order, representing the indexes of those messages

Note that this operation works by first stripping the extra elements added to the BBS signature by the `ExtendedSign` operation (see (#signature-generation)) and then passes the result to the `ProofGen` operation, defined in [Section 3.4.3](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-03.html#name-proof-generation-proofgen) of [@!I-D.irtf-cfrg-bbs-signatures]. To avoid malleability of the signature, the Prover MUST validate the signature value before passing it to the `ExtendedProofGen` operation defined in this section.

```
proof = ExtendedProofGen(PK, signature, header, ph, messages,
                                                      disclosed_indexes)

Inputs:

- PK (REQUIRED), an octet string of the form outputted by the SkToPk
                 operation.
- signature (REQUIRED), an octet string of the form outputted by the
                        ExtendedSign operation.
- header (OPTIONAL), an octet string containing context and application
                     specific information. If not supplied, it defaults
                     to an empty string.
- ph (OPTIONAL), an octet string containing the presentation header. If
                 not supplied, it defaults to an empty string.
- messages (OPTIONAL), a vector of input\_messages. If not supplied, it
                       defaults to the empty array "()".
- disclosed_indexes (OPTIONAL), vector of unsigned integers in ascending
                                order. Indexes of disclosed messages. If
                                not supplied, it defaults to the empty
                                array "()".

Outputs:

- proof, an octet string; or INVALID.

Parameters:

- pubkey_size, an integer representing the size of the public key octet
               representation, defined by the ciphersuite.

Procedure:

1. if length(PK) != pubkey_size, return INVALID

2. truncated_sig_size = octet_point_length + octet_scalar_length
3. sig_size = truncated_sig_size + 2 * octet_scalar_length
4. if length(signature) != sig_size, return INVALID
5. truncated_sig = signature[0..truncated_sig_size]

6. proof = ProofGen(PK, truncated_sig, header, ph, messages,
                                                 disclosed_indexes)
7. if proof is INVALID, return INVALID
8. return proof
```

# Deployments

A BBS Deployment, consists of the secret and public key generation operations, as well as the signature generation, signature verification, proof generation and proof verification procedures. The deployment's defined in this document use the secret key generation defined in [Section 3.1.1](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-secret-key) of [@!I-D.irtf-cfrg-bbs-signatures]. The signature generation, signature verification and proof generation operations used will be the ones defined in (#signature-generation), (#pairing-free-signature-verification) and (#proof-generation) correspondingly.

The distinguishing factor for the two described deployments will be the public key generation and proof verification operations.

## Publicly Verifiable BBS Proofs

This section describes a public key generation and a proof verification procedures, which together with the secret key generation operation defined in [Section 3.1.1](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-secret-key) of [@!I-D.irtf-cfrg-bbs-signatures], and the operations defined in (#scheme-definition), allow for a BBS Signature deployment that uses pairings during proof verification, to support publicly verifiable BBS proofs. Note that this deployment requires the use of pairing-friendly curves.

### Public Keys Generation

This operation on input a secret key (SK), returns the encoding of a public key, consisting of 2 points, the first in G1 and the second in G2.

```
PK = SkToPk(SK)

Inputs:

- SK (REQUIRED), a secret integer such that 0 < SK < r.

Outputs:

- PK, a public key encoded as an octet string.

Procedure:

1. W_1 = SK * P1
2. W_2 = SK * P2
3. return point_to_octets_g1(W_1) || point_to_octets_g2(W_2)
```

### Proof Verification

This operation validates a BBS proof, given the Signer's public key (PK), a header and presentation header values, the disclosed messages and the indexes those messages had in the original vector of signed messages. The `ProofVerifyInit` and `ProofChallengeCalculate` are defined in TBD of [@!I-D.irtf-cfrg-bbs-signatures].

```
result = PublicProofVerify(PK, proof, header, ph,
                            disclosed_messages,
                            disclosed_indexes)

Inputs:

- PK (REQUIRED), an octet string representing the encoded public key of
                 the Signer.
- proof (REQUIRED), an octet string of the form outputted by the
                    ProofGen operation.
- header (OPTIONAL), an optional octet string containing context and
                     application specific information. If not supplied,
                     it defaults to an empty string.
- ph (OPTIONAL), an octet string containing the presentation header. If
                 not supplied, it defaults to an empty string.
- disclosed_messages (OPTIONAL), a vector of input_messages. If not
                                 supplied, it defaults to the empty
                                 array "()".
- disclosed_indexes (OPTIONAL), vector of unsigned integers in ascending
                                order. Indexes of disclosed messages. If
                                not supplied, it defaults to the empty
                                array "()".

Parameters:

- P1, fixed point of G1, defined by the ciphersuite.
- pubkey_size, an integer representing the size of the public key octet
               representation, defined by the ciphersuite.

Outputs:

- result, either VALID or INVALID.

Deserialization:

1.  proof_result = octets_to_proof(proof)
2.  if proof_result is INVALID, return INVALID
3.  (Abar, Bbar, r2^, r3^, commitments, cp) = proof_result

4.  if length(PK) != pubkey_size, return INVALID
5.  public_keys = deserialize_public_keys(PK)
6.  if public_keys is INVALID, return INVALID
7.  if length(public_keys) != 2, return INVALID
8.  PK_2 = public_keys[2]
9.  W = octets_to_pubkey_g2(PK_2)
10. if W is INVALID, return INVALID

11. (i1, ..., iR) = disclosed_indexes
12. msg_scalars = messages_to_scalars(messages)

Procedure:

1. init_res = ProofVerifyInit(PK, proof_result, header, msg_scalars,
                                                      disclosed_indexes)
3. challenge = ProofChallengeCalculate(init_res, disclosed_indexes,
                                                        msg_scalars, ph)
4. if cp != challenge, return INVALID
5. if e(Abar, W) * e(Bbar, -BP2) != Identity_GT, return INVALID
6. return VALID
```

## Privately Verifiable BBS Proofs

This section describes a public key generation and a proof verification procedures, which together with the secret key generation operation defined in [Section 3.1.1](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-secret-key) of [@!I-D.irtf-cfrg-bbs-signatures], and the operations defined in (#scheme-definition), allow for a BBS Signature deployment that supports privately verifiable BBS proofs, entirely avoiding the need for pairing operations. Note that this deployment does not require the use of pairing-friendly curves.

### Public Key Generation

This operation on input a secret key (SK), returns the encoding of the elliptic curve point that represents the public key.

```
PK = SkToPk(SK)

Inputs:

- SK (REQUIRED), a secret integer such that 0 < SK < r.

Outputs:

- PK, a public key encoded as an octet string.

Procedure:

1. W_1 = SK * P1
2. return point_to_octets_g1(W_1)
```

### Proof Verification

This operation validates a BBS proof, given the Signer's secret key (SK) and public key (PK), a header and presentation header values, the disclosed messages and the indexes those messages had in the original vector of signed messages. The `ProofVerifyInit` and `ProofChallengeCalculate` are defined in TBD of [@!I-D.irtf-cfrg-bbs-signatures].

```
result = PrivateProofVerify(SK, PK, proof, header, ph,
                             disclosed_messages,
                             disclosed_indexes)

Inputs:

- PK (REQUIRED), an octet string representing the encoded public key of
                 the signer corresponding to the above SK.
- proof (REQUIRED), an octet string of the form outputted by the
                    ProofGen operation.
- header (OPTIONAL), an optional octet string containing context and
                     application specific information. If not supplied,
                     it defaults to an empty string.
- ph (OPTIONAL), an octet string containing the presentation header. If
                 not supplied, it defaults to an empty string.
- disclosed_messages (OPTIONAL), a vector of input_messages. If not
                                 supplied, it defaults to the empty
                                 array "()".
- disclosed_indexes (OPTIONAL), vector of unsigned integers in ascending
                                order. Indexes of disclosed messages. If
                                not supplied, it defaults to the empty
                                array "()".

Parameters:

- P1, fixed point of G1, defined by the ciphersuite.
- pubkey_size, an integer representing the size of the public key octet
               representation, defined by the ciphersuite.

Outputs:

- result, either VALID or INVALID.

Deserialization:

1. proof_result = octets_to_proof(proof)
2. if proof_result is INVALID, return INVALID
3. (Abar, Bbar, r2^, r3^, commitments, cp) = proof_result
4. if length(PK) != pubkey_size, return INVALID
5. (i1, ..., iR) = disclosed_indexes
6. msg_scalars = messages_to_scalars(messages)

Procedure:

1. init_res = ProofVerifyInit(PK, proof_result, header, msg_scalars,
                                                      disclosed_indexes)
3. challenge = ProofChallengeCalculate(init_res, disclosed_indexes,
                                                        msg_scalars, ph)
4. if cp != challenge, return INVALID
5. if Abar * SK != Bbar, return INVALID
6. return VALID
```

# Utility Operations

## Public Key Utilities

### Public Keys Deserialization

This operation describes how to deserialize a public key to its (possibly 2) components. Note that an encoded public key, depending on the deployment, may consist of either 2 or 1 encoded points (see (#public-keys)). This operation parses the encoded public key and will return the encoding of its components (a set of either 1 or 2 octet strings, depending on the public key's size).

```
public_keys = deserialize_public_keys(PK)

Inputs:

PK (REQUIRED), an octet string representing the encoded public key of
               the Signer.

Parameters:

- octet_point_length_g1, positive integer representing the length of the
                         octet representation of a point in G1, defined
                         by the ciphersuite.
- octet_point_length_g2, positive integer representing the length of the
                         octet representation of a point in G2, defined
                         by the ciphersuite.
- pubkey_size, an integer representing the size of the public key octet
               representation, defined by the ciphersuite.

Outputs:

- public_keys, set of either 1 or 2 octet strings, representing the
               encoding of either 1 point of G1, or the encoding of 1
               point of G1 and the encoding 1 point of G2; or INVALID.

Procedure:

1. if length(PK) != pubkey_size, return INVALID

2. if length(PK) < octet_point_length_g1, return INVALID
3. PK_1 = PK[0..octet_point_length_g1]
4. if length(PK) == octet_point_length_g1, return (PK_1)

5. pk_size = octet_point_length_g1 + octet_point_length_g2
6. if length(PK) != pk_size, return INVALID
7. PK_2 = PK[octet_point_length_g1 + 1..pk_size]
8. return (PK_1, PK_2)
```

### Octets to Public Key in G1

```
W = octets_to_pubkey_g1(PK)

Inputs:

- PK (REQUIRED), an octet string representing the encoded public key of
                 the Signer.

Outputs:

- W, a valid point in G1 or INVALID

Procedure:

1. W = octets_to_point_g1(PK)
2. If W is INVALID, return INVALID
3. if subgroup_check_g1(W) is INVALID, return INVALID
4. If W == Identity_G1, return INVALID
5. return W
```

### Octets to Public Key in G2

```
W = octets_to_pubkey_g2(PK)

Inputs:

- PK (REQUIRED), an octet string representing the encoded public key of
                 the Signer.

Outputs:

- W, a valid point in G2 or INVALID

Procedure:

1. W = octets_to_point_g2(PK)
2. If W is INVALID, return INVALID
3. if subgroup_check_g2(W) is INVALID, return INVALID
4. If W == Identity_G2, return INVALID
5. return W
```

## Signature Utilities
### Extended Signature to Octets

```
signature_octets = extended_signature_to_octets(signature)

Inputs:

- signature (REQUIRED), a valid signature, in the form (A, e, s1, s2),
                         where A is a point in G1 and e, s1 and s2 are a
                         non-zero scalars mod r.

Outputs:

- signature_octets, an octet string or INVALID.

Procedure:

1. (A, e, s1, s2) = signature
2. return serialize((A, e, s1, s2))
```

### Octets to Extended Signature

```
signature = octets_to_extended_signature(signature_octets)

Inputs:

- signature_octets (REQUIRED), an octet string of the form output from
                               signature_to_octets operation.

Outputs:

signature, a signature in the form (A, e, s1, s2), where A is a point in
           G1 and e, s1 and s2 are non-zero scalars mod r.

Procedure:

1.  expected_len = octet_point_length + 3 * octet_scalar_length
2.  if length(signature_octets) != expected_len, return INVALID

3.  A_octets = signature_octets[0..(octet_point_length - 1)]
4.  A = octets_to_point_g1(A_octets)
5.  if A is INVALID, return INVALID
6.  if A == Identity_G1, return INVALID

7.  index = octet_point_length
8.  end_index = index + octet_scalar_length - 1
9.  e = OS2IP(signature_octets[index..end_index])
10. if e = 0 OR e >= r, return INVALID

11. return (A, e, s1, s2)
```

# Security Considerations

## Public Keys Validation

// TODO

## Signature Validation

// TODO

# Ciphersuites

This section defines the format of the extended BBS ciphersuites. The ciphersuite defined in this document include all the parameters necessary to use the BBS operations defined that are defined in the [@!I-D.irtf-cfrg-bbs-signatures]. More specifically, the `Sign`, `ProofGen`, `hash_to_scalar`, `serialize` `ProofVerifyInit` and `ProofChallengeCalculate` operations that are defined in [@!I-D.irtf-cfrg-bbs-signatures], MUST be instantiated using the parameters defined by the ciphersuites of this document.

## Ciphersuite Format

The parameters defined by a ciphersuite include:
- The ciphersuite id.
- Basic parameters that are defined by the underlying curve used, and need to be defined by all ciphersuites.
- Elliptic curve point serialization functions, that need to be defined by all ciphersuites.
- Some additional parameters that need to be defined only by ciphersuites that support the publicly verifiable BBS proofs deployment ((#publicly-verifiable-bbs-proofs))

### Ciphersuite ID

The following section defines the format of the unique identifier for the ciphersuite denoted `ciphersuite_id`, which will be represented as an ASCII encoded octet string. The REQUIRED format for this string is:

```
"PAIRING_FREE_BBS_" || H2C_SUITE_ID || DEPLOYMENT_ID || ADD_INFO
```


*  H2C\_SUITE\_ID is the suite ID of the hash-to-curve suite used to define the hash_to_curve function.

* DEPLOYMENT\_ID is either "PUBLIC\_" or "PRIVATE\_", depending om the targeted deployment.

*  ADD\_INFO is an optional octet string indicating any additional information used to uniquely qualify the ciphersuite. When present this value MUST only contain ASCII encoded characters with codes between 0x21 and 0x7e (inclusive) and MUST end with an underscore (ASCII code: 0x5f), other than the last character the string MUST not contain any other underscores (ASCII code: 0x5f).

### Basic Parameters

All ciphersuites MUST define the following parameters.

- publicly\_verifiable: Boolean value. True if the ciphersuite supports publicly verifiable BBS proofs deployment defined in (#publicly-verifiable-bbs-proofs). False if the ciphersuite supports the privately verifiable BBS proofs deployment defined in (#privately-verifiable-bbs-proofs).

- octet\_scalar\_length: Number of bytes to represent a scalar value, in the multiplicative group of integers mod r, encoded as an octet string. It is RECOMMENDED this value be set to ceil(log2(r)/8).

- octet\_point\_g1\_length: Number of bytes to represent a point encoded as an octet string outputted by the point\_to\_octets\_g1 function. It is RECOMMENDED that this value is set to ceil(log2(p)/8).

- hash\_to\_curve\_suite: The hash-to-curve ciphersuite id, in the form defined in [@!I-D.irtf-cfrg-hash-to-curve]. This defines the hash\_to\_curve\_g1 (the hash\_to\_curve operation for the G1 subgroup, see the [Notation](#notation) section) and the expand\_message (either expand\_message\_xmd or expand\_message\_xof) operations used in this document.

- expand\_len: Must be defined to be at least `ceil((ceil(log2(r))+k)/8)`, where `log2(r)` and `k` are defined by each ciphersuite (see Section 5 in [@!I-D.irtf-cfrg-hash-to-curve] for a more detailed explanation of this definition). This value is used by the hash\_to\_scalar operation, defined in [@!I-D.irtf-cfrg-bbs-signatures] and used by this document.

- P1: A fixed point in the G1 subgroup, different from the point BP1 (i.e., the base point of G1, see (#terminology)). This leaves the base point "free", to be used with other protocols, like key commitment and proof of possession schemes (for example, like the one described in Section 3.3 of [@I-D.irtf-cfrg-bls-signature]).

### Serialization functions

All ciphersuites MUST define the following serialization functions.

- point\_to\_octets\_g1:
a function that returns the canonical representation of the point P for the G1 subgroup as an octet string.

- octets\_to\_point\_g1:
a function that returns the point P in the subgroup G1 corresponding to the canonical representation ostr, or INVALID if ostr is not a valid output of `point_to_octets_g1`.


### Extra Parameters

If a ciphersuite is indented to support the publicly verifiable BBS proofs deployment defined in (#publicly-verifiable-bbs-proofs), (i.e., the publicly\_verifiable value will be set to True) then it MUST also define the following extra basic parameters and serialization functions.

- octet\_point\_g2\_length: Number of bytes to represent a point encoded as an octet string outputted by the point\_to\_octets\_g2 function. It is RECOMMENDED that this value is set to 2*ceil(log2(p)/8).

- point\_to\_octets\_g2:
a function that returns the canonical representation of the point P for the G2 subgroup as an octet string.

- octets\_to\_point\_g2:
a function that returns the point P in the subgroup G2 corresponding to the canonical representation ostr, or INVALID if ostr is not a valid output of `point_to_octets_g2`.

### Public Key Size

Depending on its supporting deployment model, i.e., either publicly or privately verifiable BBS proofs, the ciphersuite MUST set the pubkey\_size operation accordingly, as follows.

- pubkey\_size, an integer representing the size of the public key octet representation. If publicly\_verifiable is true, this value MUST equal octet\_point\_g1\_length + octet\_point\_g2\_length. If publicly\_verifiable is false, this value MUST equal octet\_point\_g1\_length exactly.

## Publicly Verifiable Deployment Ciphersuites

### BLS12-381-SHA-256

The following ciphersuite is based on the BLS12-381 pairing-friendly elliptic curves defined in Section 4.2.1 of [@!I-D.irtf-cfrg-pairing-friendly-curves]. The targeted security level in bits is `k = 128`. The number of bits of the order `r`, of the G1 and G2 subgroups, is `log2(r) = 255`. The base points `BP1` and `BP2` of G1 and G2 are the points `BP` and `BP'` correspondingly, as defined in Section 4.2.1 of [@!I-D.irtf-cfrg-pairing-friendly-curves].

**Ciphersuite ID**

- Ciphersuite\_ID: "PAIRING\_FREE\_BBS\_BLS12381G1\_XMD:SHA-256\_SSWU\_RO\_PUBLIC\_"

**Basic Parameters**

- publicly\_verifiable: True

- octet\_scalar\_length: 32

- octet\_point\_g1\_length: 48

- hash\_to\_curve\_suite: "BLS12381G1\_XMD:SHA-256\_SSWU\_RO\_" as defined in Section 8.8.1 of the [@!I-D.irtf-cfrg-hash-to-curve] for the G1 subgroup.

- expand\_len: 48

- P1: The point defined (in hex encoding) is "a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c596
 98588e70d11406d161b4e28c9"

**Serialization functions**

- point\_to\_octets\_g1: follows the format documented in Appendix C section 1 of [@!I-D.irtf-cfrg-pairing-friendly-curves] for the G1 subgroup, using compression (i.e., setting C\_bit = 1).

- octets\_to\_point\_g1: follows the format documented in Appendix C section 2 of [@!I-D.irtf-cfrg-pairing-friendly-curves] for the G1 subgroup.

**Extra Parameters**

- octet\_point\_g2\_length: 96

- point\_to\_octets\_g2: follows the format documented in Appendix C section 1 of [@!I-D.irtf-cfrg-pairing-friendly-curves] for the G2 subgroup, using compression (i.e., setting C\_bit = 1).

- octets\_to\_point\_g2: follows the format documented in Appendix C section 2 of [@!I-D.irtf-cfrg-pairing-friendly-curves] for the G2 subgroup.

**Public Key Size**

- pubkey\_size: 144

## Privately Verifiable Deployment Ciphersuites

### P256-SHA-256

The following ciphersuite is based on the P-256 elliptic curve defined in Appendix D.1.2.3 of [@!FIPS186-4]. The targeted security level in bits is `k = 128`. The number of bits of the order `r` of the G1 subgroup, is `log2(r) = 256`. The base point `BP1` of G1 is the `BP1 = (Gx, Gy)`, where `Gx` and `Gy` are defined in Appendix D.1.2.3 of[@!FIPS186-4].

**Ciphersuite ID**

- Ciphersuite\_ID: "PAIRING\_FREE\_BBS\_P256_XMD:SHA-256\_SSWU\_RO\_PRIVATE\_"

**Basic Parameters**

- publicly\_verifiable: False

- octet\_scalar\_length: 32

- octet\_point\_g1\_length: 64 (//TODO: should use SEC-1 compression??)

- hash\_to\_curve\_suite: "P256\_XMD:SHA-256\_SSWU\_RO\_" as defined in Section 8.8.1 of the [@!I-D.irtf-cfrg-hash-to-curve] for the G1 subgroup.

- expand\_len: 48

- P1: The point defined (in hex encoding) is TBD.

**Serialization functions**

- point\_to\_octets\_g1: follows the procedure described in section 2.3.3 of [@!SEC1], without using compression.

- octets\_to\_point\_g1: follows the procedure described in section 2.3.4 of [@!SEC1].

**Public Key Size**

- pubkey\_size: 64

# IANA Considerations

This document has no IANA actions.


{backmatter}

# Acknowledgments

TODO acknowledge.

<reference anchor="Bowe19" target="https://eprint.iacr.org/2019/814">
  <front>
    <title>Faster subgroup checks for BLS12-381</title>
    <author initials="S." surname="Bowe" fullname="Sean Bowe">
      <organization>Electric Coin Company</organization>
    </author>
    <date year="2019" month="July"/>
  </front>
</reference>

<reference anchor="BBS04" target="https://link.springer.com/chapter/10.1007/978-3-540-28628-8_3">
 <front>
   <title>Short Group Signatures</title>
   <author initials="D." surname="Boneh" fullname="Dan Boneh">
    </author>
    <author initials="X." surname="Boyen" fullname="Xavier Boyen">
    </author>
    <author initials="H." surname="Shacham" fullname="Hovav Scacham">
    </author>
    <date year="2004"/>
 </front>
 <seriesInfo name="In" value="Advances in Cryptology"/>
 <seriesInfo name="pages" value="41-55"/>
</reference>

<reference anchor="CDL16" target="https://eprint.iacr.org/2016/663.pdf">
 <front>
   <title>Anonymous Attestation Using the Strong Diffie Hellman Assumption Revisited</title>
   <author initials="J." surname="Camenisch" fullname="Jan Camenisch">
      <organization>IBM Research</organization>
    </author>
    <author initials="M." surname="Drijvers" fullname="Manu Drijvers">
      <organization>IBM Research</organization>
      <organization>Department of Computer Science, ETH Zurich</organization>
    </author>
    <author initials="A." surname="Lehmann" fullname="Anja Lehmann">
      <organization>IBM Research</organization>
    </author>
    <date year="2016"/>
 </front>
 <seriesInfo name="In" value="International Conference on Trust and Trustworthy Computing"/>
 <seriesInfo name="pages" value="1-20"/>
 <seriesInfo name="Springer," value="Cham"/>
</reference>

<reference anchor="TZ23" target="https://ia.cr/2023/275">
  <front>
    <title>Revisiting BBS Signatures</title>
    <author initials="S. T." surname="Tessaro" fullname="Stefano Tessaro">
      <organization>University of Washington</organization>
    </author>
    <author initials="C. Z." surname="Zhu" fullname="Chenzhi Zhu">
      <organization>University of Washington</organization>
    </author>
    <date year="2023"/>
  </front>
  <seriesInfo name="In" value="EUROCRYPT"/>
</reference>


<reference anchor="BBDT16" target="https://link.springer.com/chapter/10.1007/978-3-319-69453-5_20">
  <front>
    <title>Improved Algebraic MACs and Practical Keyed-Verification Anonymous Credentials</title>
    <author initials="B." surname="Barki" fullname="Amira Barki">
      <organization>Orange Labs</organization>
    </author>
    <author initials="S." surname="Brunet" fullname="Solenn Brunet">
      <organization>Orange Labs</organization>
    </author>
    <author initials="N." surname="Desmoulins" fullname="Nicolas Desmoulins">
      <organization>Orange Labs</organization>
    </author>
    <author initials="J." surname="Traoré" fullname="Jacques Traoré">
      <organization>Orange Labs</organization>
    </author>
    <date year="1016"/>
  </front>
  <seriesInfo name="In" value="International Conference on Selected Areas in Cryptography"/>
</reference>

<reference anchor="SEC1" target="https://www.secg.org/sec1-v2.pdf">
 <front>
   <title>SEC 1: Elliptic Curve Cryptography</title>
   <author><organization>Standards for Efficient Cryptography Group</organization></author>
 </front>
</reference>

<reference anchor="FIPS186-4" target="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf">
 <front>
   <title>Digital Signature Standard (DSS)</title>
   <author><organization>NIST</organization></author>
 </front>
</reference>
