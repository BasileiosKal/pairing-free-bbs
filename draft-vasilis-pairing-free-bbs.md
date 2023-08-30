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

TODO Abstract


{mainmatter}

# Introduction

TODO Introduction


# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Core Scheme Definition

## Signature Generation

```
signature = ExtendedSign(SK, PK, header, messages)

Inputs:

- SK (REQUIRED), a non negative integer mod r outputted by the KeyGen
                 operation.
- PK (REQUIRED), an octet string of the form outputted by the SkToPkG1
                   operation provided the above SK as input.
- PK_2 (OPTIONAL), an octet string of the form outputted by the SkToPkG2
                   operation provided the above SK as input. If not
                   supplied, it defaults to the empty octet string ("").
- header (OPTIONAL), an octet string containing context and application
                     specific information. If not supplied, it defaults
                     to an empty string.
- messages (OPTIONAL), a vector of scalars. If not supplied, it defaults
                       to the empty array "()".

Deserialization:


Procedure:

1. sig = Sign(SK, PK, header, messages)
2. if sig is INVALID, return INVALID
3. (A, e) = octets_to_signature(sig)

4. sk~ = hash_to_scalar(serialize(SK, e))
5. PK_1_bar = P1 * sk~
6. A_bar = A * sk~

7. c = hash_to_scalar(serialize(PK_1_bar, A_bar, e, messages,
                                                       header, PK))

8. sk^ = sk~ + SK * c
9. return (A, e, sk^, c)
```

## Pairing Free Signature Verification

```
result = ExtendedVerify(signature, PK, header, messages)

Inputs:

- signature (REQUIRED), an octet string of the form outputted by the
                        Sign operation.
- PK_1 (REQUIRED), an octet string of the form outputted by the SkToPkG1
                   operation provided the above SK as input.
- PK_2 (OPTIONAL), an octet string of the form outputted by the SkToPkG2
                   operation provided the above SK as input. If not
                   supplied, it defaults to the empty octet string ("").
- header (OPTIONAL), an octet string containing context and application
                     specific information. If not supplied, it defaults
                     to an empty string.
- messages (OPTIONAL), a vector of scalars. If not supplied, it defaults
                       to the empty array "()".

Parameters:

- P1, fixed point of G1, defined by the ciphersuite.
- create_generators, an operation that returns a number of generator
                     points, defined by the ciphersuite.

Definitions:

- L, is the non-negative integer representing the number of signed
     messages.

Outputs:

- result, either VALID or INVALID.

Deserialization:

1.  signature_result = octets_to_signature(signature)
2.  if signature_result is INVALID, return INVALID
3.  (A, e, sk^, c) = signature_result

4.  PublicKeys = deserialize_public_keys(PK)
5.  if PublicKeys is INVALID, return INVALID
6.  (PK_1, PK_2) = PublicKeys

7.  W = octets_to_pubkey(PK_1)
8.  if W is INVALID, return INVALID

9.  L = length(messages)
10. (msg_1, ..., msg_L) = messages

Procedure:

1.  (Q_1, H_1, ..., H_L) = create_generators(L+1, PK_2, header)
2.  domain = calculate_domain(PK_2, Q_1, (H_1, ..., H_L), header)
3.  if domain is INVALID, return INVALID
4.  B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L

5.  if e(A, W + P2 * e) * e(B, -P2) != Identity_GT, return INVALID

6.  PK_1_bar = P1 * sk^ - W * c
7.  D = B + A * (-e)
8.  A_bar = A * sk^ + D * (-c)

9.  cv = hash_to_scalar(serialize(PK_1_bar, A_bar, e, messages,
                                                         header, PK))

10. if c != cv, return INVALID

11. return VALID
```

## Proof Generation

```
proof = ExtendedProofGen(signature, PK, header, ph,
                                            messages, disclosed_indexes)

Inputs:

- signature (REQUIRED), an octet string of the form outputted by the
                        Sign operation.
- PK (REQUIRED), an octet string of the form outputted by the SkToPkG1
                   operation provided the above SK as input.
- header (OPTIONAL), an octet string containing context and application
                     specific information. If not supplied, it defaults
                     to an empty string.
- ph (OPTIONAL), an octet string containing the presentation header. If not
                 supplied, it defaults to an empty string.
- messages (OPTIONAL), a vector of scalars. If not supplied, it defaults
                       to the empty array "()".
- disclosed_indexes (OPTIONAL), vector of unsigned integers in ascending
                                order. Indexes of disclosed messages. If
                                not supplied, it defaults to the empty
                                array "()".

Procedure:

1. proof = ProofGen(PK, signature, PK, header, ph, messages,
                                                      disclosed_indexes)
2. if proof is INVALID, return INVALID
3. return proof
```

# Deployments

## Publicly Verifiable BBS Proofs

Publicly verifiable BBS scheme.

### Public Keys Generation

```
PK = SkToPks(SK)

Inputs:

- SK (REQUIRED), a secret integer such that 0 < SK < r.

Outputs:

- PK, a public key encoded as an octet string.

Procedure:

1. W_1 = SK * P1
2. W_2 = SK * P2
2. return point_to_octets_g1(W_1) || point_to_octets_g2(W_2)
```

### ProofVerify

```
result = ProofVerify(SK, PK, proof, header, ph,
                     disclosed_messages,
                     disclosed_indexes)

Inputs:

- PK (REQUIRED), an octet string of the form outputted by the SkToPk
                 operation.
- proof (REQUIRED), an octet string of the form outputted by the
                    ProofGen operation.
- header (OPTIONAL), an optional octet string containing context and
                     application specific information. If not supplied,
                     it defaults to an empty string.
- ph (OPTIONAL), an octet string containing the presentation header. If not
                 supplied, it defaults to an empty string.
- disclosed_messages (OPTIONAL), a vector of input_messages. If not
                                 supplied, it defaults to the empty
                                 array "()".
- disclosed_indexes (OPTIONAL), vector of unsigned integers in ascending
                                order. Indexes of disclosed messages. If
                                not supplied, it defaults to the empty
                                array "()".

Parameters:

- P1, fixed point of G1, defined by the ciphersuite.

Outputs:

- result, either VALID or INVALID.

Deserialization:

1.  proof_result = octets_to_proof(proof)
2.  if proof_result is INVALID, return INVALID
3.  (Abar, Bbar, r2^, r3^, commitments, cp) = proof_result

4.  public_keys = deserialize_public_keys(PK)
5.  if public_keys is INVALID, return INVALID
6.  (PK_1, PK_2) = public_keys
7.  W = octets_to_pubkey(PK_2)
8.  if W is INVALID, return INVALID

9.  (i1, ..., iR) = disclosed_indexes
10. msg_scalars = messages_to_scalars(messages)

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

### Public Key Generation

### ProofVerify

```
result = ProofVerify(SK, PK, proof, header, ph,
                     disclosed_messages,
                     disclosed_indexes)

Inputs:

- PK (REQUIRED), an octet string of the form outputted by the SkToPk
                 operation.
- proof (REQUIRED), an octet string of the form outputted by the
                    ProofGen operation.
- header (OPTIONAL), an optional octet string containing context and
                     application specific information. If not supplied,
                     it defaults to an empty string.
- ph (OPTIONAL), an octet string containing the presentation header. If not
                 supplied, it defaults to an empty string.
- disclosed_messages (OPTIONAL), a vector of input_messages. If not
                                 supplied, it defaults to the empty
                                 array "()".
- disclosed_indexes (OPTIONAL), vector of unsigned integers in ascending
                                order. Indexes of disclosed messages. If
                                not supplied, it defaults to the empty
                                array "()".

Parameters:

- P1, fixed point of G1, defined by the ciphersuite.

Outputs:

- result, either VALID or INVALID.

Deserialization:

1. proof_result = octets_to_proof(proof)
2. if proof_result is INVALID, return INVALID
3. (Abar, Bbar, r2^, r3^, commitments, cp) = proof_result
4. W = octets_to_pubkey(PK)
5. if W is INVALID, return INVALID
6. (i1, ..., iR) = disclosed_indexes
7. msg_scalars = messages_to_scalars(messages)

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

## Public Keys Deserialization

```
(PK_1, PK_2) = deserialize_public_keys(PK)

Inputs:

PK (REQUIRED)

Parameters:

- octet_point_length_g1
- octet_point_length_g2

Procedure:

1. pk_size = octet_point_length_g1 + octet_point_length_g2
2. if length(PK) != pk_size, return INVALID
3. PK_1 = PK[0..octet_point_length_g1]
4. PK_2 = PK[octet_point_length_g1 + 1..PK_size]
5. return (PK_1, PK_2)
```


# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


{backmatter}

# Acknowledgments

TODO acknowledge.
