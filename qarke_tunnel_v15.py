#!/usr/bin/env python3
"""QARKE TUNNEL v1.5 — E2E encrypted tunnel / pipeline for mission comms.
KEM-TRAIL-2160 Phase 3.

Single-file drop-in. Needs: pynacl + python-cryptography (both on the
Commander's Termux phone already).

WHAT IT IS
----------
An end-to-end encrypted TCP tunnel between two parties (serve/connect),
with an interactive chat mode after the handshake so it is immediately
usable for mission comms.

CRYPTO ARCHITECTURE (honest label — printed at runtime)
------------------------------------------------------
- Identity ......... Ed25519 long-term keypair per side (PyNaCl)
- Handshake ........ mutually-authenticated ephemeral X25519 + ML-KEM
                     hybrid (KEM-TRAIL-2160 Phase 2). Initiator sends
                     ML-KEM encapsulation key; responder encapsulates;
                     both mix X25519 + ML-KEM shared secrets into a
                     transcript-bound HKDF key schedule (Phase 2,
                     TLS 1.3-style). kem_id negotiated, no silent
                     downgrade.
- Key schedule ..... HKDF-SHA512 (RFC 5869), TLS 1.3-style:
                     handshake_secret = HKDF-Extract(salt=transcript_hash,
                       IKM=x25519_ss || mlkem_ss); directional traffic
                     secrets via HKDF-Expand with distinct labels and the
                     transcript hash as context. Rekey derives fresh
                     secrets per epoch.
- Transport ........ ChaCha20-Poly1305, separate directional session keys
                     (init->resp / resp->init) so reflection attacks fail,
                     per-direction replay windows, epoch+seq nonces.
- Rekey ............ after 2^20 frames or on /rekey command: fresh
                     ephemeral X25519 over the encrypted channel, epoch+1,
                     keys re-derived via the HKDF schedule.
- PQC .............. HYBRID ACTIVE (kem_id=1: ML-KEM-768 + X25519, or
                     kem_id=2: ML-KEM-1024 + X25519). Pure-Python FIPS 203
                     implementation, NIST ACVP KAT-validated (25/25 keygen,
                     25/25 encap, 10/10 decap for both 768 and 1024).

SECURITY NOTES
--------------
- This is a v1.2 built for real use, not a toy — but it has NOT had an
  external audit. Rekey is stop-the-world (outbound queues during it).
- TOFU is only as good as your first contact: prefer --peer-key pinning
  exchanged over a trusted channel.
- Identity file is created mode 0600. Guard it like a password.
- ML-KEM is pure Python (no liboqs needed). Slower than C, but no
  dependency. Handshake adds ~1-3s for PQ ops on phone-class hardware.

USAGE (phone / Termux)
---------------------
  python qarke_tunnel_v13.py --gen-key
      # generate ~/.qarke_tunnel_identity, prints fingerprint + pubkey hex

  # Side A (listener), default hybrid ML-KEM-768:
  python qarke_tunnel_v13.py serve --port 8471 --peer-key <B-pubkey-hex>

  # Side B (dialer):
  python qarke_tunnel_v13.py connect --host <A-ip> --port 8471 --peer-key <A-pubkey-hex>

  # --kem 768 | 1024 | off  (both sides must agree; mismatch aborts)

  # Chat: type lines, Enter to send. Commands: /rekey /ping /quit

  python qarke_tunnel_v13.py --selftest   # loopback crypto self-test
"""
import argparse
import collections
import hashlib
import hmac
import json
import math
import os
import queue
import socket
import struct
import sys
import threading
import time

import nacl.signing
import nacl.bindings
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

# --------------------------------------------------------------------------
# Phase 4: ML-DSA-65 (FIPS 204, real lattice crypto) + hybrid identity
# --------------------------------------------------------------------------
# Vendored from dilithium-py (GiacomoPope, MIT/Apache-2.0), cross-validated.
# Integrated from qarke_hybrid_sig_v2.py (phone-verified 9/9).
# ======== REAL ML-DSA-65 (vendored, FIPS 204) ========
# Cross-validated against reference implementation.
# ======== utilities/utils.py ========

def reduce_mod_pm(r, n):
    """
    Takes an integer 0 < r < n and computes the value
    r' = r mod^± n, defined to be integer in the range

    for n even:
        -(n / 2) < r' <= (n / 2)
    for n odd:
        -(n - 1) / 2 <= r' <= (n - 1) / 2
    """
    r = r % n
    if r > (n >> 1):
        r -= n
    return r


def decompose(r, a, q):
    """
    Takes an element r and represents
    it as:

    r = r1*a + r0

    With r0 in the range

    -(a << 1) < r0 <= (a << 1)
    """
    rp = r % q
    r0 = reduce_mod_pm(rp, a)
    r1 = rp - r0
    if rp - r0 == q - 1:
        r1 = 0
        r0 = r0 - 1
    else:
        r1 = (rp - r0) // a

    # assert r0 > -(a >> 1)
    # assert r0 <= (a >> 1)
    # assert r % q == (r0 + r1 * a) % q
    return r1, r0


def high_bits(r, a, q):
    r1, _ = decompose(r, a, q)
    return r1


def low_bits(r, a, q):
    _, r0 = decompose(r, a, q)
    return r0


def make_hint(z, r, a, q):
    """
    Check whether the top bit of z will change when r is added
    """
    r1 = high_bits(r, a, q)
    v1 = high_bits(r + z, a, q)
    return int(r1 != v1)


def make_hint_optimised(z0, r1, a, q):
    """
    Optimised version of the above used when the low bits w0 are extracted from
    `w = (A_hat @ y_hat).from_ntt()` during signing
    """
    gamma2 = a >> 1
    if z0 <= gamma2 or z0 > (q - gamma2) or (z0 == (q - gamma2) and r1 == 0):
        return 0
    return 1


def use_hint(h, r, a, q):
    m = (q - 1) // a
    r1, r0 = decompose(r, a, q)
    if h == 1:
        if r0 > 0:
            return (r1 + 1) % m
        return (r1 - 1) % m
    return r1


def check_norm_bound(n, b, q):
    """
    Norm bound is checked in the following four steps:
    x ∈ {0,        ...,                    ...,     q-1}
    x ∈ {-(q-1)/2, ...,       -1,       0, ..., (q-1)/2}
    x ∈ { (q-3)/2, ...,        0,       0, ..., (q-1)/2}
    x ∈ {0, 1,     ...,  (q-1)/2, (q-1)/2, ...,       1}
    """
    x = n % q
    x = ((q - 1) >> 1) - x
    x = x ^ (x >> 31)
    x = ((q - 1) >> 1) - x
    return x >= b


def xor_bytes(a, b):
    """
    XOR two byte arrays, assume that they are
    of the same length
    """
    return bytes(a ^ b for a, b in zip(a, b))


# ======== shake/shake_wrapper.py ========

from hashlib import shake_128, shake_256

"""
hashlib has implemented shake_128, shake_256 but they haven't designed it so you
can read bytes properly... every call generates all bytes without updating

shake_128.digest(1) == shake_128.digest(1)

and we have no shake_128.read() :(

So, here's a wrapper which calls to shake_128.digest and collects a bunch of
bytes which we can then read through.
"""


class Shake:
    def __init__(self, algorithm, block_length):
        self.algorithm = algorithm
        self.block_length = block_length
        self.buf = b""
        self.len_buf = 0

    def absorb(self, input_bytes):
        """
        Initialise the XOF with the seed and reset other init.
        """
        # Initalize the buffer
        self.index = 0

        # Set the reading method from hashlib digest
        self.xof_read = self.algorithm(input_bytes).digest

        # Start by requesting 5 blocks from the XOF
        self.buf = self.xof_read(5 * self.block_length)
        self.len_buf = 5 * self.block_length

    def read(self, n):
        """
        Read n bytes from the XOF
        """
        # Make sure there are enough bytes to read
        while self.index + n > self.len_buf:
            # double the size of the buffer
            self.len_buf *= 2
            self.buf = self.xof_read(self.len_buf)

        # Read from the buffer data the bytes requested
        send = self.buf[self.index : self.index + n]

        # Shift the index along the buffer
        self.index += n

        return send

    def __call__(self, input_bytes):
        self.absorb(input_bytes)
        return self


shake128 = Shake(shake_128, 168)
shake256 = Shake(shake_256, 136)


# ======== polynomials/polynomials_generic.py ========

import random


class PolynomialRingGeneric:
    """
    Initialise the polynomial ring:

        R = GF(q) / (X^n + 1)
    """

    def __init__(self, q, n):
        self.q = q
        self.n = n
        self.element = PolynomialGeneric

    def zero(self):
        """
        Return the value `0` of the polynomial ring
        """
        return self([0])

    def gen(self):
        """
        Return the generator `x` of the polynomial ring
        """
        return self([0, 1])

    def random_element(self):
        """
        Compute a random element of the polynomial ring with coefficients in the
        canonical range: ``[0, q-1]``
        """
        coefficients = [random.randint(0, self.q - 1) for _ in range(self.n)]
        return self(coefficients)

    def __call__(self, coefficients):
        if isinstance(coefficients, int):
            return self.element(self, [coefficients])
        if not isinstance(coefficients, list):
            raise TypeError(
                f"Polynomials should be constructed from a list of integers, of length at most d = {self.n}"
            )
        return self.element(self, coefficients)

    def __repr__(self):
        return f"Univariate Polynomial Ring in x over Finite Field of size {self.q} with modulus x^{self.n} + 1"


class PolynomialGeneric:
    def __init__(self, parent, coefficients):
        self.parent = parent
        self.coeffs = self._parse_coefficients(coefficients)

    def is_zero(self):
        """
        Return if polynomial is zero: f = 0
        """
        return all(c == 0 for c in self.coeffs)

    def is_constant(self):
        """
        Return if polynomial is constant: f = c
        """
        return all(c == 0 for c in self.coeffs[1:])

    def _parse_coefficients(self, coefficients):
        """
        Helper function which right pads with zeros
        to allow polynomial construction as
        f = R([1,1,1])
        """
        l = len(coefficients)
        if l > self.parent.n:
            raise ValueError(
                f"Coefficients describe polynomial of degree greater than maximum degree {self.parent.n}"
            )
        elif l < self.parent.n:
            coefficients = coefficients + [0 for _ in range(self.parent.n - l)]
        return coefficients

    def reduce_coefficients(self):
        """
        Reduce all coefficients modulo q
        """
        self.coeffs = [c % self.parent.q for c in self.coeffs]
        return self

    def _add_mod_q(self, x, y):
        """
        add two coefficients modulo q
        """
        return (x + y) % self.parent.q

    def _sub_mod_q(self, x, y):
        """
        sub two coefficients modulo q
        """
        return (x - y) % self.parent.q

    def _schoolbook_multiplication(self, other):
        """
        Naive implementation of polynomial multiplication
        suitible for all R_q = F_1[X]/(X^n + 1)
        """
        n = self.parent.n
        a = self.coeffs
        b = other.coeffs
        new_coeffs = [0 for _ in range(n)]
        for i in range(n):
            for j in range(0, n - i):
                new_coeffs[i + j] += a[i] * b[j]
        for j in range(1, n):
            for i in range(n - j, n):
                new_coeffs[i + j - n] -= a[i] * b[j]
        return [c % self.parent.q for c in new_coeffs]

    def __neg__(self):
        """
        Returns -f, by negating all coefficients
        """
        neg_coeffs = [(-x % self.parent.q) for x in self.coeffs]
        return self.parent(neg_coeffs)

    def _add_(self, other):
        if isinstance(other, type(self)):
            new_coeffs = [
                self._add_mod_q(x, y) for x, y in zip(self.coeffs, other.coeffs)
            ]
        elif isinstance(other, int):
            new_coeffs = self.coeffs.copy()
            new_coeffs[0] = self._add_mod_q(new_coeffs[0], other)
        else:
            raise NotImplementedError("Polynomials can only be added to each other")
        return new_coeffs

    def __add__(self, other):
        new_coeffs = self._add_(other)
        return self.parent(new_coeffs)

    def __radd__(self, other):
        return self.__add__(other)

    def __iadd__(self, other):
        self = self + other
        return self

    def _sub_(self, other):
        if isinstance(other, type(self)):
            new_coeffs = [
                self._sub_mod_q(x, y) for x, y in zip(self.coeffs, other.coeffs)
            ]
        elif isinstance(other, int):
            new_coeffs = self.coeffs.copy()
            new_coeffs[0] = self._sub_mod_q(new_coeffs[0], other)
        else:
            raise NotImplementedError(
                "Polynomials can only be subtracted from each other"
            )
        return new_coeffs

    def __sub__(self, other):
        new_coeffs = self._sub_(other)
        return self.parent(new_coeffs)

    def __rsub__(self, other):
        return -self.__sub__(other)

    def __isub__(self, other):
        self = self - other
        return self

    def __mul__(self, other):
        if isinstance(other, type(self)):
            new_coeffs = self._schoolbook_multiplication(other)
        elif isinstance(other, int):
            new_coeffs = [(c * other) % self.parent.q for c in self.coeffs]
        else:
            raise NotImplementedError(
                "Polynomials can only be multiplied by each other, or scaled by integers"
            )
        return self.parent(new_coeffs)

    def __rmul__(self, other):
        return self.__mul__(other)

    def __imul__(self, other):
        self = self * other
        return self

    def __pow__(self, n):
        if not isinstance(n, int):
            raise TypeError(
                "Exponentiation of a polynomial must be done using an integer."
            )

        # Deal with negative scalar multiplication
        if n < 0:
            raise ValueError(
                "Negative powers are not supported for elements of a Polynomial Ring"
            )
        f = self
        g = self.parent(1)
        while n > 0:
            if n % 2 == 1:
                g = g * f
            f = f * f
            n = n // 2
        return g

    def __eq__(self, other):
        if isinstance(other, type(self)):
            return self.coeffs == other.coeffs
        elif isinstance(other, int):
            if self.is_constant() and (other % self.parent.q) == self.coeffs[0]:
                return True
        return False

    def __getitem__(self, idx):
        return self.coeffs[idx]

    def __repr__(self):
        if self.is_zero():
            return "0"

        info = []
        for i, c in enumerate(self.coeffs):
            if c != 0:
                if i == 0:
                    info.append(f"{c}")
                elif i == 1:
                    if c == 1:
                        info.append("x")
                    else:
                        info.append(f"{c}*x")
                else:
                    if c == 1:
                        info.append(f"x^{i}")
                    else:
                        info.append(f"{c}*x^{i}")
        return " + ".join(info)

    def __str__(self):
        return self.__repr__()


# ======== polynomials/polynomials.py ========




class PolynomialRing(PolynomialRingGeneric):
    def __init__(self):
        self.q = 8380417
        self.n = 256
        self.element = Polynomial
        self.element_ntt = PolynomialNTT

        root_of_unity = 1753
        self.ntt_zetas = [
            pow(root_of_unity, self.br(i, 8), 8380417) for i in range(256)
        ]
        self.ntt_f = pow(256, -1, 8380417)

    @staticmethod
    def br(i, k):
        """
        bit reversal of an unsigned k-bit integer
        """
        bin_i = bin(i & (2**k - 1))[2:].zfill(k)
        return int(bin_i[::-1], 2)

    def sample_in_ball(self, seed, tau):
        """
        Figure 2 (Sample in Ball)
            https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf

        Create a random 256-element array with τ ±1’s and (256 − τ) 0′s using
        the input seed ρ (and an SHAKE256) to generate the randomness needed
        """

        def rejection_sample(i, xof):
            """
            Sample random bytes from `xof_bytes` and
            interpret them as integers in {0, ..., 255}

            Rejects values until a value j <= i is found
            """
            while True:
                j = xof.read(1)[0]
                if j <= i:
                    return j

        # Initialise the XOF
        xof = shake256(seed)

        # Set the first 8 bytes for the sign, and leave the rest for
        # sampling.
        sign_bytes = xof.read(8)
        sign_int = int.from_bytes(sign_bytes, "little")

        # Set the list of coeffs to be 0
        coeffs = [0 for _ in range(256)]

        # Now set tau values of coeffs to be ±1
        for i in range(256 - tau, 256):
            j = rejection_sample(i, xof)
            coeffs[i] = coeffs[j]
            coeffs[j] = 1 - 2 * (sign_int & 1)
            sign_int >>= 1

        return self(coeffs)

    def rejection_sample_ntt_poly(self, rho, i, j):
        """
        Samples an element in the NTT domain of R^q using rejection sampling
        """

        def rejection_sample(xof):
            """
            Sample three random bytes from `xof` and
            interpret them as integers in {0, ..., 2^23 - 1}

            Rejects values until a value j < q is found
            """
            while True:
                j_bytes = xof.read(3)
                j = int.from_bytes(j_bytes, "little")
                j &= 0x7FFFFF
                if j < 8380417:
                    return j

        # Initialise the XOF
        seed = rho + bytes([j, i])
        xof = shake128(seed)
        coeffs = [rejection_sample(xof) for _ in range(256)]
        return self(coeffs, is_ntt=True)

    def rejection_bounded_poly(self, rho_prime, i, eta):
        """
        Computes an element of the polynomial ring with coefficients between
        -eta and eta using rejection sampling from an XOF
        """

        def coefficient_from_half_byte(j, eta):
            """
            Rejects values until a value j < 2η is found
            """
            if eta == 2 and j < 15:
                return 2 - (j % 5)
            elif j < 9:
                assert eta == 4
                return 4 - j
            return False

        # Initialise the XOF
        seed = rho_prime + int.to_bytes(i, 2, "little")
        xof = shake256(seed)

        # Sample bytes for all n coeffs
        i = 0
        coeffs = [0 for _ in range(256)]
        while i < 256:
            # Consider two values for each byte (top and bottom four bits)
            j = xof.read(1)[0]

            c0 = coefficient_from_half_byte(j % 16, eta)
            if c0 is not False:
                coeffs[i] = c0
                i += 1

            c1 = coefficient_from_half_byte(j // 16, eta)
            if c1 is not False and i < 256:
                coeffs[i] = c1
                i += 1

        return self(coeffs)

    def sample_mask_polynomial(self, rho_prime, i, kappa, gamma_1):
        """
        Samples an element in the polynomial ring with elements bounded
        between -gamma_1 + 1 and gamma_1.
        """
        if gamma_1 == (1 << 17):
            bit_count = 18
            total_bytes = 576  # (256 * 18) / 8
        else:
            bit_count = 20
            total_bytes = 640  # (256 * 20) / 8

        # Initialise the XOF
        seed = rho_prime + int.to_bytes(kappa + i, 2, "little")
        xof_bytes = shake256(seed).read(total_bytes)
        r = int.from_bytes(xof_bytes, "little")
        mask = (1 << bit_count) - 1
        coeffs = [gamma_1 - ((r >> bit_count * i) & mask) for i in range(self.n)]

        return self(coeffs)

    def __bit_unpack(self, input_bytes, n_bits):
        if (len(input_bytes) * n_bits) % 8 != 0:
            raise ValueError(
                "Input bytes do not have a length compatible with the bit length"
            )

        r = int.from_bytes(input_bytes, "little")
        mask = (1 << n_bits) - 1
        return [(r >> n_bits * i) & mask for i in range(self.n)]

    def bit_unpack_t0(self, input_bytes):
        altered_coeffs = self.__bit_unpack(input_bytes, 13)
        coefficients = [(1 << 12) - c for c in altered_coeffs]
        return self(coefficients)

    def bit_unpack_t1(self, input_bytes):
        coefficients = self.__bit_unpack(input_bytes, 10)
        return self(coefficients)

    def bit_unpack_s(self, input_bytes, eta):
        # Level 2 and 5 parameter set
        if eta == 2:
            altered_coeffs = self.__bit_unpack(input_bytes, 3)
        # Level 3 parameter set
        else:
            assert eta == 4, f"Expected eta to be either 2 or 4, got {eta = }"
            altered_coeffs = self.__bit_unpack(input_bytes, 4)

        coefficients = [eta - c for c in altered_coeffs]
        return self(coefficients)

    def bit_unpack_w(self, input_bytes, gamma_2):
        # Level 2 parameter set
        if gamma_2 == 95232:
            coefficients = self.__bit_unpack(input_bytes, 6)
        # Level 3 and 5 parameter set
        else:
            assert gamma_2 == 261888, (
                f"Expected gamma_2 to be either (q-1)/88 or (q-1)/32, got {gamma_2 = }"
            )
            coefficients = self.__bit_unpack(input_bytes, 4)

        return self(coefficients)

    def bit_unpack_z(self, input_bytes, gamma_1):
        # Level 2 parameter set
        if gamma_1 == (1 << 17):
            altered_coeffs = self.__bit_unpack(input_bytes, 18)
        # Level 3 and 5 parameter set
        else:
            assert gamma_1 == (1 << 19), (
                f"Expected gamma_1 to be either 2^17 or 2^19, got {gamma_1 = }"
            )
            altered_coeffs = self.__bit_unpack(input_bytes, 20)

        coefficients = [gamma_1 - c for c in altered_coeffs]
        return self(coefficients)

    def __call__(self, coefficients, is_ntt=False):
        if not is_ntt:
            element = self.element
        else:
            element = self.element_ntt

        if isinstance(coefficients, int):
            return element(self, [coefficients])
        if not isinstance(coefficients, list):
            raise TypeError(
                f"Polynomials should be constructed from a list of integers, of length at most d = {256}"
            )
        return element(self, coefficients)


class Polynomial(PolynomialGeneric):
    def __init__(self, parent, coefficients):
        self.parent = parent
        self.coeffs = self._parse_coefficients(coefficients)

    def to_ntt(self):
        """
        Convert a polynomial to number-theoretic transform (NTT)
        """
        k, l = 0, 128
        coeffs = self.coeffs[:]
        zetas = self.parent.ntt_zetas
        while l > 0:
            start = 0
            while start < 256:
                k = k + 1
                zeta = zetas[k]
                j = start
                for j in range(start, start + l):
                    t = zeta * coeffs[j + l]
                    coeffs[j + l] = coeffs[j] - t
                    coeffs[j] = coeffs[j] + t
                start = l + (j + 1)
            l >>= 1

        for j in range(256):
            coeffs[j] = coeffs[j] % 8380417

        return self.parent(coeffs, is_ntt=True)

    def from_ntt(self):
        raise TypeError(f"Polynomial is of type: {type(self)}")

    def power_2_round(self, d):
        power_2 = 1 << d
        r1_coeffs = []
        r0_coeffs = []
        for c in self.coeffs:
            r = c % self.parent.q
            r0 = reduce_mod_pm(r, power_2)
            r1_coeffs.append((r - r0) >> d)
            r0_coeffs.append(r0)

        r1_poly = self.parent(r1_coeffs)
        r0_poly = self.parent(r0_coeffs)

        return r1_poly, r0_poly

    def high_bits(self, alpha, is_ntt=False):
        coeffs = [high_bits(c, alpha, self.parent.q) for c in self.coeffs]
        return self.parent(coeffs, is_ntt=is_ntt)

    def low_bits(self, alpha, is_ntt=False):
        coeffs = [low_bits(c, alpha, self.parent.q) for c in self.coeffs]
        return self.parent(coeffs, is_ntt=is_ntt)

    """
    Compute the high and low bits at the same time
    Not in the pseudocode, but needed for the more
    efficient signing which we implement based on
    section 5.1
    """

    def decompose(self, alpha):
        coeff_high = []
        coeff_low = []
        for c in self.coeffs:
            r1, r0 = decompose(c, alpha, self.parent.q)
            coeff_high.append(r1)
            coeff_low.append(r0)
        return self.parent(coeff_high), self.parent(coeff_low)

    def check_norm_bound(self, bound):
        """
        Returns true if the inf norm of any coeff
        is greater or equal to the bound.
        """
        return any(check_norm_bound(c, bound, self.parent.q) for c in self.coeffs)

    """
    The following bit_pack functions are specific for Dilithium
    but are currently added as methods for the Polynomial class
    as it seemed the most natural way to do this.
    """

    @staticmethod
    def __bit_pack(coeffs, n_bits, n_bytes):
        r = 0
        for c in reversed(coeffs):
            r <<= n_bits
            r |= c
        return r.to_bytes(n_bytes, "little")

    def bit_pack_t0(self):
        # 416 = 256 * 13 // 8
        altered_coeffs = [(1 << 12) - c for c in self.coeffs]
        return self.__bit_pack(altered_coeffs, 13, 416)

    def bit_pack_t1(self):
        # 320 = 256 * 10 // 8
        return self.__bit_pack(self.coeffs, 10, 320)

    def bit_pack_s(self, eta):
        altered_coeffs = [self._sub_mod_q(eta, c) for c in self.coeffs]
        # Level 2 and 5 parameter set
        if eta == 2:
            return self.__bit_pack(altered_coeffs, 3, 96)
        # Level 3 parameter set
        assert eta == 4, f"Expected eta to be either 2 or 4, got {eta = }"
        return self.__bit_pack(altered_coeffs, 4, 128)

    def bit_pack_w(self, gamma_2):
        # Level 2 parameter set
        if gamma_2 == 95232:
            return self.__bit_pack(self.coeffs, 6, 192)
        # Level 3 and 5 parameter set
        assert gamma_2 == 261888, (
            f"Expected gamma_2 to be either (q-1)/88 or (q-1)/32, got {gamma_2 = }"
        )
        return self.__bit_pack(self.coeffs, 4, 128)

    def bit_pack_z(self, gamma_1):
        altered_coeffs = [self._sub_mod_q(gamma_1, c) for c in self.coeffs]
        # Level 2 parameter set
        if gamma_1 == (1 << 17):
            return self.__bit_pack(altered_coeffs, 18, 576)
        # Level 3 and 5 parameter set
        assert gamma_1 == (1 << 19), (
            f"Expected gamma_1 to be either 2^17 or 2^19, got: {gamma_1 = }"
        )
        return self.__bit_pack(altered_coeffs, 20, 640)

    def make_hint(self, other, alpha):
        coeffs = [
            make_hint(r, z, alpha, 8380417) for r, z in zip(self.coeffs, other.coeffs)
        ]
        return self.parent(coeffs)

    def make_hint_optimised(self, other, alpha):
        coeffs = [
            make_hint_optimised(r, z, alpha, 8380417)
            for r, z in zip(self.coeffs, other.coeffs)
        ]
        return self.parent(coeffs)

    def use_hint(self, other, alpha):
        coeffs = [
            use_hint(h, r, alpha, 8380417) for h, r in zip(self.coeffs, other.coeffs)
        ]
        return self.parent(coeffs)


class PolynomialNTT(Polynomial):
    def __init__(self, parent, coefficients):
        self.parent = parent
        self.coeffs = self._parse_coefficients(coefficients)

    def to_ntt(self):
        raise TypeError(f"Polynomial is of type: {type(self)}")

    def from_ntt(self):
        """
        Convert a polynomial from number-theoretic transform (NTT) form in place
        The input is in bit-reversed order, the output is in standard order.
        """
        l, k = 1, 256
        coeffs = self.coeffs[:]
        zetas = self.parent.ntt_zetas
        while l < 256:
            start = 0
            while start < 256:
                k = k - 1
                zeta = -zetas[k]
                j = start
                for j in range(start, start + l):
                    t = coeffs[j]
                    coeffs[j] = t + coeffs[j + l]
                    coeffs[j + l] = t - coeffs[j + l]
                    coeffs[j + l] = zeta * coeffs[j + l]
                start = j + l + 1
            l = l << 1

        for j in range(256):
            coeffs[j] = (coeffs[j] * self.parent.ntt_f) % 8380417

        return self.parent(coeffs, is_ntt=False)

    def ntt_coefficient_multiplication(self, f_coeffs, g_coeffs):
        return [(c1 * c2) % 8380417 for c1, c2 in zip(f_coeffs, g_coeffs)]

    def ntt_multiplication(self, other):
        """
        Number Theoretic Transform multiplication.
        """
        if not isinstance(other, type(self)):
            raise ValueError

        new_coeffs = self.ntt_coefficient_multiplication(self.coeffs, other.coeffs)
        return new_coeffs

    def __add__(self, other):
        new_coeffs = self._add_(other)
        return self.parent(new_coeffs, is_ntt=True)

    def __sub__(self, other):
        new_coeffs = self._sub_(other)
        return self.parent(new_coeffs, is_ntt=True)

    def __mul__(self, other):
        if isinstance(other, type(self)):
            new_coeffs = self.ntt_multiplication(other)
        elif isinstance(other, int):
            new_coeffs = [(c * other) % 8380417 for c in self.coeffs]
        else:
            raise NotImplementedError(
                f"Polynomials can only be multiplied by each other, or scaled by integers, {type(other) = }, {type(self) = }"
            )
        return self.parent(new_coeffs, is_ntt=True)


# ======== modules/modules_generic.py ========

class MatrixGeneric:
    def __init__(self, parent, matrix_data, transpose=False):
        self.parent = parent
        self._data = matrix_data
        self._transpose = transpose
        if not self._check_dimensions():
            raise ValueError("Inconsistent row lengths in matrix")

    def _check_dimensions(self):
        """
        Ensure that the matrix is rectangular
        """
        return len(set(map(len, self._data))) == 1

    def dim(self):
        """
        Return the dimensions of the matrix with m rows
        and n columns

        :return: the dimension of the matrix ``(m, n)``
        :rtype: tuple(int, int)
        """
        if not self._transpose:
            return len(self._data), len(self._data[0])
        else:
            return len(self._data[0]), len(self._data)

    def transpose(self):
        """
        Return a matrix with the rows and columns of swapped
        """
        return self.parent(self._data, not self._transpose)

    def transpose_self(self):
        """
        Swap the rows and columns of the matrix in place
        """
        self._transpose = not self._transpose
        return

    T = property(transpose)

    def reduce_coefficients(self):
        """
        Reduce every element in the polynomial
        using the modulus of the PolynomialRing
        """
        for row in self._data:
            for ele in row:
                ele.reduce_coefficients()
        return self

    def __getitem__(self, idx):
        """
        matrix[i, j] returns the element on row i, column j
        """
        assert isinstance(idx, tuple) and len(idx) == 2, "Can't access individual rows"
        if not self._transpose:
            return self._data[idx[0]][idx[1]]
        else:
            return self._data[idx[1]][idx[0]]

    def rows(self):
        """
        Return the rows of `self`
        """
        if not self._transpose:
            return zip(*self._data)
        else:
            return self._data

    def __eq__(self, other):
        if self.dim() != other.dim():
            return False
        m, n = self.dim()
        return all([self[i, j] == other[i, j] for i in range(m) for j in range(n)])

    def __neg__(self):
        """
        Returns -self, by negating all elements
        """
        m, n = self.dim()
        return self.parent(
            [[-self[i, j] for j in range(n)] for i in range(m)],
            False,
        )

    def __add__(self, other):
        if not isinstance(other, MatrixGeneric):
            raise TypeError("Can only add matrices to other matrices")
        if self.parent != other.parent:
            raise TypeError("Matrices must have the same base ring")
        if self.dim() != other.dim():
            raise ValueError("Matrices are not of the same dimensions")

        m, n = self.dim()
        return self.parent(
            [[self[i, j] + other[i, j] for j in range(n)] for i in range(m)],
            False,
        )

    def __iadd__(self, other):
        self = self + other
        return self

    def __sub__(self, other):
        if not isinstance(other, MatrixGeneric):
            raise TypeError("Can only add matrices to other matrices")
        if self.parent != other.parent:
            raise TypeError("Matrices must have the same base ring")
        if self.dim() != other.dim():
            raise ValueError("Matrices are not of the same dimensions")

        m, n = self.dim()
        return self.parent(
            [[self[i, j] - other[i, j] for j in range(n)] for i in range(m)],
            False,
        )

    def __isub__(self, other):
        self = self - other
        return self

    def __matmul__(self, other):
        """
        Denoted A @ B
        """
        if not isinstance(other, MatrixGeneric):
            raise TypeError("Can only multiply matrcies with other matrices")
        if self.parent != other.parent:
            raise TypeError("Matrices must have the same base ring")

        m, n = self.dim()
        n_, l = other.dim()
        if not n == n_:
            raise ValueError("Matrices are of incompatible dimensions")

        return self.parent(
            [
                [sum(self[i, k] * other[k, j] for k in range(n)) for j in range(l)]
                for i in range(m)
            ]
        )

    def scale(self, other):
        """
        Multiply each element of the matrix by a polynomial or integer
        """
        if not (isinstance(other, self.parent.ring.element) or isinstance(other, int)):
            raise TypeError("Can only multiply elements with polynomials or integers")

        matrix = [[other * ele for ele in row] for row in self._data]
        return self.parent(matrix, transpose=self._transpose)

    def dot(self, other):
        """
        Compute the inner product of two vectors
        """
        if not isinstance(other, MatrixGeneric):
            raise TypeError("Can only perform dot product with other matrices")
        res = self.T @ other
        assert res.dim() == (1, 1)
        return res[0, 0]

    def __repr__(self):
        m, n = self.dim()

        if m == 1 and n == 1:
            return str(self._data[0])

        max_col_width = [max(len(str(self[i, j])) for i in range(m)) for j in range(n)]
        info = "]\n[".join(
            [
                ", ".join([f"{str(self[i, j]):>{max_col_width[j]}}" for j in range(n)])
                for i in range(m)
            ]
        )
        return f"[{info}]"


class ModuleGeneric:
    def __init__(self, ring):
        """
        Initialise a module over the ring ``ring``.
        """
        self.ring = ring
        self.matrix_element = MatrixGeneric

    def random_element(self, m, n):
        """
        Generate a random element of the module of dimension m x n

        :param int m: the number of rows in the matrix
        :param int m: the number of columns in tge matrix
        :return: an element of the module with dimension `m times n`
        """
        elements = [[self.ring.random_element() for _ in range(n)] for _ in range(m)]
        return self(elements)

    def __repr__(self):
        return f"Module over the commutative ring: {self.ring}"

    def __str__(self):
        return f"Module over the commutative ring: {self.ring}"

    def __call__(self, matrix_elements, transpose=False):
        if not isinstance(matrix_elements, list):
            raise TypeError(
                "elements of a module are matrices, built from elements of the base ring"
            )

        if isinstance(matrix_elements[0], list):
            for element_list in matrix_elements:
                if not all(isinstance(aij, self.ring.element) for aij in element_list):
                    raise TypeError(
                        f"All elements of the matrix must be elements of the ring: {self.ring}"
                    )
            return self.matrix_element(self, matrix_elements, transpose=transpose)

        elif isinstance(matrix_elements[0], self.ring.element):
            if not all(isinstance(aij, self.ring.element) for aij in matrix_elements):
                raise TypeError(
                    f"All elements of the matrix must be elements of the ring: {self.ring}"
                )
            return self.matrix_element(self, [matrix_elements], transpose=transpose)

        else:
            raise TypeError(
                "elements of a module are matrices, built from elements of the base ring"
            )


# ======== modules/modules.py ========

from typing import cast


class Matrix(MatrixGeneric):
    def __init__(self, parent, matrix_data, transpose=False):
        super().__init__(parent, matrix_data, transpose=transpose)

    def check_norm_bound(self, bound):
        for row in self._data:
            if any(p.check_norm_bound(bound) for p in row):
                return True
        return False

    def power_2_round(self, d):
        """
        Applies `power_2_round` on every element in the
        Matrix to create two matrices.
        """
        m, n = self.dim()

        m1_elements = [[0 for _ in range(n)] for _ in range(m)]
        m0_elements = [[0 for _ in range(n)] for _ in range(m)]

        for i in range(m):
            for j in range(n):
                m1_ele, m0_ele = self[i, j].power_2_round(d)
                m1_elements[i][j] = m1_ele
                m0_elements[i][j] = m0_ele

        return self.parent(m1_elements, transpose=self._transpose), self.parent(
            m0_elements, transpose=self._transpose
        )

    def decompose(self, alpha):
        """
        Applies `power_2_round` on every element in the
        Matrix to create two matrices.
        """
        m, n = self.dim()

        m1_elements = [[0 for _ in range(n)] for _ in range(m)]
        m0_elements = [[0 for _ in range(n)] for _ in range(m)]

        for i in range(m):
            for j in range(n):
                m1_ele, m0_ele = self[i, j].decompose(alpha)
                m1_elements[i][j] = m1_ele
                m0_elements[i][j] = m0_ele

        return self.parent(m1_elements, transpose=self._transpose), self.parent(
            m0_elements, transpose=self._transpose
        )

    def __bit_pack(self, algorithm, *args):
        return b"".join(algorithm(poly, *args) for row in self.rows() for poly in row)

    def bit_pack_t1(self):
        algorithm = self.parent.ring.element.bit_pack_t1
        return self.__bit_pack(algorithm)

    def bit_pack_t0(self):
        algorithm = self.parent.ring.element.bit_pack_t0
        return self.__bit_pack(algorithm)

    def bit_pack_s(self, eta):
        algorithm = self.parent.ring.element.bit_pack_s
        return self.__bit_pack(algorithm, eta)

    def bit_pack_w(self, gamma_2):
        algorithm = self.parent.ring.element.bit_pack_w
        return self.__bit_pack(algorithm, gamma_2)

    def bit_pack_z(self, gamma_1):
        algorithm = self.parent.ring.element.bit_pack_z
        return self.__bit_pack(algorithm, gamma_1)

    def to_ntt(self):
        """
        Convert every element of the matrix into NTT form
        """
        data = [[x.to_ntt() for x in row] for row in self._data]
        return self.parent(data, self._transpose)

    def from_ntt(self):
        """
        Convert every element of the matrix from NTT form
        """
        data = [[x.from_ntt() for x in row] for row in self._data]
        return self.parent(data, self._transpose)

    def high_bits(self, alpha, is_ntt=False):
        matrix = [
            [ele.high_bits(alpha, is_ntt=is_ntt) for ele in row] for row in self.rows()
        ]
        return self.parent(matrix)

    def low_bits(self, alpha, is_ntt=False):
        matrix = [
            [ele.low_bits(alpha, is_ntt=is_ntt) for ele in row] for row in self.rows()
        ]
        return self.parent(matrix)

    def make_hint(self, other, alpha):
        """
        Figure 3 (Supporting algorithms for Dilithium)
        https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf
        """
        matrix = [
            [p.make_hint(q, alpha) for p, q in zip(r1, r2)]
            for r1, r2 in zip(self.rows(), other.rows())
        ]
        return self.parent(matrix)

    def make_hint_optimised(self, other, alpha):
        """
        Figure 3 (Supporting algorithms for Dilithium)
        https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf
        """
        matrix = [
            [p.make_hint_optimised(q, alpha) for p, q in zip(r1, r2)]
            for r1, r2 in zip(self.rows(), other.rows())
        ]
        return self.parent(matrix)

    def use_hint(self, other, alpha):
        """
        Figure 3 (Supporting algorithms for Dilithium)
        https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf
        """
        matrix = [
            [p.use_hint(q, alpha) for p, q in zip(r1, r2)]
            for r1, r2 in zip(self.rows(), other.rows())
        ]
        return self.parent(matrix)

    def sum_hint(self):
        """
        Helper function to count the number of coeffs == 1
        in all the polynomials of a matrix
        """
        return sum(c for row in self.rows() for p in row for c in p)


class Vector(Matrix):
    def __init__(self, parent, vector_elements):
        super().__init__(parent, [vector_elements], transpose=True)


class Module(ModuleGeneric):
    def __init__(self):
        self.ring = PolynomialRing()
        self.matrix_element = Matrix
        self.vector_element = Vector

    def __call__(self, matrix_elements, transpose=False) -> Matrix:
        """
        NOTE: This is simply a wrapper function of the Module method to ensure correct
        type casting
        """
        mat = super().__call__(matrix_elements, transpose)
        return cast(Matrix, mat)

    def vector(self, elements) -> Vector:
        """
        Construct a vector given a list of elements of the module's ring

        :param list: a list of elements of the ring
        :return: a vector of the module
        """
        return Vector(self, elements)

    def __bit_unpack(self, input_bytes, k, alg, packed_len, *args) -> Vector:
        poly_bytes = [
            input_bytes[i : i + packed_len]
            for i in range(0, len(input_bytes), packed_len)
        ]
        matrix = [alg(poly_bytes[i], *args) for i in range(k)]
        return self.vector(matrix)

    def bit_unpack_t0(self, input_bytes, k) -> Vector:
        packed_len = 416
        algorithm = self.ring.bit_unpack_t0
        return self.__bit_unpack(input_bytes, k, algorithm, packed_len)

    def bit_unpack_t1(self, input_bytes, k):
        packed_len = 320
        algorithm = self.ring.bit_unpack_t1
        return self.__bit_unpack(input_bytes, k, algorithm, packed_len)

    def bit_unpack_s(self, input_bytes, k, eta) -> Vector:
        # Level 2 and 5 parameter set
        if eta == 2:
            packed_len = 96
        # Level 3 parameter set
        elif eta == 4:
            packed_len = 128
        else:
            raise ValueError("Expected eta to be either 2 or 4")
        algorithm = self.ring.bit_unpack_s
        return self.__bit_unpack(input_bytes, k, algorithm, packed_len, eta)

    def bit_unpack_w(self, input_bytes, k, gamma_2) -> Vector:
        # Level 2 parameter set
        if gamma_2 == 95232:
            packed_len = 192
        # Level 3 and 5 parameter set
        elif gamma_2 == 261888:
            packed_len = 128
        else:
            raise ValueError("Expected gamma_2 to be either (q-1)/88 or (q-1)/32")
        algorithm = self.ring.bit_unpack_w
        return self.__bit_unpack(input_bytes, k, algorithm, packed_len, gamma_2)

    def bit_unpack_z(self, input_bytes, k, gamma_1) -> Vector:
        # Level 2 parameter set
        if gamma_1 == (1 << 17):
            packed_len = 576
        # Level 3 and 5 parameter set
        elif gamma_1 == (1 << 19):
            packed_len = 640
        else:
            raise ValueError("Expected gamma_1 to be either 2^17 or 2^19")
        algorithm = self.ring.bit_unpack_z
        return self.__bit_unpack(input_bytes, k, algorithm, packed_len, gamma_1)


# ======== ml_dsa/ml_dsa.py ========

import os



class ML_DSA:
    def __init__(self, parameter_set: dict):
        self.d = parameter_set["d"]
        self.k = parameter_set["k"]
        self.l = parameter_set["l"]
        self.eta = parameter_set["eta"]
        self.tau = parameter_set["tau"]
        self.omega = parameter_set["omega"]
        self.gamma_1 = parameter_set["gamma_1"]
        self.gamma_2 = parameter_set["gamma_2"]
        self.beta = self.tau * self.eta
        self.c_tilde_bytes = parameter_set["c_tilde_bytes"]

        self.M = Module()
        self.R = self.M.ring
        self.oid = parameter_set["oid"] if "oid" in parameter_set else None

        # Use system randomness by default, for deterministic randomness
        # use the method `set_drbg_seed()`
        self.random_bytes = os.urandom

    def set_drbg_seed(self, seed: bytes):
        """
        Change entropy source to a DRBG and seed it with provided value.

        Setting the seed switches the entropy source from :func:`os.urandom()`
        to an AES256 CTR DRBG.

        Used for both deterministic versions of Kyber as well as testing
        alignment with the KAT vectors

        Note:
          currently requires pycryptodome for AES impl.
        """
        try:

            self._drbg = AES256_CTR_DRBG(seed)
            self.random_bytes = self._drbg.random_bytes
        except ImportError as e:  # pragma: no cover
            print(f"Error importing AES from pycryptodome: {e = }")
            raise Warning(
                "Cannot set DRBG seed due to missing dependencies, try installing requirements: pip -r install requirements"
            )

    """
    H() uses Shake256 to hash data to 32 and 64 bytes in a
    few places in the code
    """

    @staticmethod
    def _h(in_bytes: bytes, length: int) -> bytes:
        """
        H: B^*  -> B^*
        """
        return shake256(in_bytes).read(length)

    def _expand_matrix_from_seed(self, rho: bytes) -> Matrix:
        """
        Helper function which generates a element of size
        k x l from a seed `rho`.
        """
        A_data = [[self.R.zero() for _ in range(self.l)] for _ in range(self.k)]
        for i in range(self.k):
            for j in range(self.l):
                A_data[i][j] = self.R.rejection_sample_ntt_poly(rho, i, j)
        return self.M(A_data)

    def _expand_vector_from_seed(self, rho_prime: bytes) -> tuple[Vector, Vector]:
        s1_elements = [
            self.R.rejection_bounded_poly(rho_prime, i, self.eta) for i in range(self.l)
        ]
        s2_elements = [
            self.R.rejection_bounded_poly(rho_prime, i, self.eta)
            for i in range(self.l, self.l + self.k)
        ]

        s1 = self.M.vector(s1_elements)
        s2 = self.M.vector(s2_elements)
        return s1, s2

    def _expand_mask_vector(self, rho: bytes, mu: int) -> Vector:
        elements = [
            self.R.sample_mask_polynomial(rho, i, mu, self.gamma_1)
            for i in range(self.l)
        ]
        return self.M.vector(elements)

    @staticmethod
    def _pack_pk(rho: bytes, t1: Vector) -> bytes:
        return rho + t1.bit_pack_t1()

    def _pack_sk(
        self,
        rho: bytes,
        k: bytes,
        tr: bytes,
        s1: Vector,
        s2: Vector,
        t0: Vector,
    ) -> bytes:
        s1_bytes = s1.bit_pack_s(self.eta)
        s2_bytes = s2.bit_pack_s(self.eta)
        t0_bytes = t0.bit_pack_t0()
        return rho + k + tr + s1_bytes + s2_bytes + t0_bytes

    def _pack_h(self, h: Vector) -> bytes:
        non_zero_positions = [
            [i for i, c in enumerate(poly.coeffs) if c == 1]
            for row in h._data
            for poly in row
        ]
        packed = []
        offsets = []
        for positions in non_zero_positions:
            packed.extend(positions)
            offsets.append(len(packed))

        padding_len = self.omega - offsets[-1]
        packed.extend([0 for _ in range(padding_len)])
        return bytes(packed + offsets)

    def _pack_sig(self, c_tilde: bytes, z: Vector, h: Vector) -> bytes:
        return c_tilde + z.bit_pack_z(self.gamma_1) + self._pack_h(h)

    def _pk_size(self) -> int:
        return 32 + 32 * self.k * 10

    def _unpack_pk(self, pk: bytes) -> tuple[bytes, Vector]:
        if len(pk) != self._pk_size():
            raise ValueError("PK packed bytes is of the wrong length")
        rho, t1_bytes = pk[:32], pk[32:]
        t1 = self.M.bit_unpack_t1(t1_bytes, self.k)
        return rho, t1

    def _sk_size(self) -> int:
        if self.eta == 2:
            s_bytes = 96
        else:
            s_bytes = 128
        s1_len = s_bytes * self.l
        s2_len = s_bytes * self.k
        t0_len = 416 * self.k
        return 2 * 32 + 64 + s1_len + s2_len + t0_len

    def _sig_size(self) -> int:
        if self.gamma_1 == 131072:
            s_bytes = 18
        else:
            assert self.gamma_1 == 524288
            s_bytes = 20
        return self.c_tilde_bytes + self.l * 32 * s_bytes + self.omega + self.k

    def _unpack_sk(
        self, sk: bytes
    ) -> tuple[bytes, bytes, bytes, Vector, Vector, Vector]:
        if self.eta == 2:
            s_bytes = 96
        else:
            s_bytes = 128
        s1_len = s_bytes * self.l
        s2_len = s_bytes * self.k
        t0_len = 416 * self.k
        if len(sk) != self._sk_size():
            raise ValueError("sk packed bytes is of the wrong length")

        # Split bytes between seeds and vectors
        sk_seed_bytes, sk_vec_bytes = sk[:128], sk[128:]

        # Unpack seed bytes
        rho, k, tr = (
            sk_seed_bytes[:32],
            sk_seed_bytes[32:64],
            sk_seed_bytes[64:128],
        )

        # Unpack vector bytes
        s1_bytes = sk_vec_bytes[:s1_len]
        s2_bytes = sk_vec_bytes[s1_len : s1_len + s2_len]
        t0_bytes = sk_vec_bytes[-t0_len:]

        # Unpack bytes to vectors
        s1 = self.M.bit_unpack_s(s1_bytes, self.l, self.eta)
        s2 = self.M.bit_unpack_s(s2_bytes, self.k, self.eta)
        t0 = self.M.bit_unpack_t0(t0_bytes, self.k)

        return rho, k, tr, s1, s2, t0

    def _unpack_h(self, h_bytes: bytes) -> Vector:
        offsets = [0] + list(h_bytes[-self.k :])

        # ensure offsets are monotonic increasing
        if any(offsets[i] > offsets[i + 1] for i in range(len(offsets) - 1)):
            raise ValueError("offsets in h_bytes are not monotonically increasing")

        # ensure offset[-1] is smaller than the length of h_bytes
        if offsets[-1] > self.omega:
            raise ValueError("accumulate offset of hints exceeds omega")

        # ensure zero fields are all zeros
        if any(b != 0 for b in h_bytes[offsets[-1] : self.omega]):
            raise ValueError("non-zero fields in h_bytes are not all zeros")

        non_zero_positions = [
            list(h_bytes[offsets[i] : offsets[i + 1]]) for i in range(self.k)
        ]

        vector_coeffs = []
        for poly_non_zero in non_zero_positions:
            coeffs = [0 for _ in range(256)]
            for i, non_zero in enumerate(poly_non_zero):
                if i > 0 and non_zero <= poly_non_zero[i - 1]:
                    raise ValueError(
                        "non-zero positions in h_bytes are not monotonically increasing"
                    )
                coeffs[non_zero] = 1
            vector_coeffs.append(self.R(coeffs))

        return self.M.vector(vector_coeffs)

    def _unpack_sig(self, sig: bytes) -> tuple[bytes, Vector, Vector]:
        if len(sig) != self._sig_size():
            raise ValueError("Incorrect signature size")
        c_tilde = sig[: self.c_tilde_bytes]
        z_bytes = sig[self.c_tilde_bytes : -(self.k + self.omega)]
        h_bytes = sig[-(self.k + self.omega) :]

        z = self.M.bit_unpack_z(z_bytes, self.l, self.gamma_1)
        h = self._unpack_h(h_bytes)

        return c_tilde, z, h

    def _keygen_internal(self, zeta: bytes) -> tuple[bytes, bytes]:
        """
        Generates a public-private key pair from a seed following
        Algorithm 6 (FIPS 204)
        """
        # Expand with an XOF (SHAKE256)
        seed_domain_sep = zeta + bytes([self.k]) + bytes([self.l])
        seed_bytes = self._h(seed_domain_sep, 128)

        # Split bytes into suitable chunks
        rho, rho_prime, K = seed_bytes[:32], seed_bytes[32:96], seed_bytes[96:]

        # Generate matrix A ∈ R^(kxl) in the NTT domain
        A_hat = self._expand_matrix_from_seed(rho)

        # Generate the error vectors s1 ∈ R^l, s2 ∈ R^k
        s1, s2 = self._expand_vector_from_seed(rho_prime)

        # Matrix multiplication
        s1_hat = s1.to_ntt()
        t = (A_hat @ s1_hat).from_ntt() + s2

        t1, t0 = t.power_2_round(self.d)

        # Pack up the bytes
        pk = self._pack_pk(rho, t1)
        tr = self._h(pk, 64)
        sk = self._pack_sk(rho, K, tr, s1, s2, t0)

        return pk, sk

    def _sign_internal(
        self, sk: bytes, m: bytes, rnd: bytes, external_mu: bool = False
    ) -> bytes:
        """
        Deterministic algorithm to generate a signature for a formatted message
        M' following Algorithm 7 (FIPS 204)

        When `external_mu` is `True`, the message `m` is interpreted instead as
        the pre-hashed message `mu = prehash_external_mu()`
        """
        # unpack the secret key
        rho, k, tr, s1, s2, t0 = self._unpack_sk(sk)

        # Precompute NTT representation
        s1_hat = s1.to_ntt()
        s2_hat = s2.to_ntt()
        t0_hat = t0.to_ntt()

        # Generate matrix A ∈ R^(kxl) in the NTT domain
        A_hat = self._expand_matrix_from_seed(rho)

        # Set seeds and nonce (kappa)
        if external_mu:
            mu = m
        else:
            mu = self._h(tr + m, 64)
        rho_prime = self._h(k + rnd + mu, 64)

        kappa = 0
        alpha = self.gamma_2 << 1
        while True:
            y = self._expand_mask_vector(rho_prime, kappa)
            y_hat = y.to_ntt()
            w = (A_hat @ y_hat).from_ntt()

            # increment the nonce
            kappa += self.l

            # NOTE: there is an optimisation possible where both the high and
            # low bits of w are extracted here, which speeds up some checks
            # below and requires the use of make_hint_optimised() -- to see the
            # implementation of this, look at the signing algorithm for
            # dilithium. We include this slower version to mirror the FIPS 204
            # document precisely.
            # Extract out only the high bits
            w1 = w.high_bits(alpha)

            # Create challenge polynomial
            w1_bytes = w1.bit_pack_w(self.gamma_2)
            c_tilde = self._h(mu + w1_bytes, self.c_tilde_bytes)
            c = self.R.sample_in_ball(c_tilde, self.tau)
            c_hat = c.to_ntt()

            # NOTE: unlike FIPS 204 we start again as soon as a vector
            # fails the norm bound to reduce any unneeded computations.
            c_s1 = s1_hat.scale(c_hat).from_ntt()
            z = y + c_s1
            if z.check_norm_bound(self.gamma_1 - self.beta):
                continue

            c_s2 = s2_hat.scale(c_hat).from_ntt()
            r0 = (w - c_s2).low_bits(alpha)
            if r0.check_norm_bound(self.gamma_2 - self.beta):
                continue

            c_t0 = t0_hat.scale(c_hat).from_ntt()
            if c_t0.check_norm_bound(self.gamma_2):
                continue

            h = (-c_t0).make_hint(w - c_s2 + c_t0, alpha)
            if h.sum_hint() > self.omega:
                continue

            return self._pack_sig(c_tilde, z, h)

    def _verify_internal(self, pk: bytes, m: bytes, sig: bytes) -> bool:
        """
        Internal function to verify a signature sigma for a formatted message M'
        following Algorithm 8 (FIPS 204)
        """
        rho, t1 = self._unpack_pk(pk)
        try:
            c_tilde, z, h = self._unpack_sig(sig)
        except ValueError:
            return False

        if h.sum_hint() > self.omega:
            return False

        if z.check_norm_bound(self.gamma_1 - self.beta):
            return False

        A_hat = self._expand_matrix_from_seed(rho)

        tr = self._h(pk, 64)
        mu = self._h(tr + m, 64)
        c = self.R.sample_in_ball(c_tilde, self.tau)

        # Convert to NTT for computation
        c = c.to_ntt()
        z = z.to_ntt()

        t1 = t1.scale(1 << self.d)
        t1 = t1.to_ntt()

        Az_minus_ct1 = (A_hat @ z) - t1.scale(c)
        Az_minus_ct1 = Az_minus_ct1.from_ntt()

        w_prime = h.use_hint(Az_minus_ct1, 2 * self.gamma_2)
        w_prime_bytes = w_prime.bit_pack_w(self.gamma_2)

        return c_tilde == self._h(mu + w_prime_bytes, self.c_tilde_bytes)

    def keygen(self) -> tuple[bytes, bytes]:
        """
        Generates a public-private key pair following
        Algorithm 1 (FIPS 204)
        """
        zeta = self.random_bytes(32)
        pk, sk = self._keygen_internal(zeta)
        return (pk, sk)

    def key_derive(self, seed: bytes) -> tuple[bytes, bytes]:
        """
        Derive a verification key and corresponding signing key
        following the approach from Section 6.1 (FIPS 204)
        with storage of the ``seed`` value for later expansion.

        ``seed`` is a byte-encoded concatenation of the ``xi`` value.

        :return: Tuple with verification key and signing key.
        :rtype: tuple(bytes, bytes)
        """
        if len(seed) != 32:
            raise ValueError("The seed must be 32 bytes long")

        pk, sk = self._keygen_internal(seed)
        return (pk, sk)

    def sign(
        self, sk: bytes, m: bytes, ctx: bytes = b"", deterministic: bool = False
    ) -> bytes:
        """
        Generates an ML-DSA signature following
        Algorithm 2 (FIPS 204)
        """
        if len(ctx) > 255:
            raise ValueError(
                f"ctx bytes must have length at most 255, ctx has length {len(ctx) = }"
            )

        if deterministic:
            rnd = bytes([0] * 32)
        else:
            rnd = self.random_bytes(32)

        # Format the message using the context
        m_prime = bytes([0]) + bytes([len(ctx)]) + ctx + m

        # Compute the signature of m_prime
        sig_bytes = self._sign_internal(sk, m_prime, rnd)
        return sig_bytes

    def verify(self, pk: bytes, m: bytes, sig: bytes, ctx: bytes = b"") -> bool:
        """
        Verifies a signature sigma for a message M following
        Algorithm 3 (FIPS 204) — external interface.
        """
        if len(ctx) > 255:
            raise ValueError(
                f"ctx bytes must have length at most 255, ctx has length {len(ctx) = }"
            )

        # Format the message using the context
        m_prime = bytes([0]) + bytes([len(ctx)]) + ctx + m

        return self._verify_internal(pk, m_prime, sig)

    def verify_internal(self, pk: bytes, m: bytes, sig: bytes) -> bool:
        """
        Verifies a signature sigma for an internal message M following
        Algorithm 8 (FIPS 204) — internal interface: mu = H(tr || M),
        no domain separation. Used by ACVP 'internal' test vectors.
        """
        return self._verify_internal(pk, m, sig)

    def verify_mu(self, pk: bytes, mu: bytes, sig: bytes) -> bool:
        """
        Verifies a signature sigma against a caller-supplied 64-byte mu
        (external-mu interface, FIPS 204 Algorithms 7/8 with mu given).
        Used by ACVP 'externalMu' test vectors.
        """
        if len(mu) != 64:
            return False
        rho, t1 = self._unpack_pk(pk)
        try:
            c_tilde, z, h = self._unpack_sig(sig)
        except ValueError:
            return False
        if h.sum_hint() > self.omega:
            return False
        if z.check_norm_bound(self.gamma_1 - self.beta):
            return False
        A_hat = self._expand_matrix_from_seed(rho)
        c = self.R.sample_in_ball(c_tilde, self.tau).to_ntt()
        z = z.to_ntt()
        t1 = t1.scale(1 << self.d).to_ntt()
        Az_minus_ct1 = (A_hat @ z) - t1.scale(c)
        Az_minus_ct1 = Az_minus_ct1.from_ntt()
        w_prime = h.use_hint(Az_minus_ct1, 2 * self.gamma_2)
        w_prime_bytes = w_prime.bit_pack_w(self.gamma_2)
        return c_tilde == self._h(mu + w_prime_bytes, self.c_tilde_bytes)

    # DER OIDs for HashML-DSA pre-hash functions (FIPS 204, Section 7.3)
    _PREHASH_OIDS = {
        "SHA2-224": "0609608648016503040204",
        "SHA2-256": "0609608648016503040201",
        "SHA2-384": "0609608648016503040202",
        "SHA2-512": "0609608648016503040203",
        "SHA2-512/224": "0609608648016503040205",
        "SHA2-512/256": "0609608648016503040206",
        "SHA3-224": "0609608648016503040207",
        "SHA3-256": "0609608648016503040208",
        "SHA3-384": "0609608648016503040209",
        "SHA3-512": "060960864801650304020a",
        "SHAKE128": "060960864801650304020b",
        "SHAKE256": "060960864801650304020c",
        "SHAKE-128": "060960864801650304020b",
        "SHAKE-256": "060960864801650304020c",
    }

    @staticmethod
    def _prehash_digest(hash_name: str, m: bytes) -> bytes:
        import hashlib as _hl
        hn = hash_name.replace("SHAKE-128", "SHAKE128").replace("SHAKE-256", "SHAKE256")
        if hn == "SHAKE128":
            return _hl.shake_128(m).digest(64)
        if hn == "SHAKE256":
            return _hl.shake_256(m).digest(64)
        _map = {
            "SHA2-224": "sha224", "SHA2-256": "sha256", "SHA2-384": "sha384",
            "SHA2-512": "sha512", "SHA2-512/224": "sha512_224",
            "SHA2-512/256": "sha512_256", "SHA3-224": "sha3_224",
            "SHA3-256": "sha3_256", "SHA3-384": "sha3_384",
            "SHA3-512": "sha3_512",
        }
        return _hl.new(_map[hn], m).digest()

    def verify_prehash(
        self, pk: bytes, m: bytes, sig: bytes, ctx: bytes = b"",
        hash_name: str = "SHA2-512",
    ) -> bool:
        """
        Verifies a HashML-DSA signature (FIPS 204, Section 5.4):
        mu = H(tr || 0x01 || len(ctx) || ctx || OID || PH(M)).
        hash_name is an ACVP-style name, e.g. 'SHA2-512', 'SHA3-256'.
        """
        if len(ctx) > 255:
            raise ValueError("ctx too long")
        hn = hash_name.replace("SHAKE-128", "SHAKE128").replace("SHAKE-256", "SHAKE256")
        oid = bytes.fromhex(self._PREHASH_OIDS[hn])
        phm = self._prehash_digest(hash_name, m)
        m_prime = bytes([1]) + bytes([len(ctx)]) + ctx + oid + phm
        return self._verify_internal(pk, m_prime, sig)

    """
    The following additional function follows an outline from:
        https://github.com/aws/aws-lc/pull/2142
    which computes pk_bytes when only the sk_bytes are known.
    """

    def pk_from_sk(self, sk: bytes) -> bytes:
        """
        Given the packed representation of a ML-DSA secret key,
        compute the corresponding packed public key bytes.
        """
        # First unpack the secret key
        rho, _, tr, s1, s2, _ = self._unpack_sk(sk)

        # Compute the matrix A from rho in NTT form
        A_hat = self._expand_matrix_from_seed(rho)

        # Convert s1 to NTT form
        s1_hat = s1.to_ntt()

        # Compute the polynomial t, we have the lower bits t0,
        # but we need the higher bits t1 for the public key
        t = (A_hat @ s1_hat).from_ntt() + s2
        t1, _ = t.power_2_round(self.d)

        # The packed public key is made from rho || t1
        pk = self._pack_pk(rho, t1)

        # Ensure the public key matches the hash within the secret key
        if tr != self._h(pk, 64):
            raise ValueError("malformed secret key")

        return pk

    """
    The following external mu functions are not in FIPS 204, but are in
    Appendix D of the following IETF draft and are included for experimentation
    for researchers and engineers

    https://datatracker.ietf.org/doc/html/draft-ietf-lamps-dilithium-certificates-07
    """

    def prehash_external_mu(self, pk: bytes, m: bytes, ctx: bytes = b"") -> bytes:
        """
        Prehash the message `m` with context `ctx` together with
        the public key. For use with `sign_external_mu()`
        """
        # Ensure the length of the context is as expected
        if len(ctx) > 255:
            raise ValueError(
                f"ctx bytes must have length at most 255, ctx has length {len(ctx) = }"
            )
        if len(pk) != self._pk_size():
            raise ValueError(
                f"Public key size doesn't match this ML-DSA object parameters,"
                f"received {len(pk) = }, expected: {self._pk_size()}"
            )

        # Format the message using the context
        m_prime = bytes([0]) + bytes([len(ctx)]) + ctx + m

        # Compute mu by hashing the public key into the message
        tr = self._h(pk, 64)
        mu = self._h(tr + m_prime, 64)

        return mu

    def sign_external_mu(
        self, sk: bytes, mu: bytes, deterministic: bool = False
    ) -> bytes:
        """
        Generates an ML-DSA signature of a message given the prehash
        mu = H(H(pk), M')
        """
        # Ensure the length of the context is as expected
        if len(mu) != 64:
            raise ValueError(
                f"mu bytes must have length 64, mu has length {len(mu) = }"
            )

        if deterministic:
            rnd = bytes([0] * 32)
        else:
            rnd = self.random_bytes(32)

        # Compute the signature given external mu, we set the external_mu
        # to True
        sig = self._sign_internal(sk, mu, rnd, external_mu=True)
        return sig


_ML_DSA_65_PARAMS = {
    "d": 13, "tau": 49, "gamma_1": 524288, "gamma_2": 261888,
    "k": 6, "l": 5, "eta": 4, "omega": 55, "c_tilde_bytes": 48,
}
ML_DSA_65 = ML_DSA(_ML_DSA_65_PARAMS)

class HybridSignatureEngine:
    """
    Ed25519 + ML-DSA-65 hybrid. Both signatures required.
    Fail closed on any error. No mocks.
    """

    @staticmethod
    def generate_composite_keypair():
        # Ed25519 via PyNaCl
        ed_sk = nacl.signing.SigningKey.generate()
        ed_pub = ed_sk.verify_key
        ed_priv_bytes = bytes(ed_sk)
        ed_pub_bytes = bytes(ed_pub)

        # ML-DSA-65 (real)
        pq_pub, pq_priv = ML_DSA_65.keygen()

        # Composite: [len_ed_pub][ed_pub][len_pq_pub][pq_pub]
        composite_pub = (
            struct.pack('!H', len(ed_pub_bytes)) + ed_pub_bytes +
            struct.pack('!H', len(pq_pub)) + pq_pub
        )
        composite_priv = (
            struct.pack('!H', len(ed_priv_bytes)) + ed_priv_bytes +
            struct.pack('!H', len(pq_priv)) + pq_priv
        )
        return composite_priv, composite_pub

    @staticmethod
    def _parse_composite_key(composite_key: bytes):
        try:
            ed_len = struct.unpack('!H', composite_key[:2])[0]
            ed_key = composite_key[2:2+ed_len]
            offset = 2 + ed_len
            pq_len = struct.unpack('!H', composite_key[offset:offset+2])[0]
            pq_key = composite_key[offset+2:offset+2+pq_len]
            # Strict: no trailing bytes, exact lengths
            if offset+2+pq_len != len(composite_key):
                raise ValueError("Trailing bytes in composite key")
            if ed_len != 32:
                raise ValueError(f"Bad Ed25519 key length: {ed_len}")
            if pq_len != 1952 and pq_len != 4032:
                raise ValueError(f"Bad ML-DSA-65 key length: {pq_len}")
            return ed_key, pq_key
        except Exception as e:
            raise ValueError(f"Malformed composite key: {e}")

    @staticmethod
    def sign(message: bytes, composite_priv: bytes) -> bytes:
        ed_priv_bytes, pq_priv = HybridSignatureEngine._parse_composite_key(composite_priv)
        # Note: _parse accepts both pub (1952) and priv (4032) PQ lengths

        # Ed25519 sign
        ed_sk = nacl.signing.SigningKey(ed_priv_bytes)
        ed_sig = bytes(ed_sk.sign(message).signature)  # 64 bytes

        # ML-DSA-65 sign (real)
        pq_sig = ML_DSA_65.sign(pq_priv, message)  # 3309 bytes

        # Composite: [len_ed_sig][ed_sig][len_pq_sig][pq_sig]
        return (
            struct.pack('!H', len(ed_sig)) + ed_sig +
            struct.pack('!H', len(pq_sig)) + pq_sig
        )

    @staticmethod
    def verify(signature: bytes, message: bytes, composite_pub: bytes) -> bool:
        try:
            ed_pub_bytes, pq_pub = HybridSignatureEngine._parse_composite_key(composite_pub)
            # composite_pub must have 1952-byte PQ pub
            if len(pq_pub) != 1952:
                return False

            ed_sig_len = struct.unpack('!H', signature[:2])[0]
            ed_sig = signature[2:2+ed_sig_len]
            offset = 2 + ed_sig_len
            pq_sig_len = struct.unpack('!H', signature[offset:offset+2])[0]
            pq_sig = signature[offset+2:offset+2+pq_sig_len]

            # Strict: no trailing bytes, exact sig lengths
            if offset+2+pq_sig_len != len(signature):
                return False
            if ed_sig_len != 64 or pq_sig_len != 3309:
                return False
        except Exception:
            return False

        # Verify both (no short-circuit for timing safety)
        try:
            ed_vk = nacl.signing.VerifyKey(ed_pub_bytes)
            ed_vk.verify(message, ed_sig)
            ed_valid = True
        except Exception:
            ed_valid = False

        pq_valid = ML_DSA_65.verify(pq_pub, message, pq_sig)

        return bool(ed_valid and pq_valid)

VERSION = 5
DEFAULT_PORT = 8471
DEFAULT_KEYFILE = os.path.expanduser("~/.qarke_tunnel_identity")

HS_MAGIC = b"QKHS"
HS_VERSION = 4
ID_SCHEME_ED25519 = 0   # legacy Ed25519-only identity (migration mode)
ID_SCHEME_HYBRID = 1    # hybrid Ed25519 + ML-DSA-65 (default, required)
DEFAULT_KEYFILE_V15 = os.path.expanduser("~/.qarke_tunnel_identity_v15")
HS_DOMAIN_INIT = b"qarke-hs1"   # initiator handshake signature domain
HS_DOMAIN_RESP = b"qarke-hs2"   # responder handshake signature domain
# v1.3 framing is variable-length: magic(4)+ver(1)+kem_id(2)+x_pub(32)
#   + pq_len(2)+pq_blob(var: ek or ct)+id_pub(32)+sig(64)

KEM_NONE = 0        # classical X25519 only
KEM_MLKEM768 = 1    # hybrid X25519 + ML-KEM-768 (default)
KEM_MLKEM1024 = 2   # hybrid X25519 + ML-KEM-1024

# --------------------------------------------------------------------------
# ML-KEM (FIPS 203) — pure Python, NIST ACVP KAT-validated.
# KEM-TRAIL-2160 Phase 0. See module docstring in /tmp/mlkem/mlkem.py.
# --------------------------------------------------------------------------
Q = 3329
N = 256


class MLKEM:
    """FIPS 203 ML-KEM, parameterized. Use ML_KEM_768 / ML_KEM_1024."""

    def __init__(self, name, k, eta1, eta2, du, dv):
        self.name = name
        self.K = k
        self.ETA1 = eta1
        self.ETA2 = eta2
        self.DU = du
        self.DV = dv
        self.EK_LEN = 384 * k + 32
        self.DK_LEN = 768 * k + 96
        self.CT_LEN = 32 * (du * k + dv)
        if MLKEM._ZETAS is None:
            MLKEM._ZETAS = [pow(17, MLKEM._bitrev7(i), Q) for i in range(128)]

    # -- NTT -------------------------------------------------------------
    @staticmethod
    def _bitrev7(x: int) -> int:
        r = 0
        for _ in range(7):
            r = (r << 1) | (x & 1)
            x >>= 1
        return r

    _ZETAS = None  # built per-class below
    _INV128 = 3303  # 128^-1 mod 3329

    def _ntt(self, f):
        f = [x % Q for x in f]
        i = 1
        length = 128
        while length >= 2:
            start = 0
            while start < 256:
                zeta = self._ZETAS[i]
                i += 1
                for j in range(start, start + length):
                    t = zeta * f[j + length] % Q
                    f[j + length] = (f[j] - t) % Q
                    f[j] = (f[j] + t) % Q
                start += 2 * length
            length //= 2
        return f

    def _invntt(self, f):
        f = [x % Q for x in f]
        i = 127
        length = 2
        while length <= 128:
            start = 0
            while start < 256:
                zeta = self._ZETAS[i]
                i -= 1
                for j in range(start, start + length):
                    t = f[j]
                    f[j] = (t + f[j + length]) % Q
                    f[j + length] = zeta * (f[j + length] - t) % Q
                start += 2 * length
            length *= 2
        return [(x * self._INV128) % Q for x in f]

    def _basemul(self, f, g):
        h = [0] * 256
        for i in range(128):
            a0, a1 = f[2 * i], f[2 * i + 1]
            b0, b1 = g[2 * i], g[2 * i + 1]
            gamma = pow(17, 2 * self._bitrev7(i) + 1, Q)
            h[2 * i] = (a0 * b0 + a1 * b1 * gamma) % Q
            h[2 * i + 1] = (a0 * b1 + a1 * b0) % Q
        return h

    @staticmethod
    def _add(f, g):
        return [(x + y) % Q for x, y in zip(f, g)]

    @staticmethod
    def _sub(f, g):
        return [(x - y) % Q for x, y in zip(f, g)]

    # -- encode / decode / compress --------------------------------------
    @staticmethod
    def _byte_encode(f, d):
        b = bytearray(32 * d)
        for i in range(256):
            for j in range(d):
                bit = (f[i] >> j) & 1
                b[(i * d + j) // 8] |= bit << ((i * d + j) % 8)
        return bytes(b)

    @staticmethod
    def _byte_decode(byts, d):
        f = [0] * 256
        for i in range(256):
            for j in range(d):
                bit = (byts[(i * d + j) // 8] >> ((i * d + j) % 8)) & 1
                f[i] |= bit << j
        return f

    @staticmethod
    def _compress(x, d):
        return ((x << d) + Q // 2) // Q % (1 << d)

    @staticmethod
    def _decompress(y, d):
        return (y * Q + (1 << (d - 1))) // (1 << d)

    # -- sampling ---------------------------------------------------------
    def _sample_ntt(self, rho: bytes, i: int, j: int):
        """FIPS 203 Algorithm 7. Note: A[i][j] uses XOF(rho||j||i)."""
        h = hashlib.shake_128(rho + bytes([i, j]))
        data = bytearray(h.digest(840))
        a = [0] * 256
        idx = 0
        jx = 0
        while jx < 256:
            if idx + 3 > len(data):
                h2 = hashlib.shake_128(rho + bytes([i, j]) + b"ext" + idx.to_bytes(4, "little"))
                data += h2.digest(840)
            d1 = data[idx] + 256 * (data[idx + 1] % 16)
            d2 = (data[idx + 1] // 16) + 16 * data[idx + 2]
            idx += 3
            if d1 < Q:
                a[jx] = d1
                jx += 1
            if d2 < Q and jx < 256:
                a[jx] = d2
                jx += 1
        return a

    @staticmethod
    def _prf(eta: int, s: bytes, b: int) -> bytes:
        return hashlib.shake_256(s + bytes([b])).digest(64 * eta)

    @staticmethod
    def _sample_cbd(prf_out: bytes):
        eta = len(prf_out) // 64
        b = int.from_bytes(prf_out, "little")
        f = [0] * 256
        for i in range(256):
            x = y = 0
            for j in range(eta):
                x += (b >> (2 * i * eta + j)) & 1
                y += (b >> (2 * i * eta + eta + j)) & 1
            f[i] = (x - y) % Q
        return f

    # -- K-PKE ------------------------------------------------------------
    def _kpke_keygen(self, d: bytes):
        k = self.K
        g = hashlib.sha3_512(d + bytes([k])).digest()
        rho, sigma = g[:32], g[32:]
        n = 0
        a_hat = [[self._sample_ntt(rho, j, i) for j in range(k)] for i in range(k)]
        s, e = [], []
        for _ in range(k):
            s.append(self._sample_cbd(self._prf(self.ETA1, sigma, n))); n += 1
        for _ in range(k):
            e.append(self._sample_cbd(self._prf(self.ETA1, sigma, n))); n += 1
        s_hat = [self._ntt(x) for x in s]
        e_hat = [self._ntt(x) for x in e]
        t_hat = []
        for i in range(k):
            acc = self._basemul(a_hat[i][0], s_hat[0])
            for j in range(1, k):
                acc = self._add(acc, self._basemul(a_hat[i][j], s_hat[j]))
            t_hat.append(self._add(acc, e_hat[i]))
        ek = b"".join(self._byte_encode(p, 12) for p in t_hat) + rho
        dk = b"".join(self._byte_encode(p, 12) for p in s_hat)
        return ek, dk

    def _kpke_encrypt(self, ek: bytes, m: bytes, r: bytes) -> bytes:
        k = self.K
        t_hat = [self._byte_decode(ek[384 * i:384 * (i + 1)], 12) for i in range(k)]
        rho = ek[384 * k:]
        y = self._byte_decode(m, 1)
        n = 0
        # a_hat_T[i][j] = A_hat[j][i]; A[j][i] uses XOF(rho||i||j)
        a_hat_T = [[self._sample_ntt(rho, i, j) for j in range(k)] for i in range(k)]
        rvec, e1, e2 = [], [], []
        for _ in range(k):
            rvec.append(self._sample_cbd(self._prf(self.ETA1, r, n))); n += 1
        for _ in range(k):
            e1.append(self._sample_cbd(self._prf(self.ETA2, r, n))); n += 1
        e2.append(self._sample_cbd(self._prf(self.ETA2, r, n)))
        r_hat = [self._ntt(x) for x in rvec]
        u = []
        for i in range(k):
            acc = self._basemul(a_hat_T[i][0], r_hat[0])
            for j in range(1, k):
                acc = self._add(acc, self._basemul(a_hat_T[i][j], r_hat[j]))
            u.append(self._add(self._invntt(acc), e1[i]))
        acc = self._basemul(t_hat[0], r_hat[0])
        for j in range(1, k):
            acc = self._add(acc, self._basemul(t_hat[j], r_hat[j]))
        mu = [self._decompress(c, 1) for c in y]
        v = self._add(self._add(self._invntt(acc), e2[0]), mu)
        c1 = b"".join(self._byte_encode([self._compress(x, self.DU) for x in p], self.DU) for p in u)
        c2 = self._byte_encode([self._compress(x, self.DV) for x in v], self.DV)
        return c1 + c2

    def _kpke_decrypt(self, dk_pke: bytes, c: bytes):
        k = self.K
        c1, c2 = c[:32 * self.DU * k], c[32 * self.DU * k:]
        u = [self._byte_decode(c1[32 * self.DU * i:32 * self.DU * (i + 1)], self.DU) for i in range(k)]
        v = self._byte_decode(c2, self.DV)
        u = [[self._decompress(y, self.DU) for y in p] for p in u]
        v = [self._decompress(y, self.DV) for y in v]
        s_hat = [self._byte_decode(dk_pke[384 * i:384 * (i + 1)], 12) for i in range(k)]
        w = v
        for i in range(k):
            w = self._sub(w, self._invntt(self._basemul(s_hat[i], self._ntt(u[i]))))
        return self._byte_encode([self._compress(x, 1) for x in w], 1)

    # -- ML-KEM API --------------------------------------------------------
    def keygen_from_coins(self, d: bytes, z: bytes):
        """Deterministic keygen for KAT. d, z: 32 bytes each."""
        assert len(d) == 32 and len(z) == 32
        ek_pke, dk_pke = self._kpke_keygen(d)
        ek = ek_pke
        h = hashlib.sha3_256(ek).digest()
        dk = dk_pke + ek + h + z
        assert len(ek) == self.EK_LEN and len(dk) == self.DK_LEN
        return ek, dk

    def keygen(self):
        return self.keygen_from_coins(os.urandom(32), os.urandom(32))

    def encaps_deterministic(self, ek: bytes, m: bytes):
        """Deterministic encaps for KAT. m: 32 bytes."""
        assert len(ek) == self.EK_LEN and len(m) == 32
        g = hashlib.sha3_512(m + hashlib.sha3_256(ek).digest()).digest()
        K_, r = g[:32], g[32:]
        c = self._kpke_encrypt(ek, m, r)
        return K_, c

    def encaps(self, ek: bytes):
        return self.encaps_deterministic(ek, os.urandom(32))

    def decaps(self, dk: bytes, c: bytes) -> bytes:
        assert len(dk) == self.DK_LEN and len(c) == self.CT_LEN
        k = self.K
        dk_pke = dk[:384 * k]
        ek = dk[384 * k:768 * k + 32]
        h = dk[768 * k + 32:768 * k + 64]
        z = dk[768 * k + 64:]
        m = self._kpke_decrypt(dk_pke, c)
        g = hashlib.sha3_512(m + h).digest()
        Kp, rp = g[:32], g[32:]
        Kb = hashlib.shake_256(z + c).digest(32)
        c2 = self._kpke_encrypt(ek, m, rp)
        diff = 0
        for x, y in zip(c, c2):
            diff |= x ^ y
        return Kp if diff == 0 else Kb


ML_KEM_512 = MLKEM("ML-KEM-512", k=2, eta1=3, eta2=2, du=10, dv=4)
ML_KEM_768 = MLKEM("ML-KEM-768", k=3, eta1=2, eta2=2, du=10, dv=4)
ML_KEM_1024 = MLKEM("ML-KEM-1024", k=4, eta1=2, eta2=2, du=11, dv=5)

BY_NAME = {"ML-KEM-512": ML_KEM_512, "ML-KEM-768": ML_KEM_768, "ML-KEM-1024": ML_KEM_1024}

KEM_BY_ID = {0: None, 1: ML_KEM_768, 2: ML_KEM_1024}

# Frame plaintext types
PT_DATA = 0x01
PT_REKEY_REQ = 0x02
PT_PING = 0x03
PT_PONG = 0x04
PT_CLOSE = 0x05
PT_REKEY_ACK = 0x06

AAD_PREFIX = b"QARKE-TUN\x00"
DIR_I2R = b"I2R\x00"
DIR_R2I = b"R2I\x00"

REKEY_AFTER_FRAMES = 2 ** 20
REPLAY_WINDOW = 1024


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
class TunnelError(Exception):
    pass


class HandshakeError(TunnelError):
    pass


class ReplayError(TunnelError):
    pass


class EpochError(TunnelError):
    pass


def fingerprint(pubkey: bytes) -> str:
    """Stable peer fingerprint: Blake2b-256 of the identity pubkey, hex."""
    return hashlib.blake2b(pubkey, digest_size=32).hexdigest()


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise TunnelError("connection closed by peer")
        buf += chunk
    return buf


def send_all(sock: socket.socket, data: bytes) -> None:
    sock.sendall(data)


class ReplayWindow:
    """Sliding replay window (same design as qarke_packet.py)."""

    def __init__(self, n=REPLAY_WINDOW):
        self.n = n
        self.last = 0
        self.seen = set()

    def check(self, seq: int) -> bool:
        if seq > self.last:
            self.last = seq
            self.seen = {seq}
            return True
        if self.last - seq >= self.n:
            return False
        if seq in self.seen:
            return False
        self.seen.add(seq)
        return True


# --------------------------------------------------------------------------
# Phase 2: HKDF key schedule (TLS 1.3-style, RFC 5869 + RFC 8446 semantics)
# --------------------------------------------------------------------------
# Replaces the v1.2 keyed-BLAKE2b KDF. The schedule:
#   transcript_hash = SHA-512(transcript)   # binds every handshake value
#   ikm             = x25519_ss || mlkem_ss  # mlkem_ss empty if kem_id=0
#   hs_secret       = HKDF-Extract(salt=transcript_hash, ikm)
#   k_i2r           = Derive-Secret(hs_secret, "qarke15 init->resp", th)
#   k_r2i           = Derive-Secret(hs_secret, "qarke15 resp->init", th)
# Derive-Secret uses the TLS 1.3 HkdfLabel construction with the transcript
# hash as context, so each key is bound to the exact handshake transcript.
_HKDF_HASH = hashes.SHA512()
_HKDF_LEN = 64  # SHA-512 output length


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract(salt, IKM) -> PRK. RFC 5869, Section 2.2."""
    if not salt:
        salt = b"\x00" * _HKDF_LEN
    return hmac.new(salt, ikm, hashlib.sha512).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand(PRK, info, L) -> OKM. RFC 5869, Section 2.3."""
    return HKDFExpand(
        algorithm=_HKDF_HASH,
        length=length,
        info=info,
    ).derive(prk)


def _derive_secret(secret: bytes, label: bytes, transcript_hash: bytes,
                   length: int = 32) -> bytes:
    """TLS 1.3 Derive-Secret (RFC 8446, Section 7.1).
    Derive-Secret(Secret, Label, Messages) =
        HKDF-Expand(Secret, HkdfLabel, Hash.length)
    HkdfLabel = struct { uint16 length; opaque label<7..255>;
                         opaque context<0..255>; }
    label = "qarke15 " + Label; context = transcript_hash.
    """
    full_label = b"qarke15 " + label
    hkdf_label = (struct.pack("!H", length)
                  + bytes([len(full_label)]) + full_label
                  + bytes([len(transcript_hash)]) + transcript_hash)
    return _hkdf_expand(secret, hkdf_label, length)


def kdf_v13(x_ss: bytes, k_ss: bytes, kem_id: int,
            e_pub_init: bytes, e_pub_resp: bytes,
            pq_init_blob: bytes, pq_resp_blob: bytes,
            id_init: bytes, id_resp: bytes, epoch: int):
    """QARKE v1.3 hybrid HKDF key schedule.

    x_ss: X25519 shared secret (32 bytes). k_ss: ML-KEM shared secret
    (32 bytes, or b"" when kem_id=0). pq_init_blob = ML-KEM ek,
    pq_resp_blob = ML-KEM ct (both b"" when kem_id=0).

    The transcript binds: protocol version, kem_id, epoch, both ephemeral
    X25519 pubs, ML-KEM ek/ct, both long-term Ed25519 identities. The
    transcript hash salts the Extract, so any handshake tampering yields
    unrelated keys (fail closed). No silent downgrade: kem_id and version
    are in the transcript.
    """
    transcript = (b"QARKE-tunnel-v3" + struct.pack("!H", kem_id)
                  + struct.pack("!I", epoch)
                  + e_pub_init + e_pub_resp
                  + pq_init_blob + pq_resp_blob
                  + id_init + id_resp)
    th = hashlib.sha512(transcript).digest()
    ikm = x_ss + k_ss  # k_ss == b"" for classical kem_id=0
    hs_secret = _hkdf_extract(salt=th, ikm=ikm)
    k_i2r = _derive_secret(hs_secret, b"init->resp traffic", th)
    k_r2i = _derive_secret(hs_secret, b"resp->init traffic", th)
    return k_i2r, k_r2i


def kdf_rekey_v13(shared: bytes, e_pub_init: bytes, e_pub_resp: bytes,
                  id_init: bytes, id_resp: bytes, epoch: int):
    """QARKE v1.3 rekey schedule: fresh X25519 secret through the HKDF.
    Rekey uses kem_id=0 (classical X25519 only) with empty PQ blobs —
    the PQ hybrid was established at handshake; rekey refreshes forward
    secrecy via fresh ephemeral X25519 + HKDF.
    """
    return kdf_v13(shared, b"", 0, e_pub_init, e_pub_resp,
                   b"", b"", id_init, id_resp, epoch)


# --------------------------------------------------------------------------
# Phase 3: SENTINEL / WARDEN / Audit Ledger
# KEM-TRAIL-2160 Phase 3 — dual monitors + tamper-evident audit.
# Monitors are LOCAL-ONLY: they observe tunnel events, never touch the wire.
# v1.4 is wire-compatible with v1.3 (HS_VERSION unchanged).
# --------------------------------------------------------------------------
ALERT_INFO = "INFO"
ALERT_WARN = "WARN"
ALERT_CRITICAL = "CRITICAL"


class AuditLedger:
    """Append-only, SHA-256 hash-chained, tamper-evident event log."""

    def __init__(self, path=None):
        self.path = path
        self._lock = threading.Lock()
        self.entries = []
        if path and os.path.exists(path):
            self._load()

    def _canonical(self, seq, ts, event_type, severity, details_json, prev_hash):
        return (f"{seq}|{ts:.6f}|{event_type}|{severity}|"
                f"{details_json}|{prev_hash}").encode()

    def append(self, event_type, severity=ALERT_INFO, details=None):
        with self._lock:
            seq = len(self.entries)
            ts = time.time()
            details_json = json.dumps(details or {}, sort_keys=True,
                                      separators=(",", ":"))
            prev_hash = (self.entries[-1]["entry_hash"]
                         if self.entries else "GENESIS")
            entry_hash = hashlib.sha256(
                self._canonical(seq, ts, event_type, severity,
                                details_json, prev_hash)).hexdigest()
            entry = {"seq": seq, "ts": ts, "event": event_type,
                     "severity": severity, "details": details or {},
                     "prev_hash": prev_hash, "entry_hash": entry_hash}
            self.entries.append(entry)
            if self.path:
                with open(self.path, "a") as f:
                    f.write(json.dumps(entry, separators=(",", ":")) + "\n")
            return entry

    def verify(self):
        """Recompute the chain. Returns (ok, bad_index)."""
        prev = "GENESIS"
        for i, e in enumerate(self.entries):
            details_json = json.dumps(e["details"], sort_keys=True,
                                       separators=(",", ":"))
            want = hashlib.sha256(
                self._canonical(e["seq"], e["ts"], e["event"],
                                e["severity"], details_json, prev)).hexdigest()
            if want != e["entry_hash"] or e["prev_hash"] != prev:
                return False, i
            prev = e["entry_hash"]
        return True, -1

    def _load(self):
        with open(self.path) as f:
            for line in f:
                line = line.strip()
                if line:
                    self.entries.append(json.loads(line))

    def tail(self, n=20):
        return self.entries[-n:]


class Sentinel:
    """Statistical anomaly detection (Welford's running mean/variance)."""

    WARN_Z = 3.0
    CRIT_Z = 5.0
    MIN_SAMPLES = 10

    def __init__(self):
        self._lock = threading.Lock()
        self.stats = {}
        self.anomalies = []

    def observe(self, name, value):
        """Feed a sample. Returns (z_score, alert_level or None)."""
        with self._lock:
            s = self.stats.get(name)
            if s is None:
                s = [0, 0.0, 0.0]
                self.stats[name] = s
            count, mean, M2 = s
            count += 1
            delta = value - mean
            mean += delta / count
            delta2 = value - mean
            M2 += delta * delta2
            s[0], s[1], s[2] = count, mean, M2

            if count < self.MIN_SAMPLES:
                return 0.0, None
            variance = M2 / (count - 1) if count > 1 else 0
            if variance <= 0:
                return 0.0, None
            stddev = math.sqrt(variance)
            z = abs(value - mean) / stddev

            level = None
            if z >= self.CRIT_Z:
                level = ALERT_CRITICAL
            elif z >= self.WARN_Z:
                level = ALERT_WARN
            if level:
                self.anomalies.append(
                    {"ts": time.time(), "metric": name, "value": value,
                     "mean": mean, "stddev": stddev, "z": z, "level": level})
            return z, level

    def baseline(self, name):
        s = self.stats.get(name)
        if not s or s[0] < 2:
            return None
        count, mean, M2 = s
        var = M2 / (count - 1) if count > 1 else 0
        return {"count": count, "mean": mean,
                "stddev": math.sqrt(var) if var > 0 else 0}


class Warden:
    """Signature-based attack detection (sliding-window counters)."""

    RULES = [
        ("handshake_failed", 60, 3, 5, "handshake flood — possible DoS probe"),
        ("replay_detected", 60, 5, 10, "replay burst — possible active attack"),
        ("tamper_detected", 60, 2, 3,
         "ciphertext tampering — active MITM probe"),
        ("downgrade_attempt", 60, 1, 2, "downgrade attempt — policy attack"),
        ("malformed_frame", 60, 10, 20,
         "malformed frame flood — fuzzing probe"),
        ("auth_failed", 60, 3, 5,
         "peer auth failures — impersonation probe"),
    ]

    def __init__(self):
        self._lock = threading.Lock()
        self.events = {}
        self.detections = []
        self._fired = set()

    def signal(self, event_type):
        """Record a security event. Returns (level, message) or (None, None)."""
        now = time.monotonic()
        with self._lock:
            dq = self.events.get(event_type)
            if dq is None:
                dq = collections.deque()
                self.events[event_type] = dq
            dq.append(now)

            for etype, window, warn_th, crit_th, msg in self.RULES:
                if etype != event_type:
                    continue
                while dq and dq[0] < now - window:
                    dq.popleft()
                count = len(dq)
                level = None
                if count >= crit_th:
                    level = ALERT_CRITICAL
                elif count >= warn_th:
                    level = ALERT_WARN
                if level:
                    key = (event_type, count)
                    if key not in self._fired:
                        self._fired.add(key)
                        self.detections.append(
                            {"ts": time.time(), "event": event_type,
                             "count": count, "window_sec": window,
                             "level": level, "message": msg})
                        return level, msg
            return None, None


class MonitorHub:
    """Phase 3 hub: AuditLedger + Sentinel + Warden, hook API for Tunnel."""

    def __init__(self, ledger_path=None, quiet=False):
        self.ledger = AuditLedger(ledger_path)
        self.sentinel = Sentinel()
        self.warden = Warden()
        self.alerts = []
        self._lock = threading.Lock()
        self.quiet = quiet
        self._last_rekey = None
        self.ledger.append("monitor_started", ALERT_INFO, {"version": VERSION})

    def _alert(self, level, source, message, details=None):
        with self._lock:
            self.alerts.append(
                {"ts": time.time(), "level": level, "source": source,
                 "message": message})
        self.ledger.append(f"alert_{source}", level,
                           {"message": message, **(details or {})})
        if level in (ALERT_WARN, ALERT_CRITICAL) and not self.quiet:
            print(f"[MONITOR:{level}] {source}: {message}", flush=True)

    def on_handshake_start(self, role, kem_id):
        self.ledger.append("handshake_started", ALERT_INFO,
                           {"role": role, "kem_id": kem_id})
        return time.monotonic()

    def on_handshake_ok(self, t0, role, kem_id, peer_fp):
        dur_ms = (time.monotonic() - t0) * 1000.0
        z, lvl = self.sentinel.observe("handshake_ms", dur_ms)
        self.ledger.append("handshake_completed", ALERT_INFO,
                           {"role": role, "kem_id": kem_id,
                            "peer_fp": peer_fp[:16],
                            "duration_ms": round(dur_ms, 2)})
        if lvl:
            self._alert(lvl, "SENTINEL",
                        f"handshake timing anomaly: {dur_ms:.1f}ms (z={z:.1f})",
                        {"metric": "handshake_ms", "z": round(z, 2)})

    def on_handshake_fail(self, role, reason):
        self.ledger.append("handshake_failed", ALERT_WARN,
                           {"role": role, "reason": reason})
        lvl, msg = self.warden.signal("handshake_failed")
        rl = reason.lower()
        if "downgrade" in rl or "kem_id" in rl:
            lvl2, msg2 = self.warden.signal("downgrade_attempt")
            if lvl2:
                lvl, msg = lvl2, msg2
        if lvl:
            self._alert(lvl, "WARDEN", msg, {"reason": reason})

    def on_message_sent(self, size):
        z, lvl = self.sentinel.observe("msg_size_out", size)
        if lvl:
            self._alert(lvl, "SENTINEL",
                        f"outbound msg size anomaly: {size}B (z={z:.1f})")

    def on_message_recv(self, size):
        z, lvl = self.sentinel.observe("msg_size_in", size)
        if lvl:
            self._alert(lvl, "SENTINEL",
                        f"inbound msg size anomaly: {size}B (z={z:.1f})")

    def on_tamper(self, detail):
        self.ledger.append("tamper_detected", ALERT_CRITICAL,
                           {"detail": detail})
        lvl, msg = self.warden.signal("tamper_detected")
        if lvl:
            self._alert(lvl, "WARDEN", msg, {"detail": detail})

    def on_replay(self, detail):
        self.ledger.append("replay_detected", ALERT_WARN, {"detail": detail})
        lvl, msg = self.warden.signal("replay_detected")
        if lvl:
            self._alert(lvl, "WARDEN", msg, {"detail": detail})

    def on_rekey(self, old_epoch, new_epoch):
        now = time.monotonic()
        if self._last_rekey is not None:
            z, lvl = self.sentinel.observe("rekey_interval_s",
                                           now - self._last_rekey)
            if lvl:
                self._alert(lvl, "SENTINEL",
                            f"rekey timing anomaly (z={z:.1f})")
        self._last_rekey = now
        self.ledger.append("rekey", ALERT_INFO,
                           {"from": old_epoch, "to": new_epoch})

    def on_peer_reject(self, detail):
        self.ledger.append("auth_failed", ALERT_WARN, {"detail": detail})
        lvl, msg = self.warden.signal("auth_failed")
        if lvl:
            self._alert(lvl, "WARDEN", msg, {"detail": detail})

    def on_malformed(self, detail):
        self.ledger.append("malformed_frame", ALERT_WARN, {"detail": detail})
        lvl, msg = self.warden.signal("malformed_frame")
        if lvl:
            self._alert(lvl, "WARDEN", msg, {"detail": detail})

    def status(self):
        ok, bad = self.ledger.verify()
        return {"ledger_entries": len(self.ledger.entries),
                "ledger_valid": ok, "ledger_bad_index": bad,
                "alerts": len(self.alerts),
                "criticals": sum(1 for a in self.alerts
                                 if a["level"] == ALERT_CRITICAL),
                "sentinel_anomalies": len(self.sentinel.anomalies),
                "warden_detections": len(self.warden.detections)}


# --------------------------------------------------------------------------
# identity
# --------------------------------------------------------------------------
def gen_identity(path: str = DEFAULT_KEYFILE):
    sk = nacl.signing.SigningKey.generate()
    old_umask = os.umask(0o177)  # new files -> 0600
    try:
        with open(path, "w") as f:
            f.write(sk.encode().hex() + "\n")
    finally:
        os.umask(old_umask)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return sk


def load_identity(path: str = DEFAULT_KEYFILE):
    if not os.path.exists(path):
        print(f"[*] no identity at {path} — generating fresh Ed25519 identity")
        return gen_identity(path)
    with open(path) as f:
        seed = bytes.fromhex(f.read().strip().split()[0])
    if len(seed) != 32:
        raise TunnelError(f"bad identity file {path}")
    return nacl.signing.SigningKey(seed)


# --------------------------------------------------------------------------
# Phase 4: hybrid identity (Ed25519 + ML-DSA-65)
# --------------------------------------------------------------------------
def gen_identity_v15(path: str = DEFAULT_KEYFILE_V15):
    """Generate a v1.5 composite hybrid identity (Ed25519 + ML-DSA-65)."""
    comp_priv, comp_pub = HybridSignatureEngine.generate_composite_keypair()
    old_umask = os.umask(0o177)
    try:
        with open(path, "w") as f:
            f.write(comp_priv.hex() + "\n")
        with open(path + ".pub", "w") as pf:
            pf.write(comp_pub.hex() + "\n")
    finally:
        os.umask(old_umask)
    try:
        os.chmod(path, 0o600)
        os.chmod(path + ".pub", 0o600)
    except OSError:
        pass
    fp = fingerprint(comp_pub)
    print(f"[+] v1.5 hybrid identity generated at {path} (mode 0600)")
    print(f"    fingerprint: {fp}")
    return comp_priv, comp_pub


def load_identity_v15(path: str = DEFAULT_KEYFILE_V15):
    """Load a v1.5 composite identity. Returns (comp_priv, comp_pub, scheme).

    Falls back to legacy Ed25519 identity at DEFAULT_KEYFILE if no v15
    identity exists — returns scheme ID_SCHEME_ED25519 in that case.
    """
    if os.path.exists(path):
        with open(path) as f:
            comp_priv = bytes.fromhex(f.read().strip().split()[0])
        try:
            ed_priv, pq_priv = HybridSignatureEngine._parse_composite_key(comp_priv)
            # Reconstruct composite pub from priv components
            ed_sk = nacl.signing.SigningKey(ed_priv)
            ed_pub = bytes(ed_sk.verify_key)
            # PQ pub must be derived — we store it alongside; for now
            # require the pub to be recoverable. Actually we need the PQ pub:
            # it's not derivable from priv alone in our format, so we expect
            # the file to contain priv; pub is reconstructed on first use.
            # Simpler: store pub in a .pub sidecar.
            pub_path = path + ".pub"
            if os.path.exists(pub_path):
                with open(pub_path) as pf:
                    comp_pub = bytes.fromhex(pf.read().strip().split()[0])
            else:
                raise TunnelError(
                    f"v1.5 identity pubkey sidecar missing: {pub_path}\n"
                    f"    regenerate with --gen-key or restore from backup")
            # Validate the composite pub parses
            HybridSignatureEngine._parse_composite_key(comp_pub)
            return comp_priv, comp_pub, ID_SCHEME_HYBRID
        except TunnelError:
            raise
        except Exception as e:
            raise TunnelError(f"bad v1.5 identity file {path}: {e}")
    # Fallback: legacy Ed25519
    legacy = DEFAULT_KEYFILE
    if os.path.exists(legacy):
        print(f"[*] no v1.5 identity at {path} — using legacy Ed25519 at {legacy}")
        print(f"    run --upgrade-identity to migrate to hybrid")
        sk = load_identity(legacy)
        return bytes(sk), bytes(sk.verify_key), ID_SCHEME_ED25519
    print(f"[*] no identity found — generating fresh v1.5 hybrid identity")
    comp_priv, comp_pub = gen_identity_v15(path)
    # Write pub sidecar
    with open(path + ".pub", "w") as pf:
        pf.write(comp_pub.hex() + "\n")
    try:
        os.chmod(path + ".pub", 0o600)
    except OSError:
        pass
    return comp_priv, comp_pub, ID_SCHEME_HYBRID


def upgrade_identity(legacy_path: str = DEFAULT_KEYFILE,
                     v15_path: str = DEFAULT_KEYFILE_V15):
    """Migrate legacy Ed25519 identity to v1.5 hybrid, preserving the Ed keypair.

    The Ed25519 keypair is kept as the classical component; a fresh ML-DSA-65
    keypair is generated as the PQ component. The legacy file is left intact.
    """
    if not os.path.exists(legacy_path):
        raise TunnelError(f"no legacy identity at {legacy_path}")
    if os.path.exists(v15_path):
        raise TunnelError(
            f"v1.5 identity already exists at {v15_path} — refusing to overwrite")
    sk = load_identity(legacy_path)
    ed_priv_bytes = bytes(sk)
    ed_pub_bytes = bytes(sk.verify_key)
    # Fresh ML-DSA-65 keypair
    pq_pub, pq_priv = ML_DSA_65.keygen()
    comp_priv = (struct.pack('!H', len(ed_priv_bytes)) + ed_priv_bytes
                 + struct.pack('!H', len(pq_priv)) + pq_priv)
    comp_pub = (struct.pack('!H', len(ed_pub_bytes)) + ed_pub_bytes
                 + struct.pack('!H', len(pq_pub)) + pq_pub)
    old_umask = os.umask(0o177)
    try:
        with open(v15_path, "w") as f:
            f.write(comp_priv.hex() + "\n")
        with open(v15_path + ".pub", "w") as pf:
            pf.write(comp_pub.hex() + "\n")
    finally:
        os.umask(old_umask)
    try:
        os.chmod(v15_path, 0o600)
        os.chmod(v15_path + ".pub", 0o600)
    except OSError:
        pass
    fp_old = fingerprint(ed_pub_bytes)
    fp_new = fingerprint(comp_pub)
    print(f"[+] upgraded legacy Ed25519 identity to v1.5 hybrid")
    print(f"    legacy file preserved: {legacy_path}")
    print(f"    new identity: {v15_path} (mode 0600)")
    print(f"    old fp: {fp_old}")
    print(f"    new fp: {fp_new}")
    return comp_priv, comp_pub


# --------------------------------------------------------------------------
# tunnel
# --------------------------------------------------------------------------
class Tunnel:
    """E2E encrypted channel over a connected TCP socket."""

    def __init__(self, sock: socket.socket,
                 id_priv: bytes, id_pub: bytes, id_scheme: int,
                 role: str, peer_pub_expected: bytes | None,
                 tofu_interactive: bool = True, kem_id: int = KEM_MLKEM768,
                 monitor: MonitorHub | None = None,
                 require_hybrid_peer: bool = True):
        assert role in ("init", "resp")
        assert kem_id in KEM_BY_ID, f"unknown kem_id={kem_id}"
        assert id_scheme in (ID_SCHEME_ED25519, ID_SCHEME_HYBRID), \
            f"unknown id_scheme={id_scheme}"
        self.sock = sock
        # v1.5: id_priv is composite_priv bytes (hybrid) or Ed25519 seed (legacy)
        #       id_pub is composite_pub bytes (hybrid) or 32B Ed25519 pub (legacy)
        self.id_priv = id_priv
        self.id_pub = id_pub
        self.id_scheme = id_scheme
        self.require_hybrid_peer = require_hybrid_peer
        # Legacy compat: keep id_sk for Ed25519-only path
        self.id_sk = (nacl.signing.SigningKey(id_priv)
                      if id_scheme == ID_SCHEME_ED25519 else None)
        self.role = role
        self.peer_expected = peer_pub_expected
        self.tofu_interactive = tofu_interactive
        self.kem_id = kem_id
        self.kem = KEM_BY_ID[kem_id]  # None for classical
        # Phase 3: dual monitors (local-only, never touch the wire)
        self.monitor = monitor if monitor is not None else MonitorHub(quiet=True)

        self.peer_pub: bytes | None = None
        self.epoch = 0
        self.send_seq = 0
        self.frames_sent = 0
        self.k_send: bytes | None = None
        self.k_recv: bytes | None = None
        self.win = ReplayWindow()
        self.dir_send = DIR_I2R if role == "init" else DIR_R2I
        self.dir_recv = DIR_R2I if role == "init" else DIR_I2R

        # rekey state
        self._rekey_wait = False
        self._rekey_priv: bytes | None = None
        self._rekey_pub: bytes | None = None
        self._pending: list[bytes] = []  # plaintext payloads queued mid-rekey
        self._lock = threading.Lock()

        # socket-read discipline: exactly one thread may be inside a socket
        # read at a time (_read_lock). DATA frames picked up by a non-owner
        # read loop are parked in _inbox. PONGs are routed to _pong_waiters.
        # run_chat() sets _single_reader=True: its reader thread owns the
        # socket and ping() just waits on an event (no competing reads).
        self._read_lock = threading.Lock()
        self._inbox: queue.Queue = queue.Queue()
        self._pong_waiters: dict = {}
        self._single_reader = False

    # -- handshake (v1.5 hybrid identity, HKDF schedule) -------------------------------
    def _hs_msg(self, e_pub: bytes, pq_blob: bytes, domain: bytes) -> bytes:
        """Build a v1.5 handshake message.

        Format:
          HS_MAGIC(4B) + HS_VERSION(1B) + kem_id(2B) + id_scheme(1B)
          + e_pub(32B) + pq_len(2B) + pq_blob
          + id_pub_len(2B) + id_pub + sig_len(2B) + sig

        pq_blob: init->resp carries ML-KEM ek; resp->init carries ML-KEM ct;
        b"" when kem_id=0. The signature binds id_scheme + kem_id + x25519 pub
        + pq blob + identity, so downgrade/tampering breaks verification.
        """
        sig_msg = (domain + struct.pack("!B", self.id_scheme)
                   + struct.pack("!H", self.kem_id)
                   + e_pub + pq_blob + self.id_pub)
        if self.id_scheme == ID_SCHEME_HYBRID:
            sig = HybridSignatureEngine.sign(sig_msg, self.id_priv)
        else:
            sig = self.id_sk.sign(sig_msg).signature
        return (HS_MAGIC + struct.pack("!B", HS_VERSION)
                + struct.pack("!H", self.kem_id)
                + struct.pack("!B", self.id_scheme)
                + e_pub
                + struct.pack("!H", len(pq_blob)) + pq_blob
                + struct.pack("!H", len(self.id_pub)) + self.id_pub
                + struct.pack("!H", len(sig)) + sig)

    def _parse_hs_msg(self, raw: bytes, domain: bytes, expect_pq: str):
        """Parse peer v1.5 handshake. expect_pq: 'ek' (init msg) or 'ct' (resp msg)."""
        # Minimum: magic(4) + ver(1) + kem_id(2) + scheme(1) + e_pub(32)
        #          + pq_len(2) + id_pub_len(2) + sig_len(2) = 46
        if len(raw) < 46:
            raise HandshakeError(f"short handshake ({len(raw)} bytes)")
        magic, ver = raw[:4], raw[4]
        if magic != HS_MAGIC or ver != HS_VERSION:
            raise HandshakeError(
                f"bad handshake magic/version (got ver={ver}, want {HS_VERSION}) — "
                f"cross-version peers rejected")
        kem_id = struct.unpack("!H", raw[5:7])[0]
        if kem_id != self.kem_id:
            raise HandshakeError(
                f"kem_id mismatch: peer offered kem_id={kem_id}, "
                f"local policy kem_id={self.kem_id} — aborting (no silent downgrade)")
        id_scheme = raw[7]
        if id_scheme not in (ID_SCHEME_ED25519, ID_SCHEME_HYBRID):
            raise HandshakeError(f"unknown peer id_scheme={id_scheme}")
        # Stripped-PQ rejection: if we require hybrid and peer sends Ed25519-only
        if self.require_hybrid_peer and id_scheme != ID_SCHEME_HYBRID:
            self.monitor.on_peer_reject(
                f"stripped PQ identity — peer sent Ed25519-only (scheme 0), "
                f"hybrid required")
            raise HandshakeError(
                "stripped PQ identity rejected — peer must use hybrid "
                "Ed25519+ML-DSA-65 (run with --allow-legacy-peer to override)")
        e_pub = raw[8:40]
        pq_len = struct.unpack("!H", raw[40:42])[0]
        pq_blob = raw[42:42 + pq_len]
        off = 42 + pq_len
        if len(raw) < off + 2:
            raise HandshakeError("truncated id_pub_len")
        id_pub_len = struct.unpack("!H", raw[off:off + 2])[0]
        off += 2
        if len(raw) < off + id_pub_len + 2:
            raise HandshakeError("truncated id_pub/sig_len")
        id_pub = raw[off:off + id_pub_len]
        off += id_pub_len
        sig_len = struct.unpack("!H", raw[off:off + 2])[0]
        off += 2
        if len(raw) < off + sig_len:
            raise HandshakeError("truncated signature")
        sig = raw[off:off + sig_len]
        if off + sig_len != len(raw):
            raise HandshakeError("trailing bytes in handshake")
        # Validate identity lengths by scheme
        if id_scheme == ID_SCHEME_HYBRID:
            # Composite pub: 2+32+2+1952 = 1988 bytes
            if id_pub_len != 1988:
                raise HandshakeError(
                    f"bad hybrid id_pub length {id_pub_len} (want 1988)")
            # Composite sig: 2+64+2+3309 = 3377 bytes
            if sig_len != 3377:
                raise HandshakeError(
                    f"bad hybrid sig length {sig_len} (want 3377)")
            try:
                HybridSignatureEngine._parse_composite_key(id_pub)
            except Exception as e:
                raise HandshakeError(f"malformed hybrid identity: {e}")
        else:
            if id_pub_len != 32 or sig_len != 64:
                raise HandshakeError(
                    f"bad Ed25519 identity lengths ({id_pub_len}/{sig_len})")
        # Validate pq blob length against kem_id
        kem = KEM_BY_ID[kem_id]
        if kem is None:
            if pq_len != 0:
                raise HandshakeError("non-empty pq blob with kem_id=0")
        else:
            want = kem.EK_LEN if expect_pq == "ek" else kem.CT_LEN
            if pq_len != want:
                raise HandshakeError(
                    f"bad pq blob length {pq_len} (want {want} for kem_id={kem_id})")
        # Verify signature (binds id_scheme — downgrade breaks verification)
        sig_msg = (domain + struct.pack("!B", id_scheme)
                   + struct.pack("!H", kem_id) + e_pub + pq_blob + id_pub)
        if id_scheme == ID_SCHEME_HYBRID:
            if not HybridSignatureEngine.verify(sig, sig_msg, id_pub):
                self.monitor.on_peer_reject("hybrid handshake signature invalid")
                raise HandshakeError("peer hybrid handshake signature invalid")
        else:
            try:
                nacl.signing.VerifyKey(id_pub).verify(sig_msg, sig)
            except Exception as e:
                self.monitor.on_peer_reject(f"Ed25519 handshake signature invalid: {e}")
                raise HandshakeError(f"peer handshake signature invalid: {e}")
        return e_pub, pq_blob, id_pub, id_scheme

    def _confirm_peer(self, id_pub: bytes):
        fp = fingerprint(id_pub)
        if self.peer_expected is not None:
            if id_pub != self.peer_expected:
                self.monitor.on_peer_reject(
                    f"identity MISMATCH — got fp {fp}, "
                    f"expected {fingerprint(self.peer_expected)}")
                raise HandshakeError(
                    f"peer identity MISMATCH — got fp {fp}, "
                    f"expected {fingerprint(self.peer_expected)}")
            self.peer_pub = id_pub
            self._peer_via = "pinned"
            return
        # trust-on-first-use
        print(f"[!] UNKNOWN PEER identity — fingerprint:\n    {fp}")
        if self.tofu_interactive:
            ans = input("[?] Trust this peer for this session? [y/N] ").strip().lower()
            if ans != "y":
                raise HandshakeError("peer rejected by operator (TOFU declined)")
        else:
            raise HandshakeError("no pinned peer key and non-interactive TOFU")
        self.peer_pub = id_pub
        self._peer_via = "TOFU-confirmed"

    def _finish_handshake(self, e_pub_init, e_pub_resp, id_init, id_resp,
                          e_priv_mine, pq_init_blob, pq_resp_blob, k_ss):
        x_ss = nacl.bindings.crypto_scalarmult(
            e_priv_mine, e_pub_resp if self.role == "init" else e_pub_init)
        k_i2r, k_r2i = kdf_v13(x_ss, k_ss, self.kem_id,
                             e_pub_init, e_pub_resp,
                             pq_init_blob, pq_resp_blob,
                             id_init, id_resp, self.epoch)
        if self.role == "init":
            self.k_send, self.k_recv = k_i2r, k_r2i
        else:
            self.k_send, self.k_recv = k_r2i, k_i2r
        self.send_seq = 0
        self.win = ReplayWindow()

    def handshake_as_init(self):
        mon_t0 = self.monitor.on_handshake_start("init", self.kem_id)
        try:
            self._handshake_as_init_inner()
        except Exception as e:
            self.monitor.on_handshake_fail("init", str(e))
            raise
        self.monitor.on_handshake_ok(mon_t0, "init", self.kem_id,
                                     fingerprint(self.peer_pub))

    def _handshake_as_init_inner(self):
        eph = nacl.public.PrivateKey.generate()
        e_pub, e_priv = eph.public_key.encode(), eph.encode()
        # ML-KEM keypair for the responder to encapsulate to
        pq_blob = b""
        dk = None
        if self.kem is not None:
            ek, dk = self.kem.keygen()
            pq_blob = ek
        msg = self._hs_msg(e_pub, pq_blob, HS_DOMAIN_INIT)
        send_all(self.sock, struct.pack("!I", len(msg)) + msg)
        raw = recv_exact(self.sock, struct.unpack("!I", recv_exact(self.sock, 4))[0])
        r_e_pub, r_pq_blob, r_id_pub, r_scheme = self._parse_hs_msg(raw, HS_DOMAIN_RESP, "ct")
        self._confirm_peer(r_id_pub)
        k_ss = self.kem.decaps(dk, r_pq_blob) if self.kem is not None else b""
        self._finish_handshake(e_pub, r_e_pub, self.id_pub, r_id_pub, e_priv,
                               pq_blob, r_pq_blob, k_ss)

    def handshake_as_resp(self):
        mon_t0 = self.monitor.on_handshake_start("resp", self.kem_id)
        try:
            self._handshake_as_resp_inner()
        except Exception as e:
            self.monitor.on_handshake_fail("resp", str(e))
            raise
        self.monitor.on_handshake_ok(mon_t0, "resp", self.kem_id,
                                     fingerprint(self.peer_pub))

    def _handshake_as_resp_inner(self):
        raw = recv_exact(self.sock, struct.unpack("!I", recv_exact(self.sock, 4))[0])
        i_e_pub, i_pq_blob, i_id_pub, i_scheme = self._parse_hs_msg(raw, HS_DOMAIN_INIT, "ek")
        self._confirm_peer(i_id_pub)
        eph = nacl.public.PrivateKey.generate()
        e_pub, e_priv = eph.public_key.encode(), eph.encode()
        pq_blob = b""
        k_ss = b""
        if self.kem is not None:
            k_ss, ct = self.kem.encaps(i_pq_blob)
            pq_blob = ct
        msg = self._hs_msg(e_pub, pq_blob, HS_DOMAIN_RESP)
        send_all(self.sock, struct.pack("!I", len(msg)) + msg)
        self._finish_handshake(i_e_pub, e_pub, i_id_pub, self.id_pub, e_priv,
                               i_pq_blob, pq_blob, k_ss)

    # -- frames ---------------------------------------------------------
    def _encrypt_frame(self, ptype: int, payload: bytes) -> bytes:
        with self._lock:
            self.send_seq += 1
            seq = self.send_seq
            epoch = self.epoch
            key = self.k_send
            dirtag = self.dir_send
        nonce = struct.pack("!IQ", epoch, seq)
        aad = AAD_PREFIX + dirtag + nonce
        ct = ChaCha20Poly1305(key).encrypt(nonce, struct.pack("!B", ptype) + payload, aad)
        return struct.pack("!I", len(nonce) + len(ct)) + nonce + ct

    def _decrypt_frame(self, raw: bytes):
        if len(raw) < 12:
            self.monitor.on_malformed(f"short frame ({len(raw)} bytes)")
            raise TunnelError("short frame")
        nonce, ct = raw[:12], raw[12:]
        epoch, seq = struct.unpack("!IQ", nonce)
        if epoch != self.epoch:
            raise EpochError(f"frame epoch {epoch} != current {self.epoch}")
        aad = AAD_PREFIX + self.dir_recv + nonce
        try:
            inner = ChaCha20Poly1305(self.k_recv).decrypt(nonce, ct, aad)
        except Exception as e:
            self.monitor.on_tamper(f"frame auth failed: {e}")
            raise TunnelError(f"frame auth failed (tamper/wrong key): {e}")
        if not self.win.check(seq):
            self.monitor.on_replay(f"replay/ancient frame seq={seq}")
            raise ReplayError(f"replay/ancient frame seq={seq}")
        return inner[0], inner[1:]

    def _send_raw(self, ptype: int, payload: bytes):
        send_all(self.sock, self._encrypt_frame(ptype, payload))
        with self._lock:
            self.frames_sent += 1
            n = self.frames_sent
        if n >= REKEY_AFTER_FRAMES and not self._rekey_wait:
            self.rekey()

    def send_msg(self, data: bytes):
        self.monitor.on_message_sent(len(data))
        with self._lock:
            waiting = self._rekey_wait
            if waiting:
                self._pending.append(data)
                return
        self._send_raw(PT_DATA, data)

    def _read_frame(self, timeout: float | None):
        """Read one frame from the socket and decrypt it. Single-reader only."""
        with self._read_lock:
            if timeout is not None:
                self.sock.settimeout(timeout)
            try:
                n = struct.unpack("!I", recv_exact(self.sock, 4))[0]
                if n > 4 * 1024 * 1024:
                    raise TunnelError(f"absurd frame length {n}")
                raw = recv_exact(self.sock, n)
            finally:
                if timeout is not None:
                    self.sock.settimeout(None)
            return self._decrypt_frame(raw)

    def _dispatch_loop(self, timeout: float | None, on_data, stop_event=None):
        """Read/decrypt/dispatch loop. on_data(payload)->True stops+returns
        the payload, False parks it and keeps going. Returns DATA payload
        (or None if stop_event fires)."""
        end = None if timeout is None else time.monotonic() + timeout
        while True:
            if stop_event is not None and stop_event.is_set():
                return None
            if end is not None:
                rem = end - time.monotonic()
                if rem <= 0:
                    raise socket.timeout("timed out")
            else:
                rem = None
            try:
                ptype, payload = self._read_frame(rem)
            except (socket.timeout, TimeoutError) as e:
                raise socket.timeout("timed out") from e
            if ptype == PT_REKEY_REQ:
                self._on_rekey_req(payload)
                continue
            if ptype == PT_REKEY_ACK:
                self._on_rekey_ack(payload)
                continue
            if ptype == PT_PING:
                self._send_raw(PT_PONG, payload)
                continue
            if ptype == PT_PONG:
                with self._lock:
                    w = self._pong_waiters.pop(payload, None)
                if w is not None:
                    ev, box, t0 = w
                    box["rtt"] = (time.monotonic() - t0) * 1000.0
                    ev.set()
                continue
            if ptype == PT_CLOSE:
                raise TunnelError("peer closed the tunnel")
            if ptype == PT_DATA:
                self.monitor.on_message_recv(len(payload))
                if on_data(payload):
                    return payload
                continue
            raise TunnelError(f"unknown ptype {ptype:#x}")

    def recv_msg(self, timeout: float | None = None):
        """Returns (PT_DATA, payload). Raises TunnelError on close/problems."""
        try:
            return (PT_DATA, self._inbox.get_nowait())
        except queue.Empty:
            pass
        return (PT_DATA, self._dispatch_loop(timeout, lambda p: True))

    # -- rekey ----------------------------------------------------------
    def rekey(self):
        """Fresh ephemeral X25519 over the encrypted channel (epoch+1)."""
        with self._lock:
            if self._rekey_wait:
                return
            eph = nacl.public.PrivateKey.generate()
            self._rekey_priv = eph.encode()
            self._rekey_pub = eph.public_key.encode()
            self._rekey_wait = True
        self._send_raw(PT_REKEY_REQ, self._rekey_pub)

    def _derive_rekey(self, my_new_pub: bytes, peer_new_pub: bytes):
        if self.role == "init":
            e_pub_init, e_pub_resp = my_new_pub, peer_new_pub
            id_init, id_resp = self.id_pub, self.peer_pub
        else:
            e_pub_init, e_pub_resp = peer_new_pub, my_new_pub
            id_init, id_resp = self.peer_pub, self.id_pub
        shared = nacl.bindings.crypto_scalarmult(self._rekey_priv,
                                                 peer_new_pub)
        new_epoch = self.epoch + 1
        k_i2r, k_r2i = kdf_rekey_v13(shared, e_pub_init, e_pub_resp,
                                   id_init, id_resp, new_epoch)
        with self._lock:
            old_epoch = self.epoch
            self.epoch = new_epoch
            if self.role == "init":
                self.k_send, self.k_recv = k_i2r, k_r2i
            else:
                self.k_send, self.k_recv = k_r2i, k_i2r
            self.send_seq = 0
            self.frames_sent = 0
            self.win = ReplayWindow()
            self._rekey_wait = False
            self._rekey_priv = self._rekey_pub = None
            pending, self._pending = self._pending, []
        self.monitor.on_rekey(old_epoch, new_epoch)
        for p in pending:
            self._send_raw(PT_DATA, p)

    def _on_rekey_req(self, payload: bytes):
        peer_new_pub = payload[:32]
        if len(peer_new_pub) != 32:
            raise TunnelError("bad rekey pub")
        with self._lock:
            simultaneous = self._rekey_wait
            my_pub, my_priv = self._rekey_pub, self._rekey_priv
        if simultaneous:
            # both sides initiated: treat peer REQ as the ACK
            self._derive_rekey(my_pub, peer_new_pub)
        else:
            eph = nacl.public.PrivateKey.generate()
            my_pub, my_priv = eph.public_key.encode(), eph.encode()
            with self._lock:
                self._rekey_priv, self._rekey_pub = my_priv, my_pub
            self._send_raw(PT_REKEY_ACK, my_pub)
            self._derive_rekey(my_pub, peer_new_pub)

    def _on_rekey_ack(self, payload: bytes):
        peer_new_pub = payload[:32]
        with self._lock:
            if not self._rekey_wait:
                raise TunnelError("unsolicited rekey ACK")
            my_pub = self._rekey_pub
        self._derive_rekey(my_pub, peer_new_pub)

    # -- misc -----------------------------------------------------------
    def ping(self, timeout: float = 10.0) -> float:
        """Returns RTT in milliseconds.

        Two modes: if a dedicated reader thread owns the socket (chat mode),
        just register a waiter and wait for it to fire. Otherwise run the
        dispatch loop directly (no competing readers exist).
        """
        deadline = time.monotonic() + 5
        while self._rekey_wait and time.monotonic() < deadline:
            time.sleep(0.01)  # don't ping mid-rekey (epoch is moving)
        t0 = time.monotonic()
        token = struct.pack("!Q", int(t0 * 1e6))
        ev = threading.Event()
        box: dict = {}
        with self._lock:
            self._pong_waiters[token] = (ev, box, t0)
        try:
            self._send_raw(PT_PING, token)
            if self._single_reader:
                if not ev.wait(timeout):
                    raise TunnelError("pong timeout")
            else:
                def on_data(p):
                    self._inbox.put(p)  # park DATA; keep looping for the PONG
                    return False
                try:
                    self._dispatch_loop(timeout, on_data, stop_event=ev)
                except (socket.timeout, TimeoutError):
                    pass
                if not ev.is_set():
                    raise TunnelError("pong timeout")
            return box["rtt"]
        finally:
            with self._lock:
                self._pong_waiters.pop(token, None)

    def close(self):
        try:
            self._send_raw(PT_CLOSE, b"")
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass


# --------------------------------------------------------------------------
# banner
# --------------------------------------------------------------------------
def banner(tun: Tunnel, note: str = ""):
    kem_label = {KEM_MLKEM768: "ML-KEM-768", KEM_MLKEM1024: "ML-KEM-1024",
                 KEM_NONE: "OFF (classical X25519)"}[tun.kem_id]
    print("=" * 62)
    print(" QARKE TUNNEL v1.3 — E2E encrypted tunnel for mission comms")
    print("-" * 62)
    print(f" Identity   : Ed25519  fp {fingerprint(tun.id_pub)}")
    if tun.kem_id == KEM_NONE:
        print(" Key exch.  : X25519 ephemeral (mutual auth, Noise-XX-style)")
    else:
        print(f" Key exch.  : X25519 ephemeral + {kem_label} hybrid")
        print("              (KEM-TRAIL-2160 Phase 2, HKDF key schedule)")
    print(" Transport  : ChaCha20-Poly1305 | directional keys | replay window")
    print(f" PQC status : {kem_label}")
    print(f" Peer       : fp {fingerprint(tun.peer_pub)}  [{tun._peer_via}]")
    if note:
        print(f" Note       : {note}")
    print("=" * 62)
    sys.stdout.flush()


# --------------------------------------------------------------------------
# interactive chat
# --------------------------------------------------------------------------
def run_chat(tun: Tunnel, who: str):
    print(f"[*] tunnel up as {who} — type lines, Enter to send.")
    print("    commands: /rekey  /ping  /quit")
    stop = threading.Event()
    tun._single_reader = True  # reader thread owns the socket from here on

    def reader():
        try:
            while not stop.is_set():
                ptype, payload = tun.recv_msg()
                if ptype == PT_DATA:
                    try:
                        text = payload.decode("utf-8", "replace")
                    except Exception:
                        text = repr(payload)
                    print(f"\n<peer> {text}")
                    print("> ", end="", flush=True)
        except TunnelError as e:
            if not stop.is_set():
                print(f"\n[!] tunnel ended: {e}")
                stop.set()
        except Exception as e:
            if not stop.is_set():
                print(f"\n[!] reader error: {e}")
                stop.set()

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    try:
        while not stop.is_set():
            try:
                line = input("> ")
            except EOFError:
                break
            if line.strip() == "/quit":
                break
            if line.strip() == "/rekey":
                tun.rekey()
                print("[*] rekey initiated (epoch -> %d)" % (tun.epoch + 1))
                continue
            if line.strip() == "/ping":
                try:
                    print("[*] RTT %.1f ms" % tun.ping())
                except Exception as e:
                    print(f"[!] ping failed: {e}")
                continue
            tun.send_msg(line.encode("utf-8"))
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        tun.close()
    print("[*] tunnel closed.")


# --------------------------------------------------------------------------
# serve / connect
# --------------------------------------------------------------------------
def do_serve(port: int, keyfile: str, peer_key_hex: str | None, kem_id: int,
             allow_legacy_peer: bool = False):
    id_priv, id_pub, id_scheme = load_identity_v15(keyfile)
    scheme_name = "hybrid Ed25519+ML-DSA-65" if id_scheme == ID_SCHEME_HYBRID else "Ed25519 (legacy)"
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(5)
    print(f"[*] QARKE tunnel listening on 0.0.0.0:{port} — waiting for peer… (Ctrl-C to stop)")
    while True:
        try:
            conn, addr = srv.accept()
        except KeyboardInterrupt:
            print("\n[*] aborted.")
            return
        print(f"[*] connection from {addr[0]}:{addr[1]} — handshaking…")
        tun = Tunnel(conn, id_priv, id_pub, id_scheme, "resp",
                     bytes.fromhex(peer_key_hex) if peer_key_hex else None,
                     kem_id=kem_id, require_hybrid_peer=not allow_legacy_peer)
        try:
            tun.handshake_as_resp()
        except TunnelError as e:
            # HandshakeError subclasses TunnelError; a client that vanishes
            # mid-handshake also raises TunnelError. Either way: drop it,
            # keep listening. (v1.1: serve no longer exits on a bad attempt.)
            print(f"[!] HANDSHAKE FAILED: {e} — still listening.")
            conn.close()
            continue
        banner(tun, note=f"listening side, peer {addr[0]}")
        try:
            run_chat(tun, "responder")
        except KeyboardInterrupt:
            print("\n[*] session ended by operator.")
        except Exception as e:
            print(f"[!] session error: {e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass
        print("[*] waiting for next peer… (Ctrl-C to stop)")


def do_connect(host: str, port: int, keyfile: str, peer_key_hex: str | None,
             kem_id: int, allow_legacy_peer: bool = False):
    id_priv, id_pub, id_pub_scheme = load_identity_v15(keyfile)
    id_scheme = id_pub_scheme
    sock = socket.create_connection((host, port), timeout=15)
    sock.settimeout(None)  # clear the 15s connect timeout; the chat reader blocks indefinitely
    print(f"[*] connected to {host}:{port} — handshaking…")
    tun = Tunnel(sock, id_priv, id_pub, id_scheme, "init",
                 bytes.fromhex(peer_key_hex) if peer_key_hex else None,
                 kem_id=kem_id, require_hybrid_peer=not allow_legacy_peer)
    try:
        tun.handshake_as_init()
    except TunnelError as e:
        # v1.1: clean message instead of a traceback when the server
        # rejects us or vanishes mid-handshake.
        print(f"[!] HANDSHAKE FAILED: {e}")
        sock.close()
        return
    banner(tun, note=f"dialer side -> {host}:{port}")
    run_chat(tun, "initiator")


# --------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
# Official NIST ACVP ML-DSA-65 known-answer vectors
# Source: usnistgov/ACVP-Server, ML-DSA-sigVer-FIPS204 (prompt.json).
# 12 positive vectors across all 4 FIPS 204 verification modes:
#   pure (external iface + ctx), prehash (HashML-DSA), mu (external mu),
#   internal (Sign/Verify_internal, Algorithms 7/8).
# Full 60-vector suite (incl. 48 negative vectors) verified at build time.
# Format: (mode, pk_hex, payload_hex, sig_hex, extra)
#   pure:     payload=message, extra=ctx_hex
#   prehash:  payload=message, extra=ctx_hex|hashAlg
#   mu:       payload=mu_hex (64B), extra=""
#   internal: payload=message, extra=""
ML_DSA_65_KAT_VECTORS = [
    ("pure",
     "86720C5FA190240FF983511C8DA65E927ADAE446B663B8B3ABF9A6216C3EAB16A576EF6FB815989FC9D17BFB82C1AA10DF0F7F0E9391F3886A538CB8BB78CEF135EC0D44F880FF3984A80C33B3A5F32AB3CE6A88E251B25936ACBA499800C981B72E0264C60B335AF64DF62797FE53A5B8796949428B551899D2865044224B89769863D9C6E6DBBEC3CF85E4163AA898E7825C2BF39B4950269FB4A276821CFC4A77C4726AF9765DE1988B161C5AA4268F60C942A816B30C455EBE1C2416D66EEEE8ADA865F120C67296BB799B0A58D08F8F2057732C10980D0931F476C6D74049E1DAC0D547A75B48DC97779EE42D352E57B55B885F000399BF4870666F217FD5C6068A094C1CFC91A941C7A7A902CCF220239F54FF5EC056451891B18092A2E39F507F5AE4EF04960B63B491C855CC0BF64CEA651A8C3AB0CF2E83293D14B3495FAD64EA2C62AE9F5A8C2103E8D6272766A31529F869BC1E391078E9BFF969561F7D56ED63A5C28D138CDA69A83B93A6B6F24A13804CFEA93DFA77FA8D59D881E23F0688F8315DEB9D9876F9405FC910F48DDDEB10091057BA5817749F19C866F9843E35EF8FA4092F09864BFBE4CD45E988BA77C9FB462F149AD43E7D744DAD03D2879C75DD04C76D9BC4A5A20345CAC4F3A42BA0E14749BC10633EC621E2EE8701E5738ED40234D2E4B72011087F218DAAF6F7A0535F02A875D963FC6CE0FB687B72496240B6325799AD8A7DCB33950C4580A220C46490E8362B2032FC5ADADE85A244B6FFF49637EF80A1167B4D5F1ED66E4D804F970849A1132C7E9A0DFA1DA55DB636C89A3612D691AF2F3144B30B7EB6A7AD501F0561D2F8971CC4D66B158EC0C2086054024536C5453B6E058A045935801857B21B0E70D5A91F8A0F0E634A1F40908D8F4E251DFD301A7FC20DED777C2EE27D4944119958F0AAE0CF86FAC356D1F241A41C7F186C0615A0B1610B858C3AD53857D0DEBE8D89D8481ABB086E8A069332E3A33222B65A25367FBD7A8234BC8EF1092ABCA80F29453E64D1A5E43C8ABCB6BCF368BA9E067E686D438D8085719618B8C37AB5A3116AE41FE144395B551FFEAE81D78EFB0F9362A02A8EBBA26405EEDCA4706ED8B474BB0B79071B4BA8E766C5B46BC52E8FDF34A4AB88B84A63EB8244E49A89A94DD2C5A7048F6A17277F6FFB5F3BB5D08F0A5FE601EAAE080858A6073BF3645388421BEC396E3D547FC66DE8EBBAC65AAC2939ACC15F6D81F114B237B68AB5226087A0BC6FC4ABA68DA26433EDE7CE5BFC012EB7674CFFE8FE4F8B3ADE6FACC2EF27B4F59F3EDDF604415BEB199639707B87D1B8E00D51EC0747FE260D6B4885FE5028A493D5615088627E5183500A456D3A647AC57D0AB96966B5FE7AAACF354C61530B6DF9C477077384EC85161E012B3AE068D0B37DE138174C6E6070817922BA044BDF1DAA79818ABDB45E297114A9226A827A4E21174F8C0B27907C314534F8074E7A71AA99FAD2A0ADAA7E87B40CD7E0581DD33C71AC0ED643ABF3EFA01C65E20A5380EFB7213CBD86793299585F31B5DF85F1F0CF605024EED16981B8D9F69D51B7625A2E154B5A279CF9BC2055E22DBBEEE12D3F22D2534E176AA0F92364D264557B9B56254CA0BDAF7919BDCA09A510E85D41745C7F3B1EC4D05FF5E1F1AD523EA1262577EE949D12C140CF0EF248E45EF902F0C735CBF36FEEC57D3D4B3925F85A12367F84F4CF00B58826972C5EA8EB8D19AAC56654941BE747C221F5D930DF6EE6A32B7ED1B53C746BC875D761F22866C9BE87E5125201FAC82E9FF5581636E6344D82A62D470ECB29CA2BCA5EFECC0C9DC8A00242492513B047ECF7EC5DE8D15B769D17F514139D0C8CF8DDADE3BECA44F0588489A869CA537CF76A55301706B8AFCFFFBD54C360E73C143506C0DF52B32714790E87341D403FB4B4CBCEA4EEB0B245BE4829CBCF5F3F6BB68BE9AD5FEE52EF765A2CA2C1AF5BBCEDB0D82EA20CF41AA47DD4B639E14B1E699B351493EDEBF20F8C6C302AE2DB61886C21ECF0E02380C6471C82543BB841356EDC40B173B9459AC42A5F3042318F4E5CA84968D164EF4AD419BAE3B23CBA1E68A33579C260CB2B35F0F924C6FEA20EC72250753EF166BDEA02AD102268DE3558FDE33DF8B42A19629F2CDDE5FE4B9B92248DE16F13DE617A16B589D1C4F63268593004CD4E59DC152ADA3C3822FEB2D44B6294931DF48B3D2B8D0A009E386854177872AFB0F4028BC4A680ED8250B3DD8DA76BF82A03233FC7AD3A022678CB8D87F6640DD74A50DD00D2407466095FE77FB22BE521A3891693431CE32E9EEEC1571AA5123913A7670BA9469E500A76A4E2A35710FA037E8C2F6442CA48BAF905572D9D4D113EBAE8CE459C80FC17E4AD40B19269114BE8F294C994C9CFA00D467ADFF448D514A175F5A8A6AE8F9FBA5C4EDF90668278D08FB6969C17FE4C0F97A70B5CE5A0AF982BE5CA131AF8152C3F34D85292F9EBD5A8A5688D6884B900564E59EF6B31E60F63497D0D3F4BCAFAB7D99C261B661507A672AD253E51380A5EC33A2D5F8292E5A385221021B66DF37F3EF3B59B25F2CAD9EFA6DDDAA013584FD42307DBE09F7BD90EDC9DB10DDAE18D18B42ECF0D84E4D2FCE0753E1E85BF36A2B0A72FCB7AAA9AC282FCDFF50EA5932FE95AB9E0F928D0672B2726A732740A2EA6815344913D8033E996412FEBD59F9BC4B1E0EB97F668EFF7AD74F3A4EAAFDEE1D07B25C6C57547B431DB844C57EDDD",
     "66A63FD89E4AC965583F64C7B73552FFD49A23B9AB139606357752C4EFF45CED67F6D7E5326B7CD65A8E71F2FB3D9CCD2381C43E4F333C3D8C72431B2023F3C93260055303768198D872EDE8512279789273E8E2BE8E4E6D4ADA5BB30354484776C31574B52E410C6382CC9DA08718E726476F696B6A8C48D5BB824482E51BA5108D6F6A0A9FBF02DC544D4BD62328CC1EDE991EFA59D4E62D201475301D60B1CEA3C1C85337C6BF656AC24050BA68E930B261E396E949D156C2A1D15F256C9F949D053F0D587E80C22F07432A2AA8CEF1739A9DBDF44ED3E3CE21D2B788EE6DAEED6AF9885A5DCB4F1FD8E4BD2CA0779558594E921A8DFF968E996A24CE9F9A13C570CAA23E274AC22DB84AF3E5627C3946A1572202321FB80D37B0A420F9086ACCC91FA9D9BD36B07C51C539450CCE3E3E8B1DD60A66DDE41AA46075D7C713F2F19000B3A1BBC463786189E017395C6EAC886C33EBF9FACC7DC0659D21AF110531DC73A27A7AC7AABE09D004325BA580428124E9CD45CF65327B2E6866836C4966BC3BBCB99EEFD0713979BA5F2D47AB28CB218EF877C26D982D416A4B38E438C430327A06CD4B63101C618FB3679273E579A14ABB317998364289050200EDD3C82D22F2A12D25C915DDBF7210F8B02232436A390CAD65E622D4A72C976140CF8E72886489C5B750B3ADF721179C6CDE6E216643CF7C455191ABB8597DD8770DFED60E7DD71F4399863AB551FEF692DA2D25050E6E3FA69DEF5F83CD5E3E8B68FFF518A97799037330D582761934B0147916970841760317808617DA93746E09B1CE86AE0B0BF1C42D46857156262306391642CD473C3785A424B5695E30BAB547D99D3C3BE92BBBE4DF4578FCA73B35EF750B4D2AB5E24E0BC29837C7D6A472BF8119915C137C44646C832A8A42483D5B7C3F03A37937606AFA4FB82E9027670ACFBB44E497B22F79AFC761164D485B7AC7C8EF3DAE427AC5FE290F42F5F32BCD9A77D29EC204246B7DB1E6F4FC5F940992AE22BCF50181A25A07E9BB1EAC2A95BB5D76E151ED28E984E43F30E4D4CCE7E42EEF2089E72B1059248CEBEDA850BDE2CBC9C946783881CEABA32012DBC6E6F2D7636E690D608426BC59896FF7942705510BABBBBFBE489D592DEA6B52CDB3AEFBE282D0550FED77848805C0D5DAFC950F72DF8E75E1D55934C479FAD809AFC21A5F49F32A3777309A219C94187C61D228C274018FCE0D44D6AD07CD408898211D1E3D36AC255884746E5C8326AC073B91B983702ACCE15895F51882BBEC9FF7A4C34020B7F28BAB339FCD7026A33AEF30C2B9DF7F3DE45D3EF42937D08B2342DF8326609B37FD4A9802AE0F2A1F4DBE2DE90DDE2E7F7ACB23DC58B53D24AEE1AEF890736267D93EA1E85FF909083A96AA665B7F6CD23A70F689C874769E33F8FCB71764B6F72588697AB168EF7054EB51CE54701CAA98C65C476A87F042B852514E6A5EF48B65FED77729049897B76110B8B72EF1844666150CF01BF5FC00927E4900A6D265A408FC45F56210AED24D636083F0D5379C51F53CC398946144CCDA3AB36BE41AC194A88C658DD53CA3D9A4857D39C9DACD32B5E4C193F94C9562D3CB9FB48777D2E09A4DCBA2695135B6D0BDE52AC3179779EE3AE3B7FB5CE1732FCEDF0BF373968AAF41506054BC6C989BBCF0DBC0C430B2D692281E028222EBAD1F5FD6EAD173C098A6EFF4C96E0B1759E53A1D478F938EA4C9DD66342F319F361ACF60D3C67ED5DA376A5453D57CB4F85C4E332258057D7F329C69A74DF803FA42CA45220473A7195C754C0C12C0413384B42C332BE2005FF264476E98324F8477671416AF38AD89825F0459656FE4790A01D99D7C7B6157E1F55BB1FD2A7860CEB27CF73A4B345E52A8AE8D39E2554D16449810921E36F35E4E62E496FF3231EC3E3BBABCFABDA2116CBCB26EC0A643D9F2B12F5B649F0A6D38F1F8EE46CA0E5B1D4DE0262F3FC873F3753128A32C5047502B610E8E4E391E61EAFCC33196869EE5569A10ED940553C0BDAA9EBD6B5735B52984CD68F4B2B85DCDBA349388319D13EF94FB610570D4F8CA03400797EC1B1E8F4B62",
     "D31C1756B2EDB80DF4061C88EAB9842BBD64E0E584CCB4233093929F12147C053209413FDA3695DBC8A8BB53A951F23AD5C8CED4A069F23E7EF9A01DCC721C82D3C24041C2980EB9439BBEE25EA53146511AB0579CE4B935B0950F0C367BD97DAC8ADFC6D4F63926C7ADC8591BCDCC852E2E37AEEA2362F8B88FE92254C73089A1AF4CB06942BC22296ED34B1EDECCAB3D4DE8B9C251D40013CC0F7D4DD0A6D23E4A6EAA74E5EADDEE5645C71391B9DA206FEAB5B9663B271186D8BA953EE8A2C7F8AC195DE3DCD03B3B3F760F45325D85E6BCDC630A54B5886BD5AA9D6796D920F85FA982613BB0AFDCFA95A6F10E207FB5A70C6EC7F33F48A7A99AFB87AA2720A8D4AC5BC3CB2B2C687DBC812B720730A43B4B11DD270151F94B99E607AEE35A2FBF8E7F2FA49A7D39F1501001690C1CCF3B1A0E5F88426A920F90493E8F0880C9A0B15475CCE5F105592827D7AE19800E2F78435FB7465B3D5EDD49496BFF545510FC3775BAE6D924B5C9FA8FCFEE446162E301C8FCB103343018D275146CA47E0937AB3EF797AD09E090662A0D4ADC90364CCD372180553BBD22FB956F7014C4CAB240520623FDD262880EB6D5DBE5E912A4B96DC0647854928B01D2422A67231FA682F5475B0FDAAB0C989D8BBA182F160748CBF5DCAF478EFED053AF1F4703FB1C058123CFD008849E953EC17C98A85BF83BA8658237DFEF0953D6F8F076C70BA52CFB1E498FF0D73CC1852133E6AA23A38EC77DC2766FAEBD5DE83566FBB2C9B27CC32FE425E0751092A04EF21F331983E8338EBE17F0E5291B68BA69DF27A8343204EAE4FF7C36772B922840864325C30325B8143CCE0885B8082BEDA9B1CB324DEEE3123245128E557146B8CB8AB8017E5ED3FA169A1368F32A43B5A666799CD98D4958E4DEBE865ED14D08F60D01F1EB9ACF80A5087BBF12F4502D58C246CB805AEE85E8CEE22ADFC65869840869E670C8F0D45C87D7FE8537FAC9DC266B057F44DC36E358AD885DA5E3C1C7B8F090A6025E10A23B1874FC2B69407CB15D9481641467E6D46B426E3D0028A5E7F5A6EB9345447C7C7943EABD9289DF07E30CE2B76989013D42931E115C257A60F8A6B97BC0A9CF296C321C6B990255A16A4158266C1E88007EE9462A9387327D17A492DAF95D222CADCE02ACEB1E3E2E9F4F392202B59A970C824EC2CD354B967B322DF9ED821A87B601FD310F0450370825B69A2051AA4C3A6B119760208BEBE323B148EEB4B83245BEFD8A5573B48DEF029713875AAE5C7982D718DA5BDF8A3F9674516A1D363EE46D8D2CDA8ACC6CF4D1ABF4348E3AD2234B0C3C37F02E0745030C7A0FC08F82977C40D15399573BD976E379833317764F1C35F87B0517A046293D9C09D618AD1817FE7E7735B8A9FFF12D37CAD152C15D5CB6823A2CF3093B3629A1B8CD447BC7354AD9CE5320A1344940A4660A74DB9E65136D5075D0A9D102407B67D227D1D8CF755996ECD8BBE8D01C58EB98BFAAD8B0305F5E6051311851D71FC642A5A55335FD4DABD78A9D1FA9CB63F92B00DA4F51E1D49FB152B3AE3F0DE35977359E78C3A40DC6F85CD348858DEBDDB5E208BBCB8CAEBB49B8F6A82DC3C0D1371146E71DB07E493810F2FDC08AC9FF0208A117CEC1BCF9A50391240692B5526D898062D855B0D6451C3868624ACDA87071DB29DE27728BDC5FAE87F7B90EC3767748ABD42F3DEDEB41258937DFFC15FD424B87221BE9E84E410EE6D55348A6E0DC9B9F4664F493E1502D37F5C7A8B60F11C61705E9E38809A9A9A4ABB8C655329B8C3946823BD3ADAFF78D457F05DC5C7D8488C3B56E93D61BCDE222C00D22A46C207DB445EC7F86A14F4B8445DC53FE9B94516496F2A6C6802FB007D87FD393D0B44402EBE0B2F2194CBE32885E21CEFBD53CDA1A9727EF3802BCEDFD32912DEF13AE4BE5F21ACC02050C303E9540DBFB51FCF879783FD0D7EE250101ACBCD1DB2F155D505C19A4C06D5649A9D0BEE759B24D2D3F327E15E0DE68B499CBA74148DB4FEDEABA91C97C88A02DCD30E0727D63B5366606F0772733EFFFB6FCF8F9CFEE554F75CCEA0BB365234B3832FBE1300176B2DCFB6EB65F0B6CD5824EC4961953048CFE904D2FCFCE77BBEDDACA65148AF180C53354D458C2B51D0399CACCA5705FC4FA2BAF7C7352D2618C5E378C72D57782D54844D478FD855B18EE62E4A7B2540306FB52AE1C1A0E6E4F71D22CA8DEB554C704D3DC1FF573C8C46A41ABC60838DA583D8E6CD445421FD2F2D57AFA17682BBC95FD0245B1F1D4572C673E55F347A088EFEA0E156E077D6C7FD52EED21DD3B7F28F1AF4049AA3E7CE35F3199A943AA0F22837C2F3A3A327F5155F0B56C04DA8C317026330464B2E148A689166E8BEF9DD840FC8B22C7F3B37CFE0849F5B0CEA81E51A119B543445E81957A6428EF920F27FAB6437DEDF38A0ADD41D707B6AA28BA0FA09876338552F38D2A2378C45885E08CC18288F02867D7EAA8BB16F9E9BCF0DE5B0E5C42F0560DFE9E0387633CA2BAD2CFCA6A9C67B0D97363D9CE3E4E6C3786C4023CDA15651EDF19E426BCE2EEF7044E908CD22F60A2D12E5C9492F5A71DE86B8781ACADE59FE4F26291B73C69B8670CEE4C1CAE1127C7375F2125CC33B5C2538B2E02C66B0DE876A07C29207AF3FDAF394BEA89B58CE1875C365ECD0220431C45D19B5EB5965A5A6A408159507943F246AFC991630D23B2CA84541BD92D7EDA19689C63048DF0734F90D057F78CD6192AC19DEDC229A15B72FA7A928D7C317AB7C45F41437FBC662281A1D0D799E5966B4C156B968C09012A627BE4E8CCF432AEEB48F00A38FEBF930F286E407386D04D9371FDF4CD871933554ED8F3D8980E989764CC71737F9110052E0D5B20E4B1C285C0A6887AD7888919B6FE9B4F79E33476DFAE62E5FD98860AB67026D754CA035BAFA125D178320BB0EE4CD5864C86CC89DDC2AEF474C90D9244DE1233FE6DF8B09312364826F2A27224663C811C012890C6BC67DB909A3A0F9B671373EE921A432C5FA587B863AD764A6D721B022F4865A555F3BC54F564A0B73A7DFC16DC60BA50E7E85B0EDE7E31FC21A9F126D1D437F90549CAD54C480D925C22FC4615619C3BD8BA74D782AEDB7F20124DA48B7AF1746DE6F9E453A137768E495E44653DBEF6881A0E2310FDEBC8149BE782885CD60134791D18371435E5291E9E20C334466598B300A6A57D841FFAA3D2990C478996B4CB599229172543CA6C3CAF65947FB626205C085B501BD059682F52C25CDCEC45121B9E688FF484F58559C0F4D7A8D1A03813E7205282636120972CA945C30DCF413ECB3AA9C87B8E88737EB2360E436809245DFDCD827D964BC527E96B9CF62AA103816C13C9368887F5893A9C0EDA622388471CBB8311FE016855100C6BA0774EA2E3C174D0F9CC0E9A777C273A940F29D66B5E5253CAE3A4E37527B67243E09E6B242B07995615BD1115EC7C8493471DC886B56DF9C02A2BD2FB3588DD3E2C31C01F230A02CA3E247F5EF98557A97AC0FAF1895C03F2BE8C79063C990E706C6940CE36F4F839066BA67E6A684A5E72809A9783ACB9DB15974D291F93653F73106D3B228E498784EAE305125981ADD4921556EE9E51E0D1FEA5046F7A0C16D0DD53D57742F9C0C5457CD7194B366A962C59800417BD7675E8A6F67A4F00C9A0631D9B8828E2C8FB3A88D9D84EDEAE89CABDA03562738239478EBF8DDC471CDC7F6A9BE1B0EE42685BB4B1475330BA2C9059DA3A4C361927FE6D2388E98CB34CBEFC7A45ED40DA8D4E6593CFFE234D87D86997435B9C55C5E177979B509E673DDCEA28DF2A16085540D87D69695A4E23D88FF8C54D77A99D49C18B325978474D1D5CE1B3C77DA4B8E5082BF499BAF669F8CC29330691D01C8AC926E7E6FEFE9EB0344815F5BCE7FD5FB6401CA1F57CB4260E65C9A3D552C6EAF704A2995C490D69CA428E21301E99687178EFF32B2BDD30B3AD89B6DFC0692617AC0621EC1C16AB247311213585F2D93B52847A029B4475AA1205135C5FCB3D55564144798917AF5133336EA05865629383C3D1F194240397D73BACBECC215CF82895BE7F195E35C3D9617FB1F9EC41050017B3449882C4985DF25E7E68F11453D2FC1C57F367E26F59C63FE42A5D4ADE44B6CB4486C9C76C59C50613A8D73B957640FAF6DAD3CDB95B68A235BA839F1F216A5EAABE1CE1017C6397B63F7975AAD961791447777B12FD6939D3126200A84DAD0807B4617C1E3866480D8340C21C736B560543C9DC371349F6A144995B5F52C94E2DC81B5D5BE49A8E818FC3F28FB791D285D691C532DDE515E664EA26A036F252D40D6559CE31A4009E1555131ADF7B5AC849AD6B4EABAE63E086C776E76C8A3B6EBED214AE0E95B60205AC232F5BC8DCD14DC77DF43234000B996CC90F06848F89F34423D41AAA068CC14CA3561DD1ADE7CCFF60D781535278051EB2315A9C100C893D587AE560212F0386D989ED1D220D0127C7CD19FDAC811FE64088F8B2E759DB04071150C5C1775D39DD774FC30762AADD994858FEEAB8BF489779984BA92A93ABEFC82704530D4D3B086A9ED6184B8089E5157CA9C0C5D02C385068C3C4EBFF0C3F728A8D91A3F81046C9E065B9DC000000000000000000000000000000000000000000050B131B1F22",
     "C66E079840FA0FD9FF877E2D2DD123D4DB0D49526510F680D3E1761DB72A0423A83B37F939CBE77DF33566EAED5A9C88E283E6CB83143FFE6740642878030F66716C88C95A0557C1D8CC67A40E5EC03809EF20C6907590310491FE918DC04A5ADA7548AE92A577034A77401345449066D1F1E8C25DE9DBB91B1B6FD108A13819E0ACE99EC4922AF1B17EB06C2EAB"),
    ("pure",
     "8CB1F70B1674C4C78C4649218A87C34DE9DD3E9F9130C4D7594E7EDC92258FFEF109BB0478DBB80612C0DFF30A8BF26B6E5F9FAF0B82C62354D2FA9A6772A272F4574A9EA2C3A60C5895FF9E2A1CEA2AFAC56038492AC373AFF33C8C85B4627C438043E3D9A7F9CF0E373A5DC10C24E4E8F6D870FC4763261430F645FF5DC0647B651A0BDA2A0CCBA91809781101454D5EE841FAC5DAA25195D9542D97B5DF3B4B82256763F16049F2FCD77549C776EB9BB6E3E07A2D42F710CABA04309A0F749EF7D7161061D84DE94E5D75BBC9FC5909079D44814D26CFBB0A7B253FD6A9D4EC3FA34CEADBA4E27A3A7EE9C24427751E2B200FCD5496B3DE10D1CA2F3DC1EFE5D7FAA1535BF9D3862480EB06EAC16AB25BA9FB0B2CA114EC00DA51B295520E2C6675AD2A008B3ECE78DA59A373ACCAFB5FCC63106BACDDA7A228C7217D5C64241C79D1707536E014E568DF766B8E6FD0625B4BC498DC5106C2BE1399C56521CD317A7120848BAE8C87989C7137E2CE42CD7F87A93495B61BDD30C066406FC17B4E653024C2C8E5509D48260A3DEE501A10D52251AA84AE9B43577C65E630941CEAC380996611F746F7D3DB467B53C39AFDCECEBC527EE3D8177FAC712D7CF63F19677B4175BDB1D587132757BBC6C605C1D8D960E15D1B930119C77B88E3AF97966BE57460ADECF5B62FFDD80E700265456C26E61798BF1AADC9B4E9F57E3E2BB86F8EF652A98D416CD0FF637E1615E86078DA23500EC6C0593383C279260996DF83A99EBF018AA8B55ADCA2E4545DF37F55C58FDA23008201A0758DAE4A92C1462ABD6FDD32FEAE7CB89D53C2B6BC5BD90D41BBBECD839907BC85B3E120D292B4BA8F43C3090D6DB14A980C5B829AEB6AFED70BA32E9159F83CC8D6C2AAC1BB2CC781D7C085CCF5035DC9BA04E5E1C8741CC80E04DA0E1B43848909ED68FB03A414A8FB5F19AF05AC5DD72D7EF0456E929B2AD70FCD718563F25CEA88AC733A1AB0ECAF286EE1F6DD43DA5CA6DA784EB648C0B2F68E2F0884460EF3C13457AF80B6E999A9F5DD32E2CB95445CCD3A5180851CE9620D44B8A49C50FCEAD332AEFC9998CCB4AC88AC3F84FDBFC29F53442587542DF0174BD563DFA6B5E3B050831E0643B68DE861B7CC4273AEE0BFD938D4DF3675DE075A40FB760E480C7516CE6695FD4496B6B2FD6314F9DFF15E05A8414C3A3CEB0FC132270913489006512940B563EFF1C2A2E1AC7A92256D647E3F9B4AEEC68EA9516B4A2F2A9973F7CE2F29F2BFADF13C4F3C8DE7A28D7A7F51B5EC988ED29B2A5CBAD60F25C6AF20BED04938CE7FBAA0EB35010ABDE22A1E2227B216B0B9C98FCB3646783A76EFD584A4419FFB982D97E9DE88540E8880AF98366A4EE062C16ED195829752EC014B6F11A4633DD712D87E782268AB6E0F4F7AD197D57607AB9E6C6C4348B25D737EB9944295FAC92787BA3B1E85BF9264C2433129084B622528E06E82BF6E02C8B9E9436B33AD56EE80056890A78846DBA038A6E518A591202672926F35026EF941C048A71D87547817734CAAC02A6BC420F922BBA45D710C9195D6CBA430A7EB7D02E26CD79DBC78660DC5D1344FA26657125DB5A7688B3012F8258300EC811777CFD5F7BC3C8A332AD9EBB351300633BE668B00B32D2390C610D8D8030F23EE50F2F733875C3ED227699FE89E880782AF7260275208AD6235561EA04FBACCB7584BD34F49A6EE9C1ACF92D27EB97BB4F01F1D6D9220CDE17C0D8C2CB4010EAC33597483D26DCBD1947D7A2DB792DEE31CE27489A1D7C95E6B7096ABCCCDB610F0AB800BA9C6389EC1C830A3E4C2C18A89439FB7579D3282A5E7462308C858C4CAE7BC8A3EADD661221DB4B135D09DDCF4A2B165D46147B810CC28A1C578F80345D2533E4B87D4E3CC892AC5B420B9442104522ACAD59FCFF8A245312A4D1831148AD51A82E161BE99855BF97A0FFB9B729864AC3D1633813D4008F772B881AA2B67AA1FCCC5854C94BF6FC8622542E32BDC64FBA3639E55A2261F5AFE0720FC6C44F5431BF766E0A7B56303F91FD98E4DDE3EE1226840297E6FC9C013E28BE72C182E8AD0BB226B73AAC8C4EB49727AF1355F3236B3AED732010074DF6E79E99436DC3AF9D578D7E8A5353A6A9511F602738BA0C0069304CFE654B72C38D0593F6CA2DFB29D12BCB2935378DE6D0FB5F3E10947CF5EB7047D0C92ABA8445374FF35EED92FB33EEC983837B83D666E6B94902CDD00747BB467E69418019DDCA3EEC516A69523641D33D97ABE3F3D2D4A17BC52A9BFDD7CCCDC156300388A35D51C5A0D3FA7840A7F3CAC1FF4460DD899F58A5D4BA6A965C637D8EBDC04027917B2A30F6B766AE6ADC574EB738D49628FDF48D3F53D11BD15871127249C7D43058AD6C4E31F22DCBB56F267681522DDC96F2BCA0EEBE41B62EEE59F48BB5C6C739D2776C574DFF0BB152D5C42025EFA51E610F339A70772CA687726719CD9AA9FEF26ADED3ED2AC52E291AA28309D9446933305B69B3560F7FECADA31872E4EA93B9499D05AD53BDE53D195A18D1D7A9E2B99539EA3BBA1EC7AD9BCFC93E97CDDF4CA392BF29E4278A814C922ADBC884869B8B02B017DC3161AEC94FD33B5BB4C6900F88E791A02F898AAA7BFCFFC729974A3EA3E167BF7CE7281353EBDFF01F59686A4A8FAB8D03B67A3D791F3F12660FE45FAA33DD345C040081F6903F1F91FE836440D0F7F3B03E1CE47ED3505CF6E278BBE17AD5B94A974F24B5FA6C4357F3E27",
     "3A5103959F0DAF780CFDCDE33A4DE0B67F988A8DEAFF5153BD8D029CF0A7DDC680AEA1938B951D5472652E0FA5C67A45C8A9AE3BB3EDDBDCE58E2BBD6221DE3A0D73AAB593A9602ED33E7AC6DB37E2E94A64BECFE2EA3A2A63353DEBC4F092EC2B0A4687AFC4AA87789025ED183F11237AF0AEF50E094454FA59793E30D9BFF82B9205ED5A5CD9F85ACCD8263F3484DD736EC584E9BE7F30F7A1E488BD055351B764229C1C85",
     "9AD1B65BBFC23890E45AAFA15B7840A7BAC0C210236E05DC48D7E8C02DEBA4A2F3862D836BAEDB255DF88CAAFAF170A7DD507E9F5AF5BD10784F0BDDFD8CC9749D4521C47FB119C002C0CBD4EA8469655FAB33D664D12EFC964EA34055C4D2C2B7F61EB5B2F3ECB2FE8DE5EE88CD22428C0EFF3B23582636D0E5860528682FA0B953C6E304C344A3064D44F5B7277E4FF9FA4D1DB5476A422A3ABF88CEA5FF96CB67497254203D6146F69C449BB1A0E0DC97AE044AAEF67B1C0AA5B6547204C7DBA6B8F05F359949060A32A965159BC29EA61503E0BA0AAB638781F148C5EE096C991CCCC0B0F27F2FFAD1D9EBF7719B77A39696409DE29D8EECB109AD6B727C01CBAF7F24297FAF0152EB0DD5FD60C246AD63DC1171B45B2128A2103A98A56B0B94593350CDA5FDBF22F24B2F7B80B18BAE6F87E0A404D7DDA7E9BD97E5E6F949FBCA911666D806F2601EF9DDFF87CE418FA2E731E8E8D3FD00EBEE75A4A1DDC0236405F451FED0ABC1909F782821F561CBBAFE08E9331D7585430EF84E7C43051373F81DAA6FD6B54090E3E679277632A5A62669E5D5AB88D58C5372FB0B4420953F4A6AD34265F5615C2068FFBA1A81910267AC00AD00F30C3250A20B85EBE54EB7AF2175F20E5ACB1DDE2E943D440737EC25B7F2A6F4BA8D61C6B476B48151203CC13E4896070C94B14E52262DFC010637CB74D3A840D6A9BDA04C1C4A888F2950AD4EDFFF30525ACA3B9F10F9B983E39A4BF6CA873FBE65FA72E67E1371E2CC6F7EEAEBDD7132C222C6F4243D85C605DE8071E862BBBBFBE8258E34B393D17EEF3142BE3ECD5932B1D84B65D84D1EE3FDBF771C1C09F0DF12E33AB6E7C95B5788D97369F6DB3C3F48E11FA46EAB39E5B1583AFCA0FA574532924356E17B7B5EC0E49C176305A86B1C6FE1EB4EC78240C75A30BA658A69959C85D36B0B852EC529A602C99E75450478662C25F60AFD4FB7BC8A24C442C4DA5BD2CD9EC11B11A35CDD4BDC545DF0AD49E03D7BEBD4FB99AC984F830A679784905A6E51967E6C4575F3555519448B572391E06B1AA3E28F92D31741AAD0062130BD579206969A1F9AFBE39ABE6E0C1A9ADFDB056260F2A5A700064DC248D8A10FC04918D71714E892D4176A0C399072B142D0936763EB4EE19F2AB05F88936B818B5CACED5A237D65E2E1C0C7B498E2FCC77754965715804C7AFC2744E1E54A95CCE2F06E7F8301EDE648BE97D7A115248BDE0F7BBEB8EAA69A3B4E96B0A508F68DA84A8CC15257277021C97208FA30A0D278B28F94058D13146231D11C9C179ED4B893E3D1981CB6FA21EE5D3FDA59CDADD92A171DF7A42A6D3D7A24D1A78A43B2C9BAC2D201F0680387AA7B8303CD9E1C7B4925D08309C2732E6E23E139AB402A3787B77C15637228F056B73FD18E16009E58CEE02CCA45481F39A5D84BAAEC0A3EF7D30D6A44BD5DD2B0ECE2733C8902ECFC675C009829C67E5676D306E4ECAE4AC48AAEA2CAD8EC067185F3B0F33304C36F04C1896BD64A81B36D3F7610CEAED4B222BD24F90939E3BE183912D4D15D1B5C9E112566872765A8EDF10DE6B77F4FE7E2AE85012F7ECC560BF42EEC11BFBA0E45D90C1BFED3B3173E27AA134FD31D42FCA2B6617D553AE2B247C8C104F436D3891BF22C709AC86CF9AE3A2D5A1FFDB84E5A71AC487F8CC4AB1DF47A277C96273D8ABEF63A545E702A82771D056A89C844B66E16F867364A928B1E23F1AA98F8ADC60F3E734F62A1634FB0266EA6944C98E566D97438E25DE752F8F9ABD8C1D515A11407D6A04CEAF5F1F7DC0B94FF9DEF1FD17C6E19565599274A5CF5262357FCA3E635BCFD22C69EE7E0C5B332925B5F53EF5002D4FA784AF15C3CFB9B667B7EA866057C59542C1C87F015FDA467085E4E2D370F8EB6BC6C8E1CF232C2C8E6D30D0F9439AE0599FA35E9E0A0ED93D90562BFA12DA126A10C908A1FC0F11C92DE77B73A11577996D061532BDBEC8D8A87A1F82409E2B2DB621347B5EC3ECF1F166BF3DF24244C039BF7671487E419E1098BAAA547A4E38790FD82A05DB088CE757B5EB800ED709D1E3A88303D8079B6E0BEBF8CDB6317C7A62C944BFF7C2A62BB69639C9C2C4223A599EA4E69CB6A7E859285F827D602BC0D0D67120A60F8B79124A41DEC362D8C7A54DABFB35D2A54A870F72D9544FD9F267608487630C273512E59E2CC4998C677E74E2C33075AA4DEF12189C75360A7A24FF9D9BE2A4BA1632F5B3258701F6AC1D22ADB26C0111C7F5D4381D0A5B2F60EA699A3FD7851063AA77738A4B9819CBDE62CAB864ED918FCC7330730061AA84326CA6D39053FDF1650A5FD7BF4AE64F6E4990B725CAE8F7F92C19C56D0AF94F81777DB4FEC3C6DAAD2DFEC848557897940403AD6F914A34264E959523AB1A3A444FFCAA79A292568E438B94545F0FB1FFACA6AE95FF155D23DC97FA3EE0EED1DD3FDD8792A86CE7C7F8289D288B792C32E88B7C61AB50868E0CD35A1811D04FCC61C479F5489616317CDF87632E9DCE435DD3FD46895D16791502EF470A5E1ADB90D9E20E190F3A527BBBC4A104A48DE28D5B208C5257C943150CF550C36C5FA6E3478946E2C90A2BF916BF8D2CE7EDF6F349A38D02AAA5E36149FE6DD155A8747C94D44C499C5B57173079FC8CC10DB8BAD0863DFF99CC13F7BC5A65C4D27740876FFF2EFBBDD1F253FE3B468DC2A5A489C9CEA645679FE26571793F042FCA9C9435D88638FC4270DE60FE127F9F6FADFF489B281CAE6FD1FA8BA4F24AAA05BC262A67DDC192C783423E4A412592F2F0CBF4F03A0471605BDA6894D19D61E47419525C5437B0BED4069BD135C30C8F2049624322C1DB4DB6F54E1CC7A927E0DD4E97B1A6C29E4C7A76C8AAA951BB6E41744C1FD5352A5962561F9B63B64A7B1675487B2A6C45496248DDCB4BBF03EC6A202BFAEFBFB32F04AAB5865C88E0684D36B2EFA97EA96CB94EF7FC0E6FEC03968D1F2AC5496425FC93AC3E1DFC47B705C247EFCB5605BDD8E05CBEB11E3CDA098B691F8E71112DD5ED7D84C3E026DDFAA9627DAB526ED6B5F55F798F578B8C5F6B946F61F116235892CA2B093EDF97DA23266497D3FA3C62268579074BC1CC8B8F7B13BD9FEF435F04BE972BB84F4017E758971EB9BDA1268C56A46A302F4BB3465A1077A036A3C3106BACD9F4BC7EF1177D034051D2E5DA766AB8C41838BF6B31208034E56866DD8AFCFC65B8EADE35743B22C7DCD787EB0ABC77D912B7FB0C9CA2511FFFAE45F999B8380B1179A1F18A0CE9E19B6EAE7AC8D7D78FE9F41EF8DB39CCFC23A4C1DA7192A0CFE7BB916FBE1CCCBE1ECF36FFAFC81217F803E5B7B33F1C0649018CC3C22099F325338255B718FB850F7718A330CFB2EB4B14EA990388C9C8E9C9B62A662AC6A312F8D2BACBEFC032364597BED9F0AE145144A0804F2BF18694118B7AF7E159F9E7AD22B1B21826E3CAF679DB9B0AC72B6B4EB50FE43BB059282D30CEAD670F999D3C01F1FCAC03CA770030838A2CEC064662C6C53D10C60118FE0A74B23618BFB98FCF227E1711D80FBDC057111E6E3203F53CB043B2994D90F732000F440B2DA5E7C65C2C10738F534F55562DE16A03DF2F2909E57078AB102A5F6164B8B6F4397ABB52F225D3221287C40A1EB4067656A79006A2A9D0DC64A29D0E7896FE33DE94C261BD14696F1B33FF19B22BC2C1F9032636D323D8B8753F04F0DD099DA0B312C65A7DA81D66656862286DF205DD82439B0B63CF387E95C94EBFC406E5C37CFFCC85A930DEF8EB9770AB7C62CAD7E58FDDB00B70D888E9B8A78F0372509F221154D4C2D46FBB3521B98126F76AC171DD5F71E96C64318C622EC21916474F49BE1CC3C3340651839F77C4A54E007C4E82B0B132C734CE135D55C3AE9C5170A5545D3B03E524323E73E4D15DCC55A7148A425DE6F081E0F3DE9A01AEC6A1B2F1079A43CD22F483592D2875BA050D9E1708BD0AA1AEC0B71438712B4B457DF2358401CC3D7BCFDBBF4216284B79565040557D5A65721CF8DC364E8796ADD73C2AC0E6633C602370BFE8FFC54AE666D64EC2301ED0C50A0EE61CFE27B34EF1B8EA605E29EA6EE1F63483FB8F37BC4085AB2B28CFC6317B16B470A33445B07D76A4A53649763AFA18CE001985511CF0607474A9C52067EECB96D8A55ADB5EE47EC76A8E6FE3FF4574736A14CF66C2607E14C84DD28CEB2F5D6269A58F03A037EC3295CA0F996F907C8C6DA0E0EF45839890F81127CE5E1917B2989318F7B647946E99238F1BFC7DCF531FDA497288D126EFCDF3BB84F247F6118C1CFB272C0630E7518ACDBC660AAD8B9412D43FA46A7F63F43DACFBDBB3EC0357F249DA55DF67CCC0F09A3DF460E604E1F03EA55CCC3EBD3B6B766EC7D336734E488ED55B104F517F5616AE1FD8437C225CFB68167314E0D0258DAF0DDB993581CB1CA94332A97BC0F564A5254699EA92DDA1F1B7B17BCD9A64CA4C5A1619F541F40583AA07F522B88FE81C40252D87CFAA6A9DDB666185D1C571B1BD161B6979A47B3447C795A7ABB75D7631E4CDDBDE300F19B684F7C21AD25457841B0F672FBC5A9D816D0E6FC51EAE6816D3C2B8FE2FDC73F62C7D1DBE91E2B51546CA9B8CA304453777A8791A6071B2F313A52EAEFF1090A0F374650576C8BAFE2F71C6E8A9E0000000000000000060E161F2B2F",
     "339A8D7A51FC155E69FD1DC3FEB136A98775C4008CB767F66E04B5732C2332B04B2F4E4A991B702606FC8C60C07145BC0B183F5040979182E42795C2221C5BF55EDE34436D42C2C6C605981E3A4C1D04C7D78F8719918E8073BC8C5BE2372B9E1AC7ADDE760D949BA058E2CE18053F718278FA4EBA76BC0CBCAA5102DE621FA8D3B02379BE9F7DC2264AFED69D4B2BC4BE6ABD02E0"),
    ("pure",
     "5FEF2E3853BEEC5FFDF90988E815EDAA6B0887B8CF65C06609846AD41B71BEC9B7E93BCE9502D9B93DE1EA52E60437D3701688B823A2A32D6F1B61400FBAA25A26815F9903539FFA106805C995E3A39004032588AD99A61E4678D1DFC2FE8DBA683FE349FA73F4A57AC7DB1930B59D4D4340B935F23C1C55F87CD3B08278C55B9C395CFA0F170985441C68BD06FCE913BC1FBDD727460AFB300E6B4C5F679F837F30E8C869356E89D6B25AC2D50FCCAB0C5D6792BA7888AD22934CC955CC5369F605DB48851712647F6EFFFF6049D9AB7C25A7C38CB3791116E62768168DC0B3F6B35BB5B8C905FF3B90194BA342908B42BFA48EBE86892B6F237FD200A43836A6250658244C54E226C18B42ABDFB51FE0EA00A483729E486D37F87BA77C8637FD0D66104D098009D94BD7093D8F7DB7047AA5629D332259C27FC62EE18A5A4EDD793719EBAA8F8EBBB73E0249371E8BD60927DDA4B29633E840FCC3D1E4DF907FB8BB7B1D2CF26E141220D559F1BE3648EF8A7E503A2C0558C491670A0E935D18877C1D420CCCE1067069C28D74A459290440BC20A353040AE085489510F70FA1ED02F229BBA2F9DCE59F5457C7F04C47B29BA036C082D2A3F311310B115559E138AE7E214C771DA3A505352D536975ABCEF1C5EF46DE9090D6F0DD75B16526EC79343057305B5F0AC5BD648AC7D44D1EAAFEEF3F63C8FAD44DA60D77B4E42DB7E6438DE0914D0EA9A1966E4D54E2F037149A1BBC154EFA3AD8D55FA31C55A36F7629AB10DB2F934D5FDFA3B76BBAF6B8264E6F49321BD73949B53C8210A8FDED0F6EE5DC849204338A608593E0204D6802E901D9868E20F85F60F80E1A5D9FBCDFA11A13150751E9C87B1E3C021280D75FB097C40C6A76A13AD39430A8CCED3C576F9E6B26DA2F2F8754393825C13C18A6EAF132D24F99B40A9B34D8C5225848A9B79DB07C0A8F0A33E41221A8364F8928BA8B16B768DB9E5B5765CDCD72E2716AB6C7A39C066BF3FBC53EFEFD5E30CC81A75270AD2BAD991EA9849DABB9AA530C5B7E35FCF0576DA776CAB7B1252100F6FDC28B8574E582AD75A0EEB28DDB511F0D57855CCC5AF23FED37B41160FD71D611DAA3CC9FD395A8FC3233697A12CF330964B50CB51ADE0C0337E608DC80C6500988B5718098D3A26DBDEE59CD90428BEB25265718A4F4DD2630104B570EFA6513FCAAE2F084EE585C4565127C10AD85367890A2DD8CB2E2495FEEE36B769158D5BE7051BA84E30642EA17522179AF52C43BF1552550CBA2158111DB296E6950FFEEA1363692DE7C77ADFCB29C6EB83A09DF7C0C3B28D62069EB1E061B5B33E8F0ED292892F01EA88ECC3164EE5B6B7B9074ACC3BE20A1315D036177D17F737830F9E4CBBD614F2EDE810944EB833D35BB2BAA6D399C23F6DD65D24CBE892433C4EC6691950472213FD9581773992F8E0927376C7E1E13FF6EC36C2FBAB76945EA854399EA1FDA6E1D934323C6C1D93AE61288E4C8AC09E21B8DD0659AB38C3EC38AE051E2118992229C6B640A54FF622E5E2A96CC241C03A7BC645FEA271EFB37B4E4A973A787004710C9DD32A3274093A08B18F11D7D3914531E0C189339D11AF3B456360FDB9447A0CDF6620845A245CE240C3A1AA14AE8BE78D54EDC78C336BEAB8B38735CB7E2D6B1A9C66F5DECF80D1A3EDB57342297D91D90B284C4834A3EE94008FFDEB8A3DB0DF3CC155B5DD3A019C897F1F11F910A6CAE897598B313ADF0954EA52679D7B19D3E0B6CBA46AC06811EC96828AC0A9854A6572A09987014C8D621EB503FB6A494395D8036605CD666F2D8365D801A8C0769A379B32DBF7650789980288AF97DFB9FE0F70236C8DFF11E8993F2A434731B8FACEBD0EB282D72127E2E04D32C264685C091D37B596E6B05B16A1ECCD1A370FDFE5D851170385A80E42038F89C19D839D0B3FB75F6004F90584DA65DCE7D169D6987FF1FA699AD52FC639CE47A8F33A3975EFFE30E196F2AE7B09B3E4504DC6E859477421994145DE6451EEF06544CA706A3DB626351AC4516A57133B774F7A45E4EDA211A5E0A4139D2AC8E3322517663E6848ED2FF975DB8902BC63A51FECDC044FCA50C4506215A8614882721BCE9BBF646F95D4FCD4A6E09E4E6418B7C1CF2C6BF64AAF12297402819C597CF11A277527DB0AEAB285A652555655034497C46614F5D8B61905657E07719DD65A1BF952783E91F260F252C31A0CA29186E2B0461D86B61885260390AB18E5C701DED0688B43A9379CCE557C1EAA5E9975CAB769BBB7631DE79D535051F2F1584F3A8F15EBA444A301AE196E1CA103DAE6491B8D78021DE25DB2F93C80FACD7D15B1B544D4F169D0A695BB8C1874A6D122947F67C4ADBE731C1FE87A1CFCF1877084E5220AA704ACFE0058B16B8E322F127EE559CE784C3D7FD9093270CDB796A3122AA5037845D8AFCBF66F3ACF4AE9F5B48B95D0257762BF6B9A78E35C78A6969DBAE88344FF4FD0A6AB4DFF13AB87903B4C5009E7D535D73448FCD5FFA97922F4217471F8D66B25578B85EFC44E36DABBF2296874A4907BE83C3101E77F6290172567089E77A91570F3C56053D0A1AE61441D3CFC9FDE5F49EB8120B2FD479A825C941BAF6E5B3B1F5C951D15EB92029A4B1689B349100B1F7B7FE8C06797CF7BA70BC68A6FA95CEE9648308AF047808215FF33E0DDB86925FECD43579CFDA452B09D58E80D601E49C579FDA5BD6A3C0E46ACAA0F58555D1610D5C7721BCB9C4504911",
     "B9D588CAB27F1813E896B42FC422951067001FDCF184E8AB4C970C98EE263BDCD522DAA04A5B00CD724F9DAE30B745BC86B56489562FA39375D225B34D8A638544E5E709DF1BC6CB8A750B94185D7E714A592351AC80C2BC2CBABB11278B437EE4B50BAE288F16A907100A18ECCF4D30E44C3E9008483B50941099F5C5CEDC948EF864658E62BD88EA2C99E7D056CCC6AF80DF031FD176491B9A11E61800D6A1F7DB6FB996FDB1C44F5D617F9156EAA5F6B1F59B6FD36FFDB2FB633F260DE64BAC2B3EBBFCC378A51C4FD78FCE28447ED938F4FE4B82CC35966B7D0EA2CD1327ED30A8D5D5C4DEEBB0411E3C0906682F09050D3A35D37B5401137FDAAF28E63A8BE19537584E83E67229D2C7D6CD4816462D3789079F088267002358AB50158209F50A521CAF5C408E14D93D56E354256C2B2BC5ABEF2F9533B2E7B58E12FB4C6728AB2BF2B44172F2E27836353B354EB5B26BA69D7DABB420FC075E214F23074B0F798B320AD7D7D1C84256A450923B100804B219465BE0B4DD36CA8C133A35391D87C7774557B96584EDF85E5F9157C793715C845C24D2D7F0D189C43D5CBFC1A0B635A75ACF8265880E3E1932D18666FA07E8D2FCD6EF532E2246C7BC4273C2072B2FE6F852CF7C44585A4B7701F936994607B01EC6ECD09C2EFA294BC6BEE35AB51A2B0820AD02B80799E8A68C81284B918E7B26CE7821563706A5548783DD4101D7F82944C728C12D7F97E84308A3D44EB1CEA4FFE532AE4470D0486F2F379E812CAF2F5577FD60337A0B002666C7074E1584BF215F6DB0064EA141285B3C3980BD4E0B10F2E9D371F0046C9639FCE5B2F8A4AB69B85CD037BF213E4A6E5037E7A13A234C7A00F3C0EE787E2FA470288CEBB0799224DBBAE19B8510E5A9C1E96E3411066189D1627136CF44723D6BBCD006E80B57BF6BF9A89BAD1EDD71299032EABC9B61402E75F70738FD1D84558EB962810E3AF4D32BCF73478FFFC86AA934EDC8C7CC241F511523FF2BEA3A6CEF2BACE7481B5E7EFBB289C081924398F63323388A73803BA0AA9D6DB9EF85B48FF4D9D397BF9DCD6D783C4808C5CAEE82DCEFB09ECA61C9FE44A6E5E8CBF638FB91854B81C574E6E4C203EB3D7F8047908538AF28804515405A980CA6818F706379C8880C5B74BA8B1831E4DFA12397514D67783B59B2C31A91A7F58000FE15A7E38C6017D194F8FE7309DA445FA7E750190DA4973753F0DADF5AA153732E95F37644878874B05EF2FFAF8F4A8DA37432FA69AE95F18CEB6A15D5C72F86F7AE025367E7D4D9E1B9C7A2962322BD06AFA789274A2231E85A5D18616A2D78018823D24C503C4AFE5A458BDF7E4CEA04CB80023F310F1A814FA4A432D2342745A721E20D268986B2E7BB3765A3818CFF90EA9592731F226B31F9D5D7EF32B992AA2E600B4C7AEF6112765F537B4B7A257B93658BC7D274072C2F8815EA9928460FB2B11EA60793F5765C64E7264E9AB90FBF701779C8455C4C0713DF7065BD775D85A2150589E5EBABDE530C2EC10F3F0EF97BA71085CCB1C8B6A78CF33FD4C96893A8368EA9B28A67819D457A0D13F493061E442F260A05BB31BFB8144D6D4924CD1941B5A3462D3EAACE1A8B88E3886FBBD96088F89782D45ED9D4D7F134369C29CE5D9582B06D67A73DC6A9DF64950596A948830973F22AAFC46610ADD57B7178F9EF1DE81E18045C69FCEBC23299C4E982AC6CA5AE9519EB45B49BB5CAD1A32989DC78287E884316EE319E8CDE70645F1BDA7F79A5FA5472189B70622FF38E0888CA3396F8E0C30125129F02073287B616CAA858DA2CF4BC727109428969288E34A6BE66277B2AC43359A599B6C7E322DEFACB5781C2AF47315B1223A5F65ACBAB56C9EA5465B1E222291B897325178594AE38E434D4E4FD9113CCD95D4CEE4EE219BFCE4C77D116DFFF2C66C0415AFE346F7093453DE46A251562267C90E24E8FDBCACE234BF504417E22193F0A13F339496A3F9B7D2AADE7E21A417B139401196B70D33594479EAF0B116FEBCC4D3F57DD391192FBBA00AFFF636BEAA41053ED0DE58C496AD1725BFC3A567EDAAD4A4D04E68C66820FFEF8BA3E0607A29AEA628F4A98179B443D699F94A1F9B2BAEE066A0D848E72E237A6FD288EA83B12EF9D340838C8B4B55B8974FE48BAB5FB2048E6421992371E6BC7124DCCF7CDB268E84F56F5D302D54983A0BCADDDAA4AF3C91F5B5AA4FA3FF42ADC3B9EFD38FC4622DCF205A9C540A341E614D12C484703B14A05F314D444DB54FFBB13A616309872E8F625ADFB3ECF126F2FE9D593F4E5F0E1B42DD06E2E1901A001E794531370D0EA65202E37E46578D66243EE467B56E74F66BA860082D808255C9261B6A575B21D2F51EADB35569C3B2E5347373E5E32639E39C8C68EFF3B4FFB638E81A1A629A97A2CA4ADB986892F8114FFBD270488EB13025DCE1F2D4AD4FFA361BF851D502D106E3CC7494665FC08E7F4D8D33AF25D22149EF1D43918B7F3EEF31F82921775EDD3F71A61ABFFB1F4320837E43EC2F2C2E3519D923D0108899E7349F7592E101FD916952DB54174B1312FD541A1556737EB78B0A2364E036924CFA320B1E323074AD939A5F9DE3B94F4D3E1416A2D594193FADB7D355AF913BB8E0BF0D568851370406EFB96FA31C7F6E6FD2F62BFF730C0788836F69348B9D4D0A02AA5317AF1034400625E19B91B30D1107E13CDE35BB9B1214F59885771A2CD144F166199066411FD451BB1E2E1C7E2BF4D04EA86E91FB68B3E37DE0201891C1340FB81FEEF1F156899B6031245F0592E5C8AE08DB60D0FD01451B81CCDAAB4482EF6D33BF63E492E92A193F8F0CBDDF754ABADB5D24A091436773C394EA70A2DAFF3DE22E8ADDA093FB3D7C0224648518A07C3D7D8643C0C18BCE8D04888E26961B53F391D67FF178385190F5621D01F4784C230116BE3EF2DFB89E8C55D8F59C22DE1F26690D64C38D442BB536907A1A4AE2DD7E2A49743A8A5C9F3B338ECC5416C785DC374CD755BA4D5A8AE8B94F6EE3C20B123D0C53B8BA566330532F00E7DF046E760F6DEC46051A7A7DF23E80FD9CF25A3466AB68854D854A1392DC6034BB5CC969A6DC514E0661CDA581A13DF479F61CC353CC34987E155250BBE2A7C2BFFC2F3032FAF3A9B5BDF09B43E69AAFE5F6063AAF1020DA8CFC649A86170C06FD018C1C4123FA7030BBE374A6B194E2BFD877B7F9A4D43C0860642D7B2465A922975CD8D94A786DBDFFEF735C294AE119EFCEEBC03EAE49DA5566C991A870103F4FADE1A2AEC27EC437E697FEAE917F29F5C5EB4494E8D088FF879BC94CA59487DE21FD9874E6EFCB1380A90F274961F12016374D07FE513D4656999E9D8254E0F5BF3800829F303D12E342F62616DF9916294BA1869A4716328037B513F2BE5676CF2606D2781A7BB7CDD74F0483BD7E0BAD814BD8DBB02BB61A88AD0AF7FAEA324779D394EB36A765247D36B60D20BB2D32AD1EECE0ADF0A2CAE2191F8F9035049D4C254EEAB0B8CC7E2C76DC52E6A823A83CAB2D0F878E7CC8CE5594031591AB4999ACB5545369EDDA1E646F1AB97110862C35214B8E9E3A0189A254AE82EAD29B9195C4073E4FDD5DE6ABADB18FF66B12F426FDF82D3CEF6DA3E3A420C7C485CC25EF11249414BD1A2D5E886DFBDDE52DD31C6308A6F87AB2BA581BEB69FAAC6F19A99F75243E3F673F94E0A7FF99B5CFDF0E2B64339F65B5544552C37BECAF0DF677F7B19DC42BFE70A6A80CBDDEF80D1B97D80908A2D7015B3D39502CB00DD7A19E86E7A6D157B71724170A90B0F29D958F7389C450AC7D5F9E92F57B432287A148CDA06C8D9C9F11AC69A52036AFEE22A4934F47BF107F4EF3653360795370D9374140AF153228DEBB38E4CFEB70C4D2036EDEB3FBCEE2897CC5AEB66B4A5A91299090FB81F19173574B06A1A9EC04922BAEBAC3E49A79C83CC290B6B57019B1DA9EABF002E070BE22C35E65872F5C1D7C6436750C252FD58093DBF2AFB436A5B09DC1060970F65213B6F9146FFA6C18C5406AFC25CA4FAB94B561093294751BD7CE6FF348216DD7505C4F5BD0C48AF1AD1E9714D01E6410811927675856BE6302C9E8FAFC09375C653B1A99EAD0B4CC1CC95FE0F777E5B0B96C0",
     "17CF6FF273331AE6135DB474A95A6BF26AC8880B48BCF7C44D17ADBEEFB38DDACB27C1BD0145CEBC558F7FBB1F12C35D27EAF66E4AD83EC302A5FBA03110FE6383709A75DB491B7A290476B80A97C243A786079EE29D98B60151513F200681F4E5BB483716939541DDE727B6D38908100C48A3C17A77E8C7F3760FAD05869CFADD0E8A9982E29010D57E58E66813CD3E6ABC1BC68C037067DCAD2A1EBBACECDAC9A3E9DFD7095E005ED29DE1F8AE1895861AFDC1D628D9CE3D41FBB5965DE660881037B891D65A41E3AC71040D0F7CEDA305BC1C194401840A645CF450767C0084307D7C523F5B731D81A5C1529A733754FE3A96157E3CCD24F411DC446EDE8321D225AE29FFA5EAB45BB99042BFF5F189B47A70A16F18825D49FEAEDC62A6029E61DA596FBC9E89C0F74AAF60C18A91651C34D4A4C1185BD260785F6FBF64E473BC46E46129A004147478735F34E675FEEF47113C5845C7C4D41B2397F66EA19DC5CAC26DA283D0C383D155136D83E0FC91A70952FB17E9A254EE9CFF56E111FE17333A5247A26A437C65D8A53CF71E3E483557E14CB4788BAF990241299D686D6EB64703A5C651EA1B5D5BE6BD44A5348502828BE8F2A7696347AC3E6AC9E2BE71FEA58DBC44C81417BD1F0F8862B885DBEAD8BA0ECE7685328D4F55203CF8EF3186FD60953C932918268A833A89367B5E3B33800AF934757426791D9E43E58918435C60C21EC03172D541EE1B24A8E9CE761C56A1011ACD63740F6606A8DF48A9E23713C1B8A709036EF9CB1D8B6AEB7FEBD6717F8DBF535449B7E217C7C0482575156FD6B1FFD3FB2D9D2E133D5CEA40C3C0B09958A201237661CC66E5E95E6FF098E5A659A4CA944BF4E6256F6A4AC9828DC16CB18F8289BA8D89AB6A731DD8CA1584D1CB30C89B9999EFECDC7AA838C9F2084743B802CAA9DA42EC9497E4C96D32426CB473243172EDEC881B2E4F7B88339218148372DB5F4A82123918F51909F9B3722D04F5FAEFC8361D2FA6BA71C4B7FC00837B1CC28992D43AB5B25E5363319A9C6E3446F6F2B97FC17241A7F8FA5B336076A91EF37B7374C054710DD4C6454086F88457FAA59E0305D87F5BBFD4BA724AD14952EC2FE2AFFA9056E77E202A79B1423B4D4B95C0DC0E2ABDF9396F3A0C8CB8781BEE1CFC48F4CCC54C0C331A2397E04748DFEDC098843CEFE45DFC5CACA8440B50F2A8A4684E9596FFBECC52A147C5DFBEAF3269B21BC33B3ACEDF6AA1A21D5E1AB586B1AF42EC386CB4039D92329DCF12316CA03195DB596E0CCB03688C978BAC20D5254FAFCF0B2D33F678B8ACA6E222C10E0CCF87EB97186C232E3DEDF7B1F597EA972A7351ED6167B51867923E27FAA9CFBE45A8D0D4E6698889AF7F0017C1220118823FBB9D86230C021EF5A50DB7FF2BD6E90A191C93B05C6BF937BB56349AAAC4201C5B0CC7AC755608087A74D2E3A21C111B89EB28C273A1E7EE87B1155A47AFD038F8A1BD24E8E1B4CE04D2D978039E2C88600EE6FD1D09021F1895219E0808BE42CBF9F3BDDD4438155D09174628C04A41B8812BADFE23F95390BD423E5D2EDCE1A0C70E3E4CB1E909E20DA4E455C4285F91FAAA4879FB97053B805DF8E5E4B6B1239A5647E6B01F5087711AE5ED903E4016F5AD95F7D1E673D7222ED8017DDD1D777B0B8E044D174020CA2A521B6BFD588F68C6A68CFFE87D16FCD54E60A39D1C8D9FED0DCC7CB0778034FF7D74ABD8517FCE03758BC4CAF21BE3FBA6DDA7D5351FD58A286FB5B7251D925AA7021EF4BCC7C37B1C4CD0483C64B99E202701A789EB8925BE9982E76A82F938BFADFA1951AAB1FE97EB97F0104891C6B709E18B7F5176C6C269445D53A0C003465BFCE5A5AEC74B5980A100BCBCC2118BA38FE1253A3BE634FCA734AA62DC8F3AC61769E9D4F7B42531FAA44E41BEE549AA01783896CDA2A0C42D55106A9971039330DA2C6AECCE6A885CB32A710FD452AE4F51078B8279B27B8AFF007E04A7991615116585DFAA512E6FAE917A329F6A7E5C2AFB874EAC13CB268B1B2EA97FE75B18474E176062F0DD91EDC70553599C25BB7AEE734C731B95CF793EB69D5AB3998C228B6C7900A7D583DB32DB2533A7ABF933F6632E48611EE89C8D785681B268F3E819C3DD1083F3C6D57C581D80A2605D481A86480F9AB700B444BB8CEA22C902D4B1ECE63C22B48703DAE0433359EC567C45DA528E9F42B99CA5347729530364F2AC995085417866A999C2A27FD5FA50481169543371942F29FEE0235AEB1F72CF5DD435D43B924E248F407122A725B2D3D6F15711B2F296E38BF6E92FBF38172C062DA3DF584F2BC51A7276557122FFC72B83417363379D1E72CD0A418E8D5905A089BA2D42BC0BA07168BAB9B669B4A939BC50407C57ADAE21C2ED98A2863A6532CAC31514FB103336299F58847E8732E670C99CFE15621319D7F7B77CDC2005A96D7339A0E9A85395403845BABD78B57981CBE4D951B05388685458E2F896E0A01FB245F80AF0494FCD1C5EFF8B956E3B07A9E6DA7D9734186C9BF88FFDCE644957EDD6503F7E1C4728BEB539564912AC63FB903E81B11DDC1C99073C659444A5CDC16CC8818134E9BD51EA2446DC6813ED5F2B76D64D176A1254983C946950236FA7DFB8AB2DF40C6A37532CC25294574BC18B5B1625C35C2FBCB2ADB710CA7C8F761E4F9EA0537B32D686227C24BBA0D26DE1122E84101B2A7C690ADE56B0857324EA56358FCE702249BD587AA749886E8F65DA54D81045124ED054E4BBFFBAA5FEB523F9E08F08CC2CDB90CF2E05E0A80ED1739CC69BB8E4782F4479BB68CE79603FA0D38641EB3CD423588BB8B0153B3D9BD269DB39D78A5A6740524A2A04DDC95C2FDA8EFEE1A13B74A0CCDD1F29BAF94DF8DE69EF2C0B1ECDCB052A3C53DC2C071F5DA15F66C89FCFE1A3EDD2E39191CAEE717C9237F1B69F002EDD3AB823B6E9EB0C781AF620EF273E4B4190BB02769F95D91563343FF33E0FD725C2114F20D50FCE1BBA89A86DD629BA0457BEC8B0E342A9766DE7539DE277AE3CEBFFD29C442F713E8F82CA0838D52DC854588D4837193E1DAAC4227F86672C00FB146EE53145C3C29B84B3FF76B69F3E98D6806F86F35ED5A4D495A885AA076BDEC04FE2A79B552CF04AA5FFA0A02AB40D0A5D8858BB166CB85D0D126F61F732F3140057C3F8B728388DE68A60A51291BD29624A03FAB29D9E599F424D244A3E3B3C6B69EACA78C3F9CAB078F271B652492726B269D05912B6C59DF04B22DA23102DEE298FC128A3CCF7768C5EFD7A6FF168A9EC94388183295D97F7974D2804DF3866154A90F181F63A3E087A9EBF9EA277E163326F2B64467B1F3C2F63767F3CEC5F0A4AB0A74AC66ECC0E1A7FA1C212D7BFC30CBDE6E363D7B89C95E5DC3F27F1687B0FCFB0AB144DB028E14799C23D31AB6CD0D99B60150A90A4626E2038F32FB35281D71FB58719B2893B4E7EA68ADD56EF31360DCF6038E2601D9C669D40ECD9308DABC45F9FD76B38A711F1D7BF9C88E8D9D8A355D8A26B3F3AF22E3F94D82E053EFA3A683203DF42E3BEA37AC7E12A244634C9BF93E0E35F6B8080AAF9EF0552967B599C7E50147C484077990C90721622D57803FCC46F892924FD9C2488D8D21530204346879A56E25FA96D3EE68F207928BF49F90AF7BA34BC160DAA0D7D36A325C78A53E6127A88AADF8DE481646C941E48D7219A0D422497C0161494321A957396F9EAA7D3FA47AD42E6320C95FC48A8E4AFAEB65311BF14FC43D65F3BBB4F22EAE01A7A557E28BBD69E728AA6D0B8F10A86B02ABBA92B0C3C04F0247E78611D01C41844279404B69EE07C3F65553F407C65B00C3D7C35285E206E6F1EA938AB1773BF4964E4CE3944ACB346EEFE3EC7D6DB7C52D4220FDDFE3E5A0C122BDE30B55D49A03CF13CC5E2DC57F4C8B3BC43BD9B44CF0E94AC82129AE34937555BBC3631235E39079A7C8B0238D36F5386AADFA63C9B70AADB19EC39FBACCA1836454FCA5D365E33B9BADD0C3484F83CAC36CBBADBAF20B1B4DB85E172C8A8857AF794B933342EF53E9CE56984E79A0A1FEE0CDB742167AED1AB401793555A49029977DFC1BAE8250B85F8EFA9C94B7313AAACC19C727F747C86FC33D0A917FCEBB6ABA68E02091EEAAE635130630E8C3AF4068F07104F157ACEB1A64B6E6272322EB1DACDC2792FFC7277B8825CB68F24D465A1F853AA0F4588984568DB1AC056018CA8868FB299C9895498ADE03E156AA18C9A58BB874CF2BB752C01457C15AC57F66B2557A1960E9AD25B83EBAE4633131184218D8DB142CF32F12A272CEF64BB2FC38C9E1B5C2ED1A1229ABE4686B5CB7ED7DAA54E8796EA0211342BCA3265BD64AB30820FB64F3C712D1B9870F6C1191FEBA634ED2B15E5CEED725454526E0AFCBA54315FBC5ECC844F9BB77E79D5A79BF8A6451B905D1B2C4CE115BA922C638C642F0C3B8088E45147EFC08A30FB364F9861DF5FE406C762CAAAB9FC9B8B106C4E9A2FB5CE0A2A5484B4D99A9200DF81BF5778144F6364CBB69EB68CB261F19DAF103B0D2A0674C3F2A0EAA9C53B4E624D6340695D7761B8664B2D0A2D0D3B485663707E99B8D6E0E5FA227D9EAED0F3F60A1F3037455E78AAB4BAC901104FC5C7C9060D6570798DABDCE7E9F65084A9DDED00000D141F253035",
     "AD2DB4DA6732EC07EC6845095C03020EB44B2B758A179FC474DF6DA3192DCCDEC93FC8701D172728FFB13F9DB6EACB919B36FDFA730DE0769DD1F28F5BECB92B06FCF328959D45B1469F826B8E3D95666FC990D258D2DABC675E0D62C96EC8821CCDDB4C503A5B2B0955CD4ECA48D4AB33BBFD246ED5F8E1484462F0C84E0714ED4DB362E9"),
    ("prehash",
     "F27F6E83EAC126BE5A83B122B1CB320D6971BECA8E2E796D878735534E406E14385CE32C5033D279288B9F152A0FED1E7F7F4ABB9B9212C4BDF253DD58AB7148C40A29E143EA8A684044393DAB29FC3C9FD6874F375D0FE1BF55C4B650DA115660EA7F8BCF4D0E96A57DC249631A69F79CBC319CF6DF5BC28613209A192E8EF10E257CB0760A1700BDB26354BF8FAC6E50D1E25BE7CAD2EB1BF6CE8B3441E0D8717689AA44E81DDCEF38811D65217AE931B056DA8DCF1C02B7812A68B5A0D59F612E0423103861BAF907690E9626961F4C74878D3784E1F06F0EDC55287B1CEC3C2298E5C321A441DF4EF18BC47924F5DD87DA85AE21F1DB89FB2498A236775C8DE5A5AA8480A87AD7765567E29ECBA10E931C67025914A756A6AC571FDA8391A06F1550C4956E31AFBB166A7F30843C5FE79BCE772241B592048AD815D904619CF13B42A772A3F1B52E10B42280D7549603BC30E35AB0B8BA1FCE0BB52152C283B1AA2E325F45076C5BB8542A1725D76D3C1B58A04C6D3D30ABAF911E19DA425031344B363013B39712B06F77563E84434409DB68B368B254B9686BE35D35D2DA079E8B29AE5E63550EF6FA2AF8B1CED7C181C4D22C3D755E936760C2B30502B0BBB575C71EFD8F9998E86B5F1B428AE0E0571ECCDF6834ED98378305C307E55470D6D3E1CC3C2E9CD3E6419F52D55484A23B00C6DFE4643C17629C7E58F1732ACA6C61BB1C23A88D2DE97C9F7F6BB8326491C71855D9FB9B8BCCDA1EC07A7340B9CEAD8FB8E1EE4FC4CD00BB3DDC53F98C0D3337C02FF36B181524EFC413F462317C06A3F4A6F054394F7AE0431277CCE80FE9E869C4C772AD28C6380C456C9BAE0F69D2DF769BCA381FBC4F98D57571D77E36FCAB292FED714B70B596AE817ABBD9FB4FCFB51B8802AC1A7E78541151521B328C27D1D15974EC0DCAB812938D86D10D80DB1958B214690A3F1F79D3266C26E635FAA09A1149C255D8F94A6DA0E159B4573D11B3F9665CB41576BF2181DBDB1C12247967065E5DF26FEE6A508BCBC665F63E8153898B9250A409C405EAE9BF76FC8472645235E81B2620544CC75499F43D8D67A067F7C47C47BE9557D07F28D28EC9AFC463CEB4CE0C600BBF34E71E3570A3A68ED8089509E5E7682A0CB0C2F79C25864A19E19F7322D2588C2F71F3C1F3B01D3E83267BC5F129509D7A9F8AA1B88DB09BC489F49F741F84B74BC5C1E117A48C53DC9CCAF6EAE3E5714598774DFE5EF234F9764FF476D6BFA8332515D08C649D176CC3BC95E4D410A464E164D7C78E5EF93D37BEB8C9F8D2E2377748A64CF44DE6B140B0CD57823AA80B387B1FECF850CBD505272AB9ABDBE18E99A453C5B03341A5886E1F9A985482971B0EF0406583948FA41D6E12FC9BEE0EAE952D94CF3C484D0F0C6090C25A35FECED7A7D730700604CE2C356A6F8A88657F036E3D82BA2E7860F87CF5F5FE02694579638042536394B7F5C348F783479AB851AD2963A380C0E222C72E67FB971A58D8880BF6EF18D856F809B7BA180D781295FEC4C59CDA5173FF91510F6EE48A57ED89CF913E5D1C59B4953E6234B40748201DF0AE11F30592F9ACBB8DFA929E30873EBE7030F04D26270F0160A2414754AA9A19A2C96B0CB8F63719B4DAE62A80BB5EB33395BFD8E87524A82656353086636A75AB791FCE2C9ED662C9BC55173F4F74E91541DC7B652B9E45E027439E07DA6C83E430B7889896B15167DD5A00E07416C7AE0055122F141E9127CF22EFD61B7B169A48A4BE5006E312285E26CFBD2EBCB8DDF595193F649D5F21B407BC8BD029F8FFD453E81DB086C320EC8E9701AD73D0B8A8C2CA8E4974D8EB533A2D30BE21CDD812D09E2855AB023DEEA3F5522DEC260413C3BAB6B818A05D934845B226582836DBE2986B1F0F07F6AC8271EA477C807FC62464BBB26CC30ADC2C0E9DD1B66B5A6F5B6D1F28FEBBADBA5F56739DB8BBDF8D0E4773B209A0C4B8ECE41A1D5E22EB7D3C04ECF2F6CD64DD69811E2C538E8D2C12948D4BE5D14E97F4EBD30467451E1EE034DC0A7A4DB8A1F3EB875CC521F751A1F2308264DC0FD2C6100395308C62183FE15C2CD25F668A1B7578B65084FDA1D73ACAB03F6086CA881263D9EB34CB58288AF1C1A7626B1D9286DED8761366F25841EFF54A05E5D59428CDB7AF83DCFED769EAC26B5E97F486F9B53CE382C8C1F508BDC1BAB9917092AAFD5BEF8F54CCA3058F0B61AB4CF900832F067B18CC60187CDFE053EF5D723AACD4AF4AFF68F70326E1511A88CF723FDA47239BF8879B4FC2D9C184CE53B9E2076C4BDA9698E0D02EF65859CBC6B6DE947300D564CAB3BC6EDF85F1C367293928BD4421074EFDB20B9058AB3D83EA05E9049240224A84E96B77BA28966B7EF6E3A4D8F7868BBDB8E1F670B66342AF05A56A364F5F56C9FC48D769E1326BA4A08426417E6E1948ACEA5842FB2BB56A47C5878FA5FCD5BA949BD12D657D77808FE4EEA58011FE81435804022297A3C1FB09CDC2C0676ECD5EF54BEF41E51E46EA98A08551DFF9A26C148FB9D2D8E077C9095ADAE30CF35866A6028531C6ED0E9E1D2D4FCDCEA6B210EE61767452B8329F34E3F80BCEF1658697DFFDBE4E6D48DC1B92CD97CB13A107EB4D4A81FD0854A72E511377C8B8898B247FA2983D21AE81B22D37454D723B8ECF40A9DF76FAF97E4227C3334E03A6F721F4CB3E476C742DED74B21F531763460019C2C38EC97E9812CFA122751310D5BBEAC71A5D4A5B84",
     "BCDF3588C44B83CEC23114A44C9322169EB44B158BD81A79031AAE64E8EE40E3A159FABF648348D791606F0D039AB02048BE201E4ECCDCB69F990B0D22142E323E183EFDB36BD5BFD39AE1688FB9120F27D07917207FFBE056AE2B39421C7172C9FEC616A9D8F1C1D6419D4AAC3364CAD34D299387F730052EE7D5A52CAB0070E48D9CF484E55D5064000F51842AC82C5357E5428D560065F24BFB072956C1E59221757460B821B890B6E9875D23502AEFFEFBEE9192925A01FDACA69EEE074E886C75D454B72B4F4576D51FB002629FF19AF530A44A5107F6CA2B8C08672E66D59A89BFC341C4E42FA038E29A88242D89B50ECC54DDE8112C3816199B5BF07E596FA8D42FEB55FF66490D8D5B7E400CE3C7E7F9E687D67E6FB9AB19412B2E3C2E9461DA9507F570AEF4542A5B58CBD8525844C9971F12BA4A3EDC255C04F4BB7369E52657926427917F18F94220BC4BDE081D35E6A1A514BBB86DFA2E87F0C7ED974B18A3A9E16F8E2A6B3D33CE73B8380BAC4CCBE252BE8189D03801F351FDBC4CC7B5D9F5568B55E8183860279D8BF06FED8084AC13B54C240DF9353758A663CC64D1596427268B31F9DF979FE38F83056F5999B5C9211E2119011BE2BC4FC7AFD743B6219160C986354ECE32D6662529DCF18620553B101BF3EBC4F1ADC17FC8116D0509B85FF7F67AEEF0D93D110CDEF2C9A33C18D91CDD4D6F808956437526280B43E34418F2802E9EF972185D8A73751A3422E8A7D454504A21ABDF269473600937C78582F926EC8CE4EC2E6D276E1A5FB0EBB6D62F5FD3C8653E3FDE0C138B27DF40CBA5D32506EBF81707A81DB588608AEB39209B3F49026C58A7FF12E4A3EB954C22B0CFA44BE90C5216796240210C3D51C3AFFE217302F09A491F0E123D0F9169E83FC2C6B24E9B38410F423A9DB678B61250F434547D8BE57681F2E6214E6158B3FFF799C24FA1B7E4539EFFE7671C3C0630609E674569DFD985165406808BE00E29A2B9F37EE672EF5B7ABE5D646A8CD5F867AD2E6F8156B9EA17A9C290135F11FC6351F4F1356DDD8F0EE89B22CAF02ED8E419DF9DDD727A96AB29EBC402FD4415E027559865BA12464A0CE2FCED6513036DC48E5774F224B9EA59AC48B4289BF1E58888DEF49C9D7370538F012C65F05771A0EC9DEE299D69064A35022D839ADA0D0E61DDBD85A45A617D80125B2A031F5CD9CB4F03A9FF4666456398F6FEF1F165EB2C2F844C313CF0EF46EE6F03AE69E32B011E7400C6393EE62AEEC29449A86BF0150A94E64A5DF83F50C9E33D2C9034262D40A75CE17BF5C016CFAA2A7C40B9292B9C94E390106BA87B557CBCFA54B5D4193ED403D2978CA9ED24F6B6067495CC85DD92E2654E6501437AF46E25E3E50D86B09F120C3E07BD7EF931F511AF2270C4A19FDF613C85B850E141D9550BA31E19086629E5596E24BCF31EEA06B6E285534A79C801FF15ECD9846B7A63C4B19DE437ABF43476BB3D6AA1DE77285F3CBC5CA59E07A88856C5FC9A9FA097D8C69B6B464A43723F2BF152225158C41287792403532A5F1DE42F7B1E3360680D5FBBF9A389AFD961C0B0CFFD248CB7D1E330FB08ADF794C03EF5F623A433EFFBEF76AE0829A8428282D2FAE8EA9E12DA531F51225B58830EC4234BCC315B33BB98BA9C36660AF135525660310658E38AC1277FD8EE87B58BAD15121BDD95D8E3030141CE28D302D2F83FAA10E43124D63E29610A3F37BCDA88C40A69DDE975FC6745632B2F22B32332BF0FAA623D50B87FEF0453924028662C71F0DCF7349107EA0C4E34EAA3C6437CF44B679EE84B79A0029D6FF15F09B57A4DCFF66630177D26AE93ADB6F1BA1C5EF6B29BF6A2B4FB68570C0FB2B8B57DB90526A4C025392F8F410A52E4B3D0AC115027A7DCC3BBA0F18F1CA05FA7BF31007861879ECB6D869D8F5EB143A68B84F76BB671EAB6F51B8DC4702EACD7BEEEF24DF87038C818C7C2115ED2DE486562BEC8771D96B17EF9E89A50B6932F98FB613DFAA8084A4D6F884C2368B0DDB5DD7B045E44D2202CEDF501BA8637A114E67A0EB09426E0661C0D493DC29F74FBA2208857A816120912D220886F665AB8C60FC2DDAB80D565D3AC7457DC32FE0D7E7121E0F06823A858B9306A8BB31391642570C1ACF36CC30178C0CCBE6BC3433CAC3B83F8BFDE37D06FD01744D6DE937833C29F753BB9BAF419A0CF9FF41729D175416A468CC427C5E6FD66AD60DDA1485FC0D69494B87E16820FBDE7A41ECDD57E77227826F3390A57332EBAD03C03D68873BEC2EDA74897BA9139C6CF7FF915B736EA63B429BC1D83C43CDC5038A8BCD58C679D33850C69DBD6A2E310BDCE94107EF279F9D962EF11F147F911236D5C744A839D140993A9B0E33D1719CD0FCBBD4D00BD941D0659297BA7C72FBC4C18EDBBB120888CE2113C8796FF338C6AB8B877B55D3C5B18266A0C29F61BD03146E370A38386C74273AB3D18AD4371665371C29760032F89913F38E8CBFF8D4E5534DA7199E0DC7B4FD8B88DC5EC575E53D8298469256621540A846001171A2C39030504A2C43F7DF52BBCC7248493159F3900E62CC6515A397C36D85DD2A60C9FDD115902F79853BF554ABB809F9E8AE3E132A824BA0A4A5C07FC3A18FED240E73D67C20F77F6D2E224A03611AE6235B74ED730128E49069F20D1F8C97A785F8C5C6AE3D555D9BA1145366EC0A96B2D00C5B5905D5F9D51203C18E8320817199361E07DDC63FB6CDF358FB0DF6A43B8090301E0930BC06CDA4646D1C2B8EFA0F516D80362753101A6499C1ECC7798670EDAA021A80C2F6C6442F20D65A2B67B535B2877D15192A925A9EDC37825AFCD54AB73783343FC1D8EAA55F41E56AB930C14447B45EC128152D365A529BE16BA3611631035C38F98D66D64E4D3E57D8A4E17818EDFE6DEB8BCA93BC3DCD28AF38E28D99BE0FAAA8EA3246123A5CF2B8E964277B4B1A5E210AD440BE05133BC379109B3FE7314CDC6CC3234C2F68BFCC7898DF6990A1CFC42274DAFADC176C1D7E758AFA297B41B8DDB82D1ADE70A5E5CF2CC57130AA49040AB4BB38EA1A8499DE01BCC55E8EF94E1A0003D9B5CA88DDADC50560B14A2F3B4AD97912C96BB8D181D2D5675E43AAD48D76BB5FD583DD83D77494A2EC167CB3791B18F96386C4C55FE95D835E60524267F1772DFD984653C2EC998E2108CAEF6623D7A08602D604A4A8E82BD7A06070F2C5ABA6F5E2E740BBAEFC398B697E38053533BEE1550803A87D10D4E901F2CF2624F79F40C014A9E2B8F59E068E71B57DD12DDA7F86A5FA64EC771A8CCA09B13D02C80D2EEC19230FA335874F6CF02F879D9EF2B33FD1EE32168B59F3244D284034FB06AE09531CC3D10A4164D800E0467A3ED9E249F6380976067208DD0409E4AA6F405D3699B667813CA967EB5448888427072E31D2AF85583D47BFBA9DF08A622CC91089746D716D0BC4E97B9046BDC62C96DD9E7C11738FC9D1A41B1373462624F822120EB52AF495AA43462F5F39E152D33DE426BF6A5EDB2F3EAF6217075F0B18DACA2810A96A7AF44DD6605EAF087116222AD2513EFFB25A22B81FA5F8E380B394DE57AAF7850E103565BF1CA8FDD75E456B0A8812AFE722752F95B77AB059FCF3195C8656C6712CB2E4F126222789B86F9A5642E073DCE154BE7168A1B0F5369BD14422B646E8ABADEB0BEF914BE0E69837687FF6E5DE374C02CD4F722F17BED49272031E11FFD80A4D38CEBB18F4220DE397C96FC9C90DE45244A61EF2F8E6A9B708857DEECA2000D849BFF3B29980A8EC426B05C165DD27FFF1D831F0B0440D2C7144A99D1E405E9D8AD596E10DD63A86A6CF4706132B0BA2228C2F18CD9BBDD0A0F198D4074FAB897118FC617F4A8C10F0FF8C6E24BE2E0A28B0ECB9C9CFB68747163B89F73B76232D7BC4313524631F45F8E87412F4F6EC8B800F8D72D8F5355A2195D259C219E973AF632B9AA99A284E6F92CF0500B8DCF8955C0114F9D290976EEACF5CA17ED8C7ED84CBD1EF71D781248755699C9434F0E273D8AAD1C6F87B350B1C811B5CC5B4FC5B9945A9CF7C6DF6D2EBE24DC5927B6BEAA96733D51386CA75915BDFDE540069A33F2F1FA0EB8BEB0C7FE55DB2F0D656FC5F7F5D2F583B8AB8E6954B576A76C839A53EABF977CB5A06968C00AE3FA10AECA34A451C4A1ED1DB28876C3582718880939D63FBB30A36948BA73E3A06A34042CADDC8F2F75BC7093A5EF3AE5FD5ADD4B617518FF3D5BA7C4D3C6811181C2A2C35BC1B30464E97E51D57C16D8673D0F3B8564630CF760ED60E1F418F30E4610BBC7A2220D9662B0C4810F5F2BBB89B8ECBA8F57917E69667ECE496715AE006135A8D1612029CACBDDF6E2765DDFBCA9490AC6F46F7BB88D29C24CD76240A7A6F86D3FE764D2C2B3AFFFD34A0B9328CBA6ABA8BD54F8CE748F3633E2DD79CBB141EE0986AA6355F1C71BED3DF048C35DA52A512DF1E99402F3EA4BB9C389CF9C3CC492CFF0CEF5F8D999A6E9FBC25FDBF0F76CAC150876D4BDF954A05B2E8B6E05E8FF4F23B35411D6673568BD52FC488AA7E84FF7D4843C14B68244E0CC5F0E02643BF70AE982D84664819A448A8B403E346DBA3D8DD240DF0A39A68C9B7657017AF348923B7DF86225DCCA1564474E5C0FE056246089F5ACCD3287E2E4FE232E96FE8CD9E74F1F8B911BC6827E0E12911C8A8ABFA4EEFF06CC30E15A088A7DEC5F482376D86AE7999FFB125F8FC1DDAE8D8F6C61EA8277BA746544CFE8BF86A47A55445BBD9F2188EB75411CA8736B10FFCA198E2FF742A3A4E116FAF3D30FE117BBD3FBD2DC79A61D9B592D251B9B8A5F37A2F8A09D604D51163836463F2445A3673744FECA47A1C2B92B8F4593B9DC185C391718B2484E00D1C5197E3C60492B9EC0DEF8B4E7984EBAABE8EC611E162FB672A7884FE3634530F9E563965C6EA217F064AAE9938B04C266FB168E7FF9B729B0DAAA03611B026AC88B3FEB5AB5B6C1766B5AD640E0901DAAE96AE6CE0DBB38D1BE4B123018834B3AEAC923A8AEACD1E2E59C3A3288E8FBEDDA1BE4673C5591AFE89A068698A712A68D5E28DB7DF8C6CED222249F6B216BC5D1ABD72B29D89813A5A1A1757AA305093BA553F4ADCD98B2470E40D5693650890F812A9DB04E4CE152D6A916AA0DDC12F88DD6BBAA7B47FC48887975BAEBE94EB74B8357B6FD971161FE6FF4C9E03AC083FAC0528508D592D9E19B485FADDFC2CA72F6E4CE600DB9E05BC4800E20DDE3D0D92399AEB4C1AE3051B8C4B7776C257F7E15A6C40A99A7946F0646B605E492A552BFCCD35E41DF19BBEF6808A128E7A17B86F3B2823590A5F7F8EF94DA6A1FBAC166DF5F0EA10571C729FA9A3F9E8C5E9B2121259F530B311FDA7464B2A743B689A7A72E8682C39CAB92058E67AF806C5CA13C1E20A962689466E1D13DB004CDB76249BF0BE900D73F41CE01BBA09700ABB214B775FA18D367B218865902DD7A93C12EFFB02C1E7158B118387CC91AADED3BD31A2B978FE561FAEB295B598858794BCAD54D853C7FCD404E04E07ACD52DB73DFE25A57C65E977B84ECABEBB1A7B6F9B24A1CF620CC1D2E72F1F52661E6E697150D003F512C95E6CC6D515AAE3F31442B4160B4EAF180E022AB835C4563E9D6465A2BE3ECE23A12FE06E7A1AD3FDAF54D3B8A4ABC2DF140F0ED218B3F94EDB40FFF9988357F7FB58B1DE1DB3271CD4337C2F03217F8D5E0E260636C97C62FDFE21A127B8311B83D6DA142920DD3A15459B9526F73CFCE217A1D9AEDBDED57CEAFEEAFD3C527FC8A316302E6194FFD7C4D2059EE95DFCE91EDD7A2809BEAA16F875CE10B50EE74B3A7E74E4161BBF91C9D36D75E5DDF2B90FA00C23ADAA4717FA563A2136C9BB2257FB6CDC06FC892AF117C240D6A46D329704EA70314F46975A8BE09F36B0B99C24441A530089BDFA103D62E441A1A3DAF570D1E055EF76725E7D65C4F69968640C13F28A8F62B378E5405FA7B1A514C050D738AF24B5B016CE99C5C402A33A6FE52489566204B23E1006A615F6351C1431787821094D88957A548F3190D38F9B5655ECCDB95638D8F841FCBD5B2A7B5DCB5697824E80B5D1E242BCAADDAA701CB3F1307192E77AD90AC6A1CF2F7AD8270F6CDC00E0339C86C78FA5342F439FAA011C3823517ABAA76787C5EB178D519776DBFE6D447128EC2481FC5D8ED250D0A1C94C71125F02FDCA2072092FC118B3DD3406802431634D9D4A82547884C7D980F5AC20313ECB8D6C129EA7BEB636B6E664D246BBE1D65DE97DBFEDEC6F0068C830CF6687FF18BF8AB261FA8F4CCB4D386EC388ED901A506C342F59EE564FDE0D2DF48A036F25A9EDCFE6C632328208D7AE342C4D1D86CCBAD2D5ADA9068F6188A42D115592EB6C9B0096745CD52331D1C8507DB7C8723A3F5A1CFEDBB0BA8444439B657453D1381BFBF4BF47C616D7C1A15E538AC3A52419916526CB07588FCFEE3A73ACE4E3201BEB316CEC9BDBA480E7F634307A628EB7485A5783FD135D58D14B136A97CFB7D58EDDFD426C6C63F8F923EE54B1611B01A51B6CACC8BEF9D883D958FFC49DA4D65AE591856423D2B5071042E6FBD1323A4AE7F83C9602CB206351764F116B093C0AEA35E39B55E9AD5802BF83EF5D39FA187A6ADDC9AFB080C92CEB5DC12AB7B694223435DB4AA4A5C5C1EC5693845D4EBF3769D921AD5E3F10112E400BAF6F346953083C9BF93182438C8B27EED091F77CE70D306F1119AC5EC02F1CDCF82240F9CB37257BCA35BC77D8FA3B59BD0F4F2E0B382DF0690F907883F6D1B5A95B4DB7D4E4EE1FBFF2B514FD996EB1923055A1D4B63845EA25DEB956E57E7F5ABA0147ABCD8A02A113E4338E181647B8E76E02762C6FBAA2F9856EF79F33A436333D13D12798F032DBCE4470DB3F6F84C6489A89A4A287DDE26F44BDCCEE7F68551EBD87AB0DF171F7B728B44DAD023E432BD60EABF944E0B4CEEF291AE7E9F472821DDD7DA2B09C573682F9934C9CD1886FA5A6D2F1FA72EC3B2A6BAA58B87AA0CBF0DA8E8AADE8D2A8F0967C312BEF2A9971D3629AC0736CAC681B9B834547DD0F2ACF2BB77AFA3308319365571F5456B5EEFF908579DB8B1C91F984E0F1044C65FD9B8572A519991268DC664B800E95FD0C8C9791BDDA9AB031C0C1041C9BE4A7EEF565B541534276914E60149BCCED630D918CD5AC3B5B5350D6C5E7802A60C8F0F2087D61A38E896233CD092DFB86F7B8513E7D64D599F762C768DFDCA4BA5E578E0012B495C44C1EE1BB4622CE2AB9A6929C4A88B8570114CD1335EFAD6B2D89FFC758A53D9A54ABB735BBD6BEB4860D487D37D2344E2EE6B5505EFA6FF3449D91F4E744280223DA6E8EC6E73DB6751C0DA5E2E1F8BF7ED71B80B76164C32A8E1CE99D23D083A32B5F3091B3253A676CC1B3BD9A7151873F28C7D7CB3D830AF031EC21A52336DFBB4054338FFE979EE35BE4E46FC36C6A3E9EC06AA04EE38F92B0805AC42DB351A6237106EB9015FF837816BEBD25BB808CB04F5874ECF32C474FD395EE1B16FA0A920A2B43F91A7DE73547A37B3ACF66467E75DB17BDE3B04EB500060E0D34CB1B81E98C9C01FF028B671668AD31E15755E19322E6228BE42E962D42FBA5E50DADE4E55C821547E9915BFD93A202567BF80BABF30AD2BFF0DE6BA1D3FB905E790AB87AF3BDE952F1D4ADF5A6135A4FC07A28D35A1EEFC618E89335E5171C9796F210FDF1C2D094DB65CAD2C0EB98841440B8F083375099F8AA4DD442C4B8CCA77EE13EA77E90797ABC1ABAA8E87056BCD5FA9DE3C4168830B87C824C5B50E61073BB4142556A1EEE9CC499BF9142753C9A2F93AAD94052B03394018D8F164F55CA4BFB5DACE0EC79A5772426C6CBC4C9FA01629AA6B06C7F08EE2341E3B455C0EB607B661C6F3DFCCA4A6B45BF6B9E66D5F541D4D72AB645B207CCEAEDB6C410BCD3926522AABF4BE649C56D061E86C5C910F8A7D512947DD5AE00CBAB24469FA7716436316777DE9D16F77BA88BF3B2D3780F34466B821109C3DC9A794C52DDC57DF8F9D15A3DD8454F035733AE41A2488A180DF21C0D906B35807F3FBD1DA07E2B19EA3E3C3CFB76014053FBFD569A430C5796ECD0F8DF5827361E45B3D985930F448A3884BEA01104EEFAEB65B7A153D6330942B0AFC2A5527EECDC5DF0550C3BB9B39EAA707615AA479C93AE31D704026C4618D5B14CB2E324B90AC44A689172A92D3CCBA3B02C5BEEF40D52A5DA0B89A116B691D7A558F67F426A9CD1F4AE54EF49884D60B52922D7F07B1A4322259F55ECC8E8BD80BC216AAD70DCD3044C6A0E4084DB6961667A0F741293D6C393F01F4D911E5EBC956414F1AED72F2896FA8441DDD71244DCE6FB279552F4D1131974AFF57A0EC0ABEC27A7104648619194C71764E9DD18A014B79FDF0A98BD1B2537F738C0CD5E11E93BBAFFC2598486DA223E1000065B00BD70B2C810A9E797176969DADF4BC3C2D7176B34EDC610D78FA088F23FD4749F02C67494802529447098C5D321143763246DE474955DD7320542FD39FE583FDD3C9AEF16AEE830BB9BF092C508161A7CEA774A6FA1A129E1ED237CB0E0B545035DCDE94B8111EA6EDD8625CF4FB4557203EDFF336B8D9B25D6703889570E41B1CFE2795D982E6AD9AAB5FD4CD7006215ACD3BF327704E5D71B8169FBFB8514CAD2FCCFA1D9F255C31066385164B6B7406C241E7BC914BE9F84535FEDF17B3FE30761F38E40CE49BB4F885725947A2A7B7F6B673B782C2CC68B107",
     "DBD36654B370343EC57C95554D6BF535E788C0A0D62DC560112C3CCF36C6EC4CCD599ED45E895FB6DFC4FA5603615DE3B039B5BE1A331D4C355FD85D3B81729392148B622FB097E11930E56DD09A000862F36D28C2B406D82FD75F7A8AC23FFEC5B792FCC46A9C574CEAF118475D4459FFB3C7F9BA3C6FC59096A4B9AFCF27A7CD68E665871CA7BF79C5FD0040D6DDC8E8D05DCCD05CD44E1737F38EE6EE99F301CC1C626DB7674757E736C5F291601B898FD7519E6552EDB9042B79B89E6737DFEBF9F7DA42C06EB8458C007D7172384444280542469BB7BECE3917062E7531551214F71D1A4978288EDA66AA77DAB0AD66AD0E3CC63507ABE6EF70FDED292A28851F680EE64FF8C614739F5126F8DC737FC226EBCDC9E0470591411322389270B7D75DB3EF427AA53477C30B0CE3DF44E4BEBA1056AD845A9904C1BECF803511F4D74155932DBBC3AA00304897016A82E9349534581D31CA73B16A78C5E70197D8B64914D92FCA3DA143399EA3EB710FEDD28BE8F585A40E6DEA9CD356AB5EEA1A4909D8317766BD98A1400ADBDA4A81A8A81C95D4F6F300EC68D680CD521C3C3C7F4E6D1DCD6354ADD44A8CD87ED355E9D80241A286B150EB196C06A1B5D6022BC37AD2F2AD65432BAFABF31D6AD56625606D9C90F46E528AC96A8896B2A6777D819DE47AC19D59465BF7814B0F6AD74C153E50AF731E993299EB07807C330D5E4DE02927578DB1E09386E097E84D426E075D284E635CF96B40C742E434A60BDE2D7857FA074674F394AA4CA8D419DC89BDE91D6E2554EE15D7867BAFB2797F4493D1F0258A186C6DE3844075EADDD752C5AD8B0AE39B7B8A7620458532C440F26586B4F7F4433E70AD81FDAD424D04CA2D9F49B92BDEA20CCB82FF025B24F639FECF0E879EC7BC7ADEB52C0BE9F12FED182CC6374DBB113F5D36AE82E98251C0051CBDB3E63D2FAF50D86943204896DAE6F378DB683324CD9B7EA6E46F22794A386896B7CC8795934F0DA2BF133EA21637E105EA4BF43A3676972E106DC5AEDFC02EC2C9002E817B24DF0F246EA510B116CB001AA16318710B64B4C1A0BDCAE9F325F24826659E06B35DBD018AEC17175E8D02E8D88F9FAEE620E00F9EE448DFE9A0ABDC3B0DD7D62A2F53C726D3798848A8D1E527E4D6ED074D9241829459C4523CCE9EE8F64B5138498C5CC4920C20A8C992DD392E12DBB658BE2F7B834E7165653868B58881B854650E9826330919DD3EDA4872134C24D300AFDE667B24E2DEE8127D0117F995C80AC82D334B4BE7DA9E4F634D3224A379A6BE6D446B0FE3091FD21C6D82B09111BE01B4F4C79AB37472ED7E316194A7C98759FFD772A094A39B8422DECE52BF3ECA690361B0C4405589E09819C97F84524E49D4EF82876E6874FD6306A374CE2CB04F34B01E30727490994C65221AD225A1B869B028E954D819A57953D31A73B8C8B9B18DDCDD47CFAA78F5F5A9DC5D10620F7E7C06610B1B131C9ACA2D6DDC35AFCEBEF93DB47C5F08481ABFD6A7E98EA2E635CD4A7D56A4136DCE63011E02729326E4FF64706ADD6023DA033CD7EE4D477BF1B6C24FCD860766090F6E357661BA308CD04413A82CC4C5E2D3B0736FA37EAD1A888CAB54A4447D24731BABC629992905A494F958BFADD756EC60B93BF6E040DA92B3D294ECBBE3D8B5C8009FF07C960A40DE5C441C07D084A64DBD2BB8D532051AFB359CDF0278569086CF82254C4D67B9BF18E395134D3518195B6B8AC60346651B5B7F7B9DCF323169C77D6CDEC8F36787720486153624CEA11F38D051DF1674FBA4148C89674CCDC0A811270887464935FDD7A365BEFBF9FB487B4A2FAEA9D47A0484B2D798BA647B72AA1D7E61A0898788CC84E7044D121793B99A83D552F49B7F821612718C92065038B6E9E3F9AA60E303A18BB3793243F708D4C343ACF46F7646EE0E91E658D999FA448F9E72543895AB57D0CFCD496B30000D3C7C6AE88C0CE3CC8D88A72C0A514FB4A84200A9A2E9236627E16A6121EEC2C77C6BC783D907DC284DA45344B9BF4D1985E605F3783C9454AB7964B494D11CFAA608B060EBEEAC702ED3041033EF745A41585FBD25AC43514AEA9E743F93D48AD90EA56FC1B3BADA73EA95C36737F1D4C037BCA6EC23AC2A4062F0B4A47D82F15D3D372A0DDAE844353245F5013096C8312597A5B6CC36ED22C1EA2F5C86CD3C22D938843BABA1593A71A0735E145DA43BE09392547F7E2856AAFD28CFD58F43C0BA8C149F5A81C8C71905F3A2E65B0210E119FA0D163E8D786C74C2B55FDA151C29B227E2BDD84FA73B4CB9A9C4EB0BE05DF4AB53F042A521FA84455E2EE2E09DE1D7D1B83C2FA0E8D500AB47A35218D9DD0951E7E50F66C7230435B98BAE07D8280330C2C2BE00FB180C676D2F0AD666BBD251C0D1CD487536C4378FC7B2473DD0CF969552D7E356221CC46A7A5B37C629E3BAA7DD8CD1A0E03447101D83C2BE425880E4C8AD9F3E54C0C7C620B007BA8DA3276E55A529469B2A5EDB80029399E1D0028DCC31B1961223CB2C46C65D1735D1BB156334900C1E0432032B6D34C764158CE7BBF827BEE8CF0DB2C3C67D93CF52179D571B55D8C6D51568CABD99F4A23CEC27C59B2EB1388779DF37C07A6C9670C67C5DC3ACF47A51AB841A7DFE83D2D1F7AC88FCA999E633CFD018A60F8EC286E8104C9D0CB248D061A82BC17FD4CFD96EF823DFBE96E72C658DEB822630C9586270AD8A6C11FB57B2D034BA82DE4F16FDAA4DD9769153B2CE1386525979553921ED8F9D028223DCBF82F51606C011190F89176B1E3B8B0C9BAA5EC85EE92635C781E0396E361077A03462034B4E01FE262F778A3CF4535E67AF3AC78501D89EDAE9B0C43BE5E8E4450E331AC5CC0A21A4E0889E87BA67B71DFDED22CB7C25D476F084669BEC4A54376733F9C94A620D07D7B0CEE48A76DF412487FF36D7957461A62604298D54F5E0682F8F4D7F84A24928910F062EFB0347C8DE060C406E963C302318773301A93EE9991124AB4CAC5034DBB7FD189927703ECC07ADD43D87F9B874E99BDDDA6AA5F758E29B0CEB2031D27ADB39D14E62E2D6CFFFAF3380F014B593DFC6D9A627DAE454B3CB100E39ED163255A5F4ED57F4BD5E751D108F5509A1E1EC5D144861E1AEB5FCA84007F20EAD7923DC7AEEB49C4751449EF5CDF814B226C6E2AA479C6D6874807B398BC4BAD51B7D44CF0142C45D31587C03572FBF78DD2D35C2B0A593CB4AD30C3242706F905ECCF4B8F8681EF2CDFDD66E9681BF2A76C487F52A90D1F7717C711A9B54D71BA4D3E8118182E97DC8028975583402B6F94C45939B7CBE8F52919E59765F8B7F8E1BB314525C5BB1318D41B5C26D4A56530A8030AD02FC6A73E63A8E065CBE13C79111329A0DA692352BC64EC20058B615286175F3FA692B8481E22090B2115FB6DFB7CB3AE7469D483FB6FEA70E5D668760A0128C2CE407EFA4D39FACE696097AE60AA4519056689AF642CCA54439909C24D661D9F04CCA8C2478772F735372124B7143637AB58CA4B989CD855F2491C6F5753B72A811AF045F47F9C7DADB6E11F794C4ED50989FEC81A4FC2BADDE0A8F45DFBEBA1D83D40164D675572347A5FAAB56245744CDA6C2FD6570DE45892B11B87E6D64BE16B07453B0D1D7385F18D8880E64406D9386BB743DF35C86A44E0EF10876E56D0014388A2B313E0A060B882AD5F8E10324EC21B3F87C2F8B396255BED83FE217CD8285571DBF53093BA0DCD1E5068475377F81D85885AD706B87F077A4D5C2089E541D387E3D115B79BCF281A05155C7156E0D1E1A27FD4BC4DAAB4937E8E42516810ABC1927C1D0AC642BB5C6DA619B937366A2C44AB9388ECB5A49FCE7E43CEEC5858B3A2F64C67E8BD2D1F4D07C6BA2C9068C7F30749C61665F2B6FDF39FC1BCD888F776EA4A98E831B968F4B47BEC3FA6DE2895A8B68E9B5CFDE3705467E2D9AB81B6D995ACFAF688C28FAC0DDB8506E0EFC1C1B360F82E0765B56BFFD71E65F879D20F6A622EAD9BDF33BF67A67D2F96E6E5CD68351C73D8E8B42FCB0927C59F590D8DEE8880DE752B223461EC2AA8969687674D6FE76D378E0C84DC1A4CA21B582BFF4C94FE73A7D86CB5BFE2D65DCE8B1B8156255C6CC74B8BFA56270FD1AED38815B7B5E586A78F291814AA7225C8C5211813AE3B8C0031974FEB5ACB1BC611CC0758B8EA64A8ADC84625C9EEDBB584A03F9FB3517EB15E131C251034D9059935333934C8E027283389ED51A64F32622B5BAAED13D057EED6C5B46ACB62F90E446AA5E2D1050C440807C47ED3E1750B8E8BBCE4E0F19DE72C7F3926861FCEA3C8A202E75FF53765AE155D9FF4D06039C732AF8E7A2697CE343D83226880DC4A6780D1EA2149CDDDA7BF0299D0FD392E7DB2FD0D6A5B01B26D721630F7D83F2AE1B150133482525F6F498538E69E9FABDCCF4796A6F7FBAA12FCA9984BFCB7DC17CC4067CC44F7A3D6BA47E573B4EB3699516E8A4D21E2AD64FA0C1959885329376339BD7AE52055709EDA643DB8987942A5B9044DDBEA3F7F160E61FA9ABDC34308DE51D92777CD70E80B5F981F48254B0189E10D6272D79949FBEDB013F41D5E5F5191B5094DBE7375275CCCF6990C6E7FE295F6177A2B3B7C7CFEAFC00000000000000000000000000000000060C12171C27",
     "1604BC2193B9ADCDA645A8CF1ABDF8C01E87E4404FD246498CDFBDB91972CE38913932E44F788DA18833D4B465D94F6CB73299C5CB691248E80C9A215B36007BF90DA9692AAFF3B74DAFA9611B2F56260019EF1AEEC8463BA35C934230DB513295EFE3BB004F85A74C878E12A5B5A57C4FCBFCAC69966BDCC9AAB9B0573F3FDBC24E17C1ABA5F2FDC558B059A510E55D0DEB8270B61381ACB08F61F24D4B00FCE133228B13B368D13BB3C0EA421B6C2B9C07FC583C200FE4D92B7413772DB18543F375113B82650943BE91C6F85BD725A3D81FFFD144EF56455E0D78BCAB90CC7AB8461A|SHA3-256"),
    ("prehash",
     "FCD7103091FC660B7A7651078B430171B1EC1618BCE086B81BBF20F5998EF238C79DDCE64DCAF7E989C6CE158AE807487B00F839E0ECC9649FC25C4299B290233C504614F8055EA87EA754BD01156A33174F68B5BA1D4236D1EAFB50669B0DDD32528C2492C39D144DD2F1D7999762863C021A8CC0F346F31A77E08D853447D237F8B02CB6C17FB14D897635A3CAF8F7C093C48A6868539B8E33E3F51735F14C2A00F69E3CA9D4791D36FDCD17D68C6854E6180DDEB5FB16B1981364CBAFE04DC5CB3F93C6DD7995B82CD63FB7DF59B91E123D7EC9CF830AB68869CBF7C1895DA004391DA72EA13D2DBA0D7B8829A4F9CA07C251257C352176FB8DC178375C8B965F49BD8AE323A1E638370286FC7BE190A23C755085CC7788EF3DC4155D8AC184CEE135353032FFA5DB7F0455B832577F2F5599E5A9091A0DC607C35C61F01CC4D888C2F78C7337DFDA1CCF2DEF1C2DBD2A9BFCF8BB6584D8CB5E4160BAB54D104FF0629949D89970A35DA3DD682F0B1B3304D324808F2265C8DB4386EBFBFC41541734F00EAEC39537337B6A61188885C2BF2A4D8DC4A39B2DC23F1FCFB34E1E82324F3575723A63A16B435408B9D8A8B6F0C0D3F9282D34796B8BC935A743795094AEFF0C414F2DE7C96913575CF6364A11003A776A584747A5DFD4D06ADAA447C9DA8C51650371D85B2D9E9B02BD5978D3140401B7473876CF72FF4D7DB00F6BD0FCA51FF693FFAC0570A2C5454FCD0731DC1B5ED057C299FB64D2C5BE6252541254AF1CA82A037AB716E66A8658CCA31752A9AECCD83986C95B5DF113CF55FD0C62E7C72BD4698DD4701ED5DA0524C8A5A82C605CACC4AD0AEF4DD7C7FFBACAB7367F08AF49D66E56B1DC5E43DAB6A54E1564E349FD77B60DB4EAB520D60CE0699E17D24CC543DCD195ACDBF466C4E354274EDD8BDE33DE51E3AC92FFA516B81261E801BEECA41309036FDA0A1143AC8BA204AC74189C3281190DFEC095F720B4DA3620E392E1A7834B3F7F62A5C14CACEF18D7A10F90CE50617E564590AC39B32EA15BE652B789C4989410EB8013D0AAC583F405ACED59369911C8F4CEC57FA8F260E266DD351BE9676A036585D91B9A3955FED434E39394FDB20BC86C93634CBBADBADD7385247C48063703AA2DB6549B310535FC89551CB98FF18FCF28B8825E62E7F12AB253E846BD6573C8FFF434213CB13EC455FBFC16F21E36A939279D5261A3B31B2C1C144523AF3B7D0C366DA37CEFD00B2183F85CCD2DA90457E445259AC96143BD2DA63FBAB6588C9933C7E32DAFE40C74885B79D839B7478658C6FE4788ADA02E867291E56F1EE38F36AEBCB2D7D8AE2642991FB58D7B00868058FFB7DD2EDE75B07E824EFFA6B68EE8FB5C952852812E4A528EA35C24DC22A842A72CA3A3ECBDF88443E03288DD70BE26A0DC35092021D66F7677FCEC735971CED8A2AB81E9A8FB5947D48B6B3E9D06D9982F08E9E6D56CC3BEDA72D86B3E9DB808C6E88211ED43AA8380A65DB007A9F5AC411C2B74DC5248AC386114EC61EEC1EAF9DB621116EBA1323572529B41C3946539F45E14D2A26D3C6C591F9E0745F0EBBEAD6AF93A8C728A5C850B682A1018AD1C493C18FAAF295D3F01E14F97FDFD498425C88782FCD73F6094E949B635D33B24A90839CC3210D437ADA1AEBB1EA0510B0F6FE057ACDFB4347EE3E552D464CE39ACEB9C1E89DC6FFD939FA3F936AEB2149E80DDE0A6667D39B86C0BD223871408846A51815168CC95745EE65E77B60E21E114D7F748B66B23E85E7EFD55D29F9B279662F435659F174E869E91CEF332F3F850869ABBB885D869BCF23E212C7CD4984A990E7E1191159B639B11D5236CB58441B3DC67F381F3A034A7A4E76AC0D299BC682FFDA861236C5EF9923B4037EC87C4859D4DB7F971A68291A93FF585F4E472C3586425E7E6A9D6EEF85D675D9482C4B9BF35CBD1F7F5D27DD85098B1745E7E3C1DC765DFE227FDBCBACB3E30A7AA9818122E5654DC50D6146829A2BD614751FC1155C6A2DD3086935DAEE431818EBAF496273A6A7CBE42C017209C60D93515F00AACBA145E9AB3CBD8EFE1A32A2F705B27565529D073A2A4D891C8CAB55DA53EE4AF6242445C204444521879CF0B2B7A33E54023E9887D636B72AB08B757C9C04A331DFC975E267CC39920E5931284733598A4410AF0F57D9E796E0F0FBADC4AFF76B159CBAF9D8AB39735460FBBB2106994E9EC85A9D4C5883394DF5375AFAB16C34EB3F12C70BE64FD01771B7FBDA1458AE220AB007BABF51E58169F9A77143681B1987D1E563933C5EF1321BF40BF0477B2EEEE70BFDAC1A2A8CBECDFE6258B42CFDC24EDE086638AADA317111A24E000D9A574A2EE2A9B60C236B5B191F17DFC0EF2545BCA01AF20718E8F96A3AB83765194E3653DEF5058F585FA2CAF57ADF02059A54BC3E77E46E0F40ECF5A7BE98779D0F36E66970DDFD5A14E04E227D8E35DF1465754D228E52398D1991C6D95299FA2E407979B43584491136D4FB251B69D47FF8C57E2BBDED585787F4C33B6A05736BF1E28708598D89DDCC1C72DDDF7536484CFC2D44518D3D64B2E2F8F6059607910EE28539360D3FCE0AF4287B05DC167AB6BF6EA7D6F3AC3082CBD2ABC71AA8E7706FE603C0E676B7E1CF2320FBF877D66990C19BB9274DC24680398727EE878D3CA9B7B6117030063354A6770A8278ACC4D437349DA49B6F61DE06D18D3C19513D6BF6D1BAE954C5FA71A3E850B9D27266E94FA",
     "DF88A1E96E9860686A2F5F681FAEBDDA9661F93BA12ECB0C6452AC29B15493EF8388BCFF572000E60A64DB03828A762DE56C043A6882539C88F90A6F7F6BCC4632E2F396DBA3469B9B61BDF4CA54066FC12B947E9AC6D1761E98A39EBB9C47C858A65788F938597AEA9F0039F871342B98C60BC73425ED8A6AECCE351E313B9C9BB666FF7F9E35CDF2C9A388503B63EDCDC1D0F739E37FBEA5D7272E054C438E2850755B5E02EC68BD45AAB4E49361911BD38162C063ED1012C4016C07F2129D7D871BB2CD7FC14F23905A26F39283A7432E2117E9C116430342DA20510FF9176B9D46673AA5BF3CEB6A23D6A7F052EDE5537C00097D3AC3EF56578DBCACB946670116457F68FABF2E2B95238406995ACF97CC0B56601982E3C5D03564EE68818EA8DC404A2284B15ED26123001D88C08BBB7B242E48EE43426168041A58918F4E96410DC625164BBBFA5345A45BE34BC9EB8EF67EB617D0B6A366606D3FACB117057FE46952AB1AB2F9DA4518A4E7A9C2D543C70AA995CD7AAB607240C84596406CE98B04A6200DB2999F1384917B1616A629B2D5ED1E0191848A8A605EB3520D5FD794BBFD4FEB8819B428AA26510435C0D1F31A52F51700A5895491A92767C14A39D595B0D7E79A4405CA041EA61AD81B3387C5759C47346C4592E5EA2F8DE4B94751412A2068489769B79A2A8445376E3EC1370B20099B7B00B6191F7E03FB9FF48864DE8917DD6A93E67F37C235225EB263ED2B2DD941AC2FCA42FDD3DB7DE8EF5C5FA7A4E9D22CEC64E562B6CB4543B3EDFBFBEBEAFC543009C85B44CACF784835020878D64CAD5FD9152A2E72B6F72686C8A354C51EF165D87EF0973205028F13D46CC26CCA7B904FC109DC612DAEFA5F8E49CC5E8C1CA2C5744352DDFD20E2F18B5B20B057B4D09402E1E2C0B7D91BD0CE9452E8F31A6EF41D1A209B109330A3CA943B497EC8F3E131C079FB11C0E095DE63702EC4AC85C6A49F794B9502547CDCF380976EFA343EC2179479E113939765B69D650F0D974A2CA943B307B5F8C6395B0EA557454B7CC97F3B5BF7B170E75280008EC98ED7EB98D7DDB976FDBEFD738C2B52FBE617664467F4E7F830220963B9B0C5B36B5365AE098B6EAB8FE3BD67348C19BBD4A10245B4F91CF485F52446884959BA2531FFA6E6269CE85D1A3E84E86DED546892AD136BEBE56BF94BD4A674CBC6CD67A6D421E0824D81B46E31996516405A9B98124F17C161FA53E02834A751568EB4A39A28C788EC7AE1C4D5CCE5384C227F7CF7CB5A7B7102CF9CAACDFC2F45893A16D2B238BFD692636CCA89C43096FEAE2563EDDB91A48756D3E89E1B50E6AC4D99FC7B36FA47E369D25CFF02C7D5B73AC61EE3DB9323369209AC7FA34065BF6BCD5099E7D0C4CC093F80FEC8379102528BDF801052799E33E44CFBC75022EAD0243694CA284319472E365531561BDE0474D0C52B36E4A1611BC22BEA0BFB3F94B254E315967723510AB6F5F4DBBAF60F3606C28FB69C25084C2A424C9423FD232A31EB4C2A140B37607CC85BECEE8B5D0EBF0D091F69C59DA10E2AA1AE83CDD212E1E2671704CF440FE2F97C3AC71676CBF1CF61F610050C980351FA581B1959F803220264574EDE21041924755EA1F20883BCC8DCC6D535E447BF66E2F14829066EDBDCBA1EFA88B9AC27CC46E953576934EBA1441FC8D4DFDD215FDF088A49D05F0EC9B60B26F32501E8A49AB51206A69F6E6D3A1989143891E7E1121F89A150C28158F0F9F6D8A125BACD340065C6BE337E69A9DB0B52B8FEC2ADE3C819DFCE1DA5FF7BD03924081848466B4113FA3ECAA92BFE58BEF6C2FD29291DFFF0E96B250F48FBA491675F7DC168D1CD4FE128E0ACD3B18505DD65A0A40D3799A1C9801913BA223BDBEA9E5AB004352496660A61C3BFC871037FE03284D68E2FC21081F78C67345A42ECA07545B504E510E977333DFAAA22C10D81481465287B5FE310B5E9450D0D99475B6DE2897E84C7F597AC52EE13D2C66B3D9A75CDA19D5982FEC339CCDBA795CA2250CC708DFEA7F615B60381FD5EA74981C5EDA3D7BB9827DD7088257BDDAC9A2E504DBA1B48302A3D4D893AC537F287E9B5A98742C31A6F0BE8B8BE29E5449FF1C8B9EFE590FE2B4D3067F22BA30F962EB10BBF7C9D63E740334B1A737D5BA53FB4DED4CE2038F4742625A5AB5AA356022B3C848A8354CF9C87101E85735172D6124DCEFA12C26A359543D06D006F5051D08EC5F031B88C83D9E7908B6E8AB8F693A61AABF42791F12CB64210D7A984189B8C0F2C48067C2DF8C321A3B397EBD853A7178487ECDEDFBA0EF7ADE58546FB8A44225A620C9EAA2AA198D3064BFF236327951DA40E5CBEE77138E7B1A6CE919628EFB3BA4FFFE9C5BB93E3AAC550F3F5A854B416DD237AF7DDAA61F66466BD844399573FF5CCB8DBACFAC789539B91D32E4B176453D42F802EA88608DB96C0831C364557242141BFB907EB0CA3A99F63B23D8C24E9DABB89F07B60368B71E398076B33F2FE4410BB70003E0E5D20FC8FDE127ABE2EC7EE4F29449B35DDB1C0F716492DA0397E762DFCBBECD729E4CD8BB03EE84C69F9E1340B6C7075710C775CD868F32BABADCDC65EE3B810FCFABC9ABA0C42540E98600974D94D0744D511B4CBE8D2E57E8898F392F6E4CA02560D5873B54A82C14245AA4E71B344A060BD43AEBB660A532F4F058E03975343AE7B281DED670118BF6F32F32515CE8D27F6294927787E7E2B46DBB76341307538D06440416B968A066B2739E535990B0769D0340C8B1313BB698983F20884E6A81828BF21D5F6F72A36D53B8C3AE8B4CACDBFE727D98D608F85153763C1C0DBA6B373CEEA63D9C750F70D99ECA398D1A1EC45B3E42A991CE61223FA9C47EF38D0C1DE240B89A10F81A412C0F57373B280B27E52F9919D85D87F578B725A6B63B8030D605618841F3F3E4481AF719B3E9E955508AAA73CDE21343D8FA9E14DC525C23291B11248D5BA29FA356FBFBA160F016CC0209125EA94BF729EED3F493A74B3406A87AA3F0B567599D092D19D93D32BCFF31BC279662CB93BF11D9F4A54FA8D060C538E41DEF4888299F852A4D0B18F3E389343C77BC094F8C9883493D90F912336A14E2311646236E33D3AFA2583C426B07859E61DC3A85B76A0A6402B6BC0D4F3772795D740B69279618B241C0A986FC95FFF99E3849B5E372563C8F6DC986E615605BDF28E86B0113D6BB922DF80DA689C1DC4D9222BF8351A235DF0C7D0E51BAD049DE4000CE724D9BB0F7DD0785A825490C6C1B31B65F4EABEFE75AA89CD4DE8899A3A032EF863DF78F5881FE2F31998077A951DCDA4483EA013F96FC69CCE432F5FC491F38ACE25E48F5863A495FDB86E3C4758107C484E2C2D8DFD1D476ED1592CB4E0AC88D44ED2A69A15F2756B2E1016B7346D2870E4407019C7D8A0CB7EA54BD810C30ECE2670B580816088BE46F5669EE8C6131C323C78EF7AAE45035227FA9EB1BB6194AEFF7E488A5AAD5C2FEBC80DDCF3F27943FD947158BDCEA4B93FDA2EBDB8AA0F034391DA3F5719C7AED0AC4953FF432D55B7575BCB64D740DABE9FA4215B2DDC341B0C1F2047319B585FD630FDA86259E3FC89EA95DF2B1062B12271F272268401AAF2B6582729DFA2EC3AF6743AF1FD2F921748DF2E8727D265474A27D38793564A6BEFA692EBFA4469191C06FD75AAFB4A447A067CCF6C9A984843216E48BB0841F3EAE4ED47740C1DC5AE9B21C01AA969B86F8F90D4493450DDEE06F8180A17B43DC6181E13B4BAD40ADBC603BD77874E3C3A78607046070B08F8A1014817F88CB258994769E5A331D0FFD7DC553D487FF04E101196CA0DD70D8104B6E58AD3E2B71C4105F6779D4C4B0E2B7D1D158D0CAE878C1CFAB0A8F35D90BE0632EE3FFB7CF5F2E34AF6067C6A0AC13FBE6A67CC8836A5258650D7AAFF8BFCFDF307570D4DE9E885E1154353AC126CD15AA87E5A8DB10E89FB8DE4647AD3F88D4AB38ED7DC1CE73CC5F47D96C0A1B36AB5527DF81846B082DF33293525AD7A5FAC03F45F7D2224D8A197A03E34EDBD25C30A12F433A5903F130BF900F589D46633B2847DC67674C747B19EA986C38ED8341EBEFA13AD113081BBD6F1EA6B8A3F412702C2C6F244820425A245D512FAE9FDE36B7FC9158D36744A6F0BF879EDE9F673BB80AD8CBCA09E880FA0E3867BF1C6CE6BD75480B3FCA7AF4E8392E20A14C686CB5103C1B869BBC0007C1235E5C2CE02ED038EB370C2C5BF4265F577609E0422D5C94949F3B4D2F98BC54278BBEA1444FBF3800F369B50149BF6758A63468543F5CE1FFA07C9F56E12C44FC0D660B5B8EF59BEE6E1FAF0F5C45013E822E4BEDA8519D971A2049DB9D9620927911564AEDE986E22210B5CCE40C1FFA483CED01CECE0D53B0E94505E7BDFF23EC930B6C3F496B7F301ABBB5B54E706F2621898CCA0D35748D85944968C6FCDDC67B1B646B461BC1C9B71EF4428AE94532ADCCE48BC59EF80776B25B1B25265F1EFE40AE93B31CF306155269053CFB3FE0AF7E8F160BCC1719BF27784921E71C1014313DCAC9E4A12CE2F057DCB8A72EEEFB8CF2313663402C0B78885439D5F66D2F11BC6BDA2B6D91AFB5795BF81282377BB21F28443B21C0AD17F6378650E25C4C4FEF3AEEAAA11AA5467C5833FD33F1A00EA52C3242BD1E4C9B068B3612D81C0DBD492C14324620DE517B01497E5BA3932C4A6E7CF019957C036D24CB8F6C2047B5C69F90D72DFA7D121C4BE82911B9BFD20AA2332FD1D44CE9F3422CB342EA9D632A6B381B759DDE8D8E4EC4568F6F4599D80E6A09836220FEAB1664FC780B60D0A27798674387E074ABB691F2D2F800684E94BEA3CB4FDAB2D28B9356127A341041A74E8FD7843E86B235495E24F37A4E7C7776BC1BA287F0F76FFB821E92A9E504B6E65D367CEFB550DA564330D222CE0DB1F8BC5F48D727F4850CB7498F6108888A2057B187F07533D5F4F2DA7C76042735017FAB227F351EA7D536F2238B45DD20CFB6D64A030F31A3EECE7DE5DFD9BBFEEAC4C53E394830F6A1C487321922A462E8AA5631F30209C6ADD47AA02BB07C6C690B562FB8B5DB15E8D95C0CD5EF78697EA9A64C36250A30E47DE4046E29C00DC15D11919C131C8EF68C570D42EE4491E8E8D9FBBE3DB97AACE232C544C1A24FD6AEFB1A71614258955489FFAFB723274338D61079A6ACCC7792F2EE6BA1E3707C06B4661587DABEF943925AFA311DAFD0AE7728422E469B0500A25C104B9C37BF8420BD56F3D5BA61183EC031B1CD29EF032A07E99304ACB40B69EB323BC72803D40CC75B0CB2FAB650CB46DB0A967EFBE497D773A01BBC4B8BBA09EE8C1B2C6F09CAD820B90E86EA9DA7F55F50387E1558674D683631DEAC2D8069839D985E561A970388BBC76332001DA57EB7E9DBF53DA786EA6147061D5383E81C4087084326BD392C2DBBBCDF51BEBF3C4F2220159CAA0AA5DB851353C321347896B4F0BF49F4A0E7FF789F484D526F849AC94E87FC7ED131364247D7A53894CCF40A31B1434A058DAA2C847DEB40E8135CB89C57FE2872C86634094F825B1483E67A893575BC3D27113CB07F4737654F91CA22B9CC7B478D3FB77D707116BA6A9BDBA5408089ED7F6258C335B5B27FE3B47A664CB5A06F8BCB19CF633BAF8FD4626621C71B29CA0816E85A2C0702970F1AA92000FB2CC0CD92C07A4A81F467CC84CA384CB19A9CD48B5169867DF25C35645157937C14AE9AB2E351A7FE4559706ED82E5347FB50724C9C1599B773A0E478689FEB64C694B31D8048020CD97090FB210A2EE6D4ADF43CCC6A10C7CC2AFAF55E817ED6549168F71527F5EF8D3EB6ACDD55E27EA64309E76640063F8BC84576379F3B902D6E510378C539DE955A8CD2A99C80019122949A219C44A5A4E1BC4EF68B4A1A1150496D6773A13ADD2B83BAF5BB1148074BF181B95CE066DBB88719F006FA1915728DBAE4974D92A44DE70203106E2BFBBC55F0946F8CAF0B3DF4B5164578C43D86CB53D70CF45D4C95E135FBFBA4C07D9D6F78DB37AFD0C664C7D8F49A388573E30DA7E0DBB95B25212844405303D306F94F4EDAFCA73B3EBC3F9068298E74EA21890FCEBBC9BCEC4A758262EE9D06052002730F12B70CE2DC53AA98A595AAA39B22DD590903197C4E6191F99A179256C8360DC432000CFEE218C1C5360B4DDC7F1C8A70E3CE4B3DC6B51F1FA5EEFBAE28D093E37219C01593C1275430E0216D7137E885B5BB376C297FDE022590B0096D02A55768CF0457A2302C2B3A64BDA4B744B055E858A0CE380CA276617255CFEC51B8EE84E8A2319DD0EE66797F78DBF64F748B609C5B25F12A401AF0A2389096A59AA340A3F43BC020F2437EA1F87817A328AA02FC7576F509927914625290146D0871F7808F1EE98777E613502F83A3548D53325D0DAF178223CFC2DDB348071593AE359BDC94F65AF710AB9D0928C96556C7BA59A5B81B3E1DC4258579D09813731C78F8E90A1C37BCD80518ED354659453CBE4B6B7A221C972EA5F8CCB332FC2988C25F721E92151315D3D7C4A26CB3BCF238ACDCB1AC356BFB078B2F3F4D80BFC9BB49E9034B8DE99B0D07BF9E07AEB9C5281A33E2C5E4D2AB52CD9C8BA0101D9375DC411678D50C7C9FA2967EE0CEC8A416DF4F5B2425960C5061E857FA893D9386A06CC042C094677568186BE1331D4B259714EDB39433D29C93D71D4C71D4A80E87B20E09FE3B3BBCF2FF67F83290377F24D9CF313C2B38BE76BE8E0C415A74C010AE817A9C600F665629DEDCF2495B11E36EA6E694C8AD192C9A79FD9181D6C1DC5A419DB21AEDCBC063F9E9346548E0BC1F8E282C411A524C43957A3BCFCA401313423B3A07316186C337AF1AE95CB214B5CD6BD1E9D51E858BA4E38C649F080314D291275DA6798B5002016F9FDDE13711EEDAD7DD64E5A46998D080BCB198C4974EF8DA83D3F380953936DF89882E5C25A04E0D53AF521DBD14FB51370EB486E18AE7CE3A16D75FEC2E772F72A2B964FA078F71487A4F8F0D32E15B33DFBF0C58A97232ED1863B5119677A32E5F40AE703F30E60B1D3053CDC4E6ADCBE8F663D1958EB34139942AFD9A8E88DE0D53E3D0BD442A4380A1D76CB37C7143614F901F45A07243215BC4597476ACF49D173A462A0F1B8905B98217C1D4AD0DFD9F74377315E5479A0DEFC8DD2FFD02B9A941507A7ED2D58713353AE81C51012491896189669DDE77A4B4FCE4929C3AE46A2422E5C19F86F0FD9E10F45CEC5F0AC46B796AD17CEDCC272219F5D3C325242987D46B5BC5901AE442F64469F599CEAAD0A7B7C0547C4E9F8EBB51BA6B43F3D28AF9F6BB09DB7C1339BF5DCB7D5AD283C45117B6F7AF238E9F753741A344A390C1B1C4D82D930BE86EBF7F77FADE04B5FD050F1ED4B5944FC2244E15C3DAD2B93758A97200CF98C37FFC7C9BFEE5A2DD8AFB2C75FDEAE96B33C597B6568BE4EB4B6E6DADAB8FB1198AFCF9CE20D81569EA9491A8B61E17A4F65501C1E913C079BA9D64045F8D721CA3D294159FEFB0459780DA26F5AF78BF72BD2B2DAC64FC2F1289BDD11DACEAB4CB87483EDD9A622172BE26D542E303687E71B14A423DA3FC1161AFF21122F3CE562D09F907E73124077D5B50510D90C28BCF04116B40D1C58050260EBE699ECE0E77E2D3A58F3772932C9B2403344C37706E6BBFF1024648F0BF884F69C44092915E849D450120E77F0513B199D275089F8FC30F0C302C931537D4D676A687A6DE24F6883CEBC7337D67E02D955B70D585FEE5E17B2EC797E6C1791C449E4F6F32B90D1AA80B0785713E2DC3C813549E441974C605BA6FEB4FAE83446148719B2BB840E9F9C4EEFAB4FBABDB0A07367A05EA54B6397B1773A306DF9705CC712D0937CB0E8D5A8898DFAE312D2E02E22F359900E2658AC2E6C6CE44725DCEA8F618D9DDFC267C0306CCCA310C51EE31E7893D55AEB299F6E723E17A8061455310BA930B6FEA6B5C9B37C37C6C61E6D8415EA5C7B0DF53892449B85783074ACA4926A2F33A2F808D40FE25024BCE309F7B6471CB2B8E89B3ADDD2AF077BC5AB04A0F3AAD01624CC319D1564A8301565F3A3003DDC784D983C3A46586E2AA6E9738B813A21D7ADF8F42495005125D5803541DAAD64393786DB15817D0F18F0C79D66897DB14BA6CD51657613FF28ADBEB755715EF1444FFD083385C8A5FE5E6B379429FEE48CD6A69FCBF2B3363FB961DD277B6E84275BC7656D0A88F145994319AC53B8898BE533C3F5854D0BB46B13BB770E3E4177178A4DB38ACAC09A9B2519FE68A15375D8EB65BDE59BB1A97AEF38CA238C6BB341824EA62E62774BF0A99137F786A4A3DEDE0379F282F966317B150216B0442C5D11840C443154DB655740DF02E32490F14E7A67B9C8C4C68E92D8823DDCA33089931A1C1796F15946BC41B64988F809FD53DEB9E0CEBF772D9BA3358A9A98A60E8968FBEC22E3D0075B357840F16231C8631CD682B1B9F28E073EFB67F8B47C3581A7ABBAC16C1A2A616B9AC04D7F6C960A2E3F16CE27B63423BC593D0E3273F6F5C6BF5DF93CF6A333A5AA68EE154A607C09996CAB71FC4005A4F6B70F4ECF0CD388D598DFE8A0A49AEA88CA67BBD81973688BDD3E477ECB5E9E4599E0908DBC6F1224C62FBEC907E6D8B3293D5BDF4B3DD6489D0A3F1EF74F0456A8EF867C4D14C525470716F0BC06951C5D3FCECFB547351F5CDEA28295592BDD1F7BCF9C0335F2F80D1027815D3327408CD478232C24D1788C89B23F0CD3366E887324E34621F1D562FAF487C0C2A90F1EAF55CCC8B350445E16BEF40B54F30198E743074345EFE1A140D77D69308E4B7EBE9400D4CF56CB7A68293603931639785DB84E0D28CDB2AF299C1E7FCBAC884CC187218E6B5F5136512F11F79F0A3D5F574816B8DB0D05DF226B33208C1CA97920D50DD07590C07371291A2DADD41A5DBDAB9C7426A822CF58971E2BD3C2606B5DBECCBA68FA0AF3BD3C61FDDC5E77419606E3EC880638EC8F76CB80847DB0D227F78C2415B163A098257B5E95B1452417A3A883958763E9E3E16BCC9BA319389BF6AF22828EE43F8A7974ECF01BCEFB4267239DB64BC9D61A0EB3F9F1EE190C126B7A63AD888B3B405FCF5F5D7DF896DB5CBAB5B02BA4155A5CAA0ECA259E59D8D16AE8B2A958FC1DD3C95A612332C41D7D1E8F47F2DE7C542C0D0584A90F0AB930838F421514FAEC01A88EA7F94167622FB7DA2F58895B61ACFEC6A445FEC5627053A38B94F3D5584EE8D14E3F2852F2B14B826E717A0DD30E2436EA6C48D5D2F6CDD04B3418ADB1264CAA665D6A85E2E933EC1BD1BC30419FD7A342A5FBA4F84F2EB8C50B3B259D66542BA2BBADABB266DCE610402401AF92DB875AB6130652EE6514091CEBBECF432D3FD26CC21C27325A55AB4D925E6337D5B0CA0B69CBA6279765D8D4DE0DBC8734A39E88398543A692C481B92DEA533EE8E729A84604E7CCC70CF206C3B9F7DC0FD837E59C4B1FFF59110F50976D338A6B9B8ED5E9CB606C893BD458859CB7A21519276074BFDA77BD1373A77070079B6577A37A5C0CF53739ACA576C3DC13CCB980C19E0998020F16EBE2DF029A182EB2973498697022D6B731F976CEF0629FF27641899EB9339A100DEB7FE3AD6832227367257B0543FB0960583C32121D026AC68C6BCC3BA219BCB09EAD6B2B370F6E2B89EBF2CC657EE20EC441D3EF4AAEBA57AA1ABCD75EAB5F5AF1E1842609CDA12B2C7DC1D75914E049432BE70274AE9122D375F9D83B9BA94AC34CE146C7253AAB43479EDCD08ECDA3F3F77207F623A6D3274B4B4478E472CB59916526B8D440B533DD251A81B96D1FBA71BDAD6602DC29729A1A08DB6E88686220953EAD8715B0A5D90AD24C196D425427B2014DD4EBEFD013ADCE84E68E3EAF7133EEFBC2476C730A8251F1AC3C20689FEF6AAC37DA950F9100F4F489BA282AFC7F8939D6E143925E38276AFA80D108A2573E0EB93A2EFB6DC4DC05D9CBAC31ED4C717E44C2C0DDFD24E666D503D36D06CDC035EB15776EFDCEFC96BF41B6459FFD6ECEEDD8D5628D2A2430A92CC9695B9B468F114B2E5B1A5F561A254D08215490929E6D2F094D5DD1801A7091CE54E821E4C7630BD5319BDBFEF72533340D4494C27780B28B4063A99AE77DCA3718577B4D595B4DB617071351F86F6CF6F8B9FDE4A7AA25D0367A3F141922DD45ECD46D631B2BED0B293C6C9C51E8068077C3BDC4C2B70B86BA9778466676F383A36439FFEFE4BAB57EC09CB330E068AFC1A68B0DA681AA26D35D47D6E06BCCC5F09D7CB997C72602D164456DDDDEE4026D59B1323CE321201DD1C616E78B19C42D7A9214E2D50972D9C7",
     "5B8A9400AC6DCE68A3A84086D55F2C3C4521AC5B5B4DA8A760D01F543D692513FADBE5ADCC31236262ED5DD752FE51D9A61CA7CE589FA4EEBF2C928652D3133D0684B18FE11B9D1A4F2038C4AA80AC6364386811F77E8F00895A95A961D046BAE1F9E058038070BC5098BFC732D057C712AEA75B4B77EA2E82857FE555CB7C3B33A37CAA97204EB9A28954E5090F17AD9E0F8BD5D8C7CEDE8E42FE46829D0DC7A95ACE4955A499CC57366155033A14BDDDE52FCBD3420C1DEE3071BF233138A5188B9D21001579FB4A103418EB0E4720B9926A9DFA3088262C4ED405177FC113892274BDB16A163379B7E0D5F8142BC78759267877950F23F2556BDC7881B870CCAD6D621208216052F94B8AB18E2C1F54ABB917CD707CF9FC0D8B61EFF8FD7CB7EAA8253C94E719719DD91E55079886C7289D8876CDF814136F8AF6815E843FA43B8360E16A1F6698B42E62F4E7DEA59708D773589FE7A87639B2E7E6B026143D15F86499779A4F912E040AFDB9FF861BD08A5060CF09536EE6D89D086B9AAF270B6D3AF5C91B072347BEE06E8526D723228D7BDC77ED5BBAC18D9DBB56DC1E3B88E5A540AD58DE95F7D4F9408B0D929E22E1F332F37DC5DAAAF61C395BCABBFE4DE0172D513BB38BE2BAF69EA686805E55F1FA3EAF6A0B1D10D6920B8E492C0BEA86875B7A3C15B6264F3BA737FF826557533121F8524A79606FDB188BCBA0308950361464271B90FD08D1872224F14DC0EA63220BCF438A5DB3CA395C866F98BC1003263DF6EB91CECC524B6C72ECB872C36406EF9C2A046BE46F49776EC17DAA0CD889585F1CA2D163283DB067F13B5CA38AD8247CBCFBC7D43D3A5717FCF695E1B1B01C5B11AE334A1A0F3D31C23CE45422A478B9AB1F7FBFD0B2A70DB9605C9E1C464E5CBAF8A0B3B1EDA1F03084D0128CDDF7D8D6C02FDFA9E00FE9144708A06D245D8BD0E331D3285BCC28986DEB79C4C66BE75F4746ABB3ACCC53652CF2CDEBD08D3C886B2466DF45CAE986EF6E0339D96902F7DF23A6AE082012CF4E15197CB6CAC61FB159667658D05BA907CBE6E237CC2ACEA8E39E3927FCEADF3C6F83B38A2FD340DAC72D17770CC9A683B80BC679C736C529C259FD8A3B650D581C961DB89E29AF67944CAC90900959E25020B22449FB3F5426AC5B18867CC5ADFC33F401D3453D866302B11BD972604859D12690E8BD82DA216B0B5F0DDED3BDEDE61BF19FA9826392E7CA071299EE6EDE6896EE4D64AFACC963D1C64122712DCBF54EB0711FAA9AA16824A6B55EC69A08375DE8FA0522F62B3271BA45B38A931C67BCC0D88DB07AFAD981EA7A1916D9D5B5C17646CB8CEA23DDBBB0CBB8EE836B371C702DE72BBF55D83102617254951DF1F336AE2CD2EDBCCF94451E6B9A6AF16E064DD5E734F587A462EF020020D2AA7CBE851180A4AEA1403BB4A53C96507445D4919A59F412B81899CCDACA5659035599107C21F4F82685E9380FE14EE370CC7820E89BA2FA31D635683E2A4983357C294BAD410CB060C93E6416DAA8840542AC07445C1D92FF02371C3CCB7740761C6BC14E0F6611BC86B6938631C9FE684479D0A07C79120C3B342CBD9DF8FE698141982A752B59BB034F096E9467DEB27342A4526026B9316E8A176EDA4D8DFFE6F4DD0147B125D283C70943B2DCAB9E7CC15B97BAA2EAB0A94900B13C8F71CC49B6E0DE1AE4D0FB508C1AE608833283CD953771190115F7CD5AB930C1805A554B996E650310AAD30D2F940891E2EE02CD3A356E29F539720DEDBCBBB8839FDFB8EECF93C1CF163A1077E39F3EB64046D2DC0716B0E24A38FFD5E176FB758061216E17ECBA62CFB7E75D4B6EF8222359CAD866427FB46ABAF09656934AD9EA853D565370A4896535A9300972DA48C5152E088BF6DF3A1C896C48BE751CE25A3728929D7C147459AC33E7C287A39BF32C24D15A0BCBCEBF63275A04F7434FED0BD3812C238935A756EE5F378D0CE5149BB52368AA1D661F8DD084E37ED04500CB57BB7D92A679A7D9C5F9A47DA9B5DEA5EE93F95E86AA390FDCCAEBA13A783BDDA3D4B4807328A843BF9BDF62E69FA7D9908A521E679375F1515681E2F6E755EB4AD9F50D83C235D42A0A2E142270DC378B7C21A5F985FA3A84E38EDE0CE0E0B4C8643499174DC2C10559DB1E40088F892C0BD7B47371F336901125C79DB959B0D3C9F685FD8AA18152A4670D58C9CBE43AE6866635E1EF3733C7B46831AF277AF39B5B5F40E4CF99B67A2A22A9BF6B6B2A4212CB5B4346A1DFAD51564DED6FFE235688EAB3DECF0A48BA1B863198F13C2C966978DB341B7F849EA5334AE92A7C3ED0AC8DC184407936ADC07A72CD5683642F114F714B11EF5422CF1492DF03D60AF02AF1712CEB180A735ED60F217AB698320775AC50F9A7CDC7FA87ACF0B16D3898FDC7AB2FAE2AAA38BB568B398C4003FF5D4181B3E5A7A8679F8F1DDCBE40D6D16BAF51AD13C70AE00748150FD63A80C4DB95C4EF648F05C698DA3B04D81B55425FA3BE24BBFEE84D2533B8443F88EFC8ED159A880D26E3CA35C5AF68BD36B042199754DD29CF138CF9E5583905E3D2EA1B9EA1B57F64A447C75C49404FBF67CBC3BB3980B359606728CCC5EC7CF4A2CBD710C254EA4DFBB5A7807AEA4F8EAF0A360C05D258AFB41DA4AAA2A6484F73F001E3AB604D4E3FA900B3E27A5AD6979FD7ACEC00A4E82FCD292D6FDE502EC12ECBEE64B2E3716F26B48A4426CC9D2B965447B907D2B0144C6EAAE0A51C59123F12F5D5FF4995C9FAFF55E95983CE07062A01E99E5C4424890E93027025871FFFF7343A9A18A7F56F1A8C2F5F4491D72AEFCBBFCC619B89DC3AEE630D0EE40E6A1A492151E71D60001B9A5068A59250FA6B53C7B7F811A3D992D5297B93AE33E7B2FB6542196F8BF8E9C13B48DD4C7EADB9520BEAC94A60D293D72D2A3099D3946568A363FB5EBB238013E82C22F9FC2D8BD57A24D18244DDF8E157C3DF618B5970449A47DAD40386BA1234B15CA5013F5B85245F00BE3F47508D804A7FB13487122E2F29103B001C1B07D2A1462BD689A170A0FF834AF9608B04FC755F7B6B1C981BD00100ECFF082958E3CDA78D8C68423E538AEC915930D8846AEFD5B17DC9D4C202F3692B65BD92FC5699EF6C0F71D0EB351E8FEA0D59A32A04E8F5FD74B5AD60E534392A93051DA5CCDC896DE21876FE2CAF5F15513F6F95125A29E1CDDEAC85671B32798EA4D86888BF5F33104EF1A271C4994F992D9202AB518470B768FC3BB1A76AD11503D3AA1C40892E947E513EC0FE9A80F84EC0FF8251AF4FFA13EB6D6C5ECFD20F1B7462245CCAC6A719C5407BACD79F63DD00F69A54F1700F5824E303030C0541677C0D64B83951F4F9B57A3343306B23CFE5320B651088978C1BD1CB49E85D5D0CDF7D781D0AEEAF2D60290AB258BDA752298AA42955644040C8BDF5737B5A005D77E6BCA57D2707F3A713B445ABF39432C268389AB24C8C70769B2FABAC233DD47CC3158AD00290017468F3AC86BA83E90B52CFB4D1918168E269985BC1E53AC9A5E2FFC336CC547FB7605B6337625A13DA7FEB53B9D8EC306EE7CE704A78C162D62F3224E7ABD2C3D95703E7B18E2F5D08EDDADA24BA7232E0DBCE35ED7BC360AB539BEA41A2FD1C287B304853889556A0FB1B358E73E9FB8530AF0A43ABB23D626FF192CA570766AD83FC2B45F07CE99AC7990B55AE07D55F7800362C5300F4016E93D621EBD182D06031AE9AEC8CDF9EAA29D39DA07801E61462EFB11E1770F5FB8F6D84362A320D15776100F92668E8DED7152D28DBA3FE1013B87C70A360769ABA2880C648EEBF3A68C25DB7B58B675CCDA669411B98A1619A7A67A29899D81172DCED5334F91B6AE19D3F592AB3B9CB6656110667509F9F028A69E1831E887034C7DE0BD531E1D96F0CCFC7AA37A66C38C21904B352013236EAE2AC7AD8E8A6060CDE40C8057CADF877DF20DABD7C11219CF1DAB091B432F68C3B83D03E13771632C5845D5BDBEBA1C2CFB10F0BCEF05E12352CF8FBD7F0C90F38C6771945FBCE828BCE76C93D6463E3692BE138180AE7700032B4194F80DC5A8BE66C0EB63A9B6F8D6B2DA20C03EF18073623A1017829D75E454584A260C645B39D3481226BE43E14BE9D0F3869787F375C13F0DE1BF7245957388580265557A01EA45DF783E4A75D6F7B2E5D16EB964A4F48133E1BBBDB61E6A559D019DF5067B7BBDBA6A5ACE8A78922DD514B9AEE2C0C412597BB7B59F6BE5677FCFE8D3C58B22CC0E1B347BD0ECA933C9812B628BB384D6FEEDFC25A390D44F08CB6B9C5AF97A5F05BF62010E253CBA3D8DCE19674CD94FAAD5B10555322F531640546112D5D8FC3C3A5F946E3AED7FBFE8C01CF3452AF13028363D1B1E007C4932ABD038A0AD1C17C166A9D2460302C779F0225A77B903E3EECC9FC801C159B522A42973CAA1F74BFD805E9EAD5FB2DD06D9BE5CECB914C4986AAF5A449AF210DE59A9083E199D5773E8C487CD98216AA0C6831339BF8EA4918956493E52135C776DC8A8BCF6AC78A906A156E9DEEF44D800B2571D2C17B640A6D05A32AFBF7A70A522C37B33EBD803B771D2D3B49858D9DC9D7FD2E455B5EC2DD0E2A8CA6C1F9094666879EA0AAB9F90373878AA7D7133849ACB1F1F8000000000000000000000000090F151E242B",
     "8360BB62331B86B992965BA6920758396CDF52C60C3C82EED150E0112D5B8D822D10D738C6B9B33518FAE32346363AFBFBDFA3602C50CA5B98821BE6509EB375BAA1DDCD025419103F7E16D7981B70ED3730B0E1D147240ADDDA8CE0C9F2B32ED17B3EB624722BACC175A8505AA8362562E4D904CD85F1F858013F2E01DB85E7CE717FCE40D3D210347D67C2407C0C1D098EBC4FDA829F51497F8AF682602A2938E9CC67C53FB31E34B3866CD73B78E2F7C28F2B04BDD09BD8440DF4F206C4BBEA3EFEB95E04DF98B9C10CAB1E779557747CFC471B156836A22B6BA5D76DDF405FA4E46D92EC5EF40AAA|SHA2-384"),
    ("prehash",
     "41FE1CE3369D17736FACF2CC25AA7D60A0266A718977E4D5752F502338AD5F0AECA30FC6C0F09D380E1CFD596A15DBFA987FE455D824FC6D6AA1BC031FB70F1810CB700AD2F8F5B9DFBE192535F1772D1D203FC6541950C935FEFCFB4386AA85A14D7BA76B020E7B2C5E75F7EAB6314B269159583B102DFD3F5997647A030A0393B21F4F522B781864A8AFCCF7A46C7F4C7D40DFB2B3C91FC2C9D672A721F33E85E3C3C18F6FAC6858B3734663F4426416E7C460DDDBC71C69FA16117F70D08D848B975676525AA239BEA3558E8344DAF58812E24452BC96423D950CFC5492D0CB7C1FBB42CE0BAAC108DE96233451FAA670F9EFD0503B7862AB926F6CB0C4466D4C2A708E27B2D94BD5143D451A194E35AFA1E8F33DD70FAF6DC9EF4E0DB7F8799625647F00243449670FB9F2902DDDC4378CB92B1DBC0AABD7C63CBACFC9FC6075C22E795340DB2FAEDADF4123DC3AEE2BDAEA7A6B73A54958F854565D4CE49C244945043D009C4B5D89775BDC9187D8E13953FD0D67EB65210B33503B89812D59D303B3172B2A1CA5A5DB21A899FB2B4B6EE7D4776E639447D5BD0F0DADB1D70571579AFE1C016AD754F1E14D87BF49451D2C1F9C8E41640F1BFCEDA2AA393CB168B102235B3727ACFB5A9895B74E66C93B9137C917841CA35C1EEA4C522976FEEED42DC813CBA9A521F68977BE4C1A2405168FB0AD8433E9D6197D6D7D09CAC37A25996E7E9980469E65C366CCEDB5B4852850E862A7596A507E3088130C3C16FE89A423C0902682BC13ACA07F1B586294710D7B171EACE2849A97882583B456E966DBB53575E5D88FCF73BCA7D5B9B7B8860CF4360D965AF6C44C2DC6EB6992CD878087A57708E0D220232EF01EFDA61A9FDD2D1DC768E130AD3FA5D95816BF00A7C79088DC68EE766B59026F563ED6FF0067F4B945044129904B8FF9FB25E9FBC602064D6985A3D2A4E02816CE1AB7FA9CC9CEF023BBAD4C0FB93193ADABAADEBC84DD4FFD373BA05FC2CFA857D0558EC32EBC2374B6814122C67485CD6B7FD65F3BEAAE885197E8C92441D9A862D8F745C1858B6CCB3B67D9359DB42E311E95F59E5F4CA9B40053C380D9B40ECA565237AD40C3504F399F5BC97126FD2221064885D706D43EEBDCB1D12277D2C4268F530A7AB2A2306610560AD2A46D1A3537911F85189B54F26D6FF891625E084EFE623E7B9FB99F692093608955C1A8D8A18ED1836339B2B0353EE1D7920E2111A0B0CF7816859C1FBEC506518B80ADB47CC90431E3B64C55E11C548B6944F1A113F2B804936DABF0D64D462B44EAA901BE82FBFB6F8AE2C1DB6AFEB3B48E85697C8740BC6F89AF4104E8AD9136C6C9C9FEB870067FA462A2DB29824E71862704272F3867329283E70DB54209DB7CB9A2C8FA3816627F0DD2BF99176973CD2EA0B5869CABAFC25099DD509E60C481DC193C866D5F52E706620784E30823FF8B3751D8FBF6DD0359DFBE4C8309BC76915B05755C93AD4E60B98D385A1B2089418A2A2AFC7E557C397EB1535B5C1D548C7C721EBCC59113B46C6527B07E0CAE8CC2FD679F09DED9E03034F7ABE04FE837EC00BEE4C10878809AD11447B5D5441B86F05712C0779828DA39B44CCCEFBFBA2C325154028A2AAF6C78C9D2632E956E4063263F1139394D6921807E9D07BB87C295F07199891A9DAD928239219F5256C338DA4B0324E6E872F31A557C52BEA703E3A2D2EE61CB1CEC5D3B132DC3C0D87FBF34A50D7C8FB2B84337322EF34FB160378144376B45449D9755BE070CCED2396CC35388EFF0BF35E1D3466E58714D0EDD5486971777709A2D982E22563B134FD1C2EE487AC3E43C42623D9131AAB55D8592BA02D8788E2549289E6B788404E6AA3BE70837CFCDE9C7F86BCE2817023B8179C4DC41CDB9A507FD2864B5AB9885343155B306A492630141B1C2BCC1878EFDC199BE1710D9C03CFCF6DDDE00109154D3E293855B4CF51AF25BEC12B329CC76CFA1CAE4FBC7D5048BE15FA0E8B19B1A89F90AEC1F656A935A2D7523F6A4AAE9ABA43F96A2EF1ED7045D43CC5AE95FB9DE5693D92ABE6CC1D9F8D3744420508BEE665F636314EBB07CA9AD1F2C022EAA3A078812EF8D85246E3080C56FB2DE3D42FDECE958002613A1ACE5B3B718505838FDF252699791480A0D7ED5CA44EC9FBF9635BB08A082C8B60A32FD2781F0B563DE3569BF3FB86B729B87948A173C9211318FF5B105A16104A90F681FD48A61A82DEDB2FDE55453A324863671F8B984BA4A7744A8E0B7FFBDC70F3A7946A8E4BBEF72D60A84793566A7D8E204C75960E8B39F8473EC5E88FA19B669C619CA30AAD3E9CA5C26BF3B78ECAFC25BD514A3F859B878593D33964D7990487C42A500D74EEF2C506DEC9E5ECA4DE33613B8CEA53D5746F1A40C4DBEB0EC54D97B55202E890FA8808997CDCF926142EE8A246A40D40E272BA15DC04AF73791EA74A47A39D55931E7E199067050B59578D20B3F4F2F82BE4415E88E5ABE2FB428C30CF2D7E680A848034162E070ABF1A08E1BE3D0E3FD83FC6D2FBD093BAC76EB2C109B532572E2B538FF8696FF8BCA6B61220D0D90DF176358233B868F433D7B57BC64CC353853A58FD8F466DBC8223DDC2278407889B7EDA668D2375FC06E0551918ACBF7754AA0FC30C1D3FBBC36022507A04011ADF86F7ED5AD7D6C0B586CA4B6541CF51C004455F2F600169B9E858484C902CB4B188AFBD02FF2AD58D4A7AA41275AEC0FFB1B54EE923F504CF48C",
     "C28CE2C4516291BD886396E50DFF8DD283B152105371CB9E9A443BA600CCA2A3B6B64DDFFBBE4DF18E171ADEDC10A933E4B886C51FE17B0F6CDE839E541FD4A24172F5B733718B097771F2CE80377C1EE390C6D46FE416AB6E805186C7C46380E59A15592F8CC4AA8DF5AA368DE98FBD654B63B8A0BA3D57CB2444F71C18FE21A780B810F4E1694648668FAC3BE2D0B2776D9FC6E50B009EAB093A99D20C111CA2E5185E9B072B041248C3A158E86106BE16032D35A106C0DE54181FE67C8E0B07E7959CE98EC97B9BD468ECCCDFF2C329211561181904378202ED6583C6D87A3590804BAC8A28D3781C4739D988C3CCB99BE6BFF6C39C8833422711624197E20D41758FACAC5F0FE00C25B4A1377AA9144FA71BA9E6BBAA1F2CF70C9A08DF9DD0E8715332D71C60B78FA6B26EBBB52B4EC11A42DF68CB7F94A767C80D179F86BE94705762C96A2E9286837566505287F50523398F9E314040D41C9D06AEE73B050C02C143AA3072FAAAE011A90C53B1446E76F452A493C155B302923C65D972982D81B90197F56CF976DD225F86F442665802DF20806886C50358381729E9D8CC40989D4EBA09474E9774BB2B58C4ADEB19BC253EA6B231CAD0730ADE43046E32097B2434E05C237E4085D3B13357390E377C1B981BE24864CD7DABDD8888D46B26EE8291D3E46835554120EE16FE477B519367176F94208B0DF719489179C06174EAAF7AD28AA19E938A2D3C6E555BE6C53C5648E94855D569551C7483FBBF827E8E4372E40DB7A8DB505FC46A8AE1296B9C4451FC3EEFB75C93888A327CEFF34F97C64F7EC782098D5286D9FFB268F1E04FF172EF0F1A44DDC23A661745FB622A5F77D37CC1785D0E33611682CD7996FA9FD02DDF1953C66A4210F725913DEE6909A679496391B07CD08B42D68587EEBA5FF75534646BD0D8C0360D71F52E9A76379C0ABC33F6F1F404924BEA2C87A05082ED532BB426061363AD3F5486B50F1B756E5E26D771A7B223095A6A7F3386FF8B9426054A10E595C2E12DDBA815FD5FFDCB1EB2872CE4A9F29D3B99BCC9F59088E76A84140CE69421E552BC1A9A4F5EA2173375C40FE7F5183B1230A4067A159E4875F874A0763140E2C16E21FCE505CEE09F37DE94D9FEE0DE248B3E2776E35374B8009F1D3F414E12099D0EC7D33CC750581BE9CE8956481516B3E1C5434A80D036F439AC5527FB880668EA2114F69105508272F6B38A68F2ACF5453AC9547BF4BF22BE644218D2CB119C59F249F50A5BEDAB19BE3F3FF2F5597BC528F20D245F5B33161E527EB06A41B236A57FC26D711D3847EEB3D628D54110E3F383137E4841D9B5B66728933499CD95681533053C6E483C7155663810EA7E47E5B34A38D61B4BD985FFDCB95AA99C54ECE6135488F6963DBBEA99931B5EB49321833DD0EEB97B7C69BCFCD3AC03260AE88197C57E9FCA228339F25197B49581D289BD81B485D683AB92F353191A77AD3C3048B0E0871DDE04F156C43D270E5C1015ED23B1623B3032784C9B7DCF14DAFE3079A511A697C0AD6EE4EFB608FBF82D71232DF475DDB5D659577748CA4DE8E10CCD391F3BCD3442E2998F18118A89EF9465CBB8F5E6CB6999E1DEDAD9A246FEFC014092EB8D933CDC22DA41474EB7383151EA104BE5E34C5F25ACCF0A1064BCDAD667C9C2BB417F76179ED8322B8E45B0E8EA3E5F20D463CB024D2C0C0A537AFA0D6CD69468201C8F4A312049AE4FAD51B9D95D8A5FCA46ACFB32E3D7D0CAA837E78682D8E0FF8A46759D2A67815FFEE625FDD6B28B62819045B693F367912D7499A2A9AC35D24F8F8CE9ECE15A8C638F264A68FD3E41DA9133B8AB2F8E1730617F85F4E5EF24308EFB15F466F3B548F0E6220A97F3ACFA8D8798D166604AA5814FE096A37D49B231E25CAA38CF6129041E0B79349880411528712EA15513EAA54EC4C71DBA66FC6056A31735C222FEB53A26794AEFF34517FD500979A909D4FA916C5BCE17642B97566927DE973F6632EBD8AA290D7B12A992DF81E5FE52C97E81AF742854E98EE45086C6019CD7F67E3608CC738756A90695AFB7A5497B1E1C6BC4B58DBE9C3AB74B327FB681A7594984CA611C6F3542373D32C58EA1D917D03D47A9F6217A4998243CA8CA8DE6385A3E597F604C5B6414BAD70807355EF3F4FC0D9DBA0298A3032AAD77D34AFD0E453AFAED95CD13DDDB02AB8EC47E73469C0FF2C79C2C73552CEE4D732A3666BF499C877B7BFA03E7C4A9CA2D57C491509ED8AE3A0947ABCDB575E898B5D787A530025356CE121E4A4AFC0E47F928CB1486024BB1DC97C29CF2568D99444EE4D3F1C45623D81852E9898AD1CCE39D23420F2CE699AA786986252C6E21FBA7D41CC9F2E51C6BDA416D9BF62A451DE8C860778841196AADC5D6E1C1FD1A85EEDFB4CFEFB4ACFE9BCB50465146704F4A472346F410DB5CA40C7E9FE3B8362B87BFE2667A90650C0F5488639DBD762B65BA99F828A245D1462E6054C0BB52232FED04C872D509E3404CE839E1218A04613F5A35DB65198C88553C8374A558F88E698528C2D76BBFF0745D422ECD2683B2D4FA19B3E08DB416C6A0DD95F9589D8E170708A53DD85B580E16681A2F522933D27DCC43E60F95712A659B33C3CE06DC787181F6595530A03E00C276FEDF7B62D4A164003416FF98FE62FA6D799959D18C67F9AAB4FDD5367E0059E6A794D325D214CD1D9F9343711B36F42F8CAEA197E76A0AD2044D76A1BF039478871BCEF291871B1A31403B9739FDF82B9E943A1279E102758665ACED2FFE5DDB2A7D6F146292C3C6C11A79E9DF9137B13BA69F1CDFBEF6F72F3085544EDC35AA291B2871AF33D23EB019D170D932A50CB9FACA64A986F652EF1E4734D074E0928B521B859DF1AC060A49A3D511E616776456C92E6FC0FD45A0C5635B39DD8754EFE256EFA90A6283293925A6CB9718527A811158C8CF75E142C58FFF74D53F30EF6F6C293990F975AE91FDE4A23F0A2FC4D830790D77C35C0C8F80A37F1114271EC7E6D6C7DD2BAAFB1ECF8B2B8271C3680F1089FC5DF7D6453406643BF5947E1D29661303723FD5612CD7044D089013F3BC98148F315084DAE94806B28DD7D3231C94BC95647F0023A0BB4DE2D2BF8E3AB9F113C8B89BB2E6FC78827362761D7ABAD70D97CACCE5CF60CC2AE43680526CBC6928AA518DFA2A2C86624A4F61F0CB9F8463252C4AA3E29B6556B2C5DE6C5EC2D2D55241BCFE1DFC39E26EAF8135B77FF0C2A3DF153F91BC6A6750ABF6630EF511CB84196FBB6127423A6BDC5F4C03B501A928EC62708D57EEC2FC1E266036A5BECDFB84EAB92818AE0550A396807E6686760B2C08CDC20D4F6FD297D4102D92DD025CDDB3892B0DD631BA247EDDC6C059D02F54F313A71BABAE0E16C6FE4A682ACE805C40D837B5CAFF40B0E96EBC5D8599951E7958615D5F9DB5EA3EF60C16E2A3923A3B4C59EFEFA8AC547106B961994C0DD3142D0CBD09BCA99AC7265D7753B2B6A2CF55AA926CAA4B85156A1A08387D109C6D60C899456290E6DEC69A3B2EC2BE8B0EF1DEAAE97A33DDC6521F9AA2876161618C39113DC594ADFF940DA08812D73504BC8F99DE7228A772065EDA10907AEC67224D05F7C2489E8BBD1C1222A5E4252C2F2A1D74C884AF9130D486641F6B1CA72F466C3703642FDA04626322BAD7468CC2F97BAD221CAD8F85095BF122A3ED203FCDF9EC71E825AAD83F917613359B8CC6A9070C8B5C742933DD1F290F071A95D8765756640D36C906070A9746E16CA5336BF93D38C59697235DF9A7B22BB2E2D6D7577FDACEF7C0E63FD222F498872D85D155C1EAF16C30F632245BCD1C09D829FE2FCD0EF177882DE42EA5F58CCA48B9C7C3BB03DCE106A46571515724A414E5C7AFBEE041F4488D599ECBF7119568847B807130EFA0D9BC100F023A04E2CBAF25B78BF44EC43A39F4AAA3B59E16B468AC5639F0543A9C53A40CA57C2E3D38FD53690EC6FE14DBB571C56A8CF37DC9B58B31783DDF1F19337D89092979ACFF5F37973367CC3F992594180F6D6E1ADCAE361E282D9D6F9487D1DA06973A6FCE8033D9A6CF2C00D4B45E16AD74A6EB0E83214499472C3338DD665F68A0F4F83B418DB5597C9EFDF2D0665560D64DFBE63A7AFA8F76B15B368C5544CD1ED03A09BFECFA6F8D25897DB1BA4BA362BF8E22337E39DBFDB7283CFC427F051CAEAC1B09B720646F2F647356F7479EEE57790C5B617BCBEB44C0E0516A9EF299DF75F85839FADBCCE983AF49241FBE9779A79B3418E591A705540493EC4EF3DEAE9876B5DF1795F2AD2441F222D1404854CC9F5E7DA031552BD870CEED89F02B76D21A64681264190518D5493BBC7F7623F11DDD7969B1C9FDDEC844319B0B836E7CAFA247633A71AA19C72E6A2E34F31CA169F80D5FA8257562C8A3840F33CD47407870B09C188DEA2A3D228F262CC5824C53646852C3E7ED603E5FF0249CE73C575596F3B7407006D24BD1469586B3C2B9C720F76F249CD66C27F10C1E5F35FB83B715DAEE7E4A6D4AD38CEF9A5315524A7E5059986BF36C2F857201AEBADA5E3A6B99AAD8FE410921B8626291CC5CDF29A0C7F8BD6F671D62EED930886B26AD361DBCF7323EF212770EC9FF89555B08B5FB6DD568117CF762CCE8CA10B818EBB8ECB8ECD512DA96752F0A3A66CAE94AB8E9E8A056DF99EF0992090DD46741814830CA73A014F29E9CC4B4010086896CD9BC32523A601B835F5800C8B0765A29310AC0F036C307EB3C23017262F8480A5BB9832E91738C08200036A7FF2FC19D3616FA4890E4265DEBC3C5C6683C839500FFF7721390402C5350D45C20F3AE02E96AAEE68E4909532C97BFD19FDF58F55D569BAE31AB07E5FD89929A3752F4AA9565A6C131E1EC9BAD291E1B753DB5E5EA0CAF159D4467902BE0C77AE5B77C4AB2350F54C543020C6C38F2993B33C5C4047751B49DA7DFA5BA6B0534ED58D4A0C2594E3B02B95C3CC04CBD7DE922FC3114B5D3BA583FA40170120E227FC35829B6DCBB3764D97AD731A9F341A94FB7C88E84F746828B7C7E91B2157C918EE6B48D66CDA0EA8AB60BFC5545D5BD35B4858E9FB06577E68F837DA6C21AE5762D767FB1765DD546683FEA6F2C110FFA2453CDFAF3BE04656604C3A2E652C9A07A296754CFE2888180825DB5CADEEA532664F98BBB609F94CB4E94FFDF55C8C5F4B54D1765365E1EDF885B9353CFB3FA03A3F8AF18BE56C840CD8A2D00680ADC15B0857ED8EEF61F1311491128E062557C9467E932DD76793325055C567130299A8473B5252F8F6B8C2A8D8F388AED462AE09F3091A5608866AAAE675A834AA0A1829C16268C361CC5F98F9266DC24E28D60E0A012D1AB369B99415C4C55651BBDF36C5C6C7BA60A81B2023CDCFB22A807FABCBF9F08940DDE0891CC96B8CEC7366B8E88852CDC4A207FA9A7DE8A3F2C66D8141A1C9B874B7CF18849C5C68A2A5AE0C61C2888801B15D95B275311FE6752579321E229A8FD87B6110547F2237BA7FCB9DCF29284FAF9F644C5980F018DF6D03BE941312713BDB9AEAC827A12599FF436559FF5388E40D552093D65B636629380594BC36FDD5258D12A20C4CF4C00812B4F466421772987ACB10E796C8EE3CF7152C712DACA437CBAC06C6116ED866183A9F49906D3E5486C268DB25A0C193E8B37B156AE842A20E84C3807BF95AE3A63688685CD6E0622A8759705EA2BC8F3C82CF7C427EACA0A2EC2080DF68EBD032B78DE22FFE16A83FBD940788E59E2F0592F957D99D9B2418B866737F202FCE8EE255ECC1C22225EA9909EDA2C569096FAFA0FF277AC298A44FA452240131399B36DCF1FEFDCEB69220C29C264F73CD1A9A74B069CAF55BD454EA8078B446BD25302D168273A3E4500ABA2CD696ED9ED02D067ABE6669C85D5F6592E22EC15C4D992313DE53EA21052326D38342BB49F7CCAF4A00944658440B7A7C94A90786DE4D7F81D0D56B8F67171F04BEBDD3C7DBFA4BE9A5AF99CD2B03E949E351381427E581671A974433B654E9AA51715C3D555DDDDCCD3F6C6FB49A29151921D440C170861AEB2925B9D70929020F5E575428F26BC7A20994BE006C8040411B4CEF56E908B8D5752FB1157FD651ED6CCC44DA7A2056113B29CA295B901AEA4B29AD6B167ECB9321DE49587CF2DBC3BE0990777A8B7AB8A805C5A49BDAA3CE883E184B9A1FF70D33BF55F4E90E1700DE65F40F6E93185375477B1D7C0F5277C332569403AA29A2090F0A82DEFFF0231341A3EE426700DEC21BF5C3B2001C4E4224E4E9213A52825436766F61DA6F6B0B3D1D884D949CA81B87CE562C7DE87F7E7C6D3E6B0B6030D9F182EF1F1C5680622241AA8F8ACAAF534FE4817B2C73D725858BC86AC18D5CD7AD130833FFF800193972A0550E04FA34C80FF86837DDED09B6DF071C6FC9E4C296B884750F6763384CC959198D8DF48C983834A65FE380218807AB53205CD2928C3DD30291927D0CB6485BC80F751152323769426C60F079BB16077C741980A891588EAEE026B4017A9117506D4B479F841F6CB0F573FB0ADCB3395593E79DCDA8B913570495719EE85EB6577BDD3CF46BAB5411D72951A4BF833451C5AC6030F8932D9A3FB33AD82143DA4718AA9E1114FEF1F4189660D643530A4F7DA2D2B2A5DEF219EE41F36D9F7CA847FF9507B9D2B1F4A86F060FEABD0BDC2310DA54D98BD9EC206470C3199750FA28811DD22F862B29C27C6E9C81FF668AA16B8ABE99952955D1C48DE4FC747106FB87FF5137BD47BDDF73E9F2E1BBA0AE496D378AAE4C8217D2558F6743FA9DAC6F405822ADAFF7D8E6390B1BBCFBAB612BC1DF9A20D04743BA9D013F863DF6DA9F96FE8D2CCC702907586AF5903CB4D38515953AC53D435DDD74FF1DC8FF31512E9B5861CF3086C10CA4C7643E24B8A9BADA3EB78F2575E808BDCDA39D8CCDCEBC991A58D67FADC3DD14603B154C1BAB188CAA96CDEDEA48F43EE17D0453D56CEFECA049CFD13655610CA5796E6A16EA3AC20762F9ADAB6CE2DA2A0CD50EC0728DCEA53C26466D1FFF9434794ADD232E4BB68BC4D6633B8518D6902CF125F9A575F04681885290B696DDD62532C43383072B32CEB43662D4503D9EC70CF3FDC5C9773D8E502A497E75300B49378BC2A7ADAD20EEFBB31CB38EA6BBD1D115E692171DB0F57BE120380A2E71C0F9F17B0C0F6FDCE38604E38A6CB97F8052439CF6F0F53AB297C2177A90B6E3DF3D796CFE271E157E0CE78741C058C7936BB0EEFDFDBF4A56EFA21A24EDE9DB1D56B3D3244CDB4141319AA63B4C1A64B1F6F5646BC44A8310ADA9C9785F5718B312C36C351ABE98C01CB33880CFE800A91A798BF69CEDD0B2E8FDE2D59B5DF47A2B76135CB37F3B82FBF159A50D6C0E808F54C653D1342936202FB4463184B1665845ECCE68800DE0DD6D2AB62400D29D34245A5CC45CB018448BDCB16008E016B77DA5EFF942A4D9A19AA0914C6DC1FCD1145F219B68E40E25E6111D69AF8B7E0E6723F5FDB3B19345F5B5B85AE5FE55A94660FB86EE8DDB73A3A3BAD5FADF67430B874AB36B33420FD610194457A1C990E7083916DE7985A1E7613105B169661F0A0FFCBF9F3CB17F77CA00642FB2D4D4A96C4F50EE71530836D9F01CB2C9D9D68449072C86730D266927883171BC8BD77DF3CF9B4FEA68013C8322AC631A970FFB7220BB9A42D878F78F3B46729F8B5986533759C9C558A504917F5EEC04B5A46E0AC10D16023AA55D9950989F6CA2BBD20EB118BF050ACC7F36CDD4F826025827CAA3254B6D68377BE66ED481D7EBC2767784EE6CDD6F11301C6A7E49A69BBC6DE2707B2F192366FD1DE62E164AD8E9B5078B93D2703A9845D24E7EC465555204751F6AB190C9F20B576EA765B4E37E9B2ED39F08A0218D4D220BF91B3EBE5BB54BD309B964088896843403FD87BA51DB69AD82B10AADE77ED8DECA2960863F6B5C3F1006BED838A194A9A687A0562BEC2569917E29B7F46BD9C891ACBA1D403ACBA443B3A67734FB1BAC790F09B1377A8B7436B0C10B1FAFE2B68DF3D3544E0DA8B048E7C0A7506C1A52793957D72257BC7500F82AE8FB049C145AF6E35F5D84D5C0D63C18F3EF8C7C6199BC0FABB43DBD614330E923CE7EEC61EBB023CCDDB41E78D51C14EFC90FA5EA2BF967E76677C47EC3B1137C0DBADCEB1BE2039566985B01A3762388BC812266ACE6EEAB6A0843EF558A6528C5B1EEF894C160FB6652D10A94D1EFBA572A0928E9D92DFCB361AC8CDD69F837A2EFD383207AA2B5BA0C3FDAE3921D168511494DC20818A9351F7347872AF7A62DB4ACA1E864CBA067CB30F272630C36B933A7D51025EC4F91CBE7FC2B1A80EB0EB24DEFC8C64A2CE66963BE47BA652D0B9E52181606587B9465783291B209DB7988ACE79017C50B4BBDDB789180A519FE89AE24E60A73BB99DDF79DD195EAC1D1F53EFCC463B6B9C3382289B1F2499BF349D87C73EBC0B875714B46C188437E478D7AEB2CA853D6F62200B6C2F92CE524C9162514225F4CD05BA5283AACDBC3EEE572EEE77E55196EECAEC328A1142A9985F39D5C3263BA6C525971C1C2B3A4F53957D713C66B2856725777ECBBAF39DD66FAEE51C10D46CC96A552A6BB8BC6549B8ED7DAE1918464556E5979205101B5003D5D990830840122C8A54ADF7DC4DBD0983DCD543A1AC483F682450E69953BE032248067A6FCC95C3C150C56186AD7B367E2C58CF1E724BDB54FF4F9D03D37D50B633A558833C35DCACF4B6ED879D3EB8C254BA16A37537C7A089B7A4A942B7773D4DFFC4653E8A3942FC44553AEC650CA4F9DFBB4BBA9DB5F80A960E7578D9F14AF0D9ECA9E3B1A20F06D0402A2FD237972D1D823302681639A9A717E0993F133D6F850C23FC39C27B12BDB3D1D65EA02276A7B58B1661D0FDFDE9E2A52DB5CCB9A11789D0F4AD3FE2A99994D26513238B4D449566F9B555F95501D13C1B6B15A78F19E4FAEAED660B0EAE416C5A25FECE25FE10425C5CD3861174BD5BB94E90EA05EEF863E2498A5E86F1C3CC3B676E135C8A8AAB561B96887DC643744BEDFDD27A7DD3C8385A58B0A9675DF2E4504D55E90949B6200B67D9B731BE3AFA33C5E4E4A81C89BC571CA541ABB7BEF44DB93B013DA810D2E17A9706901F55009A5C602552409E8B4F92911A1B989AA26E69D786BED55694EA372446A8D94EE936C0DA46592C5E253FFAD7933DFB0906C040E0DE088BC174A2BA52B165DD862726CF15249F5BE24E48E0127F4AF94F3CE88A232E0074B84BE579A13C7BA705517A218C8C38F191E46EE053C1D7A6EE44F7CE586A2F0048B35C4D16303F512F9CA1E926393D460B40F5532F49271499FCAAE18EAB43A63BA05BCAD3433286379E2A7BD571A2992685799C116AA1A47D2F9149B777EF5917775BC9D363CB85DD07BDD0EDA5432B4562597E055B1D96692E2E9FC90F8DF46F1720199DE8FC7F037FF72F000BD2ABCE5A59456C5F713890F8B1CFE2CF04D436BEDCC05112869EA7C5DD7693AE8E1BFD116ECDE4C4B34BD7722C2386A444E0F68BDE8F26D0BD3D283D0A1FAA49ABBD1B377327AFFA5F154D02900E4FAEDCB2E488BF3E6CA95270381DC844D9004E67807CD162562968B6CA4A397940F55AF082E420F9B02B39ED9AC95118B02A5F867CD004AA9F5E960481706AA597ED3A8A36786E3987CA38852771C1EC2EEA2635F0D0667B7F9169F01EA7C4E9B0605E5BB57F02D75F5056E24B843B084FB4AC465A1B06F549EF093950CE8ADDAD8409627910A0DA308150F6C6AF6B89CAB9BFA885716EBAC3D86C565A3358B0461C92B70D05C20E5C31B7C8D5C9CEB546646CA97ED0FA403B17683C1FFD0BE84A26C09465B1ED36633D797FB2A9D12C148B53661CA2D607B1F868FB3C254CD5B06A72A6F5E2419ACA894C54D8AB38A412A5616BD2BC52BCCCB677A64BB7C0AF92512BEA4EE3D176F626226F5FA3BD289EB4B3FDD4DE26DC54C08AC75937C0EDF8ABF896D4D758C6A2364AF999A77D577DD0DE0BA5B85A8BE700C2A6A974AD401FBC16DCFA3BF97DC058B62F690EDC1667343B0678DFA90F88F3D1CD54181E5866B40776BEE48BB9D756EB4EC8E37EB9CD16BFC8CD14F42732D4C186F5D0D4ABA77E13E8C7AA2D26FC091A6D07DCE44A79C79E28C4C5D7799CCF21EB0B87C2F2C4F32BAC2DF7806C3F848EA48D91F753C0CD0DB7C3989FD22A41DF48176DAB8AADA8FEFE30A418877E61C0639801BB7B183859B612709BC2F15B51467EFFCE00E726A6480D0F8C198420275E5A902D7B875E48E56D92B053F10B0DBCBE9CA7A6C01BF4C67D42DA601DC649C3C38DCEFF180FE326A68E1CDBEC238BE76FA9E0CEE3EBEC298F458B6A84EE74896E9D767CF37D659F6B8B92AC44830B08AC5E4E9150B8603A0AC17C7EAE4EB1383B615FF82B3745BE3A31874425F6EA0CC339B83627AFEBCE95A2B4383CA0D0F3CFB7A32F90CF42659476413B87F6DCBEFAB91E7E4181F0DE90EFC86D9DDA347C6C0E3A02B5E4C5E2B8FAB7178E7BBE5D105213711C3D010ABA581456B2FA604C8DCFB74554EC110D2A3BBB438CAB36A5457A68FD26C24B24548FEFC6F2F01E743D44C2C52104D8784F3A346861569AA91E0746D16E9D905095D84A2D6460485FA41D99265455AC8C4CD69BB713E1FD9EBC54263A4FC291D76B171ACE90244EEAF148495EF456FD454296930075FB68B0A6DA52B34B3AA7EE7C8E7D529AEE22DFD611B37C91A4790E077174F6B00D66E96AB5BDB30425FBA5C4DB036E6505B6B78D440DDBE4D265648E56D946DF6BC97FFCE35851A6B024E4EC984EF7080765E1B854627A8D63CCC20663632909E83E12D20B75CBE66F0BEFBE9A3FB1946CC7F280E22F1D7D9B8A72AE3FC0B19FE37F2C49E363CFF9E6C3E872DF1518D57A01C714030D881487F535DA6FB1AA587DCFD4B3142B9633DCF58D6B44A573D165E25FEA182F6FB83241757996ABEF732F2C1753E77DB8DAEBE04472C5BB55FD6FCC865F25DA849522BC30CD058213206853279AA2E29DEC4184C49D",
     "02E4205ECF7B2245097D25355E668CB25DF02FBE8BC8616C21CC168FED7595C2D97430354C08178522617FADCBC6C44AACC7222C63FE339681BA4F5388EF93CB323265BF1D23CD05EFF44590807DC468CD23EFF730D6CBC861837F7104A46DDE3695F7FC3E168FF16C07771A25253FBC987035BC1D98DCBEAAB907D37150BE938229D4DF582A39C0D386E6C7C17D93830A2849B4E7704D2A6458366BD716863F094758B0DEA2B7C05E76C44DD9D11866ACF2654283F4C3AB2A8901B45588C62776A56FA170C87B21F972A882691BF074732217DEE42E9CE82DBC319EFCAA1BC9EE21AF63AF7D501376FF3E2E173FE53E6C5ED585829AE48F7AFF921C6C50692F42F506E8B4EEF5434AC0C2C736E31AAD5A84BFAF0B3E2865E099642EEA3F95FDD57F4BF5169277FE50562AE1ADA43FA567A17733881E96EB7137246A6AF58D0877D61B8D327D0096D4E9FFF07FA12510877212227D0D467D5EB9F38C0369EE5C63C300D71EE91ECFD27754040DDD70651C1584F971645E7829982B54311E5704C6C9628C40AE0922F70B86AC8692B2B5D0F6183927788AC45E737D921E9D1CA90E8C68553A2D953E37D399FD87F008C3701DC448393339BCD2DF5962737603F5156B9BB43F7146E923EEC5366BC055D63041908BC986FEC2F20BD08E96B456454552F228F54A4DE523E9C1368AC3651301EC15A8A29E866F2D2C7F627DB2C50B55D06998C9944ABA5EF4B1ECD40B0BDAA4B2680B4A57AB10F258BC62C13B1A973F9DDB1770EAF1957D553D123F84BE9C2D7B1E559AA322A4E3B6D406C0BA316A78482360BED29CB5AFA4FECD0F9F61F1196EEE814561E2A7E44C4E32C26B942B132D02CD61178CBC999C00E2962AD1754B3E328284853ABCAAEFD1CABD9BFD4C9211554B78DA383CBB5C5DB16B09A92C9D7E62315AE165ED95C2457685DF584E6195965F8A54462AFB3D26912A279702CB75BFE8D54823D7A3D5BE6138E5404E8601B9FC260023BE02CFF1E264000C6EBA44C175A22868E8D15C53FDC4FD687EF03B8A789AF7FAFA75061C8ABB04842BDAEDCF9E868C361E93E2709C597A200A419AA7A0FFCD1FA67E676845D1C91CD428D769750A9A78E87328A0C4979760A68C34DA6738B3423E64725E5E32DA6E8DBC2CEF8129F381AB8E902D25C35B8670CED9CD96874F09016D9F8880DD3EA802E8C31BFD83FC86689FF3221570FC781D117685C690E6A544AA48168EF4DDF4D4247796F9C257727CEA230EC31D5BA666B393B10797C3A769C969FB9A6812C3E9FC9B40D6252E7092EE1A6845AD7C880983B8193B739A29EBBFEFCFAEBA61FAA3B8F24E773FED1EBE27CE5F9F01F0DEFA524CE30D157D6A7EA26D1C46BFF922322FF33BF2F86C694468A82B42FBCE771FE44E893C1E0F8A11C0DD46EEAE5F5C155929DE8F7C2E649A5C40AFC0E824B650766C040B192D5AFF8E969FC014F7846166E381F7D0331823C480DDBB62BE0E19DD702A341EBC4D999A03C30E9B8ED76EEE200C0D093F98C75667D46FF7A26F8A353EBCCBB6B3D63C91A4F9313E778E6BE1D0379544CE43ED0DCD3611195B4FAE99B6E3B4AC477AB7ABF76E379A1383989F6B0A245BF5AFB065BE75C546DDB4421321654D9702057584D9677AC0F9504FB5E59AA7E1E15A9E2827174967027B385B4AB30D5A889FC6B05E6B99E1868E9C0A777810965D735578ADFF81756DBFE517B2F8AC3E7CBEFEEFF670D9B22BACE0B54C55FEC7B3B0FC82C4DF842BD9B7EFF2E6037A3BDFFC9270E950AF1165095A0A3246F00CA85E19F8F0BB18270D179C1FA68059862C291FF4B842A0D41BA0FE0FED1C1BEA23A856EF6FFF9318A9A81E05C31E5953388F54AAA7C47F2C1BABC6CFE8FEE68C8BE7D2EFB09E459966A3581D997F4DCF9BA1423A8F1F507B6EA93A6DEB27A25BDA047F591634FCC87023EDF20B3E453F2E4741EED0C07372FE1044120569B62794196684FFD231CB2CB6DC9C51DA26D8E416294906A35FDB145FE13E67EC391E479583DA52255B8712DDA310A3287EE7448A263B68142C181982826B3E8B6816271F26EB37EA15F24631ABE9401B1893BA04EF834C589E98781E9CBD1520F3A6C40EC51941B03249D241FDF962D2175645FAA74A59D6E313D2D5B405E7123FD9BA46214C2D355EB5F37D539E01ABCB93388EBE3FFE4BF5950DF9EC523CF190DA7C1F6BDDDB3684E8F79E65E17CB816A3E5865C1B1580D19C3EB601A9849BE34F2E7953157FAB292CA174967E79997110E978519AF513AA0549295BBBD787057BB10641C0CD391EDDFB4C238A9B47CF87FDC92BB4109D813D445AC24B321B927287B8313CA772D1F99290CD00716F5F8DFE23BF7E6DD50E443637D18DA404EC8FDAC8A497CB9A0F01D714D9AA690D2430F023C80A115CB1F7E72A8443BC0CFF782A1615F9F2601C082E7EA5C89D7B78E21128FA780928A4A050D1C50E339A6FB4121746FA0224D162B40087CC0EF925D8AE111BBED797DE6F561A1A54A9006AAE9E11D042227C8CB95DBEEF63626E043D881028B1EA52577F3D2E2CC3BF2FD5358A70198B0B9F1FCD2ED538F0FD9E18DB46C0D86E21BC2666F9B87BCA1FB4D3C1B88E09BD2A35AEF6BEF87959695937E3F566D9F3DC05E5D7E2266BD26C525D76C7683A9958BA09B7DA4B79181E7368A04FC845199B96C40383DF9A356ABCC9031C68FBC8662EB445EC16E0463D43AAD09325989981DED0B96D0CDFEF67838E67827B76947B887A729BBC6673385567E1A7B82EBB6AC6D2075E774EB3F50788A0D4D6A26B564741D9C850D235D7A180ACDEEA5A737F88EAB7201B3D7CD0620EB7182219DB5705D3987E51956F9AF46B764BB0048228A397B624F78F086B43D67886AD306F98FAC1709EC6BBD7233B5BC9A2D5527D73E722CC381A280B1B7D0524DCD737F04C88BFFC6C56163B8B46F4331E4A7EB7B7F17473FACA3350F2EC5B37398E5FA03BEB95BE0903CD716BCB5A5BDF8B645FC4931C9B5D44E3BBCC112311CC9C00A47F379D814197C155D2DAE46E03C91A390340EF7F62678513805EE3AD3237A911C89D6CC54BBA69E12CAD16E08119A06EB63811A66A8082C7D8B0116051804941D44D864851576875EF63E53539AD4CA581947AFEBEE9EEA28222946120D3CB502086932703C87CF9F5245C09DE829D5234EE62BF5049B2C0BE2B9DA41600721865A1B03EFEF0E955AC7851669A6D80D517B93A49B6E555BE561ADD0A2E4059D988BD4F6B605B4805DF6E8780C769BACE93479B3D4B77BB403ED9ED78F71BF37F9317B807D49626417D42FF87035D4D0B18F8A18D8EDE9A7863E552D6946395D9B282EA6FAB0A3A1CDEDE90111B5AF31216834558DDF491AD68677D23F07E97395BAA8B4FC256C82ABA5E5577FDDA876D879BCC0FD2A8F9746004A87EC905DAD188B9146417ED9DD131619CEB5DB1E5BCBEE24E7333CAD311448792512895D3E2E1815702F956D97B323C60C8946581C21A5FBC51637AD8E546EC02409C7E742F6BBDE8EA52A05556B92E21C0A0C21068002CC0FDA4F94A7657B618F669B5B39B74854C79A38638AB1AC5F11495F754CE04B0956EE3143712FA92AA4959A19BDC2A17B449AAD10DDBDACBAB6D97A2469D291764E99E89AE79AA42B7B2BF668F8D5D2F2966313D2828201AF6EEA1D7190BFCDFF4AC58EAB1D4341E9058812DFCFD22BDB7F86F8EFBD2247EA198B189849BD40800B921CDE402C04F882D6C1472C18EE28EB2EAF04F57BFE7DA8F7D0ED4E104975C9A77065E09B8D59B81C1B9649D8BB2939C35888D2FA9FF8A4A4245282F076FFF5B5745ABCBA327EC1BD42527EA35919528B030C2AC682DF9B79D3A775C40CA91C645288C1C53E677AD65AC4358FDA85B6D5D7DC8B848D6BBA9C7C0845F5B2A33BB72C4BB20944F4A6261E62EC4BBFCDD0155A13BB57BE3C3D36EE779D9432B24493BFA0C178F04E56518091C576900028886EEED5936900917AD7A86084935D74D672D811CC516B54FC8D45F131142422AF52961D067E1024DA96E803FA12389AD31AF234C160FBDAA02C3AD9E1E983CF3D2366B47FAFEABBAAF125974910D7FB1A33793EA97C002262778C188A451E19989036CA88B71907181E1EEF506419D9D62E47CFCBAB164E3AD4EC5F10EC731FEEA4D5153399119A1843D6B8012DD9C51A43628C5E529944017A8F1A6491595F9586BA7FE40E158C0D9A31ECB84BD126353D878CBA5563F8320AA804011D32E4C12379DA1C2FAEFB7A8CAA30E6F739FB1C09569EDC21F707C413E4906207071039108FCD84123109B93E521166B132C910B988A55BE0B0EF06EF868E7866BD39E69E78724923564887AF51303D80E3F70A758B801BF5A601725F70930C577DD537033CFF21706D018408620BE51CE777E04D95224053B189206DE9BAAB13775F24969F95DA5B8837F94CEB6DC73BD627601CAE51DAD3733E21A679BB20FD289B29597C00FCFC89B938B10D905BB215BF12F0C0DA0131BA5349D07EE1B069A396C9388011B59CABDFD30B6207378ABA6568D52AA736CC45D815ED95723077C170C1AE8A6EAE885AF87D449F2CB16ED0D6217330016343DC1020D4E96D6EA0319292A5EBFD7EE00154E506690B63F626F8395DDEF041B458297AAC8CBCECFDBE10000000000000000000000040A1219202C",
     "44FA052177227DD1A5807B7FD57FE4E9C312C58F2BDBE42954B85E8D801D1E7FD9565C799B10E645728A2C36B75552895582522690EEEDA074A1315D67F05BD1B732D52809396B1638567D187C58CA8515C67DDCEFD5B1AE7F65B307261E9BEFA3A88F81DB6750D25E41FB419C6C0627A9587C03DFFE7946B3B090590BCA5834971985837F73DD91C95CDA681C655E0FBFBED17E533309282B0EF5B9F91A2F39AA17A6FB7BC6E57BD7CF36E827A555A96989743A03024C3E15004965EEB4610045010E710EC89833F9D5819F|SHA3-224"),
    ("mu",
     "B7DB969F1E25C4FFC5D835530A0773B60F9F74C596D4F5691A71E8653469B50E754E9213CA07F4938EC9889FDE367F52932ED4A923217448535C747BB6EC8E3372566385E3155BF4317D8B38EF326B735E9B0A9C2727DEFE380CB85858F6DD41F7FCD5C3751906A41ACDC9BE4D361AF8E6BBA97FB8F40E5991C3C337CC41E004E47E63C98694031A0E349B2C321FCEEF1C6896D844401F179F86C85EDED71DA7C71B2CDEA3A37B1536EEB6D92BD1A781DD5A106300137EAB75AE5593EABBAE6E205FCF4553923FAB2856538B37C4C552D7A5A402A4D6FAF43CD5179DDC795A586840052AB64DE23A09DDDE6ED0C54A40DBFC7DC1D20BFA015E9CB922C74790F84547BA4E97AF8A5516BC3F6EC2BBB7EB721D7A9D22BCB30C9491C3D5C8CD19A20D80A9B6080B91C797722F38CE3A85044A7404E05440ED530BA01A1F5D410A623480B0BC3BEB1EC32F72ECD36168EBFE4EBE8F53CD8A8D69C7493EB3092AE3C7AF9676BD7217E4C2FC6B9B3008B16FF53F70E258AD8C3C392ED3354C973DC8D6BA0869F708F2969F2AC6C336B1ECE69D551A31460B935F1C610690A20F906FE02FBA87D3629A7FFCD497E576A329CC5ED8AFA8BE161E3F9BA2255D66F6F90E6014F71138B12B60DA2B5AACD673FB9B729577F11D77B6449FD89963F95134F1D692D32F660F9B56DDBDDBBB960C7F690962756C8A7F88F90E899D5DD471E198797FD9C510A7C8B42C3C301BEA32533FC68064E2F6DD6C1394A970C4010C5C36B2F58465DDEFFDB1B446F23EF6AE95ACE86A3E45E7B2A2634E7F83AE5B079DB186C0CDBEFEC8299A7003C2DB1566236E7798261F73464263D08D037F84A60C29FCBB8EFC6FB991D16ABB9601297E0466862F0DAD658649106FB43A2905351531A4796CA9D2B2106D0DFA9F9894F37E89E02AF2162EB93A04C8524421FD35CD8F73DEA4133D4F1C860AFEF94BFD3682A9D9284180437FDDB11321478ED9370BA58D39B60F9B178BC41D8FC84DA00697268F79B3387F5108BAF1AF3E8D0B090C47D0A0DA24B604DB83F68B7D92E4560B1DAF55088A427B030B85D51A85AC5C353FD93ABDABB0F32B0130EF11E4111F6666171658C967F3FD9AF3F79C2A2C81A54FAF2EA97EB46FCC1AFA836251C1BEAFC28A170E49FA5D3334E9432B9487C47A34532FE820F9871898D9456E9327E545E3C2700A868B2E53C8ADCA77164FD676E2E5C5DE0A9042626E51F6BD796A465BB25C2A945F19110BEA8A846423D8506C74E1B79D2A0586A27228BF43B3CD521C66FDD45B353E8F863F8767FA02853B11B5B49770E171C269DC2A22E57A930ED16184FBAD41E03BC290E67E1DD048230F1344A1988EB1207D550CDF816AA107A270803DC39CE58E24D58454DE53306F8A0839270A76D6BD32F200C600AF0CA0708BC019601EDDCB5D700ACBBA436AD8D414D272B97C865BE72ED7153C98462140A236D7972728D5509FA688777BDD5EC85978A436C5D40677D043BE48E1A91C9127713EBBA15E4A071FBAB91E93AA597CFBE069FB4EC712E818A19E3E7A3A9937B4E3DB898D74C8B08DED614C359145E58643D65730DFC0D170DA62273E9CDA23CBF5620F669315A3807231A2799721F1ECAA75E17A433DD789292AA6672D09328C3FDF6B7CC81D3C3DF0CFFE997F31BB9141E43D44F281236A095B3E782FFD22C1CAF535AC9B0F8F9A011BABEAB7A8C04E732272A19300701B5CF2D8CEFBB9BCF41C3E567F07B6506FADD7F4883F3D9006305FC79530146EF975D2A2819F49E3B3528710E606A7342D850958C32E1101083658F811C838194C68D161ACBDDF19EB3146E65323643A37910D5BD641C5DC25D0E02819BDBADD4B6A8DAFB500DC2008C568F3742182A2625FDC6DCBB01B6DC7F7A2FFDF7848FBFD949A6DC7AC0E53FC775BAA366D6AB740CF181564436D1FDC86FF5E7595B5C90178969BABCEFE9EF495B34361D8109F10DEBD5286F7A4DE6BCFB232EE2AE4A6048E56FD90626B2DD6C2A7882D5686C95FD84EA6D28115FCBA8AAF54A314BDE08DAD3BBF0388802696089496D776A1EDB2823F19C0648CDE37487E607E34E402F0CD976A89E601DA53DF12EE607EED48A354BA02B2CFD248B0122D3BE4DF42FE5910526817993132D470E25E35A71DA23EE62F8BDB39D2BA48ACECCDECDD5EA2182792A95BDA707195606127DD5306CEAA42DC7BCEC5C1B55ACFCB50B9B79E01C40EBC3A062F569C963E932152E4DC34273717BA86C774810CA499C0738745CDFD2356C1CF35CDEB2993635EA9785517F466B208F691C99CF7B50DA40A1F3BDED8A3B141C03F9F32B9BD013AB22EFF4B82B25257DF717F09A5C609C73B971917445ADDD30701C59CD8F47DBB9342A4B4B50A5614287411959968660FB3F19789D29B57138E89EE9FE97983A172DC42ED16AA23163E305280F3FCD89346A9EB73B4B074AD3CA3CF14D3AB8B9D8EDF3C6EAE935FA01CF3B580A4CA92E7E966C609162AE9A27CBE46C6B7EAFE9861AAA0EAFBE5BA7ED0414A82199DF09FFBF0FBA6060D9E58DB3D96C42AABEBD5A288DFE28D8876DED1343E46E5F6D1A7C1103A73A875CF051A0C02C9AA91E43C1BD1ADC520F65A32E371B291595462E3B2FB6E0A0C0B953EEC9EA35579D97B2532E1D4BB3E76F6E7B1E972C20F0A6D813E31D24F2A6CCBF46E4F2FC7E11E4D64B00E23A8E841F3FBB54149132382C8D10304C0DCCD321ABF928A02D6E8E76B238AA02265D2FBF8F961C992B9432B",
     "A79EA24CEE8FCBB42370735E8EC3C19CE0C0F622457FB3130CBB21E62B49809B29F48A8CF223D6AB3ED780E65BE88FB96BCAAC16E3C085312B956FC53B098CA4",
     "D58DA9F8F429620FCFECCDF1EAA2E36CBE7AB98A67086149EC65132C072E07266ED173AAC44B80A8001A44FF4341EBA4B516F43111E7753A08600404CD741EF017972D5BC495E748B2D291B10C245A7CACC3D1E53272ADB43AB3725A0D11E142C30DC00433C3CEDD8C025AF080E39C900CCA426DB9BF3A04DB749839F937FD7A1A1EFA01584101A7FE2D9F6AA126B554AD87C5F7D58737C44A9F1CECBF50DDC2A1F3677B665E1E98494E5A73E116FCE82C26D5CDDC8291CE508D5627C82DBDC20A8ED75A1E8FC0563328422BC3058C138CF7118B7F0786B5EA7413AB3672E8ADD62A2B90EBF686EC39E44D200374E25308CEEFEFCF7539ABE31DB4CCDD21457EA1EBA98FB0EB4B0B1BDC8FEC8B0639BA309EF3C0E52A37F1F8FD9F3A5358840B8410C935494D6BA5B6AED772C667109BF583C040BA61E6F81AD20EA942F31A459094768B892CC443E0C2BDE44F4585B78AC7D4174DDDF9142624E6F174C0E4BFA349ECD03E84B464040BABE3A6ECB62C1E3860446FB75CD9BC1557AFC16454127573E3BA31820405DBABCD404CFB5C3042EE54584D273A4DD14C96456DD34217301926F0209842BBCB43C59CCB8FD68E6E97ADB7E37E08B417BCE104B85512D6DEFEA3A99638E63FBF19401AA60E72193608410A2004C3F9DEFC9792D260742155B458FF4B8495AE1EE3FEF56D073EE902FDF013B7C929E311705A782F4897D42FD8818671212A5BD8AEDB85157FCF317400F5038D874D5E42BE49CEC79FC482D06C3C3A1959E575D53F586AA5D88EFA38C255513FDF278020CB70F278FFDD441727D10376BF25BFBEAB01CDC75707DA41595D8ECFCC34C25C2714A1EFDAB84CE4D597A2169F4896A0304AF317E7875C009C4A40068FF9A02534A8A082BD6C6494F20A4629519FF49F59EDA759BCAC037CF3FCC8C4BD3EA26725AC2B32E4C0BB92434F0A746B8E9B03412B2503BBC1269031C0CADBC21C8B379ED501918D9676AB5658AA477970AB9CB47E989030C40118A80ED7D09F76F3983B2F38EDB73922C7E128347910AC72930788A521A56C7689D732BF06B19BC7F4095709D37286BC421BC5B5CBA398F32CF0B6B2E8ACCA2848026DBFA5344B1DDB8A020F1E136E91D3F93418BACD48BB8D933B539B672739A30121F798A287FB0EA45E0232F904270F629D827A683A14672ABD2022E4C653CFA8A534053B9763D5FA7500B6F03645FAD0035D6EE5C52BFF168F1221F07A9ADA7F5E1C6F0DF3510883DFA2539BE8811378BBAF25CBDEA6E3088A7B113AA0932F05029E41E7BBAEBAD1824C801193A36384F5846673C9A37CACCC1D96A818639349997E5DB6A93AF55516595782E2D9E505586737461F8489B9FFB3C71432A9FD7AEF110B8BFF825FBF77D533459B9D0AB684E4F5C7540D05021419EE4BFA7A3BD3ED3DE5B4460E5222DEEA878E2D8A212EFA6B0F0EA1568EB41BFE4F661010302A2C4B850B4B67FF55D46C1A690DD0DDF7CA4D95F49188B0FA834A4111FD72316531720A8D3DAD5E8DED430EE0A9C9E952E7E83ACB5D1312BEA74470C634498811E061536CC6118AA5E1F914B3D9E35446F163A94A771614C3B8B65B69B620851AD1B92A06ECED83847C89B9BAA93042FA31F7C5302E294835CF4F214EE351C7B449724BD716CB7AACFD3F4C33ED07BC8DADE12D54F3245BDEBBE941DA00E6032935AC0E18B65584F010DFF9E3F36CDF0274C8CF17B190A8D84034F65C17EBB5EF37249137B1FD66CCA9193A7C8C08ABB8955853BB927F9818E864C0FB437C7ACEB51DA6A2CF24FD214953976C90335A31A75E63818A6B501557B3926A393A3D15B103E443C39246247519908BCBBA7D481081A6643360F447154E65F012B4C911ADC89AE2B6640D0B5BE881CA381C3ED99578B2D1437E6DA96A8B1D730878A81D60ED1925C7D9351B50D0BFF87D7EB8D780A29749F0EE0A02F4EF9998A1451DE27D6ECA139F0CEC227E7BEAF4F20A547DC4B1CD889F17E116F8821E2B992284F56C103D455ADC497CFC505664F1A79DA0EF5ACE660B167D6A9770CC946172D9C431FD6B1FDD02784BA004A19B907E25B12E853456DFEAF5C94DD1549AE3153A67B138F10893303865E64D521141D0281E29105F7ADBE735BC940D14BA127AF55FE27E8EDC7628038CF06C80BE5D71B624899C2ED95A8E112A90506AE538A464818D20F14E7C884588DBCFB6CD6386A6406E0102137BC5C551125F28F25A97284BD38C06CB4A5A4E751224A4CD18A237288A06C77EE887B5C2D74AF7527ACA619985DFFFDB790571713298DBCC96610F521C338B0B3D163BC41AFE5D3782F7D99C8CE53C33E90748E877E2B6E61FBFCA6A0470ED63B9422AD6460576E08F60581805A4F14DAAFFEA99465ACA6DB96697B689E68CC7F28E0741496B387E78281233E390B07A06ACD61F70F34BB6AAC7AC1E1B487804EB552AD8DB8C2918A8C6D84E59CA17F75472883E730F5E9A30D92F7C2E69331BE801DC3FA5DACD00F52B02AB2C6BEC5C5C02444B7C785D0D9195549452875FFCB597F30703EEAAC94526E137D1024EC9D1802D0D449BA0E57178FBF76B1A0F0C5100F85892A26E540847A28EE1ECD7A8C68F568ED21A1686DE5D31B3F912FA7AC1F4EE04FC5DB5CE33735953CD39AE3F6AE2650CDCFE0C6B6337818BC6D2EBD7FDBBE4516435CBCD14E069B9C85F3C2763B63E951F57154FBEF9C2413E5411DFF7A37412290A6E22B9F9DDDBCE4B8A1A7A119F52A99BC785E6CB2B60AA733328687733A5BB5D602EB7088825CFE8B0AED862A6D9F6DD67C7BBF213455CDBF6E41B55ABF8DF937C2C49FFF4E96FAB61280CCFA10B806FD3BFE0FCA6C359703E1860282CD6121AE15B4626DBE3D399159DB115E55264B9DFA91C476FAFFEE82A945917DB9D0DCCE9C169139FDB5E9CE9C050F866312D5DD43EDC80ED09F5EE59C92057A97BEFABAAA912B05BA72B3748DB70EFC9E68139440C0FDC55E47B99B2346F60A706F86FC24C1E09EF0CECD68F311396EBD9766704037616DD30AE6175F7695E4D457BECD4896809D30BE3726171C82C94367A3F80105CF3ADA81CC689C12DB2363838096380714F3EAAD7E7A1EAA4F252E9B5298A8E85E7280F4ED574AFCB5B42FE8FDDDB436ACC39F91D080241F32043A046BDA382EB94DBFFF2D29D6D67DBC3AB6C3C7A4CA0217F93BC4481107AB149585E4C83948D0668F850C07A97DAA08FFBFC8386933FEFCEA6DCA2FB9A3E24633DB53412BC961778A1A2DDD53F505A17F9E70B55842080D6185475BAFFB27D270E8F284169641A37071E72D2B66CB4DF0F1EFC9462B71D9ECA6B8F66EA4A4F254E86551BAB352120ADCCE39598EF6E11B27DBE7C63744ADB8A420E370E2526EEA25A5D2AB2B31E878A3C6C546FA3628F952548BB8584116E587FF4F22AF38199B15B870931A989A5EB71F9C1C1C2CEF66FEDC02CB8AC7010A6411647CA6603A321E311FAAFFA75CD3870CBF5C74A8E5A5CCFD5989148075DF526D0411383F2250536AFDFBABFBBBB9DFE313F2F86B2BB5611489862CB3B0F1DC94CA7404C1209D3F98B23A3A79E2A28117CC43D3BF14707C259812FC86F0F521365AB098D495F095E33EC17AF11D20BF2A02658C96B608A74512B7C3974D87EF7A482924E18CFCAE719C85FD580AE64B8291A51D1713233828CCEE4CCAADA98687D1745EC78CB782008BD41B48CF6E6E42B181D15048FA2ED732F41F56FFE368382C7DD3E9115F4A42D0EF67DD5DA9BE318BC58EA96720F504356CDF235E95F0CB564F49259907EDBB3491E61C022716CCD1BF618AF8081C0410D4A6D87551B155297B8AE57DBCA294930BB00B76D6AB40BCE198144F96D367D72D5266F134BE7D339226F6399D3A4035EF7C3714C88279A06520004EEF4A6D4801B0DE98C7781FEA28587F7F8F25B0E863EA681BF2A39503033E09397AAC5F7FCA994D889D0928D17ADA326E86D44633E18643C29B90E592719504777238D658A02E293C650828A330AE0EC84A05922FF3D22E90BEC93881094BBAF178F91964B0EF1B165C32CB40CC4EA0B9C0F78C06446E1AB579508C2AD0572E9C245034EF6E5D8F6AD210E779C1B8421AEF6CF2678667ED8546B364386A9E199F28E1FE1A66C9E69353FCD1DA2A0F9928170E034DA9D2539519692C74DF2E6E63B0B8BD67AFBEF553A26F86674553F5C6004DD9D6F5C9206FEC61EDBBDC4302B37AC767BADC6EFD547B3C45E7C854BF19299ACD330984204CECD2C60390D137E3EC34417338BF15680E64A02840390618DC4DCAA8E00070CC4C73B34495F900D1672262522C9301358B82EC1FE81186D028281CDF0A101513277F2467C797DEA97A44A374EF7AE337A490444325BF72B55E3BAC3630BBA1DEE9A4BBF1FEF202DC564AAD1E620E950036FA13E644C0166B63575A9E382DB81A905FD393D4D02EC76BF1807A0FFB105F97C56F0976FEA20784E1B9CEE92E5858A02E6089D3A0122E6CF8B71CB2DD416D0CDD875CED1B8DD5CE82400F89982F347D4FA9675E1409DF4457132FBE7101BA234AE78A50551232B7076313B829F5AD2EBD5B242C96ECA87400968C37634C7494B5B67758799292B506A8185D8E4F1FF192B6796A6C8DEE4394A587A9DC1E54D506A739FB1B4B5C1C9F40214295C7483E70000000000071119202B32",
     ""),
    ("mu",
     "AB91B7E5147480E76FC881FB84BDCDFB6A20504B047FBC8ED50C3FBDFD8E970473EDCCBB26056DF6EEE04B7388E42BDCBAB073CBA3C4A5662ADB53BBAF0D07CBE11067DB4E1A136FE347103351DC345176A70F48A084D576ECD9C477B3124EF684C62115D69DF8CD5597920FE2C87403A7DF0204A4E467083A66207AB28D10DCF602ADB7EF2BDCA9E67CF0D253864380F0AA0ACC67E039BD9B7B62A3A4DA762DEE1083A354375712037E3C19DF713DD18AEC93FEA7DA09CD2775EC58AF3199A49D7BF5EF414F5032627A132CD7A91EA5C4A370A38C65FED7125A83C35EC2DB33DAA580ED2957933ABB5593C7170DE795B882A08A4BDF881E63934920033F79618ECD1EDAE39506FE06503001B355E6B4AB31D6B126888EAA1394ED6187F8E101334C87E5AB3FD958DB60E7DB6E9E13E390ED7C7F9DBFEE688E936CC188BDC62AB8C3F8394BCFBD6F5621EF6372D40B142517129C260C231942FE43B088B1AD7503F119E19BAE04C3A91128BB74FCF29562EACBD0B0E1D153343058A101A1E74F77859E8A2ABAA3B2F6D6E5E8EC9EF0B2587780C2C029BC130932EF5968BA4FC63A5839CC573D7EF24917D30D8CFCFEE908C379724A2389ED1FC67B3D55EA4A48A768027E22837FC5D004EDC41715F89FC19EC37D60BB38C7F74C14D1E483B5CD44B16B604AE43A128F4C088D3776DF65BC75A2A3482FF2A077C5F72DD7D569A7699B3262251A67FE907401262F1E8BC00A80B4D6698BA8BD5F88A6E3ED0BD667D4212B95CD77E0989B963A073EEDD6B6E346C4373F6ABACC7BC877FD17BCB2234B0BB0CD2EAD595FC8203579865C79714AD00A1DE9BAD7A7D20086EB0A7856FDA69B05C64D49B5A4CF597DA34BB58919138875F6D90D96B48E871711C5178B00CE7BA5A9CD1F772557F99D55E772AA8DB4E50277A099E8F00C472524353F33EA7E6163C2D0FB38DEB05AE6A39D51907D842FDB6119DE14888FE32274B6EA77B267260A0366AA292FB684F7A5640012F3EECC2A0E1E5C54BE3A229701FD5A43CF05D6DDB299DF2E93C446F1E2E5477961F018A50A1149F8924C046606410D381B6FC3FB28F1DD7607959D454C904A8329A01A528F0A8E9A96749C37703E70F1D973DB7B18268F0F503B816F0BFE64D57283337CD31326A9E765454641ED38943D89F70CFDE11D374EC06F13535A6174B38637441B96C7B89BDD7F3194F1CF9D0BFD6F44F64BB44E9D6186D74678E808D066972D4D5D1D448F3BB4BA82A31DFF97AFE9E07A3FADE9DF7302DD89C7A1B44DAE84FFA829A0660B5F3CECFF44855ADAFDC5F59AF9C720072C2C7D19B1D4C2D08F5D256DDA18A16F79899EB7285B509FE4E0CD2FC9AB556B3D62AC8FC1B8C2652310E491D735E2B6658963290B2D1A2CD8938283A3FCD88669A6876EF63BCE1A5CDF34A0DD3F1ADCEF571DF86D4A9E05EDD6A67993278989BEC7C520195FA9B4CF355D9ACC24316D2C8F185D6CBD45B613D75514B6B26BF434DC2FBBC58E74B124429089E069F35755A4763C0F90A1B049A4024558525AB649422DE1FD9308BA71FF381413FD07111CBA91CC71AB52C58B91A1C92038B9F04718F03B63D93270510F62AAB641D48B63A4130BF843F57F234054FFEB93FC2A51BFF5F917FA7A98D35E84D2F5C8931971ACCB94A3D427388139164AC72FD01487B90451B9612DDF65D20209F81E08A986857E210CB89D490C6C6BAC258A896EBD30607906571D039CDAADD2062EEF2456100115E8F40DB7DB1CD4CCD3D49AC95AED8533E4170F22354D1B72FDE9110534AD4B16522224EBC992DA129207F6CAE89DD74B096DD4E9C92D3DE7C5BA79F3D08E6A031BECA6E730E84E952D5AB495438AFF4B462E61875E9C77B80D39A20B1BEF4133EC836F6ED54FAB6D4BA35E89102A5FC233F2CF21AF5B41AF8F2B524C6FF909BCEC97057AB0E65046177EF1A90E686199DC47ACED496EF2178E8D7F317330313614B18C41101FC94D51FF88CCFBA43C1C44F406C40447BD22DDFD55403D81EEA7F903E6974255B868C20D1B93690D21C502516E4026CF7C2AF1AAB12C00B52A3262E42B2314BB64A049D6963C70F3070228F25D7309F585C1597C44B15E30D0408607891F02293A0EF8DF0C734F0DD76AD5B230682703BD1AB7539129A15D4A5720A2E5A4CE692EEE353A1A7A4D8D02746BF2067D23A5608F189398EF01665183A658BF1B6F11DDA39B2C2139E4622CFF5BA6B75C5F6192C0281E3A3D929CF63C3662E108D87A0F92FAE596D79CDA6309B882BBDB44C11A1FB44A19DB1DEE0BD10D1B3A4F73A5431C27D7EE3165E8F0BE5EB99681E9A7E2788FA39C0433692D51A911A2CBF3A9D77001B5786F8B349896C8CA0FE62B4B74F30FB0A9977A46D728544D83CEE1BF6E74DB3AA8ED0145040BB0522A72306DC2BA6D5E7A536E0F22C52B18A02967F76B99690BB5BE731F0B1628B2EB497A54F3FC1C11C38FDDB452C99764FBD0978107C11F545272F5DAD357EC04A286AD6E3C9CA8D8B61A1B4459DD6CA3C52B6089D520A95AEE06BD7E7A6B9135E1E318CA6AB08F6147BEF02CA7524B54AD3117167F6FE579608F70BBA926C435AC3C46A76D021A7E5004871E0AA0FD27D746C7AF7CA51A1BCBFD9ABA32209FBEE93F8A4EB52F51CED5A5D57F3E240201A193B498BE1CB819DCFBAB1C89F59D2CC2C9C0BBA32A4287E14B197DFCB5AFA47B461D86DAC66F6CD7435DE46A244086DC50705F06E8328C18484390F241E9E000CD",
     "83A5C5803A966BED32D3E5089ACBF0907D5121AA450C1DB35BDEF46CD468091CD47F88C99DD8AAD05C2D5E221B0C24508889C54692338D0B6F6259E467C81B90",
     "5B66B33DE29FC1CC0ACD303991FB349046A15382139D2C918445AFB93DF1A297DD4C9AF18F1291A3FC151FA852099AFF3DC17999659F7F64E1985852C34FB0C699FB9D3EA833B5E3832CD86275CF071B35389A9AF4FF8F13FE9A478A6A49AA4FC346FD3ED0BF1A97AD6D5A00D61EBDEB7C204C169B61600741DF48FD043F03A31C4893B5EBC95626E2DA617741830F633BD8A822ECE9FA1F411A9600AD75664810F298A6A269009D6ECF02799128765EA57EEFA7D59E60204B0CF2312192CA381F4BBD8AFED362E840B47F6FFAE816DBF2EF49CB5C57B3C0874FB64CEF895143F9E18BC06888644940A7BC315C4CEC3A96A9F2979FF139F11C198B5CDFDDC40BDC4D5386B02A377AC4BA2542221A17299DF76BC1D1F8E4469A3F1C3AE7DB515E146FB66F3BB5D0853DD0ECB23AE5BD23EC6E7B7AFFFC44273987A1F8AD21D06699C1C3B9A0495AC703CCE328D02854677CD3701D4EA7423429C7FFB725CC244835E2683BA78FCC69D21340F282F87A07A89026CB25270979F9ADD4F4661AB53EDBD5DA022F4CC5506B4E1958F9E678F088CA858006EFFD6B81C40963BFB239B5BF6FB82F5F5F8036BC4841E7C82171510DA5DE7B3215072E7453B3B11BC38BB5C06519746FF403142E8206D22545A4A202EFA967D993685AF57D3326274725BB45BFEF98112C795BFEBE252EDE6629ECE606E1D2CC3A11C277AE7BBE3F58978450A4644D561C2D5AABEF9945AFC48D207AF0A6B75D97A4D2CE359A2CFD48A48D0DE0B289C2EF0ED0678F430660A73343457252D1CD50A3DB535781574E32B853A4371EC59DFB4B9F6C032D760F9C34E9C645A801F8B32CF9EE3F2E2503037A4C89F656F2455B805A29FD6884D09721594107A02CD2C4AC4141D95A064CE7D57237CC9DACF6CBA3D00E1E89FD7411898FDEE5AA96A46188A4CFA8C7732473C95A7F897DC8C134DA631E0D4DF970B4BCB0B187EF3391E7A283B6AA09C780130238607780CABAF854EB4AAA72F6528452D83B3A495BA54E2FD54756B085BB8BB88CD95FAC109E773F6504CDA3AA638F932EA947A069A4D2085F9FB50C847FCA16E3251F9FD486CFB061C55853EDEEA3960B65A8769D10C236D8559B0AC15651B6C7A14171FEBDDCFD4C1A479158B55EEF3A33CD225F215502ABEC6C26C7038B42E43FCEE0E1BB2EB9A500AFBD7EBBCB3F5C4F2DCD9F4E398C7F5F5979177DB9B30583E88BA806855AC7FA59EC87EACFB70BA1C8CC267939DA4D7698B00E5BACA1CE87A4F214B5BEBE78D36A093B345486F704FB796C5B843792B4BF590F17ED19F775D03244C942875DF30F1B76735FB3C9B5FE8C3CDF7146834E1ADD81C50851F0D1B7BC962F54B9FADE497A3E41ED27E7F4BD352564F2F1E3F2F82141A6AF1E94472DAED473ACBD33DB912C923505EF9D24F07AA77D609592E96BD3392E76AA784C80888489D1F5094BD65515235322DEAE56E31CF2A7745E679553F2B5834CD90B537914F92CCD95E2B8B4ACC9C663AA09A57165E9D2B244D98E838FB186047CC1830C40F0AA4B6529480A83A98BC5FD97543D9083881AE6314B72351327356D07524580365E95D38A8F4DBA9210BF6DDC7B16AD1BB27266D06746EA99BED407F9C24322F07880D4BFBF42218F74AFC00EA84159FC05AAD6C9C8A47DD413DBDEF6A7BC5F1FFF431433631EB1C3DC5E15EC01B25D8A6258322871BF469592112A9A91894CD5700A1462345FCCF60A9E68066809C4DE432A041C442882E376A09389E3AE5FF7459D3D8454CAF41069B7B29372412B7649A81BED82CFE97AEA22C95A9705C89DA3846396B8070C2E785A5941D305A76495BFBDF7F4805252F676B9D117B7F0DB69C142E22E9B4FADB0215F90A9F460A0B093D091996707F2C8BAB1392A29EA5EEFB7513E86BE46AACD5B7710E0175603C1E5B8801CE5E7F73FAA5DCCE160DE2BCD3CE7B7F27FB00E8DA8534CA8F3799340BF2B59C65D658F9A695CEBC3CD2A42E6D41B310434508B80BBB353D52504A78E16E554887D652A4CCCE6B7F55BCC1FD025AF91F750C5479142EA94342E2BBDAECA1B77D94FEFB7CE07CFCA06CF4DF7AE3BCDC6857977C0A0D444193A1106B9517CCF3FAB90A316990CDAB328423F0F041777CE90E9EE5AC565C4691391EFF4E967421546B4C8F0EC0DD36D59457DCDA7DE628DA4961645FD0C46C12D9374F59DB38A63D86ADC14E8C235D23B99AE123077844A8C9D94E739E6D52A0881935CB8AE14E9AF20C2DA62D0FA3A278F26E7169289369D518A2F9CE98604BB622EBED557568BFE6AA960DA348387BA272C837B1A145E3D423B1CC5669532B8CAC7683D4B21D3FC4D9A02FC3970C027A283DECFFE5CD69E1D77799E935176A0F752B4AB0DEF4D2A9937F6CFBDE24D73CA5FC918097591908DDA900BDFE69D7CE07FCB8F66A4482F2548D821DD9AD130F489C395C7506F4E92D031F5ACFC731D132ADA97F007D49685280773A1F4F703E240089A7A1943F4DCD4A7651C0C9A4831B773C604B05AF1AF1509016152000F1ED3CC8A8C40F766CEE2B78F5E08F3DB28CAABF9E337409183E92A4E10EE3B15F7E038D54CB47524CCD1E916838E0CEC7020608F1706ECB879F6C7098E26C12E9F40725E761396672A35D7D8D660D180182772126EDD95883AC9ED561C9E616886D8AF741C5185F2D08944ADF112D21EFB8823ECDF41775F35C50EB04FDB02F56407355A54E3948B6AF49896FBEAA3BE5D6237B32C50AFACBCCF0D65332BB0E2845DC2D576F8D44EE633D30E9B0779A03BC876098DD1960F504ABF11B1C144F91E35BB3F2AECD0A7A8023CE40C7BDF5198E89AAC18EAF3C25D660F0FA51B33161FB687FF66F779173FA91F5888C440F4A95B84158C82B7E4927F2AEFD1DFBB0425D3EEE036C8D7F5C418187DCBD20A5CB9C07BC56496C24A9F6BCCDA486EF4B19E62270B5DB0AC0DC087E17AAFDC2E27AACC1E291B55F269C9AB2820539A215D6617D44F25627CD4ACB0B5228C6F18DDD05A28009C81A4B0E5DFF8C41B3867D5D82D4593FF50E492E4F1A752106A37C5183FCB508BA558C64CDDEE031A5A5026E63047480BF54940D9B11888A72C73C71BBA82D599FCBD9AB10B033D9AC3035C6FAA75C0E58F29A930CA0B2C50EC9E3831B3181B50D07FE79A9A7E9A33D2E69BF22A5AA6882B296508B6940800697967606CD2BD28EE498809AD0677A255943E5B14016D13FB81A39ED1023B2E0FBC85C4C533C36A495D79DA88DD5888F5BFC63BED71BAEB8D5DC6F5893B88D728AFA8A0C3F6F93DD796092CA079F1A1E69D398D13A23066AFD585B4B92483A1134577C410ACB4770D8800D97DEFAD5BC0E5B3F7C67A27114992A14F62672A0537C8CF7DEAA2D874333370F4EE4620CA2C22E42F25D67898AB2672167D6F1C9066CF420E07184C0969026E1285559F73225D33CD50078F65DA39DA20A091E47C71B6B6B51D7E18332E116237505377BCBA3246D7D890643237F1969AE3C3423936A9294C2A92C5E1AB1C692E16D4B7451AC2B8C6094DE4F94A15BDDD3266127B144135E81FDECB446E47AB19E17A22CAF85DC2F234140B9DF112A40BB2FE16C474007420BF59F053C4DA7B6D6A15FABF1CE112C2484634C5E8484960FBBCC0B88CB642D94185B75A8972CC1A4CECB6D4F7FA6FF5595468A40A22FD9B3FF14C94691515230D68D7BD98FE8AF48A2A4F72E4C74727F117B0C3D0A54FB207B3ED8D16A0AA3C68C4EAC49CC329842D0BDB3347BD651F8614502CCC7AE12AB51B83A8E375FFFE3FC88F8D81AC12C468A0E34942514591F7704D24900F50686EFF2330FAC3A97F752ACED2162A613DD31F5F549CA311843B3E20733C2014065360BE4391B006295A9537B04C0F03B29409AB6DC4D109C41C9DCE259A0C2F951C6ED6EA442C3B6056F747707A75A2E711A84A3DB11A0F93C9B39CE0071E76B26478FAC3895D5C6ED1A0A25F2AD4461E5E9A7B223C21E05367DBB3951518BBD0796991C48B31D3E4868DCC2273C3D0C860B37E5216C3CCC34965C18B7BD9D826CB47866F0060707E18D3BF75CB76FA687D089CF9017C53E45A341A9CDF4B9F7F0BA1249B807415DEABD7B5AD5906CE5257CEAAD0810CE82A5249ABDFCD49F57D5568927E8630BA26BAB9D6BE29237F6F60EC1FE3DB475451516074D022B125D2121EA0019067BAC0AA29E1F8B15459F4BD8859E329B7C369FACEBDC38F5CB4C73542E4F63D6BD8E680AD502ABE045580F644CC3592798380F6954CDE73023AB17C89299B32B99611FB249621B118FCE2095726A64D275E0D3DCB7F202D52113ABF302440EB63B02B6A8D83B26DF8A64AEC74E6572235B6FF20BF18A74D1D69073340F7D210F8D93CE9EA95A6E2E0CF479BCAE72A02801211E550CA6CB6471358D3BD1A72F43E81D1151701BBB5463A9E82322E82FEFF21D0524DBDCDC87EDB008B265A9819F7CD2557E322B26EF56E7B644442062AA03DE202D1C2E932BA43DDE3AF7E37A8BF1592E1AF72F2DAFE22277FFB9A0A0D2ED657F21A39F94150E06CE0DFC32D8B33426A9D848F2CDB06DD65054FF4AA1C3C5E07A5D5FAC6C5408863B4B6FAE8E31B334080FB0E70858B5F758BD4283741466E7CACAD395374787AC01B4474757AD60000000000000000000000000000000000000000000005090D151B21",
     ""),
    ("mu",
     "CBD6EFD4C8788DA76804E563A4B95BABC547772CD61785175C046D20BB0A9670C258FD5DDA41508C903567DA91F47008E439639998167827C9B56655FDCEA0B57AC382FB60335BCC9DF720A427D8825FE33CD50715928D9E6549B86F69B2EB1A7F12318A83DD5F147FFF753CC26E1EA08DC7310F7765E2666B2938B4F6604B259E0354AB2580424B31692CF7E66CDA6A80420E96A8BCF51131B2AD33F9389CB213A7515A5CC3191B4DACF3C1904E7DCE64E6BB6C19D848E4BF2B658E0FE2011DEC7E5FD3B7F15AB7107FD09B4F4AEA784211D3E0E59930E9B5F8EBD09559554E438A0C6CC17893A0E3E863AE9424FC2DA8615F7DAC65F991BF5DD31DB120A867E3B7D8F0762F80EE03641BAB90FBDA800BD88F06491F5C01CD89D5F3A58251CD9A4B11AF665B585607684EF83C844EB8753096BBA500BFF6E7AA25E6407CDDBCEF1195E4F6553F117B216A824CAA1D34488A8C16EF83DD27CF5D7C36D42177B82016ED2FB4312D3A21EF3EBC2E71554DFDBACE6F8B9BFBE9BE7CC3EEC5DF513EC959CB34540278B7C051D4F252035BFF21FF314A856824F9E9A350CAC8C64AF8BD7CB9F1C02F9721A5FDF5FEF9D93494FED33714C6B8CDAF2B5B57F83E8A6B2FE4F6AA23E2250ADA84CE239046EF834F1C919D92B6E1ADBF96157B8B032C82F37640C1E1A07F54D517A4F569206279D34BF7CAED551368EF293C913D40AA21C0A5055C85ABE1EC14BF18CDBE10FA88C2B68F7EF30AEFA9F3333FCA7734AA18C64867D6989C2FBD56EA183B9F100C12C18ADEC9183F6A50EF56A1C548E5319E2E590928D3C0DEA996EB17B0555CB45A55B36CC9F2498881D5C8ACE4B4F387EEBD0E7A36A7275D347501AE23FA59CABD824F4FE386B127220E4FBF361272E0BD7F94AE1325C26A0221B3FD8F35B5A7C1D2C2B35A0386A3A77F373AFDFEAF544FEC5DF178554BD061722524CEC12F408F040233A63E7CD8D3E2C2CCA154A5DFABB81C0E69D0ED3A1F63A35BEF03976231A20B0E90C150E79D9B79C8F4E1928E461FB610B4AB99D87C661FAAA4EAB6AF108EF60489CE1891AEEF0DAAF0A5F56FE893627509BD5BBC14899F6A494B164A0377DB8AB9B097E78297AF0870AA31CE7F84DB9B2E4C6937E2C39FBF85AA7A0B17668A5DE53634B4584A778D2B284F2265D425C2DB67FD1AF6E0C8BA84111FC8EDB533E7AB3BB508A889C67FEEB81A79401319749AE6D4B344E6A7429ACD706A6E44BA9CC72DC2408FA129F2DEAACFD3A2BE640C2044B6485B37F75D12CEDC640F37F5974756D902814C26D2687DB41A6FEEE55BE445E7A2752D813BFAEC4FA4FED15099999EE36AA89EA735F82E6D9008483121BA962A20FD03B21CE4A89EB77453D8EB78773FC6FA1A07ADEF7D8648E297C4A924D42B3D2C81462ABEDD4ED6E75BA5451C6773E3F9CBC6CF26676B9E310064E2BEE831CD92CF2D470013265F28B988676236423E3F8577ADB27F7DCB2382095CE776BBD3B9929EE5867EB7E739004050CD29BFE9D8D3A9710B4EF0CE3A2C093BAFAA37CCB328BEDEB9613083542253FB11986FBFB26AB999B5B9ECB28B03FCBFE5624F5DF6EF0EBBD7F11142C5BFB8025F099509F928510986B979233AB2555246FA90BE358F85C2120925CDE1F9E6CF73387EE0C488C9EAB8D02872A26A33C2E2B9DFDEADA3902372B2666F542834B9E1F01370BB2484297EB3D878F560585413F7BFCC891A3D539541C42B8AF4184B68F3D649BEF5820919E5141131AD0EE6E1D885649E26A73113FDE1DAC31C246D2D64760D0D0127E5474FFF6A56F17277E8CCD32D8464602987541FE0D1591EACD343EEBCA429DDBA4B7F1D3C73430B675DCF6716BB409CD5F86748D5EB6713C5862F07C042E514704392D4BF22B8B01DFBE6CAF0CC1F1F22F894B71C6E73E4CC7D7F6EA83E4493834CA9CEE5A7B35705615DE966881EAE96A79879266B7720F45E0FADDEED3DCE8C4722F96CBD6EE5494E105A2E969D69F06F7FD4FBD438602B6F1C8D3FFCB72104D5400DEEA9B44E1904A91305ADDA0B53182153A14248847AC28111D0B2A3114299BC3BAFAA796BBFA7F00AA952C1B38D6518E1744A473D349661B067CF7772269C4CB875A2F7975202E915B20B16B29E947B266988CAFD701C695074DE8D4A1AFA385161DA32447E419BB6CFCB1A424569C1B885FA4A07F0FC3E7990D4C104DE4B0B6F615CA8512F748AEB20992E87B51470595665B6ABCE1AC55E3A07DDA272D5BA60B09E7F490E82E4F1CC8522023A8890493F4DCBD4FC6D34CBF5403CA65F2FB7224086F2CBB7AE28D6C5DF9BD1A99121928C3419E48F51265EC6978AFA121DE9EFD82A71A73C6B2C0C52F80A93CADA0856932145A14D1010FBAE457CBFB8E1C83F6F85B3C3AD59E0C763ED15A1EAD442207F4DEC0092DBDD409CDC6C0E7F524DF2AB45CF24AC6451FDC9BF5EA2AC933AF89C4C3D9A89CCC3F7631865764493BEF9AB5A301121C6005FA7A7171E5EAFA34D6FF854DEE3017AE58620E1B407FB3040A3568D653A0AC3229106788D6D588D832614E7D38F3E0B5926F21489AE9C656150CE45758A108D2DE9BB1763FEEC7E942ED9E4AEF053D5A6EA108FB5C26793ABF957FCFB7331F11156CFC3D72A412B6DA853935B4EC07BC0EA89DCCC6FB7BBD36321AEA9E85FDCDD8F82D0781364CAD77000C21D289A119BA9F2F24644CCE854CA50661E1AF246C1103360E4649EC215AFD18485E3CCD68B004CD89711CC410D3BC354",
     "436953A6FBB1F350BD784C9D7F6A23316EE3232D71F3CD35884072AC8623A38BEBA2617FFBE16A807D4D12716311785921D387A6516121A5E94E876631709DCF",
     "0407EA83481B3D9DF552E9EE6297A4A23ECE4CA4EBDFDC245E074FCC6554B7FE20CEFFE3F866AD07F4CBB70F6B1B31F0373DC6E945973A241AE6B892FE7AAF72372CB0F9A8CFF989766C58672531CAB400A14036FA2F556DB5C01D1577B94B2E266A9CB70327A0613B92EA5959046DC88835E1FDCB10EA83DC91559A5BB10FE09AB833463B39095FCCFD8B9A205FBB86A7996705D628A6761BDFE6773C669B58ED67A2670B700415066D67396839D6994E04AF88BE6301B3145E1B3CDC72F936F60115DA44CC1736EBEADF186ED11ADA080BD4DC01E03580914D9B71330E504160F0C2D82580645C7F2602E6C002A3D0DC26D0BA5287E60EE32E9D17D8E60EBB783EA04BC6B30F371E522DA31EB6367F1E00174A3F99BB9BB5CA104F05862F5E0574097C17138A719CA17FC8EE236C74BF3CA9EB9AF5AE0ECFACA4EFFDC4D96EF66CDACDC8318A98B462925AEB29E75DA8D8F6BAA5A9433D5BBF664F94B42A4BA9D91EBEC88EE2107FAAE7A9E82574055E62E83D4E36ABFDAA0F58392923217C00A4D18248D625C81E79DE992605ADDA0539B8EC5DAA7CFB50C1218E8FE4853CA280DB2D74B10C526BEF392CB6E660740EB456C9F5E15B38F9B35302138B1191B7330D36BC292F4A48C20E4FB783F5D93F765DB2092BCB9678823650626175C2A36B8B58D1E46171BD123BD64956DBF183F9C0831CBFCA5725F0D9C8F9170C3FDB6BF37CB2E8ECAF1B473A93B6A986DE3469B384C87B4CF541BDEC2C4C835029B31C10F421FA7A906B561FAAE307E4BC06148C774A18ECF690A8A43F769B437E5133932CC1468B3F07D4DAD4C8BB8122005C4B9D15215BD7143AFD56DBF2B5795D4CFCCD75BC53202318822E57857FAE8D74EBF2D0B8D6F08042C32254F6C88673065F0577BE906767D9CD665CE331EF127C2F73A5F5101C7DD4E8D8E7B9CA5C319ECC2499C8B5C1B5E5FB7C32D279BA99B2CD0F69FD4742802DABD7D1631DFD2B76139EC824CF3DC6A37F68223238B847E8CD0E04306509DB228B5070B47F277227D4EB0F15092625C99EE704B607F305E3CB68C511DA9B574D68103D1F3224C0A1FEC307C4782156FF098EB5BA76F0CD29494E5C743DC8AC417572D65BD017FC229C27821FD9BA86D72F69638E61DF6D1C3438B51AEE86F063EFEA5D050E00BDFC962200AF86C51F7F23DDCAA0EA3C111FA787259E84DB818C2B642DBC9F9C6C5863B4A446504F83EA31A680642574C80812BFDFCC0B1FCF6D779B94F59C4B97ED557A102D344D8D32D5C247409A85ADA3D9873A8E94F6426DD451C0399F24D1874D671D6393BC9A7B8F1D0BE9F5A58EF441E0CDAE74AC10290DCD3298EF0AD41163CE9F4F9E6A1F8871E3D02C91E35667638743162FF1660FF5AAE95EA124FAF190047A933A28BD195166C77B6BCB0C3927AA361B59D22337EDEC3CB67DADB719247AA12A5BC0E92326A4C01B3552E3C31F22326FF1D323149D491B154A3A035D698E01BB0244509AF670B2D83D074183EC81690B24F4E9E729444FAEBA8711CB2285825934B08D556F3DB83817F56C75FB51561F24924F6D34A6A3D0A6AB26E530E7CE0F297D968D5BD3148FCF6CCFBE155296EB9F244F7C0ED9BDAB196BB05CA0193F342091E1BD026A38063D187B7E4F658488FDF94B5E52BDF7A5713C2F84CE713FDB2378D2E4612DDD6D3CFCBC1025DA7D0125316B6E6EAE98EC40834AFF21EBC6E05152B1A7A5A3C73F984FEE5BF5261BBA91F385938F22348D7686C254CDBBFBD0F6D646379210EDDAD1BAD7C4432BFF1F5C28BFA78EBDC1F3D51D67542B7348C2A2CED8AB4889B755200B24A1C022E3461BECC301A9EA9CAB32B061F3F9A57589BFC580AB9F7B6099B57F84D7FBE0446C5856F91A6F0109BEFFB5D1294A1C888357C1E8FFB8EF92D21C284AF581B179263F59AB4DF3F03C37A1102986A5D22EFAE9303336CECCF1DF52D59CBF75C331ED037BB50C62EF78C5005DD3E785F3CCE3F3CDA4872F3C2CAF36A7860A92C67B7BE73180D0006E151F0EBBB29088483E7B1E3FC667E14760FC87F53C57D884151BF4FA910BF4C2F98D6820498A41C0BC3EC3598694F7957A265F388D258DADEB36C196807732967746708E3B75FC69AEC2AC4A7534CFAABBC0EEE008CD2AD4CCC32130976B8C90E3A34D6AD96BE8A3BCE3DD39B1C64CA90B41B68D9C57A8AAF10B018A2D4EE60D9784CD827AC52477C08C115AE50C7D03D3CA79B4591C96A292CA64F3B2AE8F0587F2C18B42BC4A9A230155489F2D0C15942B6C5131ACBD18D06BA0D833D1904B99A16DB8E9E2CF9E805FCE411B91F4A676D6E656691623333A6FF86B6C689D7AA6C1693E0FAAD9037EBA94284318FD58BA39EFA257346CCFD6070A3065C0392C3D923D705C64E1DD6CF47E01F843275230DEBBF34B8A25BE6F8752B433912DC4B14C060AE07139286BA2CCAAE73444ABD8F35EBC4CD663437D2614484D1CBB9C5A17B092172AC0AC48D865F98A4811ED58B3EE661FD8DBD2B61123383A3CA8B2C3CAD9BAF5B90657EF72E9E1AA66796012C01141A2925B4D61FB2C9D7DEA9F8743ACA09BB27B4BA25FEDBE2F1ECDA6FCCD1557B894BCA6CBD639CA44330BF401BDD9D35918CAD22B06B5F4017892E139C10541382EB107924B35459301E3C7AD23A989F6155C182FB6759DB222862664A4E41395EE345D14C917D39E4A34146480EEFDAEB62972CEAC3394058D276B003AD3038908E9A18688E81A431E4358210315A09DFFD37F27924AC9B2C975B710343F8C2A6195F729D42AE34F7D0E0EF9E56FE236397D00AE1D212798B8F8818AF131D6DED26940126BFC87221A23DCCA0A55D4DD6DA32998C87063A8EA0724B6F6AD4ECFF4815C8E7FA6D72B3A5DB989B9F373507CB90C2F4D4684C88F2E29DBB046BFBC4DBEF7F1E31C1F39C6F9E6AD46A5EF8DD3AB6E817DCCFAD3C9B7B9655809BCB9D34F642C50AF4D6DDC420161A4C0DB556218C64EEFBD1267A9AB2C3DF2A6D14DB549E526C0320E3D80AF48CB6ADCAE0772A0CC10F9B727FDC3DCAD51DCCB379AC03E6CD3953F519C73F733DBF4BA61F1453F74EEE95B073B7D6384467A8A11E414AA7B451081504999F473A68BB96658367C64236D714C8958EC4E43F285F02E66ED9B1FE33B75A9CDB595E0B8F857BDF6DF6E52DED14112F625E3F88FBDC648D2E4CD16E2202B74546D268C71DBD6326A38302BD33FA8382E13F7E71D89C2162CC281A92C5B6B376EBC747B1CDEF80C2088338C334A83F62B1264BD0B2CBD60AB4E3EBA422D1012179AAE54A07599D9379C7AA09B05122B557A579296FC5FB84D2A1498B9305A6FDC85F58C07EF3CB7BAF9C255FA62811FCCE5AB428E32E3234BD338B4938DADE8F6117C9656D8ACC09E3573B185559CAED6121075A229BB39E17C6D702A09082DCDE33CEA2E1DFF344EB8A2A4B22B58636B9EDC3AB529DFDE1F688D9254A020104A150EFA66257D0DF98B243F9F3D023B8FC9BB7EA5E73878C3523CA3379EE4601042EFE4AB39748E53F561B31BAA5078CAA5AA0856A153A4F9F9A65A2CD5ADEEFAB14F7D2151149C31515B6ACA57D6C09AAFF13CC0622090AA5DBEF40A7AE47D40F07F7839F5CF96203042570C3547DC4D5CC2829903310C1AEE486FD7B2CE1A4797599695B77590A59DDC9497AEFDF009DB84235C6EA55DD20B2EEDC33DD90352C6168AC3D546CCC13C9184D8FD8A41414DF89496504A6E3BEDF2400B13667072EC6FEEEF459456314E540E6ADF7343EB07495D4F25CA8A23F6B7DAD34718C389CF77419EA1CE5E07059841E49A1B7344ADB5E6EB7536AAB5B1EF5F3ADE63491657ED87DA76C38CC6BC61890BE07187254EC715D4EAF8C4EE274D136A58440C6346AD546C5D0CDF148779AEB2536413D2C634F34CE32AD809933641282AA7AF2A7B49D36B46A9A0CFA90539D399F4025332F10E959056846103023229B3092E6F568C08C44349DEE1D021D13EDCF4F5101C5ACF6A2BE08C987460FAFC976C5D0AA37CA77CE6A50538C277763142F815F0A293948F95CF028D7F4CCA043CAF72BE9C13EBB47A9135B2E325A159606984828269EE693B7965FFF5CCE776416249B47ACBE6EE2263F3F634C56E2D93A4B4227625A0531E4F12B9E2078DFED976BA25F714F6D38D7A9CF53F9D5259529E3DE9E18D2534B9F655867549D60F2FB5BE9638961203DE981A7C5DB732D2E2BFC986B18E334201E8B6D12292AFCF963D1BB97D2DD629E7C9E9E71E3F8E46FCFAEF38FDD5A81F627405C7AB85F984B5DB69BD212F0AA5A8297774BCD38C069F37A0EEFDAF5E6BF29692ECE405184EDC32DCC2A89F338DA0202C63F5402849A289D5D5F4927A3B623A65BC517B43995ACBDB88CDFD82CDE1DA81D82C9A7A10C7542B6EFCB2C9AF69E84E75BE07BCAF27F510F782404411317FC9E1BCA91849BB41BCD7C240B95BDBD5C139B676CBEAA281DDE62C736355CD961B7F52031AED784DA6AD0DD3D20FFE42F93AA0910C0028C01D52D27215377037BDD4F60DEB85C341F4B77317DBE1283A8491573626E01CDB0A00AEEEBFC49928B8CDDF86C4D241F4A036E2E8F709F2D07755637D81BCBFCAD50414353960646F798FA8CA01186C9AA9C32F374AE0F1F800263268809713CBF0FA00000000000000000000000000000813191F2529",
     ""),
    ("internal",
     "7FEA36137FE011EC6BB71A1A9BB0F3A2AE2AA414133053F76C777E359D0911C1C4EF431D15A57E919EE6F13CFA579E3CF1044FA6FDC2C6B539EF9DAF6DDD922349A275979912DBD2E09EA2DF4C217FEADF39F3E5F1FD52D97DE2984AF6CEC388148C6EED765BDD846D2DA4344F923B542005D386063D4C0F9D7F1855CADDE685D701204E3BA899918FAFD322A8E7840A48C7F7DCCA1BFCAA19600C3D11D56451AA1E63ABD9E6AE7D495243744D68E6BF24D42D9B47BEF7662DA9FA1681F19562F9F12E0529902502F74B44846B7BA5E261C6EA4BD97292E30A531F55DE4605769124CDF8A91A47BAC7F5067EEFA4BAA44DD1AC7526089DC1F43D5F2CF7D1A79699D2DBF40ED93F2641492C1D901BC4F40ABFDAD4407B7E8C8523397994DC7AB3B580256665859E523FF64143157754EBFA0C82B8F4344C5E3126D322A6AE0B6B44928DE4A190B8E8087B989EA2C7F7E55F78737E22DAB30FE3663DDAD27AB9C611B5E5A40262418EE174A5D6FE078AA0CBAE0E29C176B221302D294FAA4750DF45ED0C87405BDD085B36E65738099E0F4555BD1E7BD935EEEBB2A5D9F0CEAE357423E12ED2B2EF78C3432C04DBC0893132566E636FEC6567A4910338FDC9A158DC2284233E8A90421BAA2D472BAA8B9D50BF0102CB7D8FD3C857B8496083CDAC40B5C90A2ADF637F3CD7C1959FCDB2E5305500CB7C0216B7439DE009713AF39B36BF1CD1BBB24C07E577B589A08B602717A5DDC456960C3B4D3E79A9A48BB8F7CBC69C0A0D2F4A728213566283F4DA8D57E1D60AD64D434FB671966049FB5FE56BF087B40B9CB6857A7CDCA52F8AFBDF15EF7AC8E7F51B5586F7BBBFEDE8BA97EE68CF5943C177709D2EC308D882EEE5AA0C883002E2A6923740B125C3332329C720BA06BCEC3F42D5631851EA687FFD120D7446033A702A1FA9F205D7EFC6A058A50AFD207933EC4CFBC114942EBCE5B8A5E6B6793487A0890FE56B4050711B0FA222F9D77239AD2C2A9A6546A8CE2C01B226A7CA24F1AF9787A2A922D2203CC397C65A087FC835E1ADCE525ECA8734073440A91184B9E79F5252894B5C1945AC25D56A034148BCFB27FBFD5AFFBC7CCD13EEE2AAFD1A409A376B8316CF45E4C75962D5673975202A2AD53640D3F8D7233FB6AB35CAD418C962CD155895613A0BE541168E2597A6033C0B95310A47CA7CA84719557EA9512C2681E796EFAF228B867F444E09A6A95B2031CD1ADE9BEA1B161419FDFE93B5E448595853B493927ACC7125D6D628A3D5B235F55A19FAF38FCD45B401BBEC9EFD4FEB08A8060DD19FF8ADA993BC74D4E454A698A9EF5FD55506526BD29EDD5BCDFB6C3B45F53B7606EC8562310039EF0CBCBFBE9BABD1BCBE70B553AA12BCBD3E645975D7ACBB6ACB8B79462BAC694186F017EA92F3F9076B36EF2BBECC01EF42C26336DDF48EFCE6E5DF2DEF30CF8AAFE62546257BF0AE65EFCCCD063D5992FE69F256FF615D9F19EBE667BCDA1D0D13B52EB4A0F59273ABC70A9C0B3D63A8EED3BCC53C1DF7D522777E432C7DA727461E3A58CAC496BADA599C41261F7F96523534530A33C40C6633ED4D9B01255BCAA6BCBE2EB94444FF092E3F91A65D2BD034BEEBE09480742CBD4ADFD935781E76C98C3B2F57521C8CA16A0E8F060378A4A4E09B65E6D211A4646C80E0F9DEFFA6CE4F7BAAC44BC0210573A5F0B9FC33D0AEEA8018B79E3B2EE69CFABC24737A62886C26E93A0EC7B8700AF1057681517CE40F0E260B4874419584F5D186AB54BA61378B4CAEBDE6BBFC05B2E0C26E735067979782EF9D229E96260D474093DA512C2883F824915192B00EE7750BAB99FDCE3B4ACD8BB0164F6DF8D96A4AD16EE661E5A79A3AF7CF529549C1F8FBFF487D37972F8F5BEB1646FC05795BCCBE88CBFD1AA20F1B00BF52902C087EA0717A8B41720CCAB213C673E6C0397B5F1F415C63A044E4F44511E2395EFD3BBE170C82E9941502DD29C43D0CA1D7B23280A065D68E0BE0C9F847530854216FD31D55C41D8AA82D74F5AB24D602F37A3F8DEBD91089073E8AEF6D724E55BDCCA2B495CD3E3C0DBEEFD4D9683493E3FB226A7382653BFFCE3141681FFEF4DA7A887E9E7424DBCD99E9E3D9EE26E287827C91C71BE229829DF663C09401A8B7A55A532A587B0B738ADDF65D8AD257D0A59CFEEC908A772492DCB479850F8CB46E310E2EF2E726B322D4C03E31C83E1090040E9A2CAFB82EBEA1FF78F847D86E5E3C57D9F51C767CBA91DAEF335FA718F1E0684D20B62A9B47EB0EA50118FBA7E266549A08A20E6F8B8A2FAA8786BFA49669AFE91D12001DD7137F77EC19A12574DDDA4E416CD08A42F8DCF77A1EA2155148B5336594258B7EA8555C1A1FBD2CDF2D84FE73968B48528D352080BD031C01A61512802ABFCB7332F445DA5E84D4890D3235D8AED85A2511742CCF482661AC4AD5AC8956D96784BCA2752EBE255DD7F9B16765638DDE36BD2948D21DC228D8C668897D68A097E83ECCAAA7EEBF4ED9262D151E2E374F5EDB0E540A27582A9A84A891C641679A74558B405CDB3C525462F0946B2F35F09D49329A34860A7299E278506F8602BF2711845B7F4094DD99FB92ABB123682331C3BAE71C65B47631740B786EF1A67E8CDB85B62FC548D27DDD9BD3468436700D2CBAA68C52FF0D9E762082E9FCA851924ED19DEAE071938FCD3DA6B7746F2F803450100DE667225D3DDCC3730EA5E129E9E2CEA81373D5AE89B1E3800507765AF8061E",
     "561E787BB0FE38247F609DB3E95C4310F03335D31425461FE153C262A758DF48E43709B848310E04BA2D184ED795048447326D2A430FA560D7C1ADBF03F35297AF7448EDE08B425E5D78E2B9861EE08F12C556F9EF8FBD2D25EA448B906C7C9DE79E6DB72417499E2B5DB9003CCB4B1C4D3D2B7F913A361D2C6D042A296EBB17791F84D13A2ECC3E45E73326ACEA9B2A156EFA4B83F5BD6C70A8E6F1558F865F8365EAD7F5608A4789AE754EA6A6C5125F5AB9AFCE3F7C63F77932C47656ECBB36DACC71FCFA84CE1EC88BFF59B4E6A26C5C47424ABC3950D7E7D1792FA81015AECF028D49326FA69C036C0890534AC9F2616D866B9B8A396716A36CA020D28AD01C53A47DD903DAE3B2DDD4F5A1677A5372990132E131027380664D0C52597AD861AAF7CE9E3C8C629F689D9DFDB9CE63AFBEFA9AAAEC7A142242B96666794B4F7BD2AF70CA2A126C34AB1E5C4624B63ACCB3859DA9F5AA111AC2F9B0A8C10EBEC4E3C1B4F49B16355CA39055FD95D61BF3622775380F333D86A30CE1606E10C5011CF11C3FA99DF428BEADDC3331B426A3591EB8860FDBB500015E918F3FF3097FC386B2BC7A74121BAD8413C5333EE4349C205477908887CEAD97B4BCB8A1ADD1720F7115E9C2C4AE96480F97A96397B51A4931ECC57C8F349B9B7F3F22A964BC1CBD28CBF3FF7ECD0D19F31FBD236A2CD6D7651C5EC98E9BDB64146890D2C78A68CDBA14906E8C80668FB654176B99B0040F11EA33CC8AD6D1B8397F7FE55CC36E0B8A57D46E3BE7C199E9E8A0605414E4944DED953696F3248F83CC564E194F7756B56B7F7D4551FCA621CAC0AE65558490CD9834D41A23770AD519C0388EE363A99706B5D9A4B12D82C1B0590DFEFAA84404E5317DF90F5D6B44242F72D4BE577AD7BEA80E998975FE162EE3778EBB2F048B94F6E65D3A6840144F621AB043B0A528E8C82DFE33D9FBCB8FB7614F71BAA63FE0B584647F63A0ECA7417284408DCE9032E948626EE440195A65C0DA55E756C2E65B3E1140D811312B9CE374F256315092B736C87C8D9A1EC6C53D9194CB898BB665DA72DD614769B1C5F0090307DF98F755A6DE730C27C1CD1C728842C3F61BA6E77BD1EE28A53995AAD5A34E683A394E7F548BE72F723236C89A839ADD1486693E713D402D184BE08E0EE63F5E89689F0D655649605A1725BCFF067385C8A4901401D8D1D946B3D69DEB424798EE35CE0E086281A49B6B17421786E1EEE9CBD0557E2E935877A770E7FBE4CB725A3C43E0F55C5198F90E4295314881B69BD282B6B4A1D43216C46B59FB7BB3DD01488B993D7CC16C8285F75360AA1CE3016B62AEC2CCBAE5D6805CB6C8D31DF161A33F4D2B8322FD8045836E87ABB3727A342D196C15814096B61C5F7A41B105F47EFE131C97172F84CEC3430D509CF2E0D6F87AD9117060B65CE543B2A6CC448990BF239D934972AF062BDC75389D7BF9CE0646863B96B3A29BA76609C635B0AB387BABCC95C0E61D7EB570C512FB5EC3EF09E857787D053C8BB95E7A66F06477F0EF7196616A03B65DBE0340D33F5CFA21CDFA2BACA09BAA120C36997744DB82F643046FF57F90E93595F713271748C253D5BE42725BBAF55E6616F254384B55D12B571B01AFCFE0106D866795F91128FE8AD2C399ADAD4E5F061EC560A157BBFC8D0C383F474D259858F020A919FB7C2C7693ABF447E3DE6397634FD46838008E308091763D9E9236C60A7C8C11E6C255F22E98A1E5EC7D1F8376DED983EBA3D47C318FDB516F5B0F3590E0C40262DA763CD3C00C0D7DBFBF5CE3E699AEC7C7A7CF7FEEEB5DFF28B33BA61FA5ABD9026A0F8DA14B9373546B1DECDB7A2397B554368C9E05CCEA03DD1E538061E8DDAC375D0930631CFD336E84BAD561DD4707BB08088258115F7340F0BD48C7E2D826F34DB8C12A52BD5CB8E4B064402AF49B671A623A0ED0FAF01E33832179B6181EE9FA005578AE211D42175352017EA7C31136FFDF01C121F4A3316F4B7000740C36B2E3E7EE06D266F963FC30C49D218E7FF321EDC34ED1CCE2EF5B4B151B813E4718EF230C27B73224C22DD28E03E3FF7C8567F23EBB2425D5EF0EA639F62927358A33A89C9D13E7E560A8E774A6BCF09595413E43B7C97AC08BC01F0E9D93CDAAA2794AF47894BEC3ABA90835E5B1960F1D43CCC3D4C9AFD52820305BD7928F68DECD263CCB0ED86105130D669FA2E0BC1CF7A12DFCAB77C8B5160251F5C3D7B810A8D8C66EB206BE70C86F4B9264EC2A71251FAE4A9F11B79395EED2CC4929755FA0CB8CCD52E23BA5EBCC0D620B5EA4E9CE9A1E383658DB34A51851EDACAA3DD5D257F009D5F90C4458E4A37B465DACE6DC7E7687FF47B691D561C65F2793898F4853BFB744816745211D80ECE9B1966C78788135398629910E358A3D3E2E62D8D08D2DDCC9245E5DB4AF0D28D8C4C6609E048D896B5A1C752F89DBA3DE1BF42F4658B1AF1135710502ED9056FC591AEAD86959335DA831813D3E113A2A614A44060981F3AF9EC9F838EA329DDC59B441C306042960FB38C74C604EDB2DA9F0348A6CB0B09ADEF0DD92B92E95707DE28B193EE41A95D4B1B6B91BD29F7B5CB16680A21ABEE5CD7FA7209AFE11B1F2E31F00CA37DE0F71D6A42B957E1986117790CBDF88539DE256501DF38C6C79DC4C373559B1F3ED7D4509F5B7A03C1E9C9BAD0677EDFD2A1878B1BD245B557ACC5CCBD29CB622BE7D08B9DDB26C1593147579490638D6A71ED4EC7B6F70F53623BB61CD34509415E4B43F4E951CFE04F3202E1A9278352E2AFF2230CC0672BC564EFAB07108B342900BC13C6700A74105B882E22D4C851D6CD2D6E7922420A6F0A64E3D5D03BD75025B671796A20100E7B555EDAD6363A58C58B42E7EB69DF82258DF68008FF65BA52F4590F211752101549E301C43FECF0E4FCD545F63A548EB59280CC3025586E57230AC3371F559AC139123FE89524A64A26B5615DCCDD6DB7801E76B223593789DB96E8D63727AA5E2312D3980C1ED41932EF896CD239FE1BE0FA5EB9A3CDD41CBA4BF7693DE929A0123397BAF95EA1EED82A700765F1C5D30026CF60C7BC91CACDCCE6BDFDBC33B2E6EF5EA80CFE42B05B26764588A1D9A0F9F515719C109F70EB94B93C0F0D155E6FF8A93F92CFC825A85B71572D8D5F7708F5BB030AA3AB902EF167D513EB0BCC8DA3C2E828E296A508202547A0BE625379CD271AC992F232E0D2223964D045CDA322159FD0D944200074A60CD68C62413ADCB569A8BEEE9333A3B17D129729BE3CFBD412FF9D202F26CFC9B83635D6924F34D08E8E82C97735052D01087AFFCA3CEC42BD2EB1760B5B43EC622623A860A4C9E80261669A7FA8F2D465A88B631331EFEBDEA67B6C274731E528F2727A197AD58C7B8E31AA28BAE9289AE8BD4D406CDED4904D1336313566440B8F5558D18DCD22E5DBDFE2167028F1ECAC919D8B4D747E5B4407D6ADCB684B70481A51BCC5D52C86488AC4EB3A289813B1019980D68C25D1022EB6BA436B7090BB2C4F184CB2EE4612641763558089FAB21A093BF9069C87329E6FA41B4EEA5FEE1A6BB4235A2DCA3D92877313587F61D2C2092DCB6EBB26E062626A7D1BD8A9E73ABBC4E25CCCBB47D49AB42D7CF994F8ECCFE3E8C18AA9EF5E10E01565AEC846B4F01CFD785EA2B5F1FF56089A74F15277D02BE41F5ED747B93D40FF72BD473AA34E927E4C1CD908B40347A8D2532C9F1062C2BCD97B95576E590A415756B939A8286BB70401C54A8CF55FA4A635A0B38E98463BE6EF631F05A6801157660E03B7FDEE7316AB2766AEB99C3C8AAAFDEE6A61A7555A713786AB82623B6863F41931DA5FA4241B2525FDA0BD1E660E9167E1E8755B8F3FEE07A2028E4BD125075BC7F24B1C02EFD6EFBD26953878D98939CE33507FCFCC1B8CF662940B0AE25C92E935E7FF486FAB426845179ACCD46A361D992E3DB7F081BFE1938BBE224F34D4C1521CE30FA6C2EC611870518C0D107210B64A3FB72DF50618F7961B5C0C5AD896A3A7DD567AFC67C8E55BACF6AAB787AED7BA8D17CB78693F636DFC0E8BC1BCB566FC3394BF49CB4361FB3F97246976E394972DC9104F82E73C8C90463FC9B414F2C16021AB2C35F5739D675E5FA5CC03A42BC84FE6BF86D71DDEB0F54F4EE0C9499F3CE07D2B1F6CE71478A716A0B5ED71EF8510830DB43FB1DD4CCA892D09EC347DFF15933DF3394C5B4DAAEF48A46A994A12593B253738B4D02E60646BC824BF57EFBB0B5F379448B035CA36790FD03DA1264151C9442438FA74CAC23BF972258413EF18D21BCF9B64127F496033399AF09C5DDDEDB8D337089D172EC2F86B3F7F3A79A29AD0DA0EF43F0A9C7B2CC611939DCA9728F15FFDC689F9BC1AB3CA6EBEFA663644DD28BB3386DF3DB699B0F25931D29D571A29E570BE8FC38C1D85D36CB1363C1F1F43762B21B152D6C0BC464D75C99087372FE5268555885343DCF4D9B60E62E00E6812C269C4870F507AC646D31769026F897B14163A873215EFEFA8B0B34196F32964DECC0010B243FB611C979E433375B59CF7A556196346EED27A76CB0AC1876DD5265ADEB7FC81207A2FADDE10E86A5673CB74D8F4D85FBFBD83FC91D2BE2B1EEAA886BD99E97111D0AA2E69230472CF1C498925D072166BD3E4C8390E51CA9898C0D293B776AFFCE1554B1B34239485BD0AE3AD56B3EFCD4C3E3449E662671BB5529CC78A3FD9FFE6DFE9C03F529A082EAE9B756D8FFB25985CC3817696DCDB257A6DDE3BC3345870512D51E9781A0FBFAAD0B33D8C861330C88ABE885A411421D338495259B2FF61D901F3A32BFE130B4BDBC7AAFEAE5DC3B027FEC296218254D07DE78B255B9B628BB1EBEA49D358C74D44A9DCA5E4AFBAC37EADF5258B13B4FC4D8684B5505FF5B86D9FAE6921326E1D144DA9D67EA257029CEB754143D01B50451B8C4175DB8AFE805B483BA257BEE3FF38F5A6740A17C9C7FA90EB4E8603A5DB50B0E0265D5609E41DE0966C1F0D3DD6C3C75775F6A1060BA29ECBE57F1C60E1B45AAF8585B7C6807B9D1500136C66C6765A5AF6F55A35F04675DE23E6857132F0A9D885D3A4312EBE4CD02CA14C7170B2B26AE04F518B9CD07339C6D684CD4BB9C65C84ED2988E14AAA4870E70673703CB4A8B3C13AF94D2EC5AF5C857BD906CDB73314CCAE256B663C2B48AEBA528FCFBF42BF9B9B02FCDB19331284EF1D75F2F73B4996433F7F64344ED427D46661D8343BA2F1DC0DF900C957FC2D999FA500532D152C3AB3FB52348B998403B6331560AC24841DC9200C57744A4E91A3EFCDD2D7EE178BC28458BFB0BAFC0A507513968DD1796D77E8314490EEBF0CBB12EF77A3E488D9D9A33225820C05FA749D463356F9A4936761B760B7F12EF4B9DACBB6B560A796B86A903264E0CF3F48F945BFE378D786D994E84B8B314479D5A716414B4EF3BA4D29AC3E808E385FBD42920C7AF4ABC01C0705A92AF4C054A910B0AD407C71EAF5B0B48F38F38DDF4E13305B95ED9A964456CDCD29F97B01B8E5220E5D8672FD9E37EA059AE016E9C43F92A5F68949DB2F1E23B36A1012EFC64F7F5FED520EE0B936D4DFB8B9B4680A37DD4CD9414128450F506C672C247307A2CF4F582111A17C7BE737A18EDA8F8A8ADF9E832A92958EC780FEF38B6C907E866E93393EF2E9C660677BD6CFFFC60E43F7C3CC92F97636088E5B0AD801E3E7BE079144E8C3825EAC218C90D8AE0D228BD6F56F445E7627A37C0CC15185F7ED084474DD1251D54967182B191119B2154FAC90DFFEEC2C32E4B396BE1CE966C74A9DBA8AB35CCF2CA6F45B70916ADB4A3A19AAB84D328AB2CF3829E17E7C3DB298BC73FC63FC3EEA64EE02899EFB6B1E95153A4A9BFF73CE9A1E86E237340AB97DFA7BFC79705F746446B7C10124D1561A61157925BBAD04B8FD6CC360A3212CAF03AE7041858FBA8E600649043CBC06E1E7856850B9BD1C6ACD71F93AEDD46A8FCC0DBD2BB34DAFD97622E2C817C23AF6A7A1451DA0E8ACC0CA338F255930B152CE50D667B2AE933C931939668DE6AE5CA7526B9F3738E092656FCA467A42E2BF8970AEB61ED24903308C46917B1230848A09683BE03AC37D16F549FBA1D3B8E9AAB478CE6B28560F8E4BDA0AB5F787AF6B6C2A332C8D64024F19EE74E1D74F0A870C88F2B1ABF0A44C94C9443D1296F56A2BC2F0EE4FE633A73A6A6BDC92945780171D4CFCF1DB2E6D087312C11B3CA985BB17862EDF21944975F48CDA6DACCFA78A5F79CC1CA081B1F1D00FD43FA99BC734C979524BE1EF80D9699D738D203D0857426AB6F3EE5F2479C210CEA26DA3136819FA9AA516E9F5067DAA6BD4FB74029EA241E2CD03D13F641E7935D6F5FE83C5727F0132DBAAA93537BAC52DB342E2F7F7B4A0F17885D71B2D665FB02F2CC142D82F17EE7BFA5343436B42EAEC6CDA7E395503C7315BE49A6D7D3D2EFDEC907AA5B18A9DB12C4CFB7BE25D6D1044885A954DACBFA776F462BCD90AC8F5DF2590C8632F64C76FBBD604AB3E25CEA163684622FE237D68EDD52651FD7CF251A6AA181C0E83ACCE8D83711A18854C1AB4BA460D1A9C893DACD6E6DC3344F32CF02D307A40835BB97560BF77612A3FC4A15996F099E27ED724589F5A3D223F4D0AD2445859ED745BAAEFEF9973AD964C3113FE7281FE0F34759A67B4DEF69954FA3314F77670E8AFCC28EE9916E4618C0D7E50C67729701FC9BAD9429D30848989068DE52993CA81EA759BF21DC8FF4EDCF4F55370126B88184E8B3102D325682AFC6216334E80F2D1D0E8E2A1886E54FBDC25B2A8AF85EB1CC123AA869C62D3584D8A7C2DEB2AF2B79E03060D78494BF911DD65B67DB5B57890016E413890D4D6F66AEAD45776D941DC305E54FE8B1E2F74E3177139C9B3386ED394B46CDEE7FC57F4989668C0DC394E9F8030EE144C24B5CB10108D3CDB8EF1539533A017E15C714C794AAFD3FA94F3A4AE0558B48BF40734DC5E2B5948D14F387A5355DFEDFCA4D8F57A18536992294B79D60E1AC77BA6FB038E14862566C681AE197613E07D8ABC10102032EF1AC2F0D450C00F62ED51E067364D68B8B4F925AD076E3C92FDAC49E570F8196C1E2150F6DD4B2E9C73990C4619118CB7602D18398C41106BB9DE2F8F5C82FBF9A7F978B304D8E5DD32B1FE27D9E6611D2BA6686CF1C16596E455CFC318614E61B0E63C8A2EA85DD89A0A0AE1D804C1799137E0AAE4ACDFE483A76B62A18FD73DA3D62C9B6002550C415D19C1A5E93E4FB86142FFAEE247DD71AC8C83B4AF25A3DBB0DB165479EAE4378F9D3C8A4181002B1001C723B2FE7EEC71154AF68C8BDE89941336F9696FCA2876A29D61345E86F77310408DBF47EEE7C47FB434035ADA1CFE60E8D888833B508F766B91E6336C35495E4166A8DCFA8CEBBF7CA4C049AED24473A49093D055C476E95AA9C4DAA74114848DB23D2E90A3017CA8DE57B249EA20206C9D7480B9D7107E85397FFBF9949DD4570A23DF02A10119115DA766430C22DA95BE6F45157B9EB1813FCF91BC22CA50349ACE6CB4C5EEDBD289FC4888A1BE54DB3C1EC3F4C26F1576E894F18CD3A31DA63007F160FE16B48254077491059A16314C756F3060904C9C2F6ADB7A713FEA0E8D5E22C7FFA140AB4F34851EFB44E1C40F62BCBDB1AAF452CFE1124EC203C6E9167FE5F76E25A4093320DB64F30C7D31B99D7E3818F07E634580ED93AA83CC2AA9782B78869B518DAAC5BE301E49E3BD84BCC29E2E605131E86C82BFA34EDEF150E9BED6CA01FE7C2BAC987A3266DFD84090E279752D14584EE57A85177D2A333FF096EE22244E673637BB32B8A02752E1AA3CCD820EE1E7D7D10B086934B3D6DF511A69B9C1727D5E64886714EC2959FDE3B9DB53F9945A6A50AFA4A1ACCBCEAED01EE1FA1546AB7590C716695C487775BCA534F352B6FE33147F006CF81E257AF1B35D53AF069318BD2E0AF7D76ED9511C9CCFC246B0522D729100B86F58A3ABBEEDD8359984027C677BB3B4D460D415376FC59BB9D458C9E8F6E7B1730A9460E2EF68AB8410B0D2287996AF7A3B146A4283C2F3C9868B17895C465A563AF60E1B2DEFF8DB16A8FA538F1244FBE2162F414DEC7918BF9EC2D833B22D0B14514ACE9281806A55A83EFCDBA35859635B3B79416EB785C4A0ACBE5A5E734595D606E77BB8472D9F60BFF5723DC95C5D1D26A6F7C2D11B38B676E9AF2FDB15ADA13A950FA56699F2334C1289F04C3B8A4BDE256410E6C06B068CD2424950DB8339F5BE7943A83B428AC7EE934C21C598C9230FFB5E4F935FA3E8B7D0A924CA11DF6EBBB5D4F4BD5BD983B3B4467453BE6D8B671372AAE1F5AB937E00F404C64E8C25079FE03324204672A640353EF311E9ABE57F634646D70EABE90924F3CE7FD3E8F339864D6A530ACA69C981F091849C92F4C2849A277F6E9DED5A862EFAA03C2830C6C39FB4EE7E6A099AC5A574EBF66F381F940A9814BFC6C93B2BE8BD04552F6EF6DC87F3D4B298DD2CAEE73627D9094333335FCFAB1F1D5EC76467775B86A8720BDD4DE539A26B7F63B5B7221E8E2DA2A33443BCD72B4C34B1C1A630220C82D3C105C4557BAC7786E036FAF753CF206D949973DE6A7987C022B991B1394BA65EAD0AE13EFBC23C2712BE265EFB7EFE4382DF8BD85B3FEEB244C017B7C39A350695E6664212A34D1061DF1E592BCC904A71554B7E523C45135D03E248D2ADF62107522B8BB96FA8CE4DDE04A0534BC62708EA55C9CB4C68B1622FA1CB719AFE767F6194F1E39934C72F16CABAEDB7430EDF53D3C1147592AC440F24FE36D7D50898F257964A957ADCBB7A3F5DF8ACC0871DE89356938778C6F7EF876E75E0416E64B367BE3E50E762AA67588D4C9A9BCB7D9ADE883649CC00A095F73208254404078BE894783E21FC60C9906F88195CEF118F83C9F458EA5D47EFFC605D483C4AD6E0A6A979AD5B0164D2D110A713E0ACF6447A34601AE4BE256241C33F86CF31EA377378C653339BC3E3E4D9071FCF89A32BF72C8A26724A596CFCAD491EE549BBD82066AD93C8FD61045AE2653E2B221F8AD224D07B1A1AAE210C8F4094902EC65A172231DF148550D7979431206B65FC4D41E93DBB93C30A6245B22929C508989C02D094276F61641FE0744E147CE3D335B9059D38BAD92ABB49914078A5414BE5B8BE144E9BB552EF11F894CE8E5403863ACE6B00EE515A172F2FDCC24076087532DC78807A1DF414168B8A14E049EB266380FEADB68EB2214E8E6C8FD9796A9C0D7518798A6717396C218FA08298958BBFA63BBB1215FA4B45F2E781576045A62C0CBD85D5AADC9F4C10B3B0CA0824261FB3E01F1F96A8CB0AEE1456F6534A2FD259A8A6CEB53FAFC54B41CAD105396A49DDE49190180FD4B37C4B054A91DA9DDB94B603627E03F45580271F6B5C4745E36EE8C0E125C4985D1B14C2A9852FEC6ABD17185B2CC932AED5C754A06CEFC84EF49A7A8E354AE2BD11203BA",
     "2C4C3C23C89A466392721A4C9BEC8EF0B0E4C34C370FF12AB5CA83786B23C9E55DAEABB482F5AF4F198B3E868D099A62750D58E81490DA8A4BA59242FA9050FE5A815C56C79C593BF4CE3365A17C4D54D25984D82027404ED68BB3B549F949F0979A0C0DE5B45F2A32403F9E3290FE3ABD673FA1CA822A9507D4A902D7318B4080C5F844DECF432244369237BDF05131D77B24561043ACED81974F78D476773049AC12EED2AD370E27BCF85A64FBB21D532C89EF56FED0C94E96B3B91D55B96C90A000942C685EF3C52EEB4C173824A40F525280C9104B85E5C9639839104516135FEDF1604AAC1838134D3DEF8981E71FCD5052B3DB407B80F103C824E4493A7F93F62FADA397570ECB2B70424BDF1FCE57CEBDDA1FD2B330A242E83993F4CE3B6C9B472A8204DAD89DDEA318088CF0314CD58FA3BD5BACD69402D70A51B7321D261D922D3065BE4469DB01676BC5BFF6E2F11E3E979E97E0E18457E2310E6B16EBF27FC292F3EDFCBB6DD8ACFCBAD52932B21F0998B72B1688A46C7D4AF6D608465DD8015F2F979B55E728B37C8E2A470367D739E6DDA609CD8C2F627CE798A3B37F61CC60A095310834AAA8A3D581AA7F7C75B4C7D598FD5240218C2BDFAEE9DECD64B1EEAED1149C188981F3A016796BA5B22724C996361A647DFB56A2D96D815D4BCEF98CFED608C6C4CF411C679C95D1AF383BB17E0DE7BCE5DC411FE7130763585F150E9A298B70996F353AA4330F12349CF31030CD00D2373AD51843ECB9674A4E29FDF70277B5753E99048B0ED85C3ACBD2D0C99BE2EC28D125D437B2F6055620C676D1DC37525D3545E08508E6CF26886D2A65EFAC797C2DAC5C5567740CFD27F96C896813C40223652C44CABE024E3929B6BAA4FDDEF92E7CB8252BA1720CB908A4DF1D8871DD06EEAA4CEED07C3D52355B6EC62F0089AB044C3E4F1B9A75FBD8C715B766E8A7E43D7860663F10CDA853D6114D7428D76041E2A685A3350494B35279BF86942CAE6610DADB0A0367112FC4E2DB9137E22E49024D7590E6C94B79F8DAF82CE53222BD32031290D8AC9033DD81AD677711904A0625CD1D0E4AEDC86B14E529D375CE0D98440191D83F6E04ADA9F7A125CD0F52B0517BA4B0FCE4B232895E747CFE5846B9463D7EC38527411271A5BFA0CC5C6B1D318CB5D3F0E9279218E7E9EF885DB5238A494C95E851D483CC1FA3E2D75021BC24EF5CCFB6D1D143A16B2589EC002CB69190D255C473155E88D0623965F3B1132A7935DC52D9416D1B9C15D067A7C4B7457F523962C0F6AF5DAB9F95C23987E5FB41926CFB7AA0FA4FA9FC2E25C5767067F33E7BB6E95B8A2A6D8274767DF52306345D1A4878E650FCFB14BB46F12D5EF420D5E4894B3AA1843A5C9D721A2D3139874BF12105A613698CDA5F98079FD776F4AA77066917B5B928C23DB49A8B9C4E4AF5E6F3E43362E6FADE02BF2C22FAE43D5D8B5A18F455CC06DAADD81554D26E53122A1063FA9AEF8CC1149A85FBFF7A6A2BCD44F0EF594944D845946BAEB7E26412976497836D10DFF592CC118E3823E49E4EE2E376F6CF12A7C67F4797A377038D6922A0318C17E6F15E9BA93F5C4EB2B987493D8348491A1736F21C32415218DAE9E0799263C183933F2260E19EAEF7DAF32773A4E43C3A25286DD2A8B456923AA5C4F53F2443525949B000C390A3ED290CFF2BF511B0B6C6D8A159A6990E808B513CD33A51E3CA75025C98907DC9B512F538572872CC46A1B040AB1669665EA0EF666BEBB5D92665ED0B7AB26B4D9B5CCD56A33277069C4897B4E54BC3CF974C084F06C2D736FB046B4BB3A5EC18BD35FBB3A12F55E7C7FFDB73BE7A591C41DB4006404CFDDEABA99D5176A4C6A34F51EBE12D48678546E17F8AD0D39EBBD372EAE005B5D7E6A9EBC6618B1CFEF187B8FB6E189279BF98D63C3099665F03BACF10F989E8817805A0D46320FBFC05BFA33BE25F187AB8D27F1F7F7AC2CBF64F850E14E97BA9A9009E0E6422E140DD18A31C0F151AB2C8C8AA391E3160F2BBA2DDD4DDEB6273927D6C5D5E43A7C7210A9ACAA6B6C012D764ED04D9D36BC1011E65F7518C797AEA6C855D429F25A450F4D0C181DF925D5237368B42C4C2D1CFC1F0783BE7BD612962D5EE3F66C23BB61198C4C34111DE4F4A5A2FF8BA741303A82EEDCACBF8A886EDD968D895D0FDA0011580B41FCE877AAF4DAAE363B3F8E63CC54EC92B5DAC530EDA259B2D8DA1590173F99F36BD285809E87C94FAECF7334BA62DF348F215FFF8D123CBE01CF0105E4E0027B242C2F6712D44BBFA9224D3450FE507DE7C976EE1CEBEBEADCED46F62BE0F52D5F0062833EAE9F27C2B9C9DA3C54A772074237499BF80115A91F8A50E3FE7B4839CCCED3091675B75B7987B6BFBDC5021C24CC87A0276E594F62FE70607A428965C9C84A9B60C153DF1E7E50BDC320C40641AF3CBD9496A1D3431928FF3F02A64B3C0EF2FF84D9A6C6EEA8561060567DED7582ED34A1A9362CD892BB7EE44D2DD3DBAFED26810654327A85687543FF7B6CD7E15F2D5C989CD5DB8CAA84DD1A6B7EF18C01C2356D5BB16C1836EC5FCDAD10042072F20332B771747BFD0EBDB1383A59C86A323E5209D2AD7FB1D962D07F0A81879DA3475F6A40A26454520131B71EB7B5AB63E25FBFDABA125CBFDC0B51C0CE5384DCF686499D670CAB5E868BDD56232885FF6D37D90B8020F42FBEAF1F8BC0E47F54F5B720524DB8ACF8331A09D5FA1C4948CD7EF137BC42332BE27B2C20A62DA377A67AF9EAA44C5874A0DC6544D1B1580C6C8BCEA70A547CF6ED62B22CB068549C20C47EA6ED0D2361B50698130F56A8A5DD05A48942BF86E9B690E22FFC58C3D56AFD5E00F1C3C22AE048CF91A266548F9CF5C4832D00EF68B03EC5218C459461C2035CD96B3EB0F3EB049406F11CA1B91AB3F3C456ADCCC4C6D26D7665823336D2109FDB21192E5AB8FA67F6CF773F01D645E8D463D9E4F53303AD7FAEF14B0713DA4B61C937F914E5BA936369D040AE0AAAE0B5CFDD5B9C222DDA0B3D3CAD3B9101A561503B806C742B5117B47B9E47D634754D7FD7515A0593167ECA617D3A421BEC41439813B4CD1C4F4019E300774712DD967DF2E43C4CE6CED8E798E3871EDC45434E08F6997BAA8929C5C8649556FBE010380AD3C2675F65C9D5996B22DF1ABFDBF943BDD5D47F3C3D21C112003265DF3DAE4DC5A06D915E1E0216A56AEEE123C4991CDBEFC3F7E613781F543FCBC21432D671E5FF56D5280549081B2D81DFAD817E84A42D0E106EAA14FFEA8F553B68F6951C06A251D81C6E78FB2EE73169B89A2BB10CCD197F9EA43FBE02AF27FEA5C9AF9B0669EF0EF8CC53BA0D819D1CEA8E4DDB7E5092EF2B23FE1B3560EFB2058B67C4FA37D0C2A2D793FB202898605FEBC0AFC769784FCB07D5FEBDD65F606CE2B2C8F9AC88F097FE390F6F4489A10D69DEACCFA27991489F95178B9BD095791B1086316B3C53B7F0BBB33940C7594870E3DF157580532BCADFA08132FD195A03EC92B522237703CB80C374CE750C6AA34FBA98637905FB3E38FA9BEC9D087FCD159FFC9B5625E74C7A0E1F6F88D502967A66981DF54AAB141FFBDF596C04C303BA5EBE911765D4E18A23DA57F05D89FABE73487F63712C36F357759E2637AD3A7715D5174153185BD976712A56026A57A7DAD1681219589612294A12849C3714EA03599CDAADDA9279F9BB1162B4289087666E53EC6BAAA0AC2EC95757A0D6EF8C2C60113A24D687BB8BA01B4B6A414EC9BA77B1C9DCDD07234D75F4085A24F85CA5C7F83000D074DCE4237AD78503C2FACC936E4CAE978CE818E36063CF5B4943055F1F5ECAAE9C29DB4F3425566D9C08AB18BC4AABBF14E92BFABBA92B4CC737EE354C26ECAE043933067AD95BCBF638912F0D90A8EA4F1664B4E56A0ABBFE0D8BE128E31374F9E4D0D40CC41F34B3D75144CD4407CDA256F883BA9A0FA3B2DA3BCA546B3E9F7C9C8D8FC1C5463BD332817CF7B4DFE28E192BB6FBBCB4A1B2EC3DABD7B089C7B13F30A9C89225670E18AA75C6BA6C9092913704AE266FEAE0F7E11739BBCB8A0AC86DA8123244D2BAC6A23DD78C15393523A876966AE039A3D778D3EBBB70C6FAB611CA3E35A915A6EAC65E4101BD465F6B6AA6E93A744722E17ED6401210610FB8004E4C52AB39567CD2C7A484D408C349D16948086D9EF9C0221E34AE8DC1381BCAF735A73637286D1A217A655B38E3A980D7B336190AA5A8BB1F98A9AC77F2A74B1EB64E1B625F75CD50DB5B771AE60D36B302CC886EBE0575E5150EB8224D57AE8600710FE387729619D42A90CC5806688B882BE90460E81193B14655147B6868EADF16A618961C3F67C24F38D9036C4D295FB5F05521C9B7B41F49F35EA60BB1ECE89B26493DDFE0770C7FD041AA0D5AF0CC293B010E83B9D0743A77AAEB12B482C6ECE91BF2B95D1A8E8CBCE5179EEF8594AB5565A08A65B1FD9BCA739E6F344FE1526411B5471EC070EBDDDA2E6A131D62AC7C1CABEACE3CC9D382B1C657AEF5915877647A67392E7F15FD8B9C49B29BD74EE55CAF7032A117D1509372D8D26789169D59F0C5AF8002F5164A6DE6CD10C17235868BE3F656B842162D5E227518DA4CC0000000000000000000000000000000000000000000000000000000006080E12161B",
     ""),
    ("internal",
     "00EBBDCFE899A878D62752FE6622B78D5253C8C6F8ACF526B408343D583AC632E70C9B8F5F1E983656F593BDA9FF777067F5595ED9834C5038F5DB8ECAFFDAF850D3D647962F7E96D53A033282A1BC4B9DE563E416DD46DB15ACA13A419E12EED3A52EFEF0E4AE80893E5DAC514BA8869E77A44D0BAE3BA90F6F88E79C47DBAC1A716EB1FAAA0FC48AB2E3EC0C2BFD3D61578103D3A0068888CD8C4B30CA167F329259004E3A9AFC9914597FE0D337033852E13A738279A43A7CCE6F83043BAA7B88E0FD8DD5D4F525A257B91F5DC563EA006D76C02A9031F955C38E37B49C225DAE7F3057C44AEAD3EDE1BCE055F95B2DC9A02F66FE49942E54BE3933A7C1FC56B608A46C13076A1F80336FB06C3EED6ED5536EDCB0DF1C0E7FAFEC6CBDEEF24C63682391764BDD990DADE813D4846DBA04D66216541997E030E7CBE6E48E49D331943302E4CF17C73609BBDA3F68A32D9ED2FBA37BA9893264D4F3DD3A11272823D6D472E2F9B6600ED136122F556BA4502C034772AEF541470CBC03817444768FDC21AF2F8D8C7CE9C9DDE7EFF3D7FD1B152A0CCAA1495D3FD74BA0D51010445071D9E328D457995BA9A6C009933C078EC933E3777A381811C2C2E2E06E4F5B51CE23AB3F31458F011A712D0681DCD512726AD430DAD8AD1596B94A38EA3FD4FAC1042109FD3F7ACB4C215C84E9D6039F0A64F35A340345D05953CF6FF2444D3E3EC4FDAAA28AE0AF885C761013BAC40FC90295F010CC488781AE456D4BCA718FCD10F4E5006916465C4CC27C43AC4CDE25F3FA65810E2B74DA58ED819A6C684C04BC26074B61EBACC59800FEB156652132C30810149F62D66EE16A9F4F87B10D78803D4C0CC1C0D3666A60AFEC5DA2CBC7CBB9D5595E5F18CEEA706744D4C293FF927629F69692732FA75E41CCDB9743A2A5D1EA6F2808EF0D5AD2C4816FF8748B7D063C09E921C6ACAEA7A11143274741EC7CEA0F99B3828169347C49C19FB501B36ACFD9556AD3AC4441B37C4951C2604F0189016D3F7271C80199A1F435B88E5C6626DF4B7F9256AACAB918B7A7EEDF459D5F313BB312FA28F81DEFDDB3B4A99A1D9795D038E6601E42014B021029D222A751652E4D9F2BABF24F30B0983AA7A2C62EEE2413212C51FF229944D410A7AD9861BD1FE80CDF2F5CAEC0960A6F99B7ABBFF6139E9208B66AAFE2AF6FF06609248721FD455FBF07E6C9D5D645F6C782E20853A5672EE6A76CBE20533CD7C4D41BD297C8258BDDBB76F8349C829819A8BEEB4DF6D10260B9AFA4C645EA39F3441AD6B0EA7C328C44104B563E78633232B1FC7C90C84055549AB2B2FD62EC752766197173174BE422AC94B9D861CDBEC84AD874F44A3051C5CD7212477D5053A561075C866CAB056ECF0CEF1F3C4F738FE7DD42BF4736E0B7A2A613837FF8A7DFA37A8CE92FA0C2C7A476ED161027221931BFD5E6FBCC9637E313B600312B413672B31AEB3F762B2A1D4E6D711811DBC3E14933C25CCCDCB7C2660EF8532F0007A0075A3598D913D4D31194E8E7A279197F723E5629A9D2F799E84139FF287872755D4491AB069B91A02C4B46F1FE943DEA813752F5371DF5E42E7AB9231ED28880C307F2F99A66945D6586ECDBCECE2CF3A955D9CAB9330140C36AB99FCB9209208735F48E591FB65574845733502791DE54B38760D85DA2AB9AABC699ECF4693935F3B7C0033D871F08828D093338ADB92C9C169A906AF24B64956397227A2248B85F540D024A2D432957F42A12F0C0BAAF642ACF5EC8EFA5E9BF0F2ECF8B0E205F8592CCBC20F8A4075EC19AF075C953424811FFEB8E9396C0A77E9E9E68F34B32C61F04B83CD836642115607776CF944B4749B154A84F099720DB29957129E7CEE539B55E4C2BC1FC7636BF8E88089430A80D1ACF66B86E7E000694B93D55EF94C26DCC072ADC4643592EC7F3187CBA573D60BE069B52652AC623E232BC61709928B50E8F9742435538606975875BF390899EB842B9433CB1DACD5E949AE7144172FA28379AFA1D512A47E2A905C4ADD91EBC9B73E6A08CB49C13A98FA758097450633A3FFFA820DB56CAD86CAF666435C0BD8AEC2016E367CE7222B332D3BD5F87A0854CA11BC943C84077DC2E6D42DA87A0CE158047DE736B8AFE6D3B43419F0CB28F92F1B565CF3D33413DB26080D43AC1F1C244D0E53C736A342D3DB8B54D4F570F657E0198767E72CE40CF6B34FB65E658057DC309503F7C3B91DD95B41F5559A193E4A5D4D397581A44620E9D160141EB9D75338C587EA955BA7FFD174835FE65F98B692FB9F548D7A6B95F961192939CBBC69C299276EF96D59EDE6FBF2462B7C3B335C0A166AB7D963C9807C698DAFADA875126476EA5285459006C95EDA889374CE460B2CD26F4F9ABEBC33E285F16C25E5471E0BD7B68DEAB6EBCC6BA71E5B9AC129581F58BD4FA38E0EF5E1145D4AB07F2EA867A388EB9CD29AE64B6D56E6EDD9889189B4876B328B9BADC3CF251164DE62179559861F47915D4C7F26E985A48D519915E06EE73A5B3FCD7C9947D7E1FA58D08029A37AC2030CB5C821FF14FF7E8B67A6C7F9DC3425DAC0917E4CF667419F107FC5EC53ADC5C6794A94EF9C9296773C22DA78E2A0DEBCD9E010CCCA3E9A504BA1B2FCB9EE468E71358D4EF091BDD5C82070266A14CCA81C2D9F0701C8EFEE96538A522064D718F8304FC37D5AC8395C47130C80E11478630AACFB8BDC683ED59F8944907EFC37D3408ADC34750C0F8BF2764",
     "B1DAD3A963FFAA78121718C1CB65470778FC3613817816F69F38361A355042771BC4C1091EC6A9FB3711A95F3D91AAF0E012DE92818D8D72E4F2700DFBE189BB76555376562719568FB8A10FEBFAE90F4631FCBF0BB9CD6E3A1731381D38B3D920945A26A1F021DCD1EA4B4FFBC889152B8D45AFBBAA50D07CF4667703EA40DB079DD77510149C8CE0B7695C8A4962A18E34235D13BB77F80A6A3A3E7C02933B46D5985E69184A4EEA596A32A35A3BB632E37A962586B0A0FC408D5A6287E54BE90DB7C500958408CB49E4C45B733997C59CC5624D7D48FD9B99F4ED211697CF1EC5A5DCF20053F845C7136E844B39F02EAF71F95603118FE9A9C6548EC9D0DFB769109564674736961C665E0C31A761ED82B7F1F64E382E5B0A443937EA15AB26209F2BAD2773E5A067478F326C992DE3FD3EA375F7005694BDBDD74DE79DDEAB98CBA65F8A5E2C252CE9F6A5CDEB18E19121D4C8C143F2C6FFB60C5499128A5DED5C1D847BBE04D20764B9E9C6554AC911705F72FACB08B650211E8E30338AE6D2BDFB18B52952F093CF94C9FA42E81D443D8823F85C1AE875D3AECDAF98A19B2EB32BAF738F06999457CE15B47D89FEEFCD27D2CFB999FE6C6EA8BCC3E74862E448478341D7EA6B0F58DD925B86561D8F71B5F7FA86E476376D875DFB16F171EA2A9C0A9B1970A4C42159B42FD16BF3CBA4D2B458328C8053E29CB17CAE8D680C0C63C67A22C162260D2987073858D41F030B897FFE7E4DF0162D5C7B97B2EDA960ED88A58AF6D62D51B3D7807D97803F18492E9B36C9F994085171F9EFB3D9E4A9049EB997EC6832A7C048F813564287264B2F719796AEFEA62091F2297EED9AABEAD6BF1EA78A47BAC632E4C89FB59A449A77DD4E84CF80C4BD60223323F8DAA51098C8F186219D287DF6661772BC0642C416215893AB43B2C8464044B3C4B02C4A5784A6F75F5ABCCF70F9C781480AFDA5D5F8D32424FD953EC050E0DD6D9877BDE75F7DBAAC18BCE9467C9041817218261EB24C3C6E14A9D53E52101B43024C003B49F360311C5722344239CDD2D491D06C24E0B999B207DBC0AFD6043AF12B7F4A62151343844BFF6CE5EF76F0698415564B0D6F829663505C36E57C1BC40724B8293756E9E81B79946250FD036412A52BF1C84215E4A882B9FEFB5FFEDF61BDE2F2DA020FB0071F8D23542B181C4E5895E35C7D81EA16932B4706F007A99DE88D691951BDA889886E492D2B77D4C9C0EE03089BC8EF26FC4498AB98397569BB4FCCFFE2DC3D5B9E7F256CA7E75A2BD7E03F667065ECB48D4BF68F184708AEDBF11486A3ACA9FF55736D877D7C72F2D3B0F2A1E7515BCFD56FAC8BDC92CF0C07A2E91ADA2EDCC98127B7CB34C22439D7D222E7541051C40CEEB47F752B270C3FA249A1B649C5F59846B1381567BE8AEF22B6039F0FAF51449F639F247510335FCC33F34C135B8ED6C1F7036195636F8ED8F5865E86D8729696B512D79CB78F4A12CE78D64C62E4A8148A778245E7FAB13B3BDB055B462D450A40AFF704A360397949498F15AACAB3FAE2A4B41E7DD645AD167AFCF008945C5E8E811616DE8AB93E96FF1C2DA7C8B538CB0EEFA28CD38B57C6D68F5C9ECF78657637DD60027F08D24640F1082D0B83A5D69BBF81FAD2956BE21996E65DFF7E880749382B6D8CD38B8FEA74213E6E705CBDEC5B1D5780AFAF624BEDD50B97BCBB6230779D67419232B81701A981F8B6CFEFA17D19BAE1B87FE7A06C00BF8CA39093F61AF43D5FFD3B0516FE10FF964FCF4BAC62AE274FB17C25B5FD657C9848B727003FD1C7017C514FA5686B5DDD34E406E8980744CA90D3C7E2F6BAB04DE06E825CED337A56B7E4B4A679B823795F1B6FADB25C07CB141533BA277FE530F7C85D8CE5BCF9A391B9459FD358E0C48EEF61DCEAA8153EFB6719E7D60C0FFD8387FE597CB168C1F85955C89B02322DFC0AC7377C69B7F521D93D4E7DF1FCE781E0A10585DCCE5527DE45A29E371838B597D8D3F491DD258D83354A07909F3DFCF400B33AE8C4D5DDBBC85A8E4579572444DE1D2FF8DC8293DCEE4AB1AB11F038D4E7178F3C7D93B507CCD01371017BCDE7F51880D811E30C8FEFB77C79DCA98CDCCB90C0473F1A5D5EF640DCE81183946AC38E549ECC0464A75FCE56DAF2AB48A8B825F495E591764AB64DDD768B6B5D46926E2525514501C026A5D8B56513ABD3B767536FCA26D8E8B4A6E3CEC48A4D3883BBEE9E7FFF0F0C94BEBCBE7A2AF19A1BA100D8A4E102800CA4256152967EE26353E056AEC774B83FF851CCA7E58DD9083565436DB18B64129C65F4B74F04E58B64A30704F9D081E46E892F46151D7298DDB1577C0A47075AE4507E495926C92897E2C55825B6B98DE24DB4B8E648631BAE4DDE192C7D6D29FC2CBAB35D63312342168E783921E5BBCA83F9777103879F04DCAC8B4A0B3E265AFE790B728411DCC526BC6EE867F85BD828246BA3C72876382D386E3FF749FF8576DF317DBEE4EFEF9D3F9A7ABFCC3C4BEC82940AC39D3930F7C95673007904C0362EB4A343485BBC2F2F4001596D0183AC6FB9FB0A36B32B8374C519A01E1EDD40F3E7C14FE8BAA67E9E4077C8BCA5BDE2F7921F5745B31EEF048CFDEED95A70A609BEFE2AE47A3E8E1141BE54A22F0F72B4F2FB8EC5E7FFF212A5CA2649B7BF5C951AF8CB1771D5F221E53E44A53095CEB246A699B705C10189159CB96D5F744F86648438FEC2B85A8BB39486E88807AE5F3786BD0746C01A52F68DCFCC61A5B56C27CDADDEF4053904ADDF771F13F717E5681B1215E0775411632D03FBBD076A2AB49AE0A0ED167A4A9C9D7E9AD27D7FFA898DD4CCD06906076E9AF46F4FD5A22B79499D93F2A1723CE7E37FE67EC2AC589C53D15F33E474512DD2415F52622D1B84FD5C7ED61C4E5BEC07B045BB33DAB0FA47D17DF02628D6C873AF40FC5E4498283A1A5972A6A06ED1C2855CBB3DC5DD133EBE96FA56559F56CF25768B201D71646C828011EDEEB9DECCD446C57FA6EDEA3A6019D0A804AABA2B47615F7E3BA5084BDB612AAF1774588F3FFF0110CA9D3085F5C6C526BD40CEAD30286246481DCCD556901CD773E001263F8EE8D357EB54A9A7A89C077B5EDBF8399D8F189A981D27D259FB1F46D82D92CE40849839074AC041FCDE65459F2E51AF63AFA072CF67C42721DAA2AB96A6860EE2A6AAB08B5CE83E02E8025D4449ADFCA7B5EC5E3C7474EA352495EF89C229FF3BAA8F4C2AF864500EDCE64452FA4BB6CA2C6EBFA5C2B871F3D4A9EFACF61BE82C54578F00772815759220F4E668BFDF1341E6A5AB565493398FC4530ED9E22FD1CCAC12D95EF8B1D11916F955F201B728B8C98E25EDB5D96731EEF829FA2F8B8B76E7E71FE897DCCF0C92612FBBC42888ED4D3D656EA5B9B4CCFA713BC8BE647A45B51A1B89A576F62EFDCBA669A562A22AC0E75EAAD141900270C45E8D0BCDD739CBD41D675248D5ACE836AF35BB249059FE4795969D461AD2816DD17A22DE64AC00628E36BCA171557DFCF0EC141170423F816C7079D89C590BD909C39E52A8D822C3472C66D0DB6BB70E6E399F25AC8A316FCDCBB78770478EF506970C2864EC368F11C09CA1B10C4D23F7EA202A4E117115EC023FDF683484E3CD18DC288EAFF98F64EE371DA01E720CAA20BBF42B5C0EE3C09BD85D7B9A7E48DE3DBF2419F843B3DF4C865DF431B1C460BB79E77D63208D3CF620D262D8DBEB4B2B4F52E2D2C8240738574CE94AD9E16E3A365786C9742E8FA2F6E11C4AEC379870A8CE121FFF9613FFB1F191B03033D83D1D4F0F745CF3F96272E268DB24B82AE9FC197EB11E8B8A45CCE2BD6E9001845FBD41031720958A267F31AB89DBDFE26E6021B1B492957E20662F09E61979931D6B44BB06278B0AAECE11479DACF075D6C8D7E8231EF0A378472AA22A435937C7CE577A50B5AB464945D0A5360EC64B095A4D3F51416275E69570B16DD4507E74475663F7FACF2308282A8693D639E9F997777BC1CD7E1D324F7420D9B36E73CB647C6FF7BFE380D50F0DD05E94C45AB54965DC471BE2F0B74D23DB7BA53216F9881A5831EE335E74BF96A4BE366B552A",
     "3026740E118B3972CC6FF2A30CCDA163A397A69BA7AC1B69416B8CF9597E9B40F248451028473351B210357CBEE28A02D9AA78F193368B599FD39039EE1BF32AA9549128741E53182AD849BF81CE0DFB507DE0BA14BE8C708ABA43060D25DA53CD795AA7F160983F8DAC0164432BCBD324C322003F43CB2BBC6A161BB182E536DF00E126A4388E4D71F6EE6D5F948E1D16CE97F3E9C64A09181583F74ACAB73C4BF7EDA1E5C549CBE8FB32624D3B01DC459F15B26CB3674EEDE7D9530D53D4826B815C56732A60682C4C43867BDA8FF9AD119BCA21F99C0BE4E530DDF28C9E5F170274BE1A0CAEF5FAF72CA7BA4FC1DDD10B59F5630F36B5DA418393E79EB2E71278237D881D7634B7946EB48583033873CE749209BA167411413F253E0E90559DDC1318D9EDC37CA6B7B5FD631B908A56ED59472590FF2892FA6925F3EA48E2B33E3C13659C898E4AB4F3C3CD8694E3EB47513E49419C0AA0062A34A0E3E9E795327D69F7B95A237AFE7C3494C52E78864993681D141DBE735618898055A37787C281FAA65966F41F23709C2F05B38C81E2A183144F8A56A7E05649172EB07104E8A71016B60CCD61D89B1CEF6257448BFDBBC897A4E2FBA0E308E04A40953992C703B3D936C3CDE8758095DD90F35464E74D8474091041DBAF5F6B04318F6E752A787B1C3784ECF4597C2ACA45248DEFA00B78A5948CAF3C32D7F2F2BA63B3B9AB0FBAABF7FFCD85FCE214755717EA35FFC3E7F7796E8ED788F72FF88EE48A4FF837D401309CE0C0B9A316680FE1A22CA4A181AF25FF6F4A5A7AFFAF5E87E2D1E16CFA73C6DF0383AF4F0959390865759F28667D328F506C4ECBE1A4D300BF45144C55B29DF5F5C2910C742FD121CDA9C4E39C76DBFDABC9C418131C0AEDCDF28A9D88C238670310223ACF5BD9FD0B170E8BAD1E3639F2434CE2300181DA605BFF2E4D606DC520AB266DF3C3300A9AEBD4A74D0BF19763F0796B5DE8AB0EDEF6D4782F0C51D13DEE936A0F3371B55F4E7ACB497BBC66717104623BCCAB896864D5C8FC95A5697BCA6FFEBCD0B1682557F30CCAFF4C0A8B482B92B9E135A41B728F6B561C75F22F7E399F0FBE599B5EEA38C266650884659E76E305169D13383A03870761F3AF749A4FE7E1EF368E5FBDECBD613D41E615E6B19BF98E19B17DABE945AD30359F5F2613F1D66C2CF97177213D3CEDCC9AE4B00963AEB21F54771AFEC4BC56228F90F93C6959A75BD1A50D2B198E01A3C5A8296E75DD2D0826C1FB92990334B545EB2E0BBCFE347CD2C95A46F407231806530AEAE2B14A683A9224B71A026DFC944C0FC565DCAD314B307A4CAF6F14FD4A5E13AC42BC8A13A74457DBA1CE5A2E03BC26D5A213C8E5D327BDBAC077E4119DFB6EDF4AFE7958F784FED9FFA10E92FDF8CBF1FA70C3C7CF070F7D7284F969E8224B8BAECBB2E2878B63E439BAA0CD1C9E1502F9D15BC4828EDCC9CF13F3FD37EB094746864C96D2F92A51583EB0399073F9A2E75D2D9A5E754DF59600BC4E1EA5079B12D0CDDE1201C0A01AB1B291EC04F1F9EA205C091E9BBE606CD8EED9F75E350955A7358A195054788DDFAA77CA3788BA72754261D176C5DA856800EBAED48D53E528E91279D7B53E6B1B248C3104429DAE630513A110D1B537B6DDD6229C2EDD56E7592044AAEF91C69472307B08D2473767D5C6ED8AA2638A56B46A106D34DC465D20D3603AD0B8C498BD16C492B0DA06B92026709385449F67BFBBAEAC188833991C668B24672DC9F242C5104A7A7703F78A938F1398960AF296EE8DA9090C33DCD7516EB304A352ACBE9FCFF7EF6F267243AE3B21B003753C95F340521F4998456BC5ED7FF7270EA072BD2E16D29DBBFEAA4C14BB3F3D4AB18A979C5141B5374590D3648BC062672E8E6B884A3625F54215DC4F969F46075BDE71A45FD198881D7723ACEBCB4647A7E37CCD8267EDF9F5EA0BECD23A284F73F933D8B1945A0C21D907436879C751CB98E83DE441850DF577F53014BD3D832AC16D521897BB50A6BE87E5DCCDD884D1B8BD540B519138DEDFA87E87DCB535E3279FE599516225AAA6422682357AEF7696A6E21B08602766E4F44B3F2386883208AE425F4E785E5B1D85BC7BB2E16BF73950D756DB81DC6D8F59770386B26A01E3DB1E35BAF2481167A3FD33A339858D99DAFA3AD2A35D8919D3289040CCDEF81A24E589F39F742A72C7876283DC5BBD16B8ACC418C6E718304911840F2304DD30B5763F1EDBF0548C6FF65A9655C4158D969EE2C56548A5F506CE0E5209676E642C92D2858636EFDB75664A78670A490DCD8A44EF690D2982C9863B2A9B58F5EBE343B9B559605B6667ACAF71DCEF3AC06F66B91F5BF4F11DC34DFCCAC61A8B5ABA657EDDF5E88F74CDF27684521441E069D410BCE158D8BAB1E2DEA5399DBE1AFC2A9369A9CED7963380FD6B53F46078C0E798DAEDCBDEACA177D43CF1A11752DA93BF9E441FB661F045B92573210B1A8F10E24F0383B7ACEF516F231FD0A47C35577084AEB974AE0374A71ECFA32FB0FBDE0D8A5383DA6D8D79538B16991BCBBBD4B9E7EACD1C6AB29D680F4223E44B9B40862AE201ADF67125C2A416931DE128790721D4844EEC6CBFEB22295A70AB2F6FCF28A8861124F141C2DEE65D8E0E030FF552AFC04A51135691CB2EE4BA41DECF5520E42681CD7D5BA0B6B8ECDD36BA453EE124252D1108F3CB310C68E361F6199D5D74B86E0006E22A61B19E2CB952713C774DA9F1911508ED39718EDAC4A59616E0ACFD27AA67A94457F2B12234DF1A2C5A48C8B61E245DF3A66ADC714BBF1FE912AC784EB665B546A77006A0E1419782BFBC95098E9FC47B4CEBB6ED532DE5843997487985E254088AC896A6C00915328959C9D7B91ECB08148A8B10EC84735FC2AF2B41351B5259FC26071B2F1638AC58404BBEEA3767C1685D5F538FDA2B78BA5D5E8575FFE9509B83722911D27F2474E23B300B443E46D65BEF952E2DE15ECB19BB82FB7E9ED2D25842EB722BB4D1CED3F3FEC03F30A1893284E3EEB6C5F7BD44DB4E9C5F1C45CBA824201708C701A026E72B449EE9C31B244FB37F4736983041095A7261D8D3C57A64F8204AE64E73F6CFD9450A87137808A0437E3D81D17E60376FF37D863B2B8A393DFAB82791F2F4A1B01B1A8238671B070A66723F7429DBB5718F046215EF861E1F2B39D8EC473BF1496D83A7E9BE24333133E136400A80E835055F02487789B3CE992B46A8AACAEC48DC3D8865B602E130906D834D1239988B5EE91CD08C2AACA6513C48FB9FBF3FFA4666F11C994102357428F77D4AB682175D5DC759CCA08754FF7C43F8EBF4ACDC8CF683FC8588256E43A2D0EE8A87AD88E851314CDC7B620D52F0DAE3869E1A9AC4581C1EC82316EA03043EC4ED007AA30649AA67B54E6F2E527942C195462587356E2DABDC1DEC59A6AE251655D385AB1DC77DED72602C2F7EC0BC967E885A9BAC4C493CED89F9C840D9C665F36345FA00D6F17744A7C351B764A75FD27A81A6F51D66EFA3CE4F1059251A2AC75F886FB8789A94EE7051E221BAFE44C5DED99167E831FED5675B4DBBAFAD58347DAEA17223ECBF49AD6341646F5C5A6C930AB72099739D8DF538E0EA7BCF5236DFA10256BD92B7BDC33D5BBA19339F698C6894EB5193500CFEBE73235C39599C572E33387147015585BA6055A57D742988385B49045818680E85EDBD1E061BC1A0BEE2809F7FA6F9F38C5231E47D478533CAD33B7BA3333E3334D0100E02D5523EC51C423759B37285A0101FCFAF558EC5587343C21CB01E573FFEE00EECAA1E4CE771C1EECCD2C3A2A5DD0E8812F29591358D3115CBE92A85811B228E3A19DA91FBDA07F08A61C06E0C37B44028CB4F434DF79C7405EFF8EA4FB14CDA1357DDDE98765DD5288DB483E57715AB630C6F906023AEA446BF40D71D6484B653C05E6A9BA0F37B14379143A11653FFB833B31A9DFDFCBA056138AFA5C5F32BF5C97312B89E888185D2468D17911FC68262A987B903F11FFE7765AD38C9D814DC9F334E85B1F8292EB89D0AD4FA9D30A1FF877D2EED76B504F977C9715505E90335D81A6A892F968F0C0B454307958BEC2CA9C3746572B772859096A84A69D95C2F3656A16A3E54DA8999FC0585ED5D0F90F23E334E203B0FB6CE1E38E699A474EB8503EB37A89A167769AB172F50A8459CC4D00957000FD2FE888100574D686D4DA6B3A5797420BB1E7A9E99401555FB95CD9DDE79AEC7B0BBBBB77D89E49E6B4B3CAB164A06B26E51F2469AD4843834138596FB72608E6013776FA4E4A84C1E28964C62B51C8970900D289FB5311E5DB951D91932D7F0C03E67D9C0F16371BED22BC5DCBDB453D0510E1022D2B84C90E2D6BBE1C1EA7E9B32BCF795BF6C2436A6FCBE83CCE24BC75A8444607812918374D5531BCF17AB3A6CEE79B5DD097A1FF7A5788D6E4158CAA127FD893B9288BD219124476303DEDE21B6373DD89877E5A122F91A983E7D6C739B591159B9217B596F41DA1DFD0BC3D8F728330112ED5B8BB838A40E8B943BA8DD55477D890D0CB76A180C25A240D80B64D47AA3B1DC3CE2505EA9ED4A87C42C0C163366959CA5BBDBDD53569AB0F0485C26275D64BEF6474C669AC5D33D688AAEFF0000000000000000000000000000000000000000000A0F11171D22",
     ""),
    ("internal",
     "9139985120A01F0C53AF19ED19532854E5A289F6FBEBEB3A9C780C9D1125707B3BC63027C3CD770A0DA3C3E68D2A3F5AF90E8A2735C48F9D152C84E18EE873425DA82556A17863B9AC06329E5572770E5D5596A437C5A83AE87A1DFCFE0150D3753788606CC18E9E70EF3792F61EAA98878940972EECF6A0314FA71F22916C0AF644305AD731F8E79CBC5FB924B55F88893C6A3AEAAC7553BD1201CF0B3015F4F0407A6BD7E8B0B3CC3D0437EC1F506BE3B999D5FB98E3BE6D6F42BD4267662A1AFFF561F9F7F35B154C984A39A56E258284DA64178641D06180AD17AE7AF27392A037B1D07C7FB5165FF2C0DDC1B44B541155809ED19457C70ED0C6CA177C201901581383E618B5D7256236DC19C93511756F63369AE5AEA3B989DA1CD3AF7AB433A5A389E89012172C1679E56D4764ECBC9436B340F1C722CF94ED8E69F8239C2CB49D31A7489E0B7DFB86A2730BEDC16937ED4C35FAC66600B30C9F7D0F07A41CF4357529A1A0C63DEFCF0CE0F1A5FC35BA2160AA4207F48DE11B62CBA86B83C4ED85E68EA0445A5C784F53A8EA281F8F6D9821483918E6ACEA181ACABED3134D230322C0B3D95280D852B9466194A1132C01B85A0434373FDE0A67D137554A10F882266691D6CA3B8945C1F3BBFE102E76C3100A44389E3FE669F14DC9450209A26ACA78069557923D88B2C13254FD3D6E1DEB4ED9061C752301B761060AFC14ECB1FAB317726DA1EB751928B44ED435B1D66C508CB784E6E47A9429C990117E54A6AA70EB44B96C1CACBBE97D2A16FE758D236DEED497868149EB6587689FB58107730151B29B1717AAE6065A6421B8D633DBC4CDD0E080F1887A73974BD96404A9BAE01FDFF7FE52095D3B08AF9244C5053C050B8B7AC7E8CC2BA4E3CBA142B155DBACB2033A5B236382172418BA83B888B6291FC6C75FBC00EE28011FC28B05BF95D055B0A7F86B3C556AE14E19B6E5CBA1FE7585CED4B43B90BFEC3058A19197C4DAB62452D02C10C8FB1BF5EBA9C429EF574FCE52F4E768D2A1C50BF093C8D010E40AF43081E16FD33B682D1AC0B16AEFBA03AEA62CD04EAEBAC2D76A03F81F7385FAB5D61EB7A4D41F82C1A4B5C412CFBBD609F8653581F52D09866F791F7294ACCED6A80545BD1689A05613EEDCBF904A521F54843A59C1F7491CAE3D9784837032A407CB8C0B3649FD492761275A3A920E0E3DFAB3A7BD20F7084B4018C27F8425156FCA7B034547B24D9FA93D4C53D9911414FA69132DD8DCE173F3D4654FC543BA863B220CEB91CDDEB07F6EEF2131147FE2F60C0C7D86D9AE5BA63B3A75BF9D5A27731C80F860930ADAE3658EF31FB8228B4349A940DBFD7C109EFFB163F6517DCD32E335FC72A6DE1C893A1E9F516B23F270EC9F3EDEE43CB75471FFD5BC8EFC139961052CC470E83DE7BE2E53FA2E260C239510D3B051D53F941A2FB7525ACDFC661778DCDB1161E1776664520B2580783BF4674560FBA07B30C895A49A7DE698EA3FE23530A6718F08B3F96390C6EB4BB065475F4A727255A822FF5793F2EE30711BAD1847C68D82A61EFDF19898574046166010DA9FE18DA6E064117A6E0BB57DE01B57A8698A81A98ABFA2EEE1C72883FBC80DCCB7E625D817FA8F818788D52159A74D2665FE930147B2D9BB4D036F3D39B1EA3135FBE599B89B5EBC5943F2F8D6DCF26DE0A532672A43596741EC39195DFAB7FE2008CAB2EE0C381B79FB1227ECF68FB161433AA38D9A2E4A23526CCE198440C52DE3114C975E771E7762850724859073A1BCDD929678D10B642E25ADF4367064FC7E8541E5AE455EBB3017FFF05DAADFA63F585F7BC573B13D0C00C35C263B3F1CF9ACF8805A7A86D607C9CE41CACEC23C8FF1C425387B4EAB7F59310837313F58263C7B067B897BDFF8365F9ADBE71D9840B17E657B1AC5ED158FB5AC136D29A0292384BF4455819F13FED3AF362740FB6BB58367AC6530C344F48313AFB6D32673BF9B0DD0E0A16E6D1F047474318F4DF2C3D0227A75239C1E70D340D2A12389E07F330BA87CC1AF4CB19EDC9D8D136BB5080AF84AC1C1DD53FCC7445AD9CC15E284E921836F5055BD16A73586DD3D1166912E8F93C27B0EEA23F0837DB4796145010A22DB0CBFC120C94FD752E8AEA08054C05935C4667C387896CA34870EF59021E9344789FA192A147E713036831A69B800A3F868E6D000F54459B08E363AE5C61DBA3FA24CA0D6027C6C8690F990785D7CC1233B56B271B1EA7EC6CF8579EEFFB51EB31F9846E1344E2545768C9F4CA9C3706C721CAECEA3597C183C6FC9C5CD121AB3B6A957196D2023A0DC1CF026A28F596B63C55767E50599FF66182463590B4D237B265A485E566247B77D12C799C465F8E7C335A5FC5D63D85E8E326841C5236E5124725E538C3E407CE08FF02385B97AE244AE6A24F1B859DCC634D0DC2612264602BF57AAB15FA85DC93148B83CA0BBE072FEF40DB57B47AE781A51812491964B68C7C058C6EB42551F2EC4358F9C6E0CFE1A02E2254418B7F8946A788708AD28CC471F12C6420116FE1F76B80B4BF3B0C7AF66237C3C5C4D92F5C60ACB3625259210606929F4FA6C58BAE7774DC0E747279AF7095FE282D190305D265121CE8AC1A52923F000FE73A37844234B4058BF6D2F2C0E06346A1446E1820907E02BFB200AFC9B4973F36C25992BB630F98787BE631D8514E15A316AAC6D0BD6D82491F09EE0D07571AC754E435C5E0931D24440A50C2A2AEC9D034FA691",
     "D622564E8E787EC33994B9A5BD5BC36E6C18293A38109230D704A6365E14BC4A98F68C40FCCDF6CAADD0E28DDDE54D4B2119FCE17A1C746363521B85422C941C22968B0AA6E58769FAA356AC73F582F38AE962F231DFE0230032258436F06E047D568360D8D735840B2DC05B40749689D65276B1301273A5F763E1DB699397BAFF97210A7F5945009A9304A484D787E10E8E18CDAB6D9B9F6002BA1DD7D01710D24532C756A417EF1F221FCCB1D4A7B180B8AB80A46900325E77AE96486422BA60B5792C88089ABA0FBC36AB9FFA160F990282FA8A78C64B71BBCFF05F27AB56CEBEC6C7E341B402B335F96BB471EE2E680EBEF4BBF178277D5D6D3D0B4EF00827EB1D8D287F1D57F73DEB029F44A8DFF9DA3F4F2FD342EC4CEF470198AB3F9F3898AF5D51E708A75DEEC7FDDDC516C55E06E84BED29A1D7496F7531267B45BF3AC8C8B60907E5E1252C79D1AA8B5BC1206D7DDD6A7A67014EB96437C92ED3D7BF728838863632DBE353C5552AEF90ADA63E60FA520431C3014FED3CE2C935EB81A4C13B3901FF8068CFE29C3D69503BF54700FE1A557B80ADC13A86B79AABC6EF03BE7B2B86F5A73C7A4FCE84DE853BD6A4D78E8F25EE401FECC12EA83CFAB79E667BC2A426E0CCD6902309959B6D6EF0E2C3B252492D6AC562A20C52CB376083E569F14D751E995629D8BC8FB4A3C2F814F9E09D7E9D0758C837C2C037F6AE4DB3BD395D6682E9C36030F0518533FD25634349798514411EC757D05EE1FA871A2A42C3B2C8253C5D7365B2C0BCCEB09996A3BBBE10D88F77700183A2DF5C2812F1AC2036CD94C91E025952148BB2204BF9B0BB0A0D78C64A78904791443EB6C67A3D72DC1AAA4951AEC837D7230807B793C8E09622A35063893AE016E677E73930751D9369B313DA46DEAD5EDC508459A72D092B78E73B97D1DC902D8490305B271428A761AFE49CF3587D5E3A22401A6765A716D30E4E581D7E424E500632C43DE8801C6AECBE4E43DC3AC6405916142BE033B7556D43A83192941FFE28792E1FBEB851366BFB9B1CFD8317B67FEBB29E4177C9345182F539B7886587DA4CC7F3F1452C0BB455A2AA6809D8627D5FB9F81BFA4AEF6C1F64EAC4068C0EA50426D5E6941638E4CD988B673554B66DBA3F43960B8B0121AD88077E10D94DE00AE0BCC0451DBDA34F03A7FB6B9DF427E3FB9E536C1885C0E61A0352B988E87594F7042A7B9A685893B0AF904CE73CB1DAC106F94EE2D70F0B385AAD755053FE94F3E3A84ECFE8EAF4ED36442790F941C879A30C877C68789F53F963845C46C9F4D6204529052A7DCE8D76B75A7662049BDF0ABB1A47D5B5390DAD794CB6776AA590BB8A959421D335BD545C32A2854CCC4619FCC7EB5AAF60B6DA4AD8603A22EAA85AE0C32E4BB5DCD2A775F7366B135886D987D96213FF717EB8E04AFDA5DC324C929EB5DED2A5CDF35EDBEACC2E199724487E3C6D6F7D4610BE95D319A83AAD9141254F0237A00415F548DF5A0F30148CF9F338526E7471E2A0ED7ED7BBC33B3E35FAFC42A6901780D1ABE1E060E7FD3D6C8FDCE479E28C3D68F5934F21D5C0D7293F410D6D811BD6D7B135FAB1D9D8343C9FAC7B9A657E770769C3C166EF3207A593BA381C3ADC190A7649F75A93A62CB7FA3E53DC666AE4785E474A9B264C21A98F8E5805902F7BF289E20449F6D54FB35FE8B310DB9633EBC0C94BB5CFA3EC7A93EE2FE25A8B9FAD4E2E739A55A441A9FD1A3E13C7B498BF71B2912FDCCA21FD7C5AEE387E4CCD9DFB7AC57356A49D51F8287FF1A069D58127AE2F28289A2814A2C93FF3F63AD17D0BDE7C9C36BF6DA0DAB9CA05DEC4C6BB4DE47350CAD97C7716FB32C345780BC32D5EB5672423659AFEF902A4123F10D58D846C01FEFEDBC145A0BF9B596C9ADC5EDD44EF99543FBAE6714FA59BC118D6978C2FE05569A0714D4FBB64DD4B0C4D9F9D662A15A862BD64C16B9F70291101049DE766B93A7AC4075997FC11A47B5111BFCFADC31C737FF2E91ACF2EA8CBE44BCD08599D1D0D6E4A2947882755A77F919A483B0D5DCE0DF68483C7A8C4EE4FE2BE51B9230DEB59FBDC0A922A690476B1C3941DF8ADA39D862C668976084B55BB72F22BCB584226B740E9B0FA55395D0EFAD0F419A9C1D5EA1C116533A39AE48D05E764C7127081B7AEC7BA838DB998929A2C10EDD95AA3D6BA3D3BD9F9D47EFA6C3EB4EDCCF73A0ABDCD744D988F2858EA5F08219551CCB9D530BF4D7B3E8522145212B51283F2A24EA53EA5147807798BB7187FF7924D7FF3C671BE9A89B0FC7388C59F08B30F03DFFFB4E2D0BF8046EF59D62C3BF9ABDAF11B682186D1A202880F6594BFF6D261E35378A26C3E9A5BE8F7903C8C390CD81D8595DB14F35658A121216B1B693E7F96626547D1C85F87F77D14DC294424A97B80FEFD7668C4489A4A6BCCC691D9FDD4BA80B0E287591B830C44D93BF0A20DEDE7FDF4671239161348CF2BE4E3933B5650CDCC51119179756510AF7FD79169754FAF5ACD304EA186D1C17401CE8194BBC3B1CD5A185C9C41CB24B5B4C0E8D4BCD0F965774FFF071E28E5AEAED3449A1BC46F67AC4E3A6FB526A9CC386CC96B7F704745699C582B2B5D1B958812C3EB975C227D2B684504166302CF7B2A653ABD6DC071BFDBF73D429BCFF15350D2B8F625F69DA687D940E1062160DA9BC7FA4F6EE55BCAB9108EFAC90505A8260B37C3DC6B4325B5A8A3C88B2BCF6AF20647A178185E87969461681B524F2AA1CC0DD68B52E0E3687367CD6DF15F1B79A94D182FA67533E2C216BD4EAC981C7610BAEA4649133F1F7747ED4B414AAD51AF14B46FC63A5BB753209F92005AB061B30FB89FB1CB8E5EBDDF6A022C870262A9BDA85DF9D085C8599C11D772FCFEE14A1AD344AC560F5871AD404B03B45365F8118FFE3BFB7B875365F5C023000BFD2A6EB77FEDFB7338BBE3587557D92D4E5C35D87DFA294F019AC03F208ECB3CCA2398253103B09BD08F89278BFD15479285848B5FCA2E9550A0BB3088CB03C1E36F558B9F6BB3D3E894A2AC8F79EFBDCA480A2350AFAB1FAE3791E5D7982F723C19A17BBAE0909DA9D53A0AE9DDCDE18592C8B73D3FDB85EA0F6B30095CA8239F8C8A5C5A754F930048632B34952F1A679A427FBCCEFFC676FCF0097391E50C016FA019F7347BC71285863C065181DA19DFC1EE69AA923FA58191D53C61188785697DB57048F92888AB2A4F0DA44807D22D6B8C186A757E241061F05D04733CD494E14E585307856CD959DE28B74F0672EEDAB09EED1B66B7D50877CD6502E28A52075DABBAF6ACDD0A7A33D02C542D872E5660E6FD8FDBF18C084FFFE48FE60D2A0B7CE5D735C94FC0AD2DC90DF3BF25085C5C4C100C95CFEC34E183456C8A374341C3EC7936E48BA370F2935EC8266E8C956C6FC62A4FEDF8F61BBBC16CC0B3408C9234614CBA74CB23775FFA8DC508F0A2F00620CBC3D675253933ABAFAF1AD0EC2024D117117C9B8C3B8A00C4133129C76B7087919F61B0634B72C9550106AE78240DBFEFCF5C137797C02D7439C0970288ACB65D92F5FADF14A17324F4324C68FE3A85AA33B27322CD1A869A41C404BE97BE874D6FADB2A9B7F2A2437EE1921D5A6E393E7F2EC010FA250A459EB2D2B6E5F106864FA6D7387905D9F4C26E48D75F244C147BEAB09D44D7F446E52CAE91E664B2C6B9F142A683B4282FCC05E7EE6CEF714D43B91B97B7BF78924D5AECA135A5F9AA5DB4C7D1728FCD9681685DBD6941A0D2CEE436E00F0F7A80C3B536514AAA9829C251300DC13F317A9A2AA632403B4783AB374CCDCEBCFB8DC18911A40A68C0289A9DF9B0C44C0A1AB1059D0B9D3C0AD45940B90BD232C6BC02F559CC59E37F3735446E4A10A0C365431EFF9578FE821B556A87899FF66C09E8095187B14D38B09A15091F57603FE1C959023E3BAFC5537C0B1992941A4D3F63C6AA4F828DBE455C3B443D51FF276FFD1BA4ED35D0CF9358D415709394ECDE535B1F7ECF3CFD6D46370E0A421E28927CAD2680F9A19A83457A8B80FB047D6A45865C7991A31C239C9D8ED053140EE454107510FF3265B0D5B122EC60990BD407621F50037CA2F1BE26B25E516F346767EC1A06D985CC65D75FF63394DA4A4EFCDF3F887B75D16E164E96CC973C0FCBE5B6C7AAE707B347EA9BC5D4EBB83F54F3499B603B1A1E2E96010D8DCDB7009C34E1ECD42F3D97973F7BA29AA4677023DB638497D943ADD18BF6E77F9EF3C38D35693B5BDC1BB777E174A4E8EBA9257D81AB8090443506703DC8EFE6B4780CE4648E43C9E5F1CF5CF4C9CDE0B3EA9A7BDD9BF7AAD7271C7833214DAB77AB40AE5558D386240219795658B861AE3A918A746792F427613C381467CCFF6A26B4AC2A7B1A45750EE26F901F0C145F31E0FF20B8D12C586A2A6F9D49940772AA98636D18928E3AB2424594EA5F51D1DA81A96F3EA9028922C4BC0A54F7B854775AF070DDEEE1DA4F3ECABA5B4E1C2734C49401E87ECC9A08415BFA6CDE797CFDA1E3078685966E8391ED0B430BCB7DBE29E8CD73B5F55A6176F5745D656C3C4A0EC626CCDB501C9208B7DED82D11FDB5B95FD81AC38AC3C8AFE2D7A128773B70C539550880371E010391FD79BE09434E969DD4A1DC028363CEA703F9521F2305319CE2715F94528E00B51D46ED926FB3DB29C14C7D6D0DA7AAB49DD2C51EB720D8EB0C2EBD1F7758EA520EE9AA2E186B7AC918093FFBF13DCA9F90D7EC3CE00E9EC77405FEE97DF43300486EAAD7463B8C890FA62D56E74CF10A173A13AB5832C0B8C1F069A4F58970465F2748E248E2D9A482456FA0C760B8DEAAF473ED3A93289150F2BA20DF0ECF7E47F5B6A02A9BFE8B274E3E81C410AB7C1148B3C508B73C16C7737E466E01F2C0C733B173DCC9265EB97CA476AAF005CE392821D2CF96B2F869936951F9B807CCC5E871C9DFE5A5331B835BBBAFA5AA31C577FE76CDB7A938FD905882FC41E11537541B5421CA46389EEF8A79CFB089C2156693DBCD3F20E13C9394251D4422A5FC2A6C3967C0975853CCB5ED99E6CB91B676C61FE7DE40A38D8314B922990454DC235F9B424038DC867AB90DE3AD64514CB7BF2298FFC85CC6AE79A09C1DD30DD9999BFD38184876995E1EB03A06520723B1D7F6A6DEED782197B38BB6D23BA42AF41336B5880223AD66008678EAF4793A3072D7C2FE01EDCF51853B3CF6DC9AE5979A2F7F8C3896889AF4A8CBBDC9A6D2F081936C203CC52393C2ED1E8BBEA10FCC434291C769BBC4DEF7FFC32580923FA4C6FA98EC6628D92BF6E948FC748099B7CD4B4F094B99EA1A7FD24915F0197C0BEA930B5759DC18924BDC6054D543B14114B33EFD9D2937D252F2C87EBB2407563D1E4026C1AD6B0C49EC32826B3D0C48510439F770BA292AB9CD05C5E9617E7D5ECC91E18C02454DABAFB7C653F09F57B7B2DF3AA16523CF00CC2807FA17BC00B286720B95C4FB313EDA5D938A29F6E1D400DDA5623103D1D726A687338428094341F04AD174579558416BA536FAF6A6535B8C2321FF42A2D0447FEC595373AA7F948E80CF4A3D6123FEA5A4D4D3155613FFDBA62FA89ED1C2BF940FD57B94FEE63F784C510AA52E02BBCBBFD1056264535468ED5259E9F8E1DF8A7578401CEEBE77A9363869AB7CED2D0019A17FB14D350D4FF16A52769076B0B5FC86935C02D46C3F83529871A346D240C8EA60A997DC1108D442F15BFDFAFCCEA90CF14E2DF5EA794A168D5E3EE192E3C550708C445AC2EED5C151ED4DB75511B0D653352998913976A40459CAE6C926303F12530BADA4FD411BE7BF2E611E4E7058440808C222D8A47C39E957040ABC80804E6C05C669F5DE5BF74C7035B5B08E5B5DD5A249A67EAB181A75A28359396857F4E411ADAACE2DE751AF40CEF0BEF2DC6DB03D721474646019B09497DD300B381A61F3A88DFB0C9B47B6BE0BDEC4C9AE0C80B3647182B9E88D9EA8B769759E10BB1F92B96DFF5C2015AFF4CD5CF2FFC267FE0C7C40C657AD1B60A7E91C224A3C841BFDDE8630AD19FCF32AC92FD5483488C4D9B4B1232BB8FD19EA1A1859143F7824A2A527878741B3BD9F6B7F55C6067BC0433061C36027C024660D7261D69B5FA91FF6DBC4F5CBF53B78114BECDD63275D7CEFF574E9981A7E6A1C537C7C2CCFEA575CB9EE63F7AF38A44B5C7AA62A41B98AEF8DA686B706D8E43FBCA5049A86D58CF1161F1DB14C09957B2BF071FEBE26C1581603015CDC6E7CD79FB00145B4D03BCD7964510212A0F28F02622682B084EFBDEBB86AC2A2065667212F523E9998DE51732183AEE3AC1080C6A36232D69D07F2EF9ADE9222AFEEFC1335AF2221B9336595FC20B776DF58C94A8C729103699DD15273F8CCFD744E93D8F98D3C765B0C3834659C736E5966E766DC067042C7F6A071257D2EF168CA32708F10DDC6BEA651FDB458F90A0EF6CFA2EA34C8A6BF23E9D753FB1CAC0AED8D5FA782652908D19BA5AD3065B1CDF46C412A38DFF62AD9F2F53AE5975A4BFE2D1A0AC7FF7A38FADAC92AF37FB21823BDEB5567AB37089826A6FC9D23E39AC5982CE27ED58AE0C1A9D670E78E517FEF925DC93220E42B1099DF52DF3CE1D04BB0B844FFA2AB81861E754CD748A1787885387FF32E4B7EDD2C85295611FF36F6AEB88806CA05281251F87D9EC15795C23663DE72D87E0339BE0E04CABDD27E9C140E2FDE63AEDC64AB577232843DEB304FE7298F9B4A04DD96ECB4A66AD36AC32A02DCAD88E5A95FF37ABDDC5C9A2573B46E9E2896A99EF0BBB8C30D0ECFDE6934CECDA9B1A09FED0FBF393A3BC0955AF9C375483D9E92F7AC8D4E28D2B81E2CB4F99CF2F41F362AB7DBC628A04A7D09E095C52DFB9362D1C0C2C8E8CB57C9D5E7D984B8CA76EFBFF071DCA07053B97475197F9B8E060638B16768E4DE279C937B377B5ABFF2225F31543402CC143829A6A70F67EA440D633444ABEDD521132473A8B4A87C601C858069E09B6A3A7D5D543E06F24C0F3B30E0F8BBDB78A3C912F09E3C49718C67AD995B772675ED5CEF2023909F3304C2B0F12635E40DB6E1F7905589C62A9D81E4DD39F60EC02D5616DDC891599A5967796467E6F27145E6906A3753CB0339B8B27D2AF99B7D2617D819A62AF4464B2FE4218CFFE24FFE0ED6D47435D8056FBC07BDD8A4C93E8906634A36F17F1CBB04A010593BC041758A21F43724848A620E0A2646AF4AEB3F3D5C4D4058DA20030EF9F8BF3A147AE34E6C2390097CE553A4A21011832AB4FD5F4A6DB5A48FE2ADB2FDB30AD72E041F1BA97164484B8AAB11F1D03A87D200C103D0EE3F34958DBFD06BDB9327F74474DC98E383ECB8CD4E8AA14A314FB2198E91DB011CA3E1B8FF2D5E1C1699144D5C2220EDA160929D04ED9220EC95BB1EED8175A874536794CA39441689BCBBE0AA8EE0EC6D9F9A043A4F548438ABF24343E8D8D17ABFDB3C0F8D8D3B64CCED5971CACBDED8FE06C652F067508F77225775A8E276152CAA766CB8EB7466EDF4A2A0E4FB5B0267EC265EEEFD253548F5FB02F328596E8D3D6D25CE45C52565B450159D988572254A9D025004539AD044B27D11D91A3D0A3F39696E804D05EE77634198F579FA730CDB0E6663ADC6A6DCA51B4BB39CC8F6E80B1693F87F00580465FECAFA76765FFD31ADA111261556CC61EE80A50954752D3C0F6BD9F8A4B97D1F8C79039308CA26C1540812F532F877F08C9C397D7891DF025D02419C215239BF97441E8C4658FE27FE1E9A33788B3E5108FA4ADE791464AB054AEC07F225E0EF3B8A8171497FEBD67BB392DD3CE54C4A0933C20141754A19B6680C322F7ADA91FCD718C4D54884CBFC8C53C32D1A13127C1B81CCB6DCC7534F57BACE4BE763CF76C0F850F7C9658B0078DD08C999707036571A92495151F428108D3BD48543D9951C5D9E8B4A6A96AECA1E07D0EF64DC938E548FC1F8EBD45E849B625F14551F80AEF82D7503FF8AE6DB8B3425B078C372ED5029A5C4878D49D3A28BD4517239FF44B849B3D6CAE3B8F953498535A7010F70B3D14E556338F7AC0340E7B8833A25116ACCB1883426BF9E7F08FD7F394D138943588C974A6A116AD2E8FC8982370251C9BF82BA8B53C9406999BF74A2C99400C969EF858CEED0ED873DDCFD6628373E7DA049CE4DDCF333DE18851B5798A7AEE563B1BA767FF1128ED0977E86A758EFB4170D4A7879637B2366057D015FBE1EBB62A4BE17EC558AEAC147B1581799E496877A15B662118A22C9A6CB0ADCD4D681EF96208BEE762F2CC3AC89038544CA31105AD535400D518330AD8D1C824E974A4B369CE1CBF4F05DB055C4B494BACF56C34E59731F22B88B77EB80DED3E08288611DBE559B8E8069CEF557F899C96FB08C61FD05D6F9680A8C37704B5EBE52074E5D7E046B5BB7C053306C882D44C3E737DE9D26E8D1E6E0212AB1534ED3993B7D843D5DB1A68E2987E5D7BCD98A353D8BBF1FF7F9D08C8CBB30AAFA853FA62AEC461262824FA656D596F6745EA110CC253692F5FE868190E7BFAC58FD64C07D5A355EE9575A741DB41E7E7A60734C6888A85F46BC00604B2F6ABDF66D5B74531156E8AB099875847D4FF55FD1B0FAA4B619B372B8D2D342E06882CCDFF16DA97D502B5A1702823C1A1718904241B3B1379CE7DA04F2A33CB000AD8BD5909C95DF37A1856231409DF4B7645C0F84428EF4575D7B874DE01ED58D8B57A076F47F74281584D0A70894176E27E41179CA3C574E02C91011BEF5BC712D6AC5570C1B9C76D6D9C19ADCF6206D8C45429D9002F851AFAC9290F54A01D61FAC9D2901A4B36982A17CC28E07FA945A055BBFCBDB1ECB93C7FCC0851F17529C4FA1D78A7A73E8040D78AECD8B19AB6C18B00D9C9D26C08428A3758CB877FB4F494EA8B367AC0A13F85DF19CA2F3373D8878FD1A679CEAF7543E378486E062FF1550C1C35634E515CA7438871D15C26028FB6D1A7610A00B11FEE74CC2D48731E50FB264545F38F593742A07A7FBF63C8BFA590D12470EC7B516228F2A7989F47BE08314514D5A81097F6285D75521348E11C64CC80211682303B2AFE14275F5F9025DC930844D5146211024B032CB68C504D29F6F83F6D8A9B3999F9FA1A31AA312B7A2BEE73860B035CFBFDBBB1CBCA25250845D1907B1A51BB068E5FE8615E1ECDFCCEF6EBA15882FB876349BF3591C7E9D25B6840783DEA61078FDC19069AC035BCF15393B40780609649CE657B694AD29756832183CBBF5052AAE321C9194555D8B51880746F30558CEC1C379E4D1BFAB195324BF098FAD571C7F2F45D0D5CA2715CB29753FC77C99273CA7E913128559F303F25CBC6B29B5C7C8CEC38D2C9476AAD68B6A2BB2AE0CAFE02B3344741FEB42BC72654C74FEA1355427EED32C7A536FEC5D32FDC71665683FD1BA0D5F0AEEB6A2EF087F0462080989324218174B809A38924E62D68E32C5F26AAE7D072A67963F051FAD158B023BC0098CF9DC57D2ED4EC137C7A12EBCC29C1D0B079DC812152C1E70E939CF5B7059F0919350CEE3FD714C45194093B5B0EF597C71FC5C2B529CDCC8BF55433A94DA775A56DEAC1B198E0763C81AAEF1F4DDC62D736336E8B446703F6BE87205D41560C7318892761DCDDFA7E41072C3DB47B1315B184FF4A2A9E3E855C9E8F936EB743BDE8A39A50E2146C358D991982FC50953E1A8F149503E516B2EA0976490378175A8A189E49B92DA4D61A033F4141289EC2D7930B8611DDC676FD538E86EA8638BCDA6AAB9B237CD126053662DA5C0406689060CF4C34E1C535B3B1C68A43AA0C8CDD9B5547912F33A6DF4067D7038A28B3DDC230F70316582FA23CCA5713A0667D1D665484C7D43AC157D2529D1167727E18EA3ABA2729E332201D2BCBF08B7931DD894E75F8419E087C6810F648784CDE08BAE29CE243F66BEC5CD655ECA72968D8AB055E357B390B771D0E2D85DF8F0673187329F441DCE2E783F1315D15257A8596D5D77EBFE67BE4E6EEBF36DDEFDD8E337B1221BF0FAE72841E2BE71DF265DC350B75BD1D39EE2A94D903F05F76F5AFD84F4F7AF1BF810C82E4B8AE0110BDEADF0EADD39FB5DD72E603D1301C21573CBC2D07CBDD44EAE2DF0562EAACD42E76091011A6B3B1DCE01B2CBFDC926011F5CF55723F96C6FAF0B551956C95E89FA5E073902E1726923E5C9E92D835A044647208C34C8A1EF9A93E38DD45E0397EADF4F57CD6D483FE92A1FC4E8070393992A77596148694AB6D5A74A215B9442AAB1F03117F32FBEA182D59D1257C441DE05E968A1AD49DA10664BFC2BE9C1BEC8321BAC49E19882931907AB237AB101D2D234E31A5C75C55E3913AF76C2D8A82DF818C458961412E804C51773A8142416C1BF0392EFB7E0F674435DF4808758307A54379EC7C391D6C6D2D23C6B3AA197072FFD1B0822812FB68B1C28EBD8BAD60283AD4AAB2B46BFDA0CB471E79782916B49CD3B5D5AB3289EE2C90D826CE27B43B9D4EECB0DE0D46B5B75BC4B201280999F94CE54FE90D67179578B00B11A50C8FF91FA171B30FF172139ED3024A1F66ECABE9DBCAB7BD5B3EB09FC0CF7F6A448A6E0ED16814A573C5079CFD343C17A766483F65563F7A9EDA77B62736D5091F00D31F29E185AF2C01400B355687D2E4D7C695D88E6B17A997F0570730B6C3C04CF3750720FF6DFC10CDD07DD9029F218EE6DDFAA5560275EA40195F71CFE9D1BDD437E5A951DBB5C13B2E90E0F1E9A15FC8C71A8881A484E91E690CA53F374F5EB17FB2A3FEFA5601667C49DAEB84434CBE9EB90F48832D86EBE493B7DD1C3D85097C6545266FEE81D6631BAF3B70CDA210D9B16CBC58DB26B4D913ED7C3C64822B755BA9366426700B756813A9E2600FC20FE4419E690A6525ABA94CDFE9F73E76C5919B709FA2051B5FD5B6BDF0C26E25F3D7637ADB47BD10DC38E87941CFD13C16047C4085F399636F1CE6261B316E84128EAFCB23548B31D221742915643835FBC1EF5F5670B4A39286CF66899F3240620DDD7A05DCFDF563C2C14A973BFA2E736FB54D71C081F008A5982159FF04936C1B550F92BBA5B11F612FE870BD493AA819559E229E5BC70D7035AB8E1D5693AB31F7E066A247C90DE7EBDD979F703E51263EA082BFC563FBCBA1EA84A3A90B3EC787E0FB9A50E6C9D84DF8025782BF6ABA5F3718955B2312F37AC78911A14BEFEE252A5EDAF8A05D5745EDE2E85776833B0C35FF88F963E1D6BBE43ABE4E1FC620E059CE15FA66E04EB001F94D09DEE7B575C731677CC047F3305941E8EF1D694F3AECB73F3C09023DAD6C593167222FFDDD29CBA75EF11D97890A1EFCA49DBB1933507F39DCB4EF417E80688A67C0FD5F45E6769A26ACAFAA2683E41B4A80CE05F",
     "AA52EF748A6DF1300D223B13A69A2111880B0FA36BA78F6CEDCE3B2E57FBF329D3194820BB41015BA982214CCB986AE65B411865AAD850395775E0034D13C0312BC377CF66EE67D84E2D7AFD623ECCB164B04498C2C664CF02CC469FC62A379B4FDE273DACF3E0C6E205B9C35CFCEB0DF6AF6A951DE2092248035010935714941EDB50777BE954BEE35E604C51ED4B1E2D5F3A7CD80E7FA57A9EA2E715005969E6C994ADFE105A2427D7768706C7F86FCD62145AE782D80F48C3400A8D4D02A80AAB89FD4C52922F3A7C45FF8878E41963D0D159E70F0E661BE9FC3771DD526EB6579CD381E06B0AD8254664DE3471D3E9214EB9DC4D69FD61270C4D1B765E15636E16D3122D9F779BB4EECA9F852A4EE29C372C2DA25F5244DDEE10A768DF3DAEECF9AF45F7BD2200474BEDE4BABFA345C337FFDD7A53EFB89F514FFC5621DB14C162C59A74099D0F873E03D55882E27132670F143580671F3CDCE34E4770644E47E4EDA77B7B426313AADEC2015FE1D8E5EB9D337DF3CBCF2D7CE39CE0EE88CE84FF9BB0453AEFEF4C8B56413F5638E6743A86BEE45015ED761B637C91C14ECA8B08BE5F9AD6E04CAAE9E3CCBDC6FBBB9AA1696C9E3EF10EEC6D0F863CA83EC347B228BA725228E3EF18D20450AB21864AB619C567F9941CEF9906B3D78C1965229E9A0865AC2B17A4600309DF4C1FBF3265F1DF140678E8AEBEC28BD064F38288A51B267F53379A2BA42017D2EAD5428BAD5CCEA67DA847B24FDD7ED65883094F8265CE0DA1A7940B2AFB6ED3B48E5AA57EC534FB1F3F9F81DB1B2F2D6504B047D8EA80BCE6D1D2967C5A1EEE88525FC9621E502A8E89DFAF4E063992ED62B06C37EED09CAA7BB32690C5CDD0A78C334155930B5A9A5979F5229EE2D2A3EE7A205EEF380F57BD873431696DF9E1471B896F6F01F8AA8465C8CD616E953DC44726556EC270B193241B65088CCBDDD6B1E3D4160F8713C52D6F5ADA4C0CF8D54EA2D857D9E5B4FE5F4DDFFCAC3BBC977CCF38C2A72C268EBF2C7F60F4F96A2F30781EE7813CD17F46BFA199DC659CFC567EDAB4C37082E784508737F62556358509777FA9236215445FF04ECA065089229D7F978A199F0CA9B885A46ACCB60C299144857F22BB0B8563150151187B0132DAC6E659170B996B0B9F2073ABFA9ECEAAAE65793BC6FFFA566006B68A28A14E9761C509FDC803459501B05AA8F131D654EEA7EFA7E19577D7EB5C9A8128446ED2072680F649EB5A5BB1EF1C03846D4D99698DDD4B07F2F5F2620BFCBADFD238B58563E69B048FFDE9DE9DF86BEA087DD714805FA813CD14CDF37AE91D4001CE52E683C61DE1DE6C44146E63673ED926C821F17BD616AB28CA5B2C9B68399F073386ADA732B82A50382C944057016D40CA8EE7F961651331886275DACB6479BBCE057DB8FA08A3834F06FF681F44FECD6BCA4545541472F9F0DF1E62D2CEF2B794DA8531118686421D85AE6AB3619F2F8E573A31D62E9EE04C94CF21466697E17A36D132CAEA6A38A044D1E486E2B0CA2D53E1610EEB48CA45CD0AB87C0CCE5408AD61A44812047C71B76CDC72796CF8F9B1A517B1B751ED5F5588CE25DD506C36306B37C18431EDB2D822B9192BA09F9FC3F69092B7D19CB18D6C6A70D19B81C622C49D95AD06177CFD6CEC194F38D30D0D1C4CD3FEB9A43A4F36AA439C1B1CF090FFAC5CFB83FB84B2296CF28DBCC417EA599F907A4F113FCD8F0CCEAF9EF1760F6ABD3892B1B6063F63C9B1626050E5C8FF809AADC1C2AB8EF80DB455E8D590668F658BF0F357B634AA9632F446BB0982A67E254E40B776E5591776384E601ACEFE393983BB4CD058A3E82ECF5E15E0376B3B5AB53896EE4D495999B7191F96B459B3D0169116C185836AE1C5B101B147F33D8BD83625FA6330AD051EA96EBDB69B4BC72A65980F8E8C2943BEDD849B5FC99ACB34007B88CAF16F9C1F2FA625C0F6D16FB3E0B3397B6623DC1317C169F7FF69F48D84C9CA078D3AF0E6BBBF57359BA7D93C9A2BF81F39A3BC5E4A388E08AA21A9510106A716AF369C25A9F80C207F8D1F781BF1C60248FC413BCAA1EF88A87C2838E8353092C998A7D1508AF096E1B976D5429FA85A7D72D0767B30B111973AB8BB86AB56E4AC54CF37FB81163A4D517996B1EA4C952006009B2139C968C556A703A1B5D72359AA4819523A9F0E59059FC5892E588188C72BBCF35922B8F81B1E4356F28352DE3171585B1547956E936E3A1FEB03E8E2474D836D3250C19903AE36D860964C34C14CE30653A27FB8FDADB8A3D69173754BEAE92993A645C1063EA6BBCE75D21ED540E52C39F348CB65B48C7AA0FB442F3F35479D811B2F4761A5387FF5872584CC06632B2CCCFBC20AE38C73ACC739051BCBA18214798CFC67CF111CE3E67B30E9334DACF5CEEA348394EB0411D74B97EFB4C8601EE184FEE3DEED35BCD1B2C7873B0EDF573EA81EFE361B5F71619E24B2AA0D137813F7D0F647D45CCF7A45D089C171FD36FD3D11645509DFA88E9D4732ECABE4BCF3CBFABDA70A64BED089ADBDB6B9FC4B45A50D509BD5E33F50410CE11DA44E96692578D5C3F2C975CF78442048C9B04062E3E8E4DFC71D7CCAAC10778BF63BB34A49E578C3C275ACC255B1419F423B9F6B46AE72EBA66145A4411CCDCBD4494FC506F7B6A2392DF840329AB285E12C16649B85515DB07D0A6CCDF0EC7139CA891E8BA84EA1B0F9B6ADDBFD328D5601CE7F794C7CB45022030EC82C8677F27012CF756B86C0CC1B32958369C07924C9A09D705A892FD8B241E99437F3AF048FE001476640FDC580C6A6875AF686003C84F4B08698D7B64F61E62A579B9146EBFCC6DD3C308C526611AC1DEEA9E1E3E62B272A69673BA61FB793CF354656619A359EF7C7F16BBC301AAB2AC042ABDF4EE5762368C9DE0644C6F7AD1AAE82BBC2D00DF2F453529AAD0BBE6925603629BFA36CB232BDDD0D5C372CFB08BE0D04D56D1A47961A0D065E90295B452AC02025AF9835736A020FD54E3AB8C766687B5F7A84063FD5B3D8BD7E2DCD9CB3648BB19045A70B023F1651103AE3BDFB810824F9A5E2AB2AFD060FD2090BB036A11A07924FED8820B14BEB20B3B7B2D7E3EEF7F1EF434C71C414754D3C8CC441DEA9852730A7D142122322ECF503D10D49C80055804E52FB03C8FB49AF10C066D4B3B951B7738A96D91671156C1CC22293C9CE8E47429FE69171C4B8FF7D766E90F7A0506B7150A754D13D3AE44A95B409C04057C2DACFD7701394C74E8CE08EA3C9068F5FC508442576203C332735A5BDC334441A09C9CE881CC8F5AFFF8D1535412AA083D0E2E635F6B1C5ABF01955D449062410BC15C21F204A79CBF1753C056F64A94737EE225ED2D944F658C3E51DF6198C5F1AD6F0AB46446DD54BC93AFDBC0C49EAA05627BC31BF34AEA9E58EC1F87B3ECBE1FA226D43DA88DF1EAA307BDE16F0EC48AE929E640D5B4AAEEA008334AED0A94D3C56960C1EDA3EBDD22EA9CBCB68C1C0B77BD239AF2D268FF881CF5BDB19442E93E189B1F98E865EBBE613699CA5A2CF405F23B7ADD7AF4E51CD75619C1A53ACEE085E78E85965DD900D77D29F4F0A1FE4C6BA4C26CBA88B41F33F60942E6DEF0E5A08595CB55633C304DFAB0E2C2763D09CB5D427A647154DB4990E6580F79FA29701ADD64AFDF6E09158B031D390AD18F140066A7B9F10E0D5C57B750973309D2C3F4620FEDDDA752596B83B8DC5CD1C4217EC8443523EEB2B8FB723DCB22BDB3F0E061B9C99E367A3D5D18310EBE40406C13F50C250DCA2AF5CBD04AF02818B93F37D97A015D74A38985C2D57F7A0047FD4E835F6C79409D5073D0C89640552674803AFBA475E6141523FBF53D1CD1D89D53DA01B2C729C862391B4D35CA7AEB3353FC93175609689F65B231D41B4CE86AE2537E48CD56AAFF48F1AB4F4F3C3BAE2A6DDD4060B3CB49F6DEEE5064B968E62B712ED1303B0F954B1EBCC7A25A13A02E210BA9765A03AABC8CB5859E5CF4FDED1CD36B41DE106E991D77A304B908E07C42A13953EAF6DDFF8C81EF02C201014FC343AF471EA9D1AF7F2EDA1EA57EBB247DD9823B25915BCA317197076BEB355540FD9FC3AD39E959D34A203DB9233070F0E23C21FE0F981024C8B621F4136A7AE3353583F582C3A7DBDDC75CAC4EB8A4DE980DA2775B407244D24F70CD35479B0F4A0B06AB5D8422621450B269DA4A6580BF3038A09CEC9022E71AF946F44C19FF62D17174F6EE8EA17A874E5AA672E02922DE26021904FFBE8077FDF75E3491C461BEBA8D57C338C3EDAF7CE6A6CCCD764AEF63D6357A9DFC7C504A025DBC6AE714CE097347D78962ED76E47274F0EA03DF2B7B3773BE5F4DC49A050D88492CA3326C66A5A34EA4B870256F143273C2B15385EEB4F09EA8FE602557C690F88C4353AC0C294345B2BC166E2D68A4DC6DD673228E5B524CD26C7EE9A0515CBC8A3B87C3E0733D02E9A7C757F255721477C774375A0CF8AA6B7CCAA25239AA23F58F0F6D09860A45478E69403439BC7C201BDE5F92B24EC4779A341CC9B1801282931E9AB07FDDF7186B94023AA18A6A06B66097A03115BB11AD6548BA3ADAFC4F426528AABCE1F23272F3977B3CCE60989A0A6CDF4FC2F45B9C3D22D496467A90000000000000000000000000000000000070C151C2126",
     ""),
]


def selftest() -> bool:
    print("=" * 62)
    print(" QARKE TUNNEL v1.5 (KEM-TRAIL-2160 Phase 4) — loopback self-test")
    print("=" * 62)
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        status = "PASS" if cond else "FAIL"
        if not cond:
            ok = False
        print(f"[{status}] {name}" + (f" — {detail}" if detail else ""))
        return cond

    # v1.5: self-test uses hybrid identities (Ed25519 + ML-DSA-65)
    comp_priv_a, comp_pub_a = HybridSignatureEngine.generate_composite_keypair()
    comp_priv_b, comp_pub_b = HybridSignatureEngine.generate_composite_keypair()
    # Legacy Ed25519 for migration/downgrade tests
    sk_a = nacl.signing.SigningKey.generate()
    sk_b = nacl.signing.SigningKey.generate()
    pk_a, pk_b = bytes(sk_a.verify_key), bytes(sk_b.verify_key)

    def hs_pair(kem_init: int, kem_resp: int):
        """Loopback handshake with given kem_ids. Returns (ok, err, cli, srv)."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        box = {}

        def server_thread():
            try:
                conn, _ = srv.accept()
                t = Tunnel(conn, comp_priv_b, comp_pub_b, ID_SCHEME_HYBRID,
                           "resp", comp_pub_a, tofu_interactive=False,
                           kem_id=kem_resp)
                t.handshake_as_resp()
                box["server"] = t
            except Exception as e:
                box["server_err"] = e

        th = threading.Thread(target=server_thread, daemon=True)
        th.start()
        try:
            cli_sock = socket.create_connection(("127.0.0.1", port), timeout=15)
            cli = Tunnel(cli_sock, comp_priv_a, comp_pub_a, ID_SCHEME_HYBRID,
                         "init", comp_pub_b, tofu_interactive=False,
                         kem_id=kem_init)
            cli.handshake_as_init()
            th.join(timeout=15)
            if "server_err" in box:
                return False, f"server: {box['server_err']}", None, None
            return True, "", cli, box["server"]
        except Exception as e:
            return False, str(e), None, None
        finally:
            srv.close()

    # 0. KEM handshake matrix — 768, 1024, classical, + downgrade rejection
    kem_names = {KEM_MLKEM768: "ML-KEM-768", KEM_MLKEM1024: "ML-KEM-1024",
                 KEM_NONE: "classical"}
    for kid in (KEM_MLKEM768, KEM_MLKEM1024, KEM_NONE):
        t0 = time.monotonic()
        good, err, _, _ = hs_pair(kid, kid)
        ms = (time.monotonic() - t0) * 1000.0
        check(f"hybrid handshake kem_id={kid} ({kem_names[kid]})", good,
              f"{ms:.0f} ms" if good else err)
    # downgrade attempt: init proposes 768, responder is classical-only
    good, err, _, _ = hs_pair(KEM_MLKEM768, KEM_NONE)
    check("downgrade rejected (768 vs off)", not good,
          "correctly aborted" if not good else "DANGER: downgrade accepted!")
    # reverse: init classical, responder demands PQ
    good, err, _, _ = hs_pair(KEM_NONE, KEM_MLKEM768)
    check("policy mismatch rejected (off vs 768)", not good,
          "correctly aborted" if not good else "DANGER: mismatch accepted!")

    # 1. full session on the default hybrid (ML-KEM-768) for the
    #    message-exchange / tamper / replay / rekey tests below
    t0 = time.monotonic()
    good, err, cli, srv_tun = hs_pair(KEM_MLKEM768, KEM_MLKEM768)
    hs_ms = (time.monotonic() - t0) * 1000.0
    check("mutual-auth handshake (pinned keys, ML-KEM-768)", good,
          f"{hs_ms:.1f} ms" if good else err)
    if not good:
        return False
    check("peer fingerprints match both sides",
          fingerprint(cli.peer_pub) == fingerprint(comp_pub_b)
          and fingerprint(srv_tun.peer_pub) == fingerprint(comp_pub_a))

    # 2. bidirectional message exchange — persistent server pump thread
    #    (recv_msg auto-replies PING and handles rekey internally)
    N = 100
    got_b, got_a = [], []
    srv_stop = threading.Event()
    srv_err = []

    def srv_pump():
        try:
            while not srv_stop.is_set():
                ptype, p = srv_tun.recv_msg(timeout=0.5)
                if ptype == PT_DATA:
                    got_b.append(p)
        except (TunnelError, socket.timeout):
            if not srv_stop.is_set():
                srv_err.append("pump died")

    pt = threading.Thread(target=srv_pump, daemon=True)
    pt.start()

    def wait_for(cond, timeout=15, desc=""):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if cond():
                return True
            time.sleep(0.01)
        return False

    t0 = time.monotonic()
    for i in range(N):
        cli.send_msg(f"c2s-{i}".encode())
    ok_c2s = wait_for(lambda: len(got_b) >= N, desc="c2s")
    for i in range(N):
        srv_tun.send_msg(f"s2c-{i}".encode())
    for i in range(N):
        ptype, p = cli.recv_msg(timeout=10)
        assert ptype == PT_DATA
        got_a.append(p)
    xfer_ms = (time.monotonic() - t0) * 1000.0
    check("bidirectional exchange 100+100 msgs, order+content intact",
          ok_c2s and not srv_err
          and got_b == [f"c2s-{i}".encode() for i in range(N)]
          and got_a == [f"s2c-{i}".encode() for i in range(N)],
          f"{xfer_ms:.1f} ms total")

    # 3. per-message latency (ping RTT; server pump auto-replies)
    rtts = [cli.ping(timeout=10) for _ in range(20)]
    check("ping/pong RTT (20 samples)",
          all(r > 0 for r in rtts),
          f"mean {sum(rtts)/len(rtts):.2f} ms min {min(rtts):.2f} max {max(rtts):.2f}")

    # 4. tamper rejection — flip a byte in a live frame, feed to decrypt
    frame = cli._encrypt_frame(PT_DATA, b"tamper-me")
    nlen = struct.unpack("!I", frame[:4])[0]
    raw = bytearray(frame[4:4 + nlen])
    raw[20] ^= 0x01  # flip a ciphertext byte
    try:
        srv_tun._decrypt_frame(bytes(raw))
        check("tamper rejection (flipped ct byte)", False, "accepted!")
    except TunnelError:
        check("tamper rejection (flipped ct byte)", True)

    # 5. replay rejection — deliver the same valid frame twice
    frame2 = cli._encrypt_frame(PT_DATA, b"replay-me")
    nlen2 = struct.unpack("!I", frame2[:4])[0]
    raw2 = frame2[4:4 + nlen2]
    try:
        srv_tun._decrypt_frame(raw2)  # first delivery OK
        try:
            srv_tun._decrypt_frame(raw2)  # replay must die
            check("replay rejection (duplicate frame)", False, "accepted!")
        except ReplayError:
            check("replay rejection (duplicate frame)", True)
    except TunnelError as e:
        check("replay rejection (duplicate frame)", False, f"first delivery failed: {e}")

    # 6. directional key separation (reflection impossible by construction)
    check("directional key separation (k_send != k_recv)",
          cli.k_send != cli.k_recv and srv_tun.k_send != srv_tun.k_recv
          and cli.k_send == srv_tun.k_recv and cli.k_recv == srv_tun.k_send)

    # 7. rekey then keep talking (server pump handles REQ; main pumps ACK)
    ep0 = cli.epoch
    cli.rekey()
    deadline = time.monotonic() + 10
    while (cli.epoch == ep0 or srv_tun.epoch == ep0) \
            and time.monotonic() < deadline:
        try:
            cli.recv_msg(timeout=0.2)  # handles the REKEY_ACK
        except (TunnelError, socket.timeout):
            pass
    rekeyed = cli.epoch == ep0 + 1 and srv_tun.epoch == ep0 + 1
    check("rekey (epoch+1 both sides)", rekeyed,
          f"epoch {ep0} -> {cli.epoch}/{srv_tun.epoch}")
    if rekeyed:
        n_before = len(got_b)
        cli.send_msg(b"post-rekey-c2s")
        ok_post = wait_for(lambda: len(got_b) > n_before)
        srv_tun.send_msg(b"post-rekey-s2c")
        ptype2, p2 = cli.recv_msg(timeout=10)
        check("traffic after rekey decrypts",
              ok_post and got_b[-1] == b"post-rekey-c2s"
              and p2 == b"post-rekey-s2c")

    srv_stop.set()
    pt.join(timeout=5)

    # 8. wrong peer key rejected
    srv2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv2.bind(("127.0.0.1", 0))
    srv2.listen(1)
    port2 = srv2.getsockname()[1]
    box2 = {}

    def server2_thread():
        conn = None
        try:
            conn, _ = srv2.accept()
            t = Tunnel(conn, comp_priv_b, comp_pub_b, ID_SCHEME_HYBRID,
                       "resp", comp_pub_a, tofu_interactive=False)
            t.handshake_as_resp()
            box2["server"] = t
        except Exception as e:
            box2["err"] = e
        finally:
            if conn is not None:  # slam the door on auth failure (mirrors do_serve)
                try:
                    conn.close()
                except Exception:
                    pass

    th2 = threading.Thread(target=server2_thread, daemon=True)
    th2.start()
    # Evil peer uses a different hybrid identity
    comp_priv_evil, comp_pub_evil = HybridSignatureEngine.generate_composite_keypair()
    s3 = socket.create_connection(("127.0.0.1", port2), timeout=10)
    evil = Tunnel(s3, comp_priv_evil, comp_pub_evil, ID_SCHEME_HYBRID,
                  "init", comp_pub_b, tofu_interactive=False)
    try:
        evil.handshake_as_init()
        check("wrong peer identity rejected", False, "handshake accepted!")
    except (HandshakeError, TunnelError, TimeoutError, socket.timeout, OSError) as e:
        th2.join(timeout=10)
        server_said = box2.get("err")
        check("wrong peer identity rejected",
              evil.peer_pub is None
              and isinstance(server_said, HandshakeError)
              and "MISMATCH" in str(server_said),
              f"client saw {type(e).__name__}; server: {server_said}")
    th2.join(timeout=10)
    s3.close()
    srv2.close()

    cli.close()
    try:
        srv_tun.close()
    except Exception:
        pass

    # -- Phase 3: monitor verification -------------------------------------
    # Ledger: hash chain intact after a full session
    st = srv_tun.monitor.status()
    check("monitor ledger intact (hash chain verifies)",
          st["ledger_valid"],
          f"{st['ledger_entries']} entries")
    check("monitor recorded handshake events",
          st["ledger_entries"] >= 4,
          f"{st['ledger_entries']} entries logged")

    # Ledger tamper-evidence: flip a byte, verify() must catch it
    hub_t = MonitorHub(quiet=True)
    hub_t.ledger.append("probe", ALERT_INFO, {"x": 1})
    hub_t.ledger.entries[-1]["details"]["x"] = 2  # tamper
    tok, bad_idx = hub_t.ledger.verify()
    check("ledger tamper-evident (modified entry detected)",
          (not tok) and bad_idx >= 0,
          f"caught at index {bad_idx}")

    # SENTINEL: learns baseline, flags extreme anomaly
    hub_s = MonitorHub(quiet=True)
    for _ in range(20):
        hub_s.sentinel.observe("probe_ms", 50.0)
    z0, l0 = hub_s.sentinel.observe("probe_ms", 50.0)
    z1, l1 = hub_s.sentinel.observe("probe_ms", 50000.0)
    check("SENTINEL baseline: normal value silent",
          l0 is None, f"z={z0:.2f}")
    check("SENTINEL anomaly: extreme value flagged",
          l1 in (ALERT_WARN, ALERT_CRITICAL), f"{l1} z={z1:.1f}")

    # WARDEN: handshake flood + downgrade signatures
    hub_w = MonitorHub(quiet=True)
    fired = None
    for _ in range(6):
        lv, ms = hub_w.warden.signal("handshake_failed")
        if lv:
            fired = lv
    check("WARDEN handshake flood detected",
          fired in (ALERT_WARN, ALERT_CRITICAL), f"level={fired}")
    lv2, _ = hub_w.warden.signal("downgrade_attempt")
    check("WARDEN downgrade attempt flagged",
          lv2 == ALERT_WARN, f"level={lv2}")

    # Tunnel-integrated: tamper + replay route to WARDEN via hooks
    hub_i = MonitorHub(quiet=True)
    hub_i.on_tamper("integration probe")
    hub_i.on_tamper("integration probe")
    hub_i.on_replay("integration probe")
    st_i = hub_i.status()
    check("tunnel hooks feed WARDEN detections",
          st_i["warden_detections"] > 0,
          f"{st_i['warden_detections']} detections")

    # --- Phase 4: hybrid identity specific checks ---
    # 24. Stripped-PQ rejection: Ed25519-only peer vs hybrid-required server
    def _stripped_pq_test():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        box = {}
        def srv_thread():
            try:
                conn, _ = srv.accept()
                # Server: hybrid identity, requires hybrid peer (default)
                t = Tunnel(conn, comp_priv_b, comp_pub_b, ID_SCHEME_HYBRID,
                           "resp", None, tofu_interactive=False,
                           kem_id=KEM_MLKEM768, require_hybrid_peer=True)
                t.handshake_as_resp()
                box["ok"] = True
            except Exception as e:
                box["err"] = str(e)
            finally:
                try: conn.close()
                except: pass
        th = threading.Thread(target=srv_thread, daemon=True)
        th.start()
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=10)
            # Client: legacy Ed25519-only identity
            evil_sk = nacl.signing.SigningKey.generate()
            evil_priv = bytes(evil_sk)
            evil_pub = bytes(evil_sk.verify_key)
            t = Tunnel(s, evil_priv, evil_pub, ID_SCHEME_ED25519,
                       "init", None, tofu_interactive=False,
                       kem_id=KEM_MLKEM768, require_hybrid_peer=True)
            try:
                t.handshake_as_init()
            except Exception:
                pass  # client-side close is expected
            s.close()
        except Exception:
            pass
        finally:
            th.join(timeout=10)
            srv.close()
        # The rejection happens server-side: check the server's error
        srv_err = box.get("err", "")
        if "stripped PQ" in srv_err:
            return True, f"server rejected: {srv_err[:80]}"
        if box.get("ok"):
            return False, "stripped-PQ handshake was NOT rejected (server accepted!)"
        return False, f"wrong server error: {srv_err[:80]}"
    sp_ok, sp_detail = _stripped_pq_test()
    check("stripped-PQ identity rejected (Ed25519-only vs hybrid-required)",
          sp_ok, sp_detail)

    # 25. Hybrid signature tamper rejection (flipped bit in ML-DSA sig)
    comp_priv_t, comp_pub_t = HybridSignatureEngine.generate_composite_keypair()
    msg_t = b"qarke v1.5 tamper probe"
    sig_t = HybridSignatureEngine.sign(msg_t, comp_priv_t)
    # Flip a byte in the PQ signature portion (offset 2+64+2 = 68)
    sig_tampered = bytearray(sig_t)
    sig_tampered[100] ^= 0x01
    check("hybrid signature tamper rejected (flipped PQ sig byte)",
          not HybridSignatureEngine.verify(bytes(sig_tampered), msg_t, comp_pub_t))
    # Sanity: untampered verifies
    check("hybrid signature valid (untampered control)",
          HybridSignatureEngine.verify(sig_t, msg_t, comp_pub_t))

    # 26. Wrong-key hybrid verification fails
    _, comp_pub_other = HybridSignatureEngine.generate_composite_keypair()
    check("hybrid signature wrong-key rejected",
          not HybridSignatureEngine.verify(sig_t, msg_t, comp_pub_other))

    # 27. NIST ACVP ML-DSA-65 known-answer vectors (official, FIPS 204)
    kat_ok = True
    for _mode, _pk_h, _pay_h, _sig_h, _extra in ML_DSA_65_KAT_VECTORS:
        _pk = bytes.fromhex(_pk_h)
        _sig = bytes.fromhex(_sig_h)
        _pay = bytes.fromhex(_pay_h)
        try:
            if _mode == "pure":
                _good = ML_DSA_65.verify(_pk, _pay, _sig,
                                         ctx=bytes.fromhex(_extra))
            elif _mode == "prehash":
                _ctx_h, _halg = _extra.split("|")
                _good = ML_DSA_65.verify_prehash(_pk, _pay, _sig,
                                                 ctx=bytes.fromhex(_ctx_h),
                                                 hash_name=_halg)
            elif _mode == "mu":
                _good = ML_DSA_65.verify_mu(_pk, _pay, _sig)
            elif _mode == "internal":
                _good = ML_DSA_65.verify_internal(_pk, _pay, _sig)
            else:
                _good = False
        except Exception:
            _good = False
        if not _good:
            kat_ok = False
            break
    # Negative probe: a tampered KAT signature must NOT verify
    if kat_ok:
        _m0, _pk0_h, _pay0_h, _sig0_h, _ex0_h = ML_DSA_65_KAT_VECTORS[0]
        _bad = bytearray(bytes.fromhex(_sig0_h))
        _bad[10] ^= 0x01
        kat_ok = not ML_DSA_65.verify(bytes.fromhex(_pk0_h),
                                      bytes.fromhex(_pay0_h), bytes(_bad),
                                      ctx=bytes.fromhex(_ex0_h))
    check("NIST ACVP ML-DSA-65 KAT (12 official vectors, 4 modes)", kat_ok)

    print("=" * 62)
    print("SELF-TEST:", "ALL CHECKS PASSED" if ok else "FAILURES PRESENT")
    print("=" * 62)
    return ok


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def build_parser():
    ap = argparse.ArgumentParser(
        description="QARKE TUNNEL v1.5 — E2E encrypted tunnel for mission comms "
                    "(Phase 4: hybrid Ed25519+ML-DSA-65 identity)")
    ap.add_argument("--gen-key", action="store_true",
                    help="generate (or show) the v1.5 hybrid identity")
    ap.add_argument("--upgrade-identity", action="store_true",
                    help="migrate legacy Ed25519 identity to v1.5 hybrid "
                         "(preserves Ed25519 keypair)")
    ap.add_argument("--keyfile", default=DEFAULT_KEYFILE_V15,
                    help="identity file path")
    ap.add_argument("--peer-key", default=None,
                    help="pinned peer pubkey (hex). If omitted: TOFU prompt.")
    ap.add_argument("--selftest", action="store_true",
                    help="run loopback crypto self-test")
    ap.add_argument("--kem", default="768", choices=["768", "1024", "off"],
                    help="KEM mode: 768 (hybrid X25519+ML-KEM-768, default), "
                         "1024 (hybrid X25519+ML-KEM-1024), off (classical). "
                         "Both sides must agree; mismatch aborts the handshake.")
    ap.add_argument("--allow-legacy-peer", action="store_true",
                    help="accept Ed25519-only peers (migration mode). "
                         "Default: reject stripped-PQ identities.")
    sub = ap.add_subparsers(dest="mode")
    # v1.1: subparser copies use SUPPRESS so a flag given BEFORE the subcommand
    # is never clobbered by a subparser default. Flag position no longer matters.
    s = sub.add_parser("serve", help="listen for peers")
    s.add_argument("--port", type=int, default=DEFAULT_PORT)
    s.add_argument("--keyfile", default=argparse.SUPPRESS)
    s.add_argument("--peer-key", default=argparse.SUPPRESS)
    s.add_argument("--kem", default=argparse.SUPPRESS)
    s.add_argument("--allow-legacy-peer", action="store_true",
                   default=argparse.SUPPRESS)
    c = sub.add_parser("connect", help="dial a listener")
    c.add_argument("--host", required=True)
    c.add_argument("--port", type=int, default=DEFAULT_PORT)
    c.add_argument("--keyfile", default=argparse.SUPPRESS)
    c.add_argument("--peer-key", default=argparse.SUPPRESS)
    c.add_argument("--kem", default=argparse.SUPPRESS)
    c.add_argument("--allow-legacy-peer", action="store_true",
                   default=argparse.SUPPRESS)
    return ap


def main():
    ap = build_parser()
    args = ap.parse_args()

    if args.selftest:
        sys.exit(0 if selftest() else 1)

    if args.upgrade_identity:
        upgrade_identity(DEFAULT_KEYFILE, args.keyfile)
        return

    if args.gen_key:
        comp_priv, comp_pub, scheme = load_identity_v15(args.keyfile)
        scheme_name = ("hybrid Ed25519+ML-DSA-65"
                       if scheme == ID_SCHEME_HYBRID else "Ed25519 (legacy)")
        print(f"identity file : {args.keyfile} (mode 0600)")
        print(f"scheme        : {scheme_name}")
        print(f"pubkey (hex)  : {comp_pub.hex()}")
        print(f"fingerprint   : {fingerprint(comp_pub)}")
        print("share the pubkey hex with your peer over a trusted channel,")
        print("then run with --peer-key <hex> on both sides.")
        return

    peer_hex = args.peer_key
    if peer_hex:
        try:
            raw = bytes.fromhex(peer_hex)
            # v1.5: accept 32B Ed25519 or 1988B hybrid composite pubkey
            assert len(raw) in (32, 1988), f"got {len(raw)} bytes"
        except Exception as e:
            sys.exit(f"[!] --peer-key must be 64 hex chars (Ed25519) or "
                     f"3976 hex chars (hybrid composite): {e}")

    kem_id = {"768": KEM_MLKEM768, "1024": KEM_MLKEM1024, "off": KEM_NONE}[args.kem]
    kem_name = {KEM_MLKEM768: "ML-KEM-768", KEM_MLKEM1024: "ML-KEM-1024",
                KEM_NONE: "classical (X25519 only)"}[kem_id]
    print(f"[*] QARKE v1.5 — KEM mode: {kem_name} — identity: hybrid Ed25519+ML-DSA-65")

    allow_legacy = getattr(args, "allow_legacy_peer", False)
    if args.mode == "serve":
        do_serve(args.port, args.keyfile, peer_hex, kem_id,
                 allow_legacy_peer=allow_legacy)
    elif args.mode == "connect":
        do_connect(args.host, args.port, args.keyfile, peer_hex, kem_id,
                   allow_legacy_peer=allow_legacy)
    else:
        ap.print_help()
        print("\nexamples:")
        print("  python qarke_tunnel_v15.py --gen-key")
        print("  python qarke_tunnel_v15.py --upgrade-identity")
        print("  python qarke_tunnel_v15.py serve --port 8471 --peer-key <hex>")
        print("  python qarke_tunnel_v15.py connect --host 10.0.0.5 --port 8471 --peer-key <hex>")


if __name__ == "__main__":
    main()
