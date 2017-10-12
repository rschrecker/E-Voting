# -*- coding: utf-8 -*-
"""
Created on Tue Aug 01 18:51:33 2017

@author: Rowan Schrecker
"""

import random
import hashlib


def mod_exp(a, n, p):
    # Returns a**n % p.
    if n < 0:
        return mod_exp(a, -n * (p-2), p)
    length = n.bit_length()
    powers = [0] * length
    powers[-1] = a
    for i in range(length-1):
        powers[-i-2] = powers[-i-1]**2 % p
    x = 1
    bin_str = format(n, 'b')
    for i in range(length):
        if bin_str[i] == '1':
            x = x*powers[i] % p
    return x


def is_prime(p):
    # Returns True if p is prime.
    if p <= 1:
        return False
    x = 2
    while 1:
        if x * x > p:
            return True
        if p % x == 0:
            return False
        x += 1


def miller_rabin(p, k=10):
    # Returns True if p is 'probably prime', with confidence 1 - 2**(-2*k).
    s = 0
    d = p - 1
    while d % 2 == 0:
        d //= 2
        s += 1
    for x in range(k):
        a = random.randint(2, p - 1)
        if mod_exp(a, d, p) != 1:
            for r in range(s):
                if mod_exp(a, 2**r * d, p) == p - 1:
                    break
            else:
                return False
    return True


primes = [p for p in range(65000) if is_prime(p)]


def sieve(m, n):
    # Returns list of ints between m, n-1 not divisble by a prime below 65000.
    remaining = list(range(m, n))
    for p in primes:
        x = -m % p
        i = 0
        while x + i*p < n - m:
            remaining[x + i*p] = 0
            i += 1
    return [x for x in remaining if x != 0]


def find_prime_iter(iterable, k=10):
    # Returns a generator which yield primes from iterable.
    for x in iterable:
        if miller_rabin(x, k):
            yield x


def find_prime(n, presieve=True, length=2**15, k=10):
    # Returns a prime between n, 2*n+length. xx
    r = random.randint(0, n)
    if presieve:
        candidates = sieve(n+r, n+r+length)
    else:
        candidates = range(n+r, n+r+length)
    return next(find_prime_iter(candidates, k))


def find_safe_prime_iter(iterable, k=10):
    # Returns a generator which yeilds safe primes 2*p+1 for p in iterable. xx
    for p in find_prime_iter(iterable, k):
        if miller_rabin(2*p + 1):
            yield 2*p + 1


def find_safe_prime(n, presieve=True, length=2**15, k=10):
    # Returns a safe prime between n, 2*n+length. xx
    N = n // 2
    r = random.randint(0, N)
    if presieve:
        candidates = sieve(N+r, N+r+length)
    else:
        candidates = range(N+r, N+r+length)
    return next(find_safe_prime_iter(candidates, k))


class ElGamal:
    
    def __init__(self, p, g, h):
        self.p, self.g, self.h = p, g, h
        self.q = p // 2
    
    def encrypt(self, m, y=None):
        # Encrypts the message m according to the ElGamal encryption scheme.
        # m should be int between 1, q.
        if y is None:
            y = random.randint(1, self.q - 1)
        M = mod_exp(m, self.q + 1, self.p)
        # Note that this is m or -m, whichever is a quadratic residue.
        c1 = mod_exp(self.g, y, self.p)
        c2 = M*mod_exp(self.h, y, self.p)
        return (c1, c2)
    
    def decrypt(self, c1, c2, x):
        # Decryts the cypher-text (c1, c2) with private key x.
        M = c2 * mod_exp(c1, -x, self.p) % self.p
        if M > self.q:
            M = self.p - M
        return M


def easy_elgamal(n):
    # Returns an ElGamal instance and the private key.
    # q is between n, 2*n+2**15. xx
    p = find_safe_prime(2 * n)
    g = 4
    x = random.randint(1, p//2 - 1)
    h = mod_exp(g, x, p)
    return ElGamal(p, g, h), x


class Commitment:
    
    def __init__(self, p, g, h):
        self.p, self.g, self.h = p, g, h
        self.q = p // 2
        
    def commit(self, s, t=None):
        # Return a commitment to s, and the key t to check it.
        # By brodcasting the commitment, one commits to s without revealing
        # what it is. Revealing s, t later will show that s was indeed the
        # value committed to.
        if t is None:
            t = random.randint(0, self.q)
        commitment = mod_exp(self.g, s, self.p)*mod_exp(self.h, t, self.p) \
                     % self.p
        return commitment, t

    def check(self, commitment, s, t):
        # Check the commitment.
        x = mod_exp(self.g, s, self.p)*mod_exp(self.h, t, self.p) % self.p
        return commitment == x
    

class Hash:
    
    def __init__(self):
        self.h = hashlib.sha256()
    
    def update(self, m):
        self.h.update(m.to_bytes((m.bit_length() + 7) // 8, byteorder='big'))
    
    def digest(self):
        return int(self.h.hexdigest(), 16)
    
    @staticmethod
    def easy_hash(m):
        h = Hash()
        h.update(m)
        return h.digest()


class Signature:
    
    def __init__(self, p, g, h):
        self.p, self.g, self.h = p, g, h
        self.q = p // 2
        
    def sign(self, m, x, k=None):
        if k is None:
            k = random.randint(1, self.q - 1)
        r = mod_exp(self.g, k, self.p) % self.q
        H = Hash.easy_hash(m)
        s = mod_exp(k, -1, self.q)*(H+x*r) % self.q
        if r * s == 0:
            return self.sign(m)
        else:
            return (r, s)
    
    def check(self, m, r, s):
        if r <= 0 or r >= self.q or s <= 0 or s >= self.q:
            return False
        w = mod_exp(s, -1, self.q)
        h = hashlib.sha256()
        h.update(m.to_bytes((m.bit_length() + 7) // 8, byteorder='big'))
        H = int(h.hexdigest(), 16)
        u1 = H*w % self.q
        u2 = r*w % self.q
        v = mod_exp(self.g, u1, self.p)*mod_exp(self.h, u2, self.p) % self.p \
            % self.q
        return v == r
