# -*- coding: utf-8 -*-
"""
Created on Tue Aug 01 18:51:33 2017

@author: Rowan Schrecker
"""

import random


def log2(n):
    #returns floor of log base 2 of n
    x = 0
    while 2**x <= n:
        x += 1
    return x-1

def binary_list(n):
    #returns the binary expansion of n as a list
    x = [0] * (log2(n)+1)
    m = n
    while m != 0:
        l = log2(m)
        x[l] = 1
        m = m - 2**l
    return x

def mod_exp(a, n, p):
    #returns a**n % p
    length = log2(n)+1
    bin_n = binary_list(n)
    powers = [0]*length
    powers[0] = a
    for i in range(length-1):
        powers[i+1] = powers[i]**2 % p
    x = 1
    for i in range(length):
        if bin_n[i]:
            x = x*powers[i] % p
    return x


def is_prime(p):
    #returns True if p is prime
    if p <= 1:
        return False
    x = 2
    while 1:
        if x*x > p:
            return True
        if p%x == 0:
            return False
        x += 1


def miller_rabin(p, k=10):
    #returns True if p is 'probably prime', with confidence 1 - 2**(-2*k)
    s = 0
    d = p-1
    while d%2 == 0:
        d //= 2
        s += 1
    for x in range(k):
        a = random.randint(2, p-1)
        if mod_exp(a, d, p) != 1:
            for r in range(s):
                if mod_exp(a, 2**r * d, p) == p-1:
                    break
            else:
                return False
    return True


primes = [p for p in range(65000) if is_prime(p)]


def sieve(m, n):
    #returns list of ints between m, n-1 not divisble by a prime below 65000.
    remaining = list(range(m, n))
    for p in primes:
        x = -m % p
        i = 0
        while x + i*p < n-m:
            remaining[x + i*p] = 0
            i += 1
    return [x for x in remaining if x != 0]


def find_prime_iter(iterable, k=10):
    #returns a generator which yield primes from iterable
    for x in iterable:
        if miller_rabin(x, k):
            yield x


def find_prime(n, presieve=True, length=2**15, k=10):
    #returns a prime between n, 2*n+length
    r = random.randint(0, n)
    if presieve:
        candidates = sieve(n+r, n+r+length)
    else:
        candidates = range(n+r, n+r+length)
    return next(find_prime_iter(candidates, k))


def find_safe_prime_iter(iterable, k=10):
    #returns a generator which yeilds safe primes 2*p+1 for p in iterable
    count = 0
    for p in find_prime_iter(iterable, k):
        if miller_rabin(2*p + 1):
            yield 2*p + 1


def find_safe_prime(n, presieve=True, length=2**15, k=10):
    #returns a safe prime between n, 2*n+length
    #works quickly up to about 2**80
    N = n // 2
    r = random.randint(0, N)
    if presieve:
        candidates = sieve(N+r, N+r+length)
    else:
        candidates = range(N+r, N+r+length)
    return next(find_safe_prime_iter(candidates, k))


def elgamal_key(n):
    #returns tuple (q, h, g, x). Let G be the group of quadratic residues
    #mod 2*q + 1. Then (G, q, h, g) is the public key, x is the private key.
    #q is between n, 2*n+2**15.
    p = find_safe_prime(2*n)
    q = (p-1) // 2
    g = 4 #xx or random.randint(1, p-1)**2 % p
    x = random.randint(1, q-1)
    h = mod_exp(g, x, p)
    return(q, h, g, x)


def elgamal_encrypt(m, q, h, g):
    #encrypts the message m according to the ElGamal encryption scheme
    #m should be int between 1, q
    p = 2*q + 1
    y = random.randint(1, q-1)
    M = mod_exp(m, q+1, p)
    #note that this is m or -m, whichever is a quadratic residue
    c1 = mod_exp(g, y, p)
    c2 = M*mod_exp(h, y, p)
    return (c1, c2)


def elgamal_decrypt(c1, c2, x, q):
    #decryts the cypher-text (c1, c2) with private key x.
    p = 2*q + 1
    M = c2*mod_exp(c1, x*(p-2), p) % p
    if M > q:
        M = p - M
    return M


