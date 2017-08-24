# -*- coding: utf-8 -*-
"""
Created on Tue Aug 01 18:51:33 2017

@author: Rowan Schrecker
"""

import random


def log2(n):
  #returns floor of log base 2 of n
  x = 0
  while  2**x <= n:
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
  #returns a**n%p
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
  if p == 1:
    return False
  x = 2
  while 1:
    if x*x > p:
      return True
    if p%x == 0:
      return False
    x += 1


def miller_rabin(p, k=10):
  #returns True if p is 'probably prime'
  #TO DO: add sieve?
  s = 0
  d = p-1
  while d%2 == 0:
    d /= 2
    s += 1
  for x in range(k):
    a = random.randint(2, p-1)
    if mod_exp(a, d, p) != 1:
      for r in range(s):
        if mod_exp(a, 2**r*d, p) == p-1:
          break
      else:
        return False
  return True


def find_prime(n, k=10):
  #returns a prime between n, 2*n
  #works quickly up to about 2**57
  while 1:
    p = random.randint(n, 2*n)
    if miller_rabin(p,k):
      return p
