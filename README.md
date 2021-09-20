
# A Practical Proxy Signature Scheme

A python implementation of a proxy signature scheme that leverages the Schnorr signature algorithm for the steps of signature and verification [1]. 
A proxy signature protocol allows an entity, called the designator or original signer, to delegate another entity,
called a proxy signer, to sign messages on its behalf, in case of say, temporal absence, lack of time or computational power, etc. The delegated proxy signer can compute a proxy signature that can be verified by anyone
with access to the original signer’s certified public key [2]. The construction of this protocol was built by referencing Aboud et al's work for a loose framework of the proxy signature scheme [3]. The main diversion of this protocol is the replacement of Aboud's signing and verifying methods with our own use of Schnorr's algorithm. Where Aboud provides simplicity, there is also a lack of formality. For those interested in the theories behind Proxy Signature I have provided below a list of works that are better suited for study.



## Dependencies

[Charm-Crypto 0.50.0](https://jhuisi.github.io/charm/)

[pbc-0.5.14](https://crypto.stanford.edu/pbc/)


## Related

Further reading on the cryptography behind proxy signatures.

- [Boldyreva et al. scheme](https://eprint.iacr.org/2003/096.pdf). Journal of Cryptography, 2012.
- [Libert et al. scheme](https://dl.acm.org/doi/pdf/10.1145/1455770.1455835). ACM CCS, 2008.
- [Fuchsbauer and Pointcheval scheme](https://www.di.ens.fr/david.pointcheval/Documents/Papers/2008_scnA.pdf). SCN, 2008.


  
## Appendix

1. Schnorr, C.P., 1991. Efficient signature generation by smart cards. Journal of cryptology, 4(3), pp.161-174.
2. Boldyreva, A., Palacio, A. and Warinschi, B., 2012. Secure proxy signature schemes for delegation of signing rights. Journal of Cryptology, 25(1), pp.57-115.
3. Aboud, S.J. and Yousef, S., 2012. A practical proxy signature scheme. IJDIWC, The Society of Digital Information and Wireless Communications, pp.297-298.
  
