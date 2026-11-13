//! `DeterministicRandom` (`contracting.stdlib.bridge.random`): the SHA3-256
//! digests of `"<seed material>|<counter>"` for counter 0, 1, 2, ...,
//! consumed in order as one byte stream.
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use sha3::{Digest, Sha3_256};
use std::collections::VecDeque;

pub(crate) struct Stream {
    /// The hasher after `"<seed material>|"`.
    prefix: Sha3_256,
    counter: u64,
    buffer: VecDeque<u8>,
}

impl Stream {
    pub(crate) fn new(seed_material: &str) -> Self {
        Self {
            prefix: Sha3_256::new()
                .chain_update(seed_material.as_bytes())
                .chain_update(b"|"),
            counter: 0,
            buffer: VecDeque::new(),
        }
    }

    fn refill(&mut self) {
        let digest = self
            .prefix
            .clone()
            .chain_update(self.counter.to_string().as_bytes())
            .finalize();
        self.counter += 1;
        self.buffer.extend(digest);
    }

    /// `getrandbits(bits)`: the next `ceil(bits / 8)` bytes as a big-endian
    /// number without its surplus low bits; no bytes for zero bits.
    pub(crate) fn getrandbits(&mut self, bits: u64) -> BigUint {
        let bytes = usize::try_from(bits.div_ceil(8)).expect("the caller bounds the bit count");
        while self.buffer.len() < bytes {
            self.refill();
        }
        let chunk: Vec<u8> = self.buffer.drain(..bytes).collect();
        BigUint::from_bytes_be(&chunk) >> (bytes as u64 * 8 - bits)
    }

    /// `randbelow(upper)` for a positive `upper`: draws of `upper - 1`'s bit
    /// length until one is below `upper`.
    pub(crate) fn randbelow(&mut self, upper: &BigUint) -> BigUint {
        let bits = (upper - 1u32).bits();
        loop {
            let candidate = self.getrandbits(bits);
            if &candidate < upper {
                return candidate;
            }
        }
    }

    /// `randbelow` of a positive length, as an index: the same draws in
    /// machine words (a shuffle or `choices` makes one per item).
    pub(crate) fn index_below(&mut self, len: usize) -> usize {
        let upper = len as u64;
        let bits = u64::BITS - (upper - 1).leading_zeros();
        loop {
            let candidate = self.word_bits(bits);
            if candidate < upper {
                return candidate as usize;
            }
        }
    }

    /// `getrandbits(bits)` for at most 64 bits.
    fn word_bits(&mut self, bits: u32) -> u64 {
        let bytes = bits.div_ceil(8) as usize;
        while self.buffer.len() < bytes {
            self.refill();
        }
        let value = self
            .buffer
            .drain(..bytes)
            .fold(0u64, |value, byte| (value << 8) | u64::from(byte));
        value >> (bytes as u32 * 8 - bits)
    }

    /// `random()`: 53 bits over 2^53, exact in a double.
    pub(crate) fn random(&mut self) -> f64 {
        let bits = self.getrandbits(53).to_u64().expect("53 bits fit a u64");
        bits as f64 / (1u64 << 53) as f64
    }
}
