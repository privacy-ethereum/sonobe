use ark_std::hash::{BuildHasherDefault, Hasher};
use hashbrown::HashSet;

#[derive(Default)]
pub struct IdentityHasher {
    value: u64,
}

impl Hasher for IdentityHasher {
    fn finish(&self) -> u64 {
        self.value
    }

    fn write(&mut self, _: &[u8]) {
        panic!("IdentityHasher only supports usize");
    }

    fn write_usize(&mut self, value: usize) {
        self.value = value as u64;
    }
}

pub type UsizeSet = HashSet<usize, BuildHasherDefault<IdentityHasher>>;

pub struct CommittedCache;
pub struct CommitmentKeyCache;
pub struct RandomnessCache;
