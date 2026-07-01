/// [`Dummy`] provides a way to construct a placeholder ("dummy") value of a
/// given type, parameterized by some configuration `Cfg`.
///
/// This is useful when initializing data structures that require a value of a
/// certain shape before the real data is available, e.g., when setting up the
/// initial state of a folding scheme.
pub trait Dummy<Cfg> {
    /// [`Dummy::dummy`] constructs a dummy value of `Self` based on the given
    /// configuration `cfg`.
    fn dummy(cfg: Cfg) -> Self;
}

impl<T: Default + Clone> Dummy<usize> for Vec<T> {
    fn dummy(cfg: usize) -> Self {
        vec![Default::default(); cfg]
    }
}

impl<Cfg, T: Dummy<Cfg> + Copy, const N: usize> Dummy<Cfg> for [T; N] {
    fn dummy(cfg: Cfg) -> Self {
        [T::dummy(cfg); N]
    }
}

impl<Cfg: Copy, A: Dummy<Cfg>, B: Dummy<Cfg>> Dummy<Cfg> for (A, B) {
    fn dummy(cfg: Cfg) -> Self {
        (A::dummy(cfg), B::dummy(cfg))
    }
}
