use ark_ff::PrimeField;
use ark_std::marker::PhantomData;

pub trait CircuitRepr {}

pub trait HasConstraintField {
    type ConstraintField: PrimeField;
}

pub type CF<X> = <X as HasConstraintField>::ConstraintField;

pub trait HasValue: HasConstraintField {
    type Value;
}

pub trait HasWidget: HasConstraintField {
    type Widget;
}

pub trait HasVar<T: CircuitRepr> {
    type Var: HasValue<Value = Self>;
}

pub trait HasGadget<T: CircuitRepr> {
    type Gadget: HasWidget<Widget = Self>;
}

pub enum Canonical {}

pub enum Emulated<F> {
    _Phantom(PhantomData<F>),
}

impl CircuitRepr for Canonical {}
impl<F> CircuitRepr for Emulated<F> {}

pub type Var<V, T> = <V as HasVar<T>>::Var;

pub type Gadget<V, T> = <V as HasGadget<T>>::Gadget;
