/// [`EVMSerialize`] encodes a value as EVM calldata (the ABI byte encoding the
/// on-chain verifier expects).
pub trait EVMSerialize {
    fn to_calldata(&self) -> Vec<u8>;
}

impl<T: EVMSerialize + ?Sized> EVMSerialize for &T {
    fn to_calldata(&self) -> Vec<u8> {
        T::to_calldata(self)
    }
}

impl<T: EVMSerialize> EVMSerialize for [T] {
    fn to_calldata(&self) -> Vec<u8> {
        self.iter().flat_map(EVMSerialize::to_calldata).collect()
    }
}

impl<T: EVMSerialize, const N: usize> EVMSerialize for [T; N] {
    fn to_calldata(&self) -> Vec<u8> {
        self[..].to_calldata()
    }
}

impl<T: EVMSerialize> EVMSerialize for Vec<T> {
    fn to_calldata(&self) -> Vec<u8> {
        self[..].to_calldata()
    }
}

impl EVMSerialize for u8 {
    fn to_calldata(&self) -> Vec<u8> {
        vec![*self]
    }
}

impl EVMSerialize for () {
    fn to_calldata(&self) -> Vec<u8> {
        Vec::new()
    }
}

macro_rules! impl_evm_serialize_tuple {
    ($($T:ident),+) => {
        impl<$($T: EVMSerialize),+> EVMSerialize for ($($T,)+) {
            fn to_calldata(&self) -> Vec<u8> {
                #[allow(non_snake_case)]
                let ($($T,)+) = self;
                let mut out = Vec::new();
                $(out.extend($T.to_calldata());)+
                out
            }
        }
    };
}

impl_evm_serialize_tuple!(A);
impl_evm_serialize_tuple!(A, B);
impl_evm_serialize_tuple!(A, B, C);
impl_evm_serialize_tuple!(A, B, C, D);
impl_evm_serialize_tuple!(A, B, C, D, E);
impl_evm_serialize_tuple!(A, B, C, D, E, F);
impl_evm_serialize_tuple!(A, B, C, D, E, F, G);
impl_evm_serialize_tuple!(A, B, C, D, E, F, G, H);
impl_evm_serialize_tuple!(A, B, C, D, E, F, G, H, I);
impl_evm_serialize_tuple!(A, B, C, D, E, F, G, H, I, J);
impl_evm_serialize_tuple!(A, B, C, D, E, F, G, H, I, J, K);
impl_evm_serialize_tuple!(A, B, C, D, E, F, G, H, I, J, K, L);
