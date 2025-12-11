// Copyright 2025, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Utilities to help with fallible allocation.

use alloc::collections::TryReserveError;
use alloc::vec::Vec;

/// Function that mimics `slice.to_vec()` but which detects allocation failures.
#[inline]
pub fn try_to_vec<T: Clone>(s: &[T]) -> Result<Vec<T>, TryReserveError> {
    let mut v = vec_try_with_capacity::<T>(s.len())?;
    v.extend_from_slice(s);
    Ok(v)
}

/// Extension trait to provide fallible-allocation variants of `Vec` methods.
pub trait FallibleAllocExt<T> {
    /// Try to add the `value` to the collection, failing on memory exhaustion.
    fn try_push(&mut self, value: T) -> Result<(), TryReserveError>;
    /// Try to extend the collection with the contents of `other`, failing on memory exhaustion.
    fn try_extend_from_slice(&mut self, other: &[T]) -> Result<(), TryReserveError>
    where
        T: Clone;
}

impl<T> FallibleAllocExt<T> for Vec<T> {
    fn try_push(&mut self, value: T) -> Result<(), TryReserveError> {
        self.try_reserve(1)?;
        self.push(value);
        Ok(())
    }
    fn try_extend_from_slice(&mut self, other: &[T]) -> Result<(), TryReserveError>
    where
        T: Clone,
    {
        self.try_reserve(other.len())?;
        self.extend_from_slice(other);
        Ok(())
    }
}

/// Create a `Vec<T>` with the given length reserved, detecting allocation failure.
pub fn vec_try_with_capacity<T>(len: usize) -> Result<Vec<T>, TryReserveError> {
    let mut v = alloc::vec::Vec::new();
    v.try_reserve(len)?;
    Ok(v)
}

/// Macro that mimics `vec!` but which detects allocation failure.
#[macro_export]
macro_rules! vec_try {
    { $elem:expr ; $len:expr } => {
        $crate::mem::vec_try_fill_with_alloc_err($elem, $len)
    };
    { $x1:expr, $x2:expr, $x3:expr, $x4:expr $(,)? } => {
        $crate::mem::vec_try4_with_alloc_err($x1, $x2, $x3, $x4)
    };
    { $x1:expr, $x2:expr, $x3:expr $(,)? } => {
        $crate::mem::vec_try3_with_alloc_err($x1, $x2, $x3)
    };
    { $x1:expr, $x2:expr $(,)? } => {
        $crate::mem::vec_try2_with_alloc_err($x1, $x2)
    };
    { $x1:expr $(,)? } => {
        $crate::mem::vec_try1_with_alloc_err($x1)
    };
}

/// Function that mimics `vec![<val>; <len>]` but which detects allocation failure with the given
/// error.
pub fn vec_try_fill_with_alloc_err<T: Clone>(
    elem: T,
    len: usize,
) -> Result<Vec<T>, TryReserveError> {
    let mut v = alloc::vec::Vec::new();
    v.try_reserve(len)?;
    v.resize(len, elem);
    Ok(v)
}

/// Function that mimics `vec![x1, x2, x3, x4]` but which detects allocation failure with the given
/// error.
pub fn vec_try4_with_alloc_err<T: Clone>(
    x1: T,
    x2: T,
    x3: T,
    x4: T,
) -> Result<Vec<T>, TryReserveError> {
    let mut v = alloc::vec::Vec::new();
    v.try_reserve(4)?;
    v.push(x1);
    v.push(x2);
    v.push(x3);
    v.push(x4);
    Ok(v)
}

/// Function that mimics `vec![x1, x2, x3]` but which detects allocation failure with the given
/// error.
pub fn vec_try3_with_alloc_err<T: Clone>(x1: T, x2: T, x3: T) -> Result<Vec<T>, TryReserveError> {
    let mut v = alloc::vec::Vec::new();
    v.try_reserve(3)?;
    v.push(x1);
    v.push(x2);
    v.push(x3);
    Ok(v)
}

/// Function that mimics `vec![x1, x2]` but which detects allocation failure with the given error.
pub fn vec_try2_with_alloc_err<T: Clone>(x1: T, x2: T) -> Result<Vec<T>, TryReserveError> {
    let mut v = alloc::vec::Vec::new();
    v.try_reserve(2)?;
    v.push(x1);
    v.push(x2);
    Ok(v)
}

/// Function that mimics `vec![x1]` but which detects allocation failure with the given error.
pub fn vec_try1_with_alloc_err<T: Clone>(x1: T) -> Result<Vec<T>, TryReserveError> {
    let mut v = alloc::vec::Vec::new();
    v.try_reserve(1)?;
    v.push(x1);
    Ok(v)
}
