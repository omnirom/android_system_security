// Copyright 2020, The Android Open Source Project
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

//! Export into Rust a function to create a KeyMintDevice and add it as a service.

#[allow(missing_docs)] // TODO remove this
extern "C" {
    fn addKeyMintDeviceService() -> i32;
}

#[allow(missing_docs)] // TODO remove this
pub fn add_keymint_device_service() -> i32 {
    // SAFETY: This is always safe to call.
    unsafe { addKeyMintDeviceService() }
}

#[cfg(test)]
mod tests;
