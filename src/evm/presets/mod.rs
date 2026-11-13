pub mod pair;

use std::{fmt::Debug, fs::File};

use libafl::schedulers::Scheduler;
use serde::{Deserialize, Deserializer};

use super::types::EVMFuzzState;
use crate::{
    evm::{
        input::{ConciseEVMInput, EVMInput, EVMInputT},
        types::EVMAddress,
        vm::EVMExecutor,
    },
    generic_vm::vm_state::VMStateT,
    input::VMInputT,
};

pub trait Preset<I, VS, SC>
where
    I: VMInputT<VS, EVMAddress, EVMAddress, ConciseEVMInput> + EVMInputT,
    VS: VMStateT,
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    fn presets(
        &self,
        function_sig: [u8; 4],
        input: &EVMInput,
        evm_executor: &EVMExecutor<VS, ConciseEVMInput, SC>,
    ) -> Vec<EVMInput>;
}

#[derive(Debug, PartialEq, Clone, serde::Serialize)]
pub struct FunctionSig {
    pub value: [u8; 4],
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
pub struct ExploitTemplate {
    pub exploit_name: String,
    pub function_sigs: Vec<FunctionSig>,
    pub calls: Vec<FunctionSig>,
}

impl ExploitTemplate {
    /// FAZA 6.1: the preset file is user-supplied external data. A missing
    /// file or malformed JSON returns a typed error instead of panicking.
    pub fn from_filename(filename: String) -> Result<Vec<Self>, anyhow::Error> {
        let file = File::open(&filename)
            .map_err(|e| anyhow::anyhow!("cannot open preset file {}: {e}", filename))?;
        let exploit_templates: Vec<Self> = serde_json::from_reader(file)
            .map_err(|e| anyhow::anyhow!("cannot parse preset file {}: {e}", filename))?;
        Ok(exploit_templates)
    }
}

impl<'de> Deserialize<'de> for FunctionSig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        // FAZA 6.1: `s` comes from the preset JSON. It must be at least a
        // `0x`-prefixed 4-byte selector; anything else is a deserialization
        // error, not a panic.
        let hex_part = s
            .strip_prefix("0x")
            .ok_or_else(|| serde::de::Error::custom(format!("function signature '{s}' is not 0x-prefixed")))?;
        let decoded = hex::decode(hex_part)
            .map_err(|e| serde::de::Error::custom(format!("function signature '{s}' is not valid hex: {e}")))?;
        if decoded.len() < 4 {
            return Err(serde::de::Error::custom(format!(
                "function signature '{s}' is shorter than 4 bytes"
            )));
        }
        let mut function_sig = [0u8; 4];
        function_sig.copy_from_slice(&decoded[..4]);
        Ok(FunctionSig { value: function_sig })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FAZA 6.1 proof: a missing preset file yields a typed error, not a panic.
    #[test]
    fn from_filename_missing_file_returns_error() {
        let err = ExploitTemplate::from_filename("/nonexistent/definitely-not-here.json".to_string());
        assert!(err.is_err(), "missing preset file must be an error");
    }

    /// FAZA 6.1 proof: malformed preset JSON yields a typed error, not a panic.
    #[test]
    fn from_filename_malformed_json_returns_error() {
        let path = std::env::temp_dir().join(format!("fs_preset_bad_{}.json", std::process::id()));
        std::fs::write(&path, b"{ this is not json ]").unwrap();
        let res = ExploitTemplate::from_filename(path.to_string_lossy().into_owned());
        assert!(res.is_err(), "malformed preset JSON must be an error");
        let _ = std::fs::remove_file(&path);
    }

    /// FAZA 6.1 proof: the `FunctionSig` deserializer rejects selectors that
    /// are not `0x`-prefixed, not hex, or shorter than 4 bytes -- instead of
    /// panicking on a short slice as it used to.
    #[test]
    fn function_sig_rejects_bad_selectors_without_panicking() {
        assert!(serde_json::from_str::<FunctionSig>("\"deadbeef\"").is_err(), "no 0x prefix");
        assert!(serde_json::from_str::<FunctionSig>("\"0xzz\"").is_err(), "not hex");
        assert!(serde_json::from_str::<FunctionSig>("\"0x12\"").is_err(), "shorter than 4 bytes");
        // A valid selector still parses.
        let ok: FunctionSig = serde_json::from_str("\"0xdeadbeef\"").unwrap();
        assert_eq!(ok.value, [0xde, 0xad, 0xbe, 0xef]);
    }
}
