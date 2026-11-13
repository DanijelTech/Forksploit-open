use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs,
};

use alloy_primitives::{Address, Keccak256};
use bytes::Bytes;
use serde_json::{Map, Value};
use tracing::debug;

use crate::evm::{
    blaz::offchain_artifacts::{ContractArtifact, OffChainArtifact},
    contract_utils::compute_address,
};

#[derive(Debug)]
pub enum LinkerError {
    MissingTargetArtifact,
    // `file`/`name` are carried for diagnostics and only surfaced through the
    // derived `Debug`; nothing else reads them.
    #[allow(dead_code)]
    MissingLibraryArtifact { file: String, name: String },
}

pub struct Linker {
    pub contracts: BTreeMap<(String, String), ContractArtifact>,
}

impl Linker {
    #[allow(dead_code)] // exercised by unit tests; not called from the binary path
    pub fn compute_address(target_salt: &(String, String)) -> String {
        let mut hasher = Keccak256::new();
        hasher.update(target_salt.0.as_bytes());
        hasher.update(target_salt.1.as_bytes());
        let result = hasher.finalize();
        Address::from_slice(&result[12..]).to_string().to_lowercase().as_str()[2..].to_string()
    }

    pub fn link_all_contract(
        offchain_artifacts: &Vec<OffChainArtifact>,
        libs: BTreeMap<(String, String), ContractArtifact>,
    ) -> Vec<OffChainArtifact> {
        let mut offchain_artifacts_clone = offchain_artifacts.clone();
        // PHASE 6.1: the deploy bytecode strings come from solc output; a
        // malformed value is skipped instead of panicking.
        let decode_bytecode = |s: &str| -> Option<Bytes> { hex::decode(s.trim()).ok().map(Bytes::from) };
        if !libs.is_empty() {
            for (index, offchain_art) in offchain_artifacts.iter().enumerate() {
                for (contract_key, contract) in &offchain_art.contracts {
                    let bytecode_str = if !contract.link_references.is_empty() {
                        match Self::link_setup_target_with_compute_address(&libs.clone(), contract.clone()) {
                            Ok(linked) => linked.deploy_bytecode_str,
                            Err(e) => {
                                debug!("cannot link contract {contract_key:?}: {e:?}, skipping");
                                continue;
                            }
                        }
                    } else {
                        contract.clone().deploy_bytecode_str
                    };
                    let Some(bytecode) = decode_bytecode(&bytecode_str) else {
                        debug!("invalid deploy bytecode for {contract_key:?}, skipping");
                        continue;
                    };
                    if let Some(target) = offchain_artifacts_clone[index].contracts.get_mut(contract_key) {
                        target.deploy_bytecode = bytecode;
                    }
                }
            }
        } else {
            for (index, offchain_art) in offchain_artifacts.iter().enumerate() {
                for (contract_key, contract) in &offchain_art.contracts {
                    let Some(bytecode) = decode_bytecode(&contract.clone().deploy_bytecode_str) else {
                        debug!("invalid deploy bytecode for {contract_key:?}, skipping");
                        continue;
                    };
                    if let Some(target) = offchain_artifacts_clone[index].contracts.get_mut(contract_key) {
                        target.deploy_bytecode = bytecode;
                    }
                }
            }
        }
        offchain_artifacts_clone
    }

    pub fn link_setup_target_with_compute_address(
        libraries: &BTreeMap<(String, String), ContractArtifact>,
        _target: ContractArtifact,
    ) -> Result<ContractArtifact, LinkerError> {
        let mut setup_contract = _target.clone();
        let mut bytecode_str = setup_contract.deploy_bytecode_str.clone();

        for ((file_name, contract_name), _) in libraries {
            let address = compute_address(&(file_name.clone(), contract_name.clone()));
            if let Some(references) = setup_contract.link_references.get(file_name) {
                if let Some(lib_references) = references.get(contract_name) {
                    for reference in lib_references {
                        let start = reference.start;
                        let length = reference.length;
                        // PHASE 6.1: link reference offsets come from solc
                        // output; an out-of-range reference is skipped rather
                        // than panicking on the slice.
                        let Some(placeholder) = bytecode_str.get(start * 2..start * 2 + length * 2) else {
                            debug!("link reference out of range ({start}, {length}), skipping");
                            continue;
                        };
                        bytecode_str = bytecode_str.replace(placeholder, address.clone().as_str());
                    }
                }
            }
        }
        setup_contract.deploy_bytecode_str = bytecode_str;
        Ok(setup_contract)
    }

    pub fn find_all_libs_in_offchain_artifacts(
        offchain_artifacts: &Vec<OffChainArtifact>,
    ) -> Result<BTreeMap<(String, String), ContractArtifact>, Box<dyn Error>> {
        let mut all_libs = BTreeMap::new();
        for artifact in offchain_artifacts {
            let artifact = artifact.clone();
            let linker = Linker {
                contracts: artifact.contracts,
            };
            for target_id in linker.contracts.keys() {
                let mut deps = BTreeSet::new();
                if let Err(e) = linker.collect_dependencies(target_id, &mut deps) {
                    debug!("Error collecting dependencies for {:?}: {:?}", target_id, e);
                } else {
                    deps.into_iter().for_each(|id| {
                        if let Some(artifact) = linker.find_artifact_by_library_path(id) {
                            all_libs.insert(id.clone(), artifact);
                        }
                    });
                }
            }
        }
        Ok(all_libs)
    }
    /// find all libs key
    #[allow(dead_code)] // exercised by unit tests; not called from the binary path
    pub fn find_all_libs_key(file_path: String) -> Result<BTreeSet<(String, String)>, Box<dyn Error>> {
        // PHASE 6.1: the file path is external; surface read/parse failures as
        // errors instead of panicking.
        let json_data = fs::read_to_string(&file_path).map_err(|e| format!("cannot read {file_path}: {e}"))?;
        let mut all_libs_vec = BTreeSet::new();
        let artifacts = Linker::from_solc_json(json_data).map_err(|e| format!("cannot parse {file_path}: {e}"))?;

        for artifact in artifacts {
            let linker = Linker {
                contracts: artifact.contracts,
            };
            for target_id in linker.contracts.keys() {
                let mut deps = BTreeSet::new();
                if let Err(e) = linker.collect_dependencies(target_id, &mut deps) {
                    debug!("Error collecting dependencies for {:?}: {:?}", target_id, e);
                } else {
                    if !deps.is_empty() {
                        let deps: Vec<_> = deps.into_iter().map(|id| id.clone()).collect();
                        all_libs_vec.extend(deps);
                    }
                }
            }
        }
        Ok(all_libs_vec)
    }

    /// link lib inner link
    pub fn link_libs_inner_lib(
        _libs: Option<BTreeMap<(String, String), ContractArtifact>>,
    ) -> Option<BTreeMap<(String, String), ContractArtifact>> {
        if let Some(libs) = _libs {
            let mut libs_clone = libs.clone();

            for (lib_key, _lib_value) in libs.into_iter() {
                if let Some(entry) = libs_clone.get_mut(&lib_key) {
                    entry
                        .lib_address
                        .entry(lib_key.clone().0)
                        .or_insert_with(BTreeMap::new)
                        .insert(lib_key.clone().1, compute_address(&lib_key));
                }
            }

            let mut ret = BTreeMap::new();
            for (lib_key, lib_value) in libs_clone {
                let mut lib_value_clone = lib_value.clone();
                let mut bytecode_str = lib_value_clone.deploy_bytecode_str.clone();

                if !lib_value.clone().link_references.is_empty() {
                    for (file_name, inner_map) in lib_value.link_references {
                        for (contract_name, link_vec) in inner_map {
                            let address = compute_address(&(file_name.clone(), contract_name));

                            for reference in link_vec {
                                let start = reference.start;
                                let length = reference.length;
                                // PHASE 6.1: guard the slice against out-of-range
                                // solc link references.
                                let Some(placeholder) = bytecode_str.get(start * 2..start * 2 + length * 2) else {
                                    debug!("link reference out of range ({start}, {length}), skipping");
                                    continue;
                                };
                                bytecode_str = bytecode_str.replace(placeholder, address.as_str());
                            }
                        }
                    }
                }
                lib_value_clone.deploy_bytecode_str = bytecode_str;
                ret.entry(lib_key).or_insert_with(|| lib_value_clone);
            }
            Some(ret)
        } else {
            return None;
        }
    }

    pub fn collect_dependencies<'a>(
        &'a self,
        target: &(String, String),
        deps: &mut BTreeSet<&'a (String, String)>,
    ) -> Result<(), LinkerError> {
        let contract = self
            .contracts
            .get(target)
            .ok_or_else(|| LinkerError::MissingTargetArtifact)?;

        let mut references = BTreeMap::new();
        references.extend(contract.link_references.clone());

        for (file, libs) in &references {
            for contract in libs.keys() {
                let id = self.find_artifact_id_by_library_path(file, contract).ok_or_else(|| {
                    LinkerError::MissingLibraryArtifact {
                        file: file.to_string(),
                        name: contract.to_string(),
                    }
                })?;
                if deps.insert(id) {
                    self.collect_dependencies(id, deps)?;
                }
            }
        }
        Ok(())
    }

    pub fn find_artifact_by_library_path(&self, id: &(String, String)) -> Option<ContractArtifact> {
        self.contracts
            .iter()
            .find(|library| library.0 == id)
            .map(|(_, artifact)| artifact.clone())
    }

    fn find_artifact_id_by_library_path(&self, file: &str, name: &str) -> Option<&(String, String)> {
        self.contracts.keys().find(|&&(ref f, ref n)| f == file && n == name)
    }

    #[allow(dead_code)] // exercised by unit tests; not called from the binary path
    pub fn from_solc_json(json: String) -> Result<Vec<OffChainArtifact>, Box<dyn Error>> {
        // PHASE 6.1: solc output is external data. Every structural access
        // below returns a typed error instead of `.expect()`-panicking on a
        // truncated/malformed/older-schema build-info file.
        let arr = serde_json::from_str::<Value>(&json)?;
        let root = arr.as_object().ok_or("solc json: top-level value is not an object")?;
        let input = root
            .get("input")
            .ok_or("solc json: missing 'input'")?
            .as_object()
            .ok_or("solc json: 'input' is not an object")?;

        let output = root
            .get("output")
            .ok_or("solc json: missing 'output'")?
            .as_object()
            .ok_or("solc json: 'output' is not an object")?;

        let sources_kv = input
            .get("sources")
            .ok_or("solc json: missing 'input.sources'")?
            .as_object()
            .ok_or("solc json: 'input.sources' is not an object")?;
        let mut sources = Vec::with_capacity(sources_kv.len());
        for (filename, source) in sources_kv {
            let content = source["content"]
                .as_str()
                .ok_or_else(|| format!("solc json: source '{}' has no string 'content'", filename))?;
            sources.push((filename.clone(), content.to_string()));
        }
        Self::_from_solc_json(sources, output)
    }

    fn _from_solc_json(
        input: Vec<(String, String)>,
        output: &Map<String, Value>,
    ) -> Result<Vec<OffChainArtifact>, Box<dyn Error>> {
        let mut result = OffChainArtifact {
            contracts: BTreeMap::new(),
            sources: vec![],
        };

        if let Some(errors) = output.get("errors") {
            let errors = errors
                .as_array()
                .ok_or("solc json: 'output.errors' is not an array")?;
            for error in errors {
                let error = error
                    .as_object()
                    .ok_or("solc json: an entry in 'output.errors' is not an object")?;
                if error.get("severity").and_then(|s| s.as_str()) == Some("error") {
                    let msg = error
                        .get("formattedMessage")
                        .and_then(|m| m.as_str())
                        .unwrap_or("solc reported an error with no formattedMessage");
                    return Err(msg.into());
                }
            }
        }

        if let Some(srclist) = output.get("sourceList") {
            let srclist = srclist
                .as_array()
                .ok_or("solc json: 'output.sourceList' is not an array")?;
            for filename in srclist {
                let filename = filename
                    .as_str()
                    .ok_or("solc json: an entry in 'output.sourceList' is not a string")?;
                for (name, source) in &input {
                    if name == filename {
                        result.sources.push((name.clone(), source.clone()));
                    }
                }
            }
        } else {
            for (name, source) in &input {
                result.sources.push((name.clone(), source.clone()));
            }
        }

        let contracts = output
            .get("contracts")
            .ok_or("solc json: missing 'output.contracts'")?
            .as_object()
            .ok_or("solc json: 'output.contracts' is not an object")?;

        for (file_name, contract) in contracts {
            if file_name.contains(":") {
                let mut parts = file_name.splitn(2, ':');
                let file = parts.next().unwrap_or(file_name);
                let contract_name = parts.next().unwrap_or("");
                let contract = contract
                    .as_object()
                    .ok_or_else(|| format!("solc json: contract entry '{}' is not an object", file_name))?;
                let bytecode = contract
                    .get("bin")
                    .and_then(|b| b.as_str())
                    .ok_or_else(|| format!("solc json: contract '{}' has no string 'bin'", file_name))?;
                let abi = serde_json::to_string(contract.get("abi").unwrap_or(&Value::Null))
                    .unwrap_or_else(|_| "[]".to_string());
                let source_map = contract
                    .get("srcmap-runtime")
                    .and_then(|s| s.as_str())
                    .ok_or_else(|| {
                        format!("solc json: contract '{}' has no string 'srcmap-runtime'", file_name)
                    })?
                    .to_string();
                result.contracts.insert(
                    (file.to_string(), contract_name.to_string()),
                    ContractArtifact {
                        deploy_bytecode_str: bytecode.to_string(),
                        deploy_bytecode: Default::default(),
                        lib_address: Default::default(),
                        abi,
                        source_map,
                        link_references: Default::default(),
                        source_map_replacements: vec![],
                    },
                );
            } else {
                let nested = contract.as_object().ok_or_else(|| {
                    format!("solc json: contracts.{} is not an object", file_name)
                })?;
                for (contract_name, contract) in nested {
                    let ctx = format!("solc json: {}.{}", file_name, contract_name);
                    let contract = contract
                        .as_object()
                        .ok_or_else(|| format!("{} is not an object", ctx))?;
                    let evm = contract
                        .get("evm")
                        .and_then(|e| e.as_object())
                        .ok_or_else(|| format!("{} has no 'evm' object", ctx))?;
                    let bytecode = evm
                        .get("bytecode")
                        .and_then(|b| b.as_object())
                        .and_then(|b| b.get("object"))
                        .and_then(|o| o.as_str())
                        .ok_or_else(|| format!("{} has no string 'evm.bytecode.object'", ctx))?;
                    let link_references = serde_json::from_value(
                        evm.get("bytecode")
                            .and_then(|b| b.get("linkReferences"))
                            .cloned()
                            .unwrap_or(Value::Null),
                    )
                    .unwrap_or_default();
                    let abi = serde_json::to_string(contract.get("abi").unwrap_or(&Value::Null))
                        .unwrap_or_else(|_| "[]".to_string());
                    let source_map = evm
                        .get("deployedBytecode")
                        .and_then(|d| d.as_object())
                        .and_then(|d| d.get("sourceMap"))
                        .and_then(|s| s.as_str())
                        .ok_or_else(|| {
                            format!("{} has no string 'evm.deployedBytecode.sourceMap'", ctx)
                        })?
                        .to_string();
                    result.contracts.insert(
                        (file_name.clone(), contract_name.clone()),
                        ContractArtifact {
                            deploy_bytecode_str: bytecode.to_string(),
                            deploy_bytecode: Default::default(),
                            lib_address: Default::default(),
                            abi,
                            source_map,
                            link_references,
                            source_map_replacements: vec![],
                        },
                    );
                }
            }
        }
        Ok(vec![result])
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    /// PHASE 6.1/6.3: malformed solc build-info must yield an `Err`, never a
    /// panic. Covers the shapes a truncated or older-schema file produces.
    #[test]
    fn test_from_solc_json_malformed_returns_err() {
        // Not JSON at all.
        assert!(Linker::from_solc_json("not json".to_string()).is_err());
        // Valid JSON but not an object.
        assert!(Linker::from_solc_json("[]".to_string()).is_err());
        // Object missing `output`.
        assert!(Linker::from_solc_json("{\"input\":{\"sources\":{}}}".to_string()).is_err());
        // Object missing `input.sources`.
        assert!(Linker::from_solc_json("{\"input\":{},\"output\":{}}".to_string()).is_err());
        // `output` present but `contracts` missing -> must not panic.
        assert!(Linker::from_solc_json(
            "{\"input\":{\"sources\":{}},\"output\":{}}".to_string()
        )
        .is_err());
        // A contract entry that is not an object.
        assert!(Linker::from_solc_json(
            "{\"input\":{\"sources\":{}},\"output\":{\"contracts\":{\"a.sol:C\":42}}}".to_string()
        )
        .is_err());
    }

    /// A minimal well-formed solc output still parses to one artifact.
    #[test]
    fn test_from_solc_json_minimal_ok() {
        let json = r#"{
            "input": {"sources": {"A.sol": {"content": "contract C {}"}}},
            "output": {
                "sourceList": ["A.sol"],
                "contracts": {
                    "A.sol:C": {"bin": "6000", "srcmap-runtime": "", "abi": []}
                }
            }
        }"#;
        let arts = Linker::from_solc_json(json.to_string()).expect("should parse");
        assert_eq!(arts.len(), 1);
        assert!(arts[0].contracts.contains_key(&("A.sol".to_string(), "C".to_string())));
        assert_eq!(arts[0].sources, vec![("A.sol".to_string(), "contract C {}".to_string())]);
    }

    /// PHASE 6.1 proof: `find_all_libs_key` on a missing file returns an error
    /// instead of panicking.
    #[test]
    fn test_find_all_libs_key_missing_file_returns_err() {
        assert!(Linker::find_all_libs_key("/nonexistent/definitely-not-here.json".to_string()).is_err());
    }

    /// PHASE 6.1 proof: `link_all_contract` must not panic when a contract's
    /// deploy bytecode is not valid hex; it skips the bad entry.
    #[test]
    fn test_link_all_contract_malformed_bytecode_does_not_panic() {
        let json = r#"{
            "input": {"sources": {"A.sol": {"content": "contract C {}"}}},
            "output": {
                "sourceList": ["A.sol"],
                "contracts": {
                    "A.sol:C": {"bin": "zznothex", "srcmap-runtime": "", "abi": []}
                }
            }
        }"#;
        let arts = Linker::from_solc_json(json.to_string()).expect("should parse");
        // Sanity: the artifact exists before linking.
        assert!(arts[0].contracts.contains_key(&("A.sol".to_string(), "C".to_string())));
        // Must return (no panic) even though "zznothex" is not valid hex.
        let out = Linker::link_all_contract(&arts, BTreeMap::new());
        assert_eq!(out.len(), 1);
    }

    // #[test]
    #[allow(dead_code)] // manual harness, run by uncommenting #[test]
    fn test_collect_dependencies() {
        let file_path = "tests/evm_manual/foundry1/.tmp-build-info-1716733433/f4e9a81f9387b1c60225de923fc6cdf9.json";
        let json_data = fs::read_to_string(file_path).expect("Unable to read file");
        let artifacts = Linker::from_solc_json(json_data).expect("Failed to parse JSON");

        for artifact in artifacts {
            let linker = Linker {
                contracts: artifact.contracts,
            };

            for target_id in linker.contracts.keys() {
                let mut deps = BTreeSet::new();
                if let Err(e) = linker.collect_dependencies(target_id, &mut deps) {
                    println!("Error collecting dependencies for {:?}: {:?}", target_id, e);
                } else {
                    if !deps.is_empty() {
                        println!("Dependencies for {:?}: dep is {:?}", target_id, deps);
                    }
                }
            }
        }
    }

    // #[test]
    #[allow(dead_code)] // manual harness, run by uncommenting #[test]
    fn test_find_libs() {
        let file_path = "tests/evm_manual/foundry1/.tmp-build-info-1716733433/f4e9a81f9387b1c60225de923fc6cdf9.json";
        let all_libs = Linker::find_all_libs_key(file_path.to_string()).unwrap();
        for lib in all_libs.into_iter() {
            println!("{:?}", lib);
        }
    }

    // #[test]
    #[allow(dead_code)] // manual harness, run by uncommenting #[test]
    fn test_link_libs_inner_lib() {
        let file_path = "tests/evm_manual/foundry1/.tmp-build-info-1716733433/f4e9a81f9387b1c60225de923fc6cdf9.json";
        let json_data = fs::read_to_string(file_path).expect("Unable to read file");
        let artifacts = Linker::from_solc_json(json_data).expect("Failed to parse JSON");

        let all_libs = Linker::find_all_libs_in_offchain_artifacts(&artifacts).unwrap();
        let _tt = Linker::link_libs_inner_lib(Some(all_libs));
    }

    // #[test]
    #[allow(dead_code)] // manual harness, run by uncommenting #[test]
    fn test_link_setup_target_with_compute_address() {
        let file_path = "tests/evm_manual/foundry1/.tmp-build-info-1716733433/f4e9a81f9387b1c60225de923fc6cdf9.json";
        let json_data = fs::read_to_string(file_path).expect("Unable to read file");
        let artifacts = Linker::from_solc_json(json_data).expect("Failed to parse JSON");

        let all_libs = Linker::find_all_libs_in_offchain_artifacts(&artifacts).unwrap();
        let _tt = Linker::link_libs_inner_lib(Some(all_libs)).unwrap();
    }
}
