use std::{
    collections::{BTreeMap, HashMap},
    default::Default,
    error::Error,
};

use bytes::Bytes;
use itertools::Itertools;
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::evm::blaz::get_client;

// #[derive(Clone, Debug)]
// pub struct ContractArtifact {
//     pub deploy_bytecode: Bytes,
//     pub abi: String,
//     pub source_map: String,
//     pub source_map_replacements: Vec<(String, String)>,
// }
//
// #[derive(Clone, Debug)]
// pub struct OffChainArtifact {
//     pub contracts: HashMap<(String, String), ContractArtifact>,
//     pub sources: Vec<(String, String)>,
// }

#[derive(Clone, Default, Debug)]
pub struct ContractArtifact {
    pub deploy_bytecode_str: String,
    pub deploy_bytecode: Bytes,
    pub lib_address: BTreeMap<String, BTreeMap<String, String>>,
    pub abi: String,
    pub source_map: String,
    pub link_references: BTreeMap<String, BTreeMap<String, Vec<LinkReference>>>,
    pub source_map_replacements: Vec<(String, String)>,
}

#[derive(Clone, Debug)]
pub struct OffChainArtifact {
    pub contracts: BTreeMap<(String, String), ContractArtifact>,
    pub sources: Vec<(String, String)>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LinkReference {
    pub start: usize,
    pub length: usize,
}

impl OffChainArtifact {
    pub fn from_json_url(url: String) -> Result<Vec<Self>, Box<dyn Error>> {
        let client = get_client();
        let resp = client.get(url).send()?;
        Self::from_json(resp.text()?)
    }

    pub fn from_file(file: String) -> Result<Vec<Self>, Box<dyn Error>> {
        let json = std::fs::read_to_string(file)?;
        Self::from_json(json)
    }

    pub fn from_json(json: String) -> Result<Vec<Self>, Box<dyn Error>> {
        let arr = serde_json::from_str::<Value>(&json)?;
        let mut artifacts = vec![];
        for json in arr.as_array().ok_or("expected a json array of build results")? {
            let mut all_bytecode = HashMap::new();
            if !json["success"].as_bool().ok_or("missing/non-bool 'success' field")? {
                return Err("retrieve onchain job failed".into());
            }
            // debug!("json: {:?}", json);
            let bytecodes = json["bytecode"].as_object().ok_or("missing/non-object 'bytecode' field")?;
            for (filename, contract) in bytecodes {
                let contract_obj = contract
                    .as_object()
                    .ok_or_else(|| format!("'bytecode.{}' is not an object", filename))?;
                for (contract_name, bytecode) in contract_obj {
                    let bytecode = bytecode
                        .as_str()
                        .ok_or_else(|| format!("bytecode for '{}.{}' is not a string", filename, contract_name))?;
                    let bytecode = Bytes::from(
                        hex::decode(bytecode)
                            .map_err(|e| format!("bytecode for '{}.{}' is not valid hex: {:?}", filename, contract_name, e))?,
                    );
                    all_bytecode.insert((filename.clone(), contract_name.clone()), bytecode);
                }
            }

            let abis = json["abi"].as_object().ok_or("missing/non-object 'abi' field")?;
            let mut all_abi = HashMap::new();
            for (filename, contract) in abis {
                let contract_obj = contract.as_object().ok_or_else(|| format!("'abi.{}' is not an object", filename))?;
                for (contract_name, abi) in contract_obj {
                    let abi = serde_json::to_string(abi)
                        .map_err(|e| format!("failed to re-serialize abi for '{}.{}': {:?}", filename, contract_name, e))?;
                    all_abi.insert((filename.clone(), contract_name.clone()), abi);
                }
            }

            let source_maps = json["sourcemap"].as_object().ok_or("missing/non-object 'sourcemap' field")?;
            let mut all_source_map = HashMap::new();
            for (filename, contract) in source_maps {
                let contract_obj = contract
                    .as_object()
                    .ok_or_else(|| format!("'sourcemap.{}' is not an object", filename))?;
                for (contract_name, source_map) in contract_obj {
                    let source_map = source_map
                        .as_str()
                        .ok_or_else(|| format!("source_map for '{}.{}' is not a string", filename, contract_name))?;
                    all_source_map.insert((filename.clone(), contract_name.clone()), source_map.to_string());
                }
            }

            let mut all_source_maps_replacement = HashMap::new();
            if let Some(source_maps_replacement) = json["replacements"].as_object() {
                for (filename, contract) in source_maps_replacement {
                    let contract_obj = contract
                        .as_object()
                        .ok_or_else(|| format!("'replacements.{}' is not an object", filename))?;
                    for (contract_name, source_map_replacements) in contract_obj {
                        let source_map_replacements = source_map_replacements.as_array().ok_or_else(|| {
                            format!("replacements for '{}.{}' is not an array", filename, contract_name)
                        })?;
                        let mut parsed = Vec::with_capacity(source_map_replacements.len());
                        for replacements in source_map_replacements {
                            let replacements = replacements
                                .as_array()
                                .ok_or("a replacements entry is not an array")?;
                            let source = replacements
                                .first()
                                .and_then(|v| v.as_str())
                                .ok_or("a replacements entry is missing its source")?;
                            let target = replacements
                                .get(1)
                                .and_then(|v| v.as_str())
                                .ok_or("a replacements entry is missing its target")?;
                            parsed.push((source.to_string(), target.to_string()));
                        }
                        all_source_maps_replacement.insert((filename.clone(), contract_name.clone()), parsed);
                    }
                }
            }

            let sources = json["sources"].as_object().ok_or("missing/non-object 'sources' field")?;
            let mut all_sources = vec![(String::new(), String::new()); sources.len()];
            for (filename, source) in sources {
                let idx = source["id"].as_u64().ok_or_else(|| format!("source '{}' has no numeric id", filename))? as usize;
                let code = source["source"]
                    .as_str()
                    .ok_or_else(|| format!("source '{}' has no source code string", filename))?;
                let slot = all_sources
                    .get_mut(idx)
                    .ok_or_else(|| format!("source '{}' has an out-of-range id {}", filename, idx))?;
                *slot = (filename.clone(), code.to_string());
            }

            let mut contracts = BTreeMap::new();
            for (loc, _) in &all_bytecode {
                let bytecode = all_bytecode.get(loc).ok_or("internal: bytecode disappeared")?.clone();
                let abi = all_abi
                    .get(loc)
                    .ok_or_else(|| format!("'{}.{}' has bytecode but no abi", loc.0, loc.1))?
                    .clone();
                let source_map = all_source_map
                    .get(loc)
                    .ok_or_else(|| format!("'{}.{}' has bytecode but no source_map", loc.0, loc.1))?
                    .clone();
                let source_map_replacements = all_source_maps_replacement.get(loc).cloned().unwrap_or(vec![]);
                contracts.insert(
                    loc.clone(),
                    ContractArtifact {
                        deploy_bytecode_str: "".to_string(),
                        deploy_bytecode: bytecode,
                        abi,
                        source_map,
                        link_references: Default::default(),
                        source_map_replacements,
                        lib_address: Default::default(),
                    },
                );
            }
            artifacts.push(Self {
                contracts,
                sources: all_sources,
            })
        }
        Ok(artifacts)
    }

    pub fn from_solc_file(file: String) -> Result<Vec<Self>, Box<dyn Error>> {
        let json = std::fs::read_to_string(file)?;
        Self::from_solc_json(json)
    }

    pub fn from_command(command: String) -> Result<Vec<Self>, Box<dyn Error>> {
        // let new_working_directory = "tests/evm_manual/story-core";
        // let new_working_directory = "tests/evm_manual/foundry1";
        // println!("Changing working directory to: {:?}", new_working_directory);
        //
        // std::env::set_current_dir(&new_working_directory)?;
        // println!("Current working directory is now: {:?}", std::env::current_dir()?);
        // println!("command is....... {:?}", command.to_string());

        // parse the command
        let mut parts = command.split_whitespace().collect_vec();
        if parts.len() < 2 {
            return Err("invalid command".into());
        }

        let bin = parts.remove(0);
        // FAZA 6.1: a pre-1970 system clock is impossible in practice, but a
        // fallback keeps this from panicking on an exotic host.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut folder = format!(".tmp-build-info-{now_secs}");
        if !std::path::Path::new(&folder).exists() {
            std::fs::create_dir_all(&folder)?;
        }

        macro_rules! remove_folder {
            () => {
                if folder.starts_with(".tmp") && std::path::Path::new(&folder).exists() {
                    std::fs::remove_dir_all(folder.clone())?;
                }
            };
        }
        let combined_json_path = folder.clone() + "/combined.json";

        match bin {
            "solc" => {
                parts.push("--combined-json=bin,bin-runtime,abi,ast,srcmap,srcmap-runtime,storage-layout");
                parts.push("--metadata");
                parts.push("--metadata-literal");
                parts.push("--overwrite");
                parts.push("-o");
                parts.push(folder.as_str());
            }
            "forge" => {
                let has_build_info = parts.iter().any(|p| p.starts_with("--build-info"));
                if !has_build_info {
                    parts.push("--build-info");
                }
                let has_build_info_path = parts.iter().any(|p| p.starts_with("--build-info-path"));
                if !has_build_info_path {
                    parts.push("--build-info-path");
                    parts.push(folder.as_str());
                } else {
                    remove_folder!();
                    return Err("build-info-path is not supported".into());
                }
            }
            "npx" | "npm" | "pnpm" | "yarn" => {
                // FAZA 6.1: a non-UTF8 current dir returns an error, not a panic.
                let cwd = std::env::current_dir()?;
                let cwd = cwd
                    .to_str()
                    .ok_or_else(|| format!("current directory is not valid UTF-8: {cwd:?}"))?;
                folder = format!("{cwd}/artifacts/build-info");
            }
            _ => {
                remove_folder!();
                return Err(format!("unsupported command: {}", parts[0]).into());
            }
        }

        // execute the command and directly output to stdout
        // FAZA 6.1: a spawn failure (binary missing) is a typed error, not a panic.
        let output = std::process::Command::new(bin)
            .args(parts)
            .status()
            .map_err(|e| format!("failed to execute '{bin}': {e}"))?;
        if !output.success() {
            remove_folder!();
            return Err(format!("command failed").into());
        }

        let res = match bin {
            "solc" => {
                let mut metadata = vec![];
                let combined_json = serde_json::from_str::<Value>(&std::fs::read_to_string(combined_json_path)?)?;
                // FAZA 6.1: solc output is external; a non-object root is an
                // error rather than a panic.
                let output = combined_json.as_object().ok_or("solc combined-json is not an object")?;
                for entry in std::fs::read_dir(folder.clone())? {
                    let entry = entry?;
                    let path = entry.path();
                    // FAZA 6.1: skip entries whose name is not UTF-8.
                    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                        continue;
                    };
                    if path.is_file() && name.ends_with("_meta.json") {
                        let json = std::fs::read_to_string(path)?;
                        // FAZA 6.1: a metadata file with an unexpected shape is
                        // skipped instead of panicking on the nested unwraps.
                        let Ok(value) = serde_json::from_str::<Value>(&json) else {
                            continue;
                        };
                        let Some(sources) = value.get("sources").and_then(|s| s.as_object()) else {
                            continue;
                        };
                        metadata.push(
                            sources
                                .iter()
                                .filter_map(|(filename, source)| {
                                    source["content"].as_str().map(|c| (filename.clone(), c.to_string()))
                                })
                                .collect::<Vec<_>>(),
                        );
                    }
                }
                Self::_from_solc_json(
                    metadata
                        .iter()
                        .flatten()
                        .map(|(filename, source)| (filename.clone(), source.clone()))
                        .collect(),
                    &output,
                )
            }
            "forge" => {
                for entry in std::fs::read_dir(folder.clone())? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.is_file()
                        && path.file_name().and_then(|n| n.to_str()).map(|n| n.ends_with(".json")).unwrap_or(false)
                    {
                        let json = std::fs::read_to_string(path)?;
                        remove_folder!();
                        return Self::from_solc_json(json);
                    }
                }
                Err("no json file found".into())
            }
            "npx" | "npm" | "pnpm" | "yarn" => {
                for entry in std::fs::read_dir(folder.clone())? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.is_file()
                        && path.file_name().and_then(|n| n.to_str()).map(|n| n.ends_with(".json")).unwrap_or(false)
                    {
                        let json = std::fs::read_to_string(path)?;
                        return Self::from_solc_json(json);
                    }
                }
                Err("no json file found in artifacts/build-info/".into())
            }
            _ => Err("unsupported command".into()),
        };
        remove_folder!();
        res
    }

    pub fn from_solc_json(json: String) -> Result<Vec<Self>, Box<dyn Error>> {
        let arr = serde_json::from_str::<Value>(&json)?;
        let obj = arr.as_object().ok_or("expected a json object")?;
        let input = obj
            .get("input")
            .ok_or("missing 'input' field")?
            .as_object()
            .ok_or("'input' is not an object")?;

        let output = obj
            .get("output")
            .ok_or("missing 'output' field")?
            .as_object()
            .ok_or("'output' is not an object")?;

        let sources_kv = input
            .get("sources")
            .ok_or("missing 'input.sources' field")?
            .as_object()
            .ok_or("'input.sources' is not an object")?;
        let mut sources = Vec::with_capacity(sources_kv.len());
        for (filename, source) in sources_kv {
            let content = source["content"]
                .as_str()
                .ok_or_else(|| format!("source '{}' has no content string", filename))?;
            sources.push((filename.clone(), content.to_string()));
        }
        Self::_from_solc_json(sources, output)
    }

    fn _from_solc_json(
        mut input: Vec<(String, String)>,
        output: &Map<String, Value>,
    ) -> Result<Vec<Self>, Box<dyn Error>> {
        let mut result = Self {
            contracts: BTreeMap::new(),
            sources: vec![],
        };

        if let Some(errors) = output.get("errors") {
            let errors = errors.as_array().ok_or("'errors' is not an array")?;
            for error in errors {
                let Some(error) = error.as_object() else {
                    continue;
                };
                if error["severity"].as_str() == Some("error") {
                    let message = error["formattedMessage"]
                        .as_str()
                        .unwrap_or("(compiler error has no formattedMessage)");
                    return Err(message.into());
                }
            }
        }

        if let Some(srclist) = output.get("sourceList") {
            let srclist = srclist.as_array().ok_or("'sourceList' is not an array")?;
            for filename in srclist {
                let Some(filename) = filename.as_str() else {
                    continue;
                };
                for (name, source) in &input {
                    if name == filename {
                        result.sources.push((name.clone(), source.clone()));
                    }
                }
            }
        } else {
            let output_sources = output
                .get("sources")
                .ok_or("missing 'output.sources' field")?
                .as_object()
                .ok_or("'output.sources' is not an object")?;
            let mut insertion_order = HashMap::new();
            for (input_idx, (name, _)) in input.iter().enumerate() {
                let real_idx = output_sources
                    .get(name)
                    .ok_or_else(|| format!("'{}' is missing from output.sources", name))?
                    .get("id")
                    .ok_or_else(|| format!("'{}' has no id in output.sources", name))?
                    .as_u64()
                    .ok_or_else(|| format!("'{}' has a non-u64 id in output.sources", name))?;

                insertion_order.insert(real_idx, (input_idx, name.clone()));
            }

            // insert source by real_idx order
            for (_, (input_idx, _name)) in insertion_order.iter().sorted() {
                let source = std::mem::take(&mut input[*input_idx]);
                result.sources.push(source);
            }
        }

        let contracts = output
            .get("contracts")
            .ok_or("missing 'output.contracts' field")?
            .as_object()
            .ok_or("'output.contracts' is not an object")?;

        for (file_name, contract) in contracts {
            if file_name.contains(":") {
                let parts = file_name.split(":").collect_vec();
                let Some(&contract_name) = parts.get(1) else {
                    return Err(format!("'{}' has a ':' but no contract name after it", file_name).into());
                };
                let file_name = parts[0];
                let contract = contract
                    .as_object()
                    .ok_or_else(|| format!("'{}' is not an object", file_name))?;
                let bytecode = contract["bin"]
                    .as_str()
                    .ok_or_else(|| format!("'{}:{}' has no 'bin' string", file_name, contract_name))?;
                let abi = serde_json::to_string(&contract["abi"])
                    .map_err(|e| format!("'{}:{}' abi failed to serialize: {:?}", file_name, contract_name, e))?;
                let source_map = contract["srcmap-runtime"]
                    .as_str()
                    .ok_or_else(|| format!("'{}:{}' has no 'srcmap-runtime' string", file_name, contract_name))?
                    .to_string();
                result.contracts.insert(
                    (file_name.to_string(), contract_name.to_string()),
                    ContractArtifact {
                        deploy_bytecode_str: bytecode.to_string(),
                        deploy_bytecode: Default::default(),
                        abi,
                        source_map,
                        link_references: Default::default(),
                        source_map_replacements: vec![],
                        lib_address: Default::default(),
                    },
                );
            } else {
                // 1. judge lib contract
                let Some(contract_obj) = contract.as_object() else {
                    continue;
                };
                for (contract_name, contract) in contract_obj {
                    // solc's combined/standard-json output legitimately
                    // omits bytecode for interfaces/abstract contracts --
                    // skip those instead of aborting the whole batch.
                    let Some(bytecode) = contract["evm"]["bytecode"]["object"].as_str() else {
                        continue;
                    };
                    let abi = serde_json::to_string(&contract["abi"])
                        .map_err(|e| format!("'{}.{}' abi failed to serialize: {:?}", file_name, contract_name, e))?;
                    let link_references = serde_json::from_value(contract["evm"]["bytecode"]["linkReferences"].clone())
                        .unwrap_or_default();
                    let source_map = contract["evm"]["deployedBytecode"]["sourceMap"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string();
                    result.contracts.insert(
                        (file_name.clone(), contract_name.clone()),
                        ContractArtifact {
                            deploy_bytecode_str: bytecode.to_string(),
                            deploy_bytecode: Bytes::default(),
                            abi,
                            source_map,
                            link_references,
                            source_map_replacements: vec![],
                            lib_address: BTreeMap::default(),
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
    // use tracing::debug;
    // use crate::evm::blaz::offchain_artifacts::OffChainArtifact;
    //
    // #[test]
    // fn test_from_url() {
    //     use super::*;
    //     // let url =
    // "/Users/shou/coding/test_foundry/build-info/
    // 685c8631ec48f140bc646da3dcfdb3d9.json";     // let artifact =
    // OffChainArtifact::from_solc_file(url.to_string()).expect("get artifact
    // failed");     // chdir
    //     let dir = "/Users/shou/coding/test_foundry";
    //     std::env::set_current_dir(dir).expect("set current dir failed");
    //
    //     let artifact = OffChainArtifact::from_command("solc
    // src/Counter.sol".to_string()).expect("get artifact failed");
    //     println!("{:?}", artifact);
    // }
}
