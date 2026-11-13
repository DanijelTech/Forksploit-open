use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    fs,
    fs::OpenOptions,
    hash::{Hash, Hasher},
    io::Write,
    path::Path,
    str::FromStr,
    thread::sleep,
    time::Duration,
};

use bytes::Bytes;
use libafl_bolts::impl_serdeany;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, error};

use crate::{
    cache::{Cache, FileSystemCache},
    evm::{blaz::get_client, srcmap::SOURCE_MAP_PROVIDER, types::EVMAddress},
};

#[derive(Clone, Debug)]
pub struct BuildJob {
    pub build_server: String,
    pub replacements: HashMap<EVMAddress, Option<BuildJobResult>>,
    work_dir: String,
    cache: FileSystemCache,
}

const NEEDS: &str = "runtimeBytecode,abi,sourcemap,sources,ast,compiler_args";

impl BuildJob {
    pub fn new(
        build_server: String,
        replacements: HashMap<EVMAddress, Option<BuildJobResult>>,
        work_dir: String,
    ) -> Self {
        let cache = FileSystemCache::new("./cache");
        Self {
            build_server,
            replacements,
            cache,
            work_dir,
        }
    }

    pub fn async_submit_onchain_job(&self, chain: String, addr: EVMAddress) -> Option<JobContext> {
        let client = get_client();
        let url = format!("{}onchain/{}/{:?}?needs={}", self.build_server, chain, addr, NEEDS);
        debug!("Submitting artifact build job to {}", url);
        let resp = match client.get(&url).send() {
            Ok(resp) => resp,
            Err(e) => {
                error!("submit onchain job request failed for {:?}: {:?}", addr, e);
                return None;
            }
        };
        let text = match resp.text() {
            Ok(text) => text,
            Err(e) => {
                error!("submit onchain job: failed to read response body for {:?}: {:?}", addr, e);
                return None;
            }
        };
        let json = match serde_json::from_str::<Value>(&text) {
            Ok(json) => json,
            Err(e) => {
                error!("submit onchain job: failed to parse response as json for {:?}: {:?}", addr, e);
                return None;
            }
        };
        match json["code"].as_u64() {
            Some(200) => {}
            _ => {
                error!("submit onchain job failed for {:?}: unexpected response {:?}", addr, json);
                return None;
            }
        }
        if let Some(task_id) = json["task_id"].as_str() {
            let path = Path::new(self.work_dir.as_str());
            if !path.exists() {
                std::fs::create_dir_all(path).unwrap();
            }
            let builder_file = format!("{}/builder_id.txt", self.work_dir.as_str());
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(builder_file)
                .expect("Failed to open or create builder_id.txt");
            writeln!(file, "0x{}:{}", hex::encode(addr), task_id)
                .expect("Failed to write addr:task_id to builder_id.txt");

            Some(JobContext::new(task_id.to_string(), self.build_server.clone()))
        } else {
            error!("submit onchain job failed for {:?}", addr);
            None
        }
    }

    pub fn onchain_job(&self, chain: String, addr: EVMAddress) -> Option<BuildJobResult> {
        if let Some(replacement) = self.replacements.get(&addr) {
            return replacement.clone();
        }

        let mut hasher = DefaultHasher::new();
        let key = format!("onchain_{}_{}", chain.as_str(), addr.to_string().as_str());
        key.hash(&mut hasher);
        let hash = hasher.finish().to_string();
        if let Ok(t) = self.cache.load(hash.as_str()) {
            if let Ok(deserialized_result) = serde_json::from_str::<BuildJobResult>(&t) {
                return Some(deserialized_result);
            }
        }

        let job = self.async_submit_onchain_job(chain, addr);
        job.as_ref()?;
        let job = job.unwrap();
        let result = job.wait_build_job();
        result.as_ref()?;
        if let Some(res) = &result {
            self.cache
                .save(hash.as_str(), &serde_json::to_string(res).unwrap())
                .unwrap();
        }
        result
    }
}

pub struct JobContext {
    id: String,
    build_server: String,
}

impl JobContext {
    pub fn new(id: String, build_server: String) -> Self {
        Self { id, build_server }
    }

    pub fn wait_build_job(&self) -> Option<BuildJobResult> {
        let client = get_client();
        let url = format!("{}task/{}/", self.build_server, self.id);
        loop {
            debug!("Retrieving artifact build job from {}", url);
            let resp = match client.get(&url).send() {
                Ok(resp) => resp,
                Err(e) => {
                    error!("retrieve onchain job request failed for {:?}: {:?}", self.id, e);
                    return None;
                }
            };
            let text = match resp.text() {
                Ok(text) => text,
                Err(e) => {
                    error!("retrieve onchain job: failed to read response body for {:?}: {:?}", self.id, e);
                    return None;
                }
            };
            let json = match serde_json::from_str::<Value>(&text) {
                Ok(json) => json,
                Err(e) => {
                    error!("retrieve onchain job: failed to parse response as json for {:?}: {:?}", self.id, e);
                    return None;
                }
            };
            if json["code"].as_u64() != Some(200) {
                error!("retrieve onchain job failed for {:?}: unexpected response {:?}", self.id, json);
                return None;
            }
            let status = match json["status"].as_str() {
                Some(status) => status,
                None => {
                    error!("retrieve onchain job: missing status field for {:?}: {:?}", self.id, json);
                    return None;
                }
            };
            if status == "error" {
                error!("retrieve onchain job failed for {:?} due to error", self.id);
                return None;
            }

            if status != "done" {
                sleep(Duration::from_millis(500));
                continue;
            }

            let results = match json["results"].as_str() {
                Some(results) => results,
                None => {
                    error!("retrieve onchain job: missing results field for {:?}: {:?}", self.id, json);
                    return None;
                }
            };
            return BuildJobResult::from_json_url(results.to_string());
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildJobResult {
    /// (file name, source code)
    pub sources: Vec<(String, String)>,
    pub source_maps: String,
    pub bytecodes: Bytes,
    pub abi: String,
    pub source_maps_replacements: Vec<(String, String)>,
    /// (file name, AST object)
    pub asts: Vec<(String, Value)>,
}

impl BuildJobResult {
    pub fn new(
        sources: Vec<(String, String)>,
        source_maps: String,
        bytecodes: Bytes,
        abi: String,
        replacements: Vec<(String, String)>,
        asts: Vec<(String, Value)>,
    ) -> Self {
        Self {
            sources,
            source_maps,
            bytecodes,
            abi,
            source_maps_replacements: replacements,
            asts,
        }
    }

    pub fn from_json_url(url: String) -> Option<Self> {
        let client = get_client();
        let resp = match client.get(&url).send() {
            Ok(resp) => resp,
            Err(e) => {
                error!("retrieve onchain job request failed for {:?}: {:?}", url, e);
                return None;
            }
        };
        let text = match resp.text() {
            Ok(text) => text,
            Err(e) => {
                error!("retrieve onchain job: failed to read response body for {:?}: {:?}", url, e);
                return None;
            }
        };
        let json = match serde_json::from_str::<Value>(&text) {
            Ok(json) => json,
            Err(e) => {
                error!("retrieve onchain job: failed to parse response as json for {:?}: {:?}", url, e);
                return None;
            }
        };
        if let Some(success) = json["success"].as_bool() {
            if !success {
                error!("retrieve onchain job failed for {:?}", url);
                return None;
            }
        } else {
            error!("retrieve onchain job status failed for {:?}", url);
            return None;
        }

        Self::from_json(&json)
    }

    pub fn from_json(json: &Value) -> Option<Self> {
        let sourcemap = match json["sourcemap"].as_str() {
            Some(s) => s,
            None => {
                error!("build artifact missing/non-string sourcemap field: {:?}", json["sourcemap"]);
                return None;
            }
        };
        let mut sourcemap_replacements = vec![];
        if let Some(_replaces) = json["replaces"].as_array() {
            for v in _replaces {
                let Some(v) = v.as_array() else {
                    error!("build artifact: a 'replaces' entry is not an array: {:?}", v);
                    return None;
                };
                let (Some(source), Some(target)) = (v.first().and_then(|x| x.as_str()), v.get(1).and_then(|x| x.as_str())) else {
                    error!("build artifact: a 'replaces' entry is missing source/target: {:?}", v);
                    return None;
                };
                sourcemap_replacements.push((source.to_string(), target.to_string()));
            }
        }
        let bytecode = match json["runtime_bytecode"].as_str() {
            Some(b) => b,
            None => {
                error!("build artifact missing/non-string runtime_bytecode field: {:?}", json["runtime_bytecode"]);
                return None;
            }
        };
        let Some(source_objs) = json["sources"].as_object() else {
            error!("build artifact missing/non-object sources field: {:?}", json["sources"]);
            return None;
        };
        let mut sources = vec![(String::new(), String::new()); source_objs.len()];
        for (k, v) in source_objs {
            let idx = match &v["id"] {
                Value::Number(v) => match v.as_u64() {
                    Some(v) => v as usize,
                    None => {
                        error!("build artifact: source {:?} has a non-u64 numeric id {:?}", k, v);
                        return None;
                    }
                },
                Value::String(v) => match v.parse::<usize>() {
                    Ok(v) => v,
                    Err(e) => {
                        error!("build artifact: source {:?} has an unparseable id {:?}: {:?}", k, v, e);
                        return None;
                    }
                },
                _ => {
                    error!("{:?} is not a valid source id", v["id"]);
                    return None;
                }
            };
            let Some(code) = v["source"].as_str() else {
                error!("build artifact: source {:?} is missing/non-string source code field", k);
                return None;
            };
            let Some(slot) = sources.get_mut(idx) else {
                error!("build artifact: source {:?} has an out-of-range id {}", k, idx);
                return None;
            };
            *slot = (k.clone(), code.to_string());
        }

        let abi = match serde_json::to_string(&json["abi"]) {
            Ok(abi) => abi,
            Err(e) => {
                error!("build artifact: failed to re-serialize abi field: {:?}", e);
                return None;
            }
        };
        let Some(ast_objs) = json["ast"].as_object() else {
            error!("build artifact missing/non-object ast field: {:?}", json["ast"]);
            return None;
        };
        let asts: Vec<(String, Value)> = ast_objs.iter().map(|(k, v)| (k.clone(), v.clone())).collect();

        Some(Self {
            sources,
            source_maps: sourcemap.to_string(),
            bytecodes: Bytes::from(hex::decode(bytecode).unwrap_or_default()),
            abi: abi.to_string(),
            source_maps_replacements: sourcemap_replacements,
            asts,
        })
    }

    pub fn from_multi_file(file_path: String) -> HashMap<EVMAddress, Option<Self>> {
        let mut results = HashMap::new();
        let content = match fs::read_to_string(&file_path) {
            Ok(content) => content,
            Err(e) => {
                error!("from_multi_file: failed to read {:?}: {:?}", file_path, e);
                return results;
            }
        };
        let json = match serde_json::from_str::<Value>(&content) {
            Ok(json) => json,
            Err(e) => {
                error!("from_multi_file: failed to parse {:?} as json: {:?}", file_path, e);
                return results;
            }
        };
        let Some(json_arr) = json.as_object() else {
            error!("from_multi_file: {:?} is not a json object", file_path);
            return results;
        };
        for (k, v) in json_arr {
            let addr = match EVMAddress::from_str(k) {
                Ok(addr) => addr,
                Err(e) => {
                    error!("from_multi_file: skipping entry with unparseable address {:?}: {:?}", k, e);
                    continue;
                }
            };
            let result = Self::from_json(v);
            results.insert(addr, result);
        }
        results
    }

    pub fn save_source_map(&self, address: &EVMAddress) {
        if SOURCE_MAP_PROVIDER.lock().unwrap().has_source_map(address) {
            return;
        }

        SOURCE_MAP_PROVIDER.lock().unwrap().decode_instructions_for_address(
            address,
            self.bytecodes.clone().to_vec(),
            self.source_maps.clone(),
            &self.sources,
            Some(&self.source_maps_replacements),
        );
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactInfoMetadata {
    pub info: HashMap<EVMAddress, BuildJobResult>,
}

impl Default for ArtifactInfoMetadata {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactInfoMetadata {
    pub fn new() -> Self {
        Self { info: HashMap::new() }
    }

    pub fn add(&mut self, addr: EVMAddress, result: BuildJobResult) {
        self.info.insert(addr, result);
    }

    pub fn get(&self, addr: &EVMAddress) -> Option<&BuildJobResult> {
        self.info.get(addr)
    }

    pub fn get_mut(&mut self, addr: &EVMAddress) -> Option<&mut BuildJobResult> {
        self.info.get_mut(addr)
    }
}

impl_serdeany!(ArtifactInfoMetadata);

#[cfg(test)]
mod tests {

    // #[test]
    // fn test_from_json_url() {
    //     let url = "https://storage.googleapis.com/faas_bucket_1/client_builds/fc0fc148-0e8e-4352-9f5f-d49f9fd421c1-results.json?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Credential=client-project-rw%40adept-vigil-394020.iam.gserviceaccount.com%2F20230821%2Fauto%2Fstorage%2Fgoog4_request&X-Goog-Date=20230821T040509Z&X-Goog-Expires=259200&X-Goog-SignedHeaders=host&X-Goog-Signature=09b8e8e4b92400e58d15e7f20f97c44ce5c7903e3bf251c6a3ce92a645cc0b9080bc6a58e39fbb10d3ac9835b53c98d51b1fdf9ea6c795bb4dfcb303ea2a41fd851f984ad67b9590d6f4a98300431a009b47c4797c8731de50a8525613d8d7f8b01cd4e5af05e8278207cdfb563149bdbb1d8f632bb7737a2bacba1c28a4116f6164519c13d9c49fe6fee43b40bd6db844bc9ac601e9b55259b7405bdcfbdee6fbe3f9e0f64e69a2656935a8b86997634a0df1fcd2c1c7a4914a24899b6db2e63c4bede49d6cd49a1cc07359357abc33d8acd76ba8ee8061281f1d566f3cd480eacff374c188090a2d336f02a199907ef7b81f00eb11ed1fe33f7c807903656c";
    //     let result =
    // BuildJobResult::from_json_url(url.to_string()).expect("get result
    // failed");     debug!("{:?}", result);
    // }
    //
    // #[test]
    // fn test_submit_onchain_job() {
    //     let addr =
    // EVMAddress::from_str("0xf3ae5d769e153ef72b4e3591ac004e89f48107a1");
    //     let chain = Chain::ETH;
    //
    //     let job = BuildJob::submit_onchain_job(chain,
    // addr.unwrap()).expect("submit onchain job failed");     debug!("{:?}"
    // , job.id); }
    //
    // #[test]
    // fn test_wait_build_job() {
    //     let job =
    // JobContext::new("fc0fc148-0e8e-4352-9f5f-d49f9fd421c1".to_string());
    //     let result = job.wait_build_job().expect("wait build job failed");
    //     debug!("{:?}", result.abi);
    // }
}
