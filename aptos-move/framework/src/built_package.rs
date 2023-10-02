// Copyright © Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::{docgen::DocgenOptions, extended_checks, natives::code::{ModuleMetadata, MoveOption, PackageDep, PackageMetadata, UpgradePolicy},
            zip_metadata, zip_metadata_str, RuntimeModuleMetadataV1, APTOS_METADATA_KEY, APTOS_METADATA_KEY_V1, METADATA_V1_MIN_FILE_FORMAT_VERSION, unzip_metadata_str, unzip_metadata};
use anyhow::bail;
use aptos_types::{account_address::AccountAddress, transaction::EntryABI};
use clap::Parser;
use codespan_reporting::{
    diagnostic::Severity,
    term::termcolor::{ColorChoice, StandardStream},
};
use itertools::Itertools;
use move_binary_format::CompiledModule;
use move_command_line_common::files::MOVE_COMPILED_EXTENSION;
use move_compiler::compiled_unit::{CompiledUnit, NamedCompiledModule};
use move_core_types::{language_storage::ModuleId, metadata::Metadata};
use move_model::model::GlobalEnv;
use move_package::{
    compilation::{compiled_package::CompiledPackage, package_layout::CompiledPackageLayout},
    source_package::manifest_parser::{parse_move_manifest_string, parse_source_manifest},
    BuildConfig, CompilerConfig, CompilerVersion, ModelConfig,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::stderr,
    path::{Path, PathBuf},
};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use tempfile::TempDir;
use move_package::resolution::resolution_graph::ResolutionGraph;
use move_package::source_package::parsed_manifest::{AddressDeclarations, Dependency, NamedAddress, SourceManifest};
use move_bytecode_source_map::source_map::SourceMap;


pub const METADATA_FILE_NAME: &str = "package-metadata.bcs";
pub const UPGRADE_POLICY_CUSTOM_FIELD: &str = "upgrade_policy";

pub const APTOS_PACKAGES: [&str; 5] = ["AptosFramework", "MoveStdlib", "AptosStdlib", "AptosToken", "AptosTokenObjects"];
pub const APTOS_COMMONS: &str = "aptos-commons";
pub const STATE_DATA: &str = "state_data";
pub const TXN_DATA: &str = "txn_data";

/// Represents a set of options for building artifacts from Move.
#[derive(Debug, Clone, Parser, Serialize, Deserialize)]
pub struct BuildOptions {
    /// Enables dev mode, which uses all dev-addresses and dev-dependencies
    ///
    /// Dev mode allows for changing dependencies and addresses to the preset [dev-addresses] and
    /// [dev-dependencies] fields.  This works both inside and out of tests for using preset values.
    ///
    /// Currently, it also additionally pulls in all test compilation artifacts
    #[clap(long)]
    pub dev: bool,
    #[clap(long)]
    pub with_srcs: bool,
    #[clap(long)]
    pub with_abis: bool,
    #[clap(long)]
    pub with_source_maps: bool,
    #[clap(long, default_value_t = true)]
    pub with_error_map: bool,
    #[clap(long)]
    pub with_docs: bool,
    /// Installation directory for compiled artifacts. Defaults to `<package>/build`.
    #[clap(long, value_parser)]
    pub install_dir: Option<PathBuf>,
    #[clap(skip)] // TODO: have a parser for this; there is one in the CLI buts its  downstream
    pub named_addresses: BTreeMap<String, AccountAddress>,
    #[clap(skip)]
    pub docgen_options: Option<DocgenOptions>,
    #[clap(long)]
    pub skip_fetch_latest_git_deps: bool,
    #[clap(long)]
    pub bytecode_version: Option<u32>,
    #[clap(long)]
    pub compiler_version: Option<CompilerVersion>,
    #[clap(long)]
    pub skip_attribute_checks: bool,
    #[clap(skip)]
    pub known_attributes: BTreeSet<String>,
}

// Because named_addresses has no parser, we can't use clap's default impl. This must be aligned
// with defaults above.
impl Default for BuildOptions {
    fn default() -> Self {
        Self {
            dev: false,
            with_srcs: false,
            with_abis: false,
            with_source_maps: false,
            with_error_map: true,
            with_docs: false,
            install_dir: None,
            named_addresses: Default::default(),
            docgen_options: None,
            // This is false by default, because it could accidentally pull new dependencies
            // while in a test (and cause some havoc)
            skip_fetch_latest_git_deps: false,
            bytecode_version: None,
            compiler_version: None,
            skip_attribute_checks: false,
            known_attributes: extended_checks::get_all_attribute_names().clone(),
        }
    }
}

/// Represents a built package.  It allows to extract `PackageMetadata`. Can also be used to
/// just build Move code and related artifacts.
pub struct BuiltPackage {
    options: BuildOptions,
    package_path: PathBuf,
    package: CompiledPackage,
}

pub fn build_model(
    dev_mode: bool,
    package_path: &Path,
    additional_named_addresses: BTreeMap<String, AccountAddress>,
    target_filter: Option<String>,
    bytecode_version: Option<u32>,
    compiler_version: Option<CompilerVersion>,
    skip_attribute_checks: bool,
    known_attributes: BTreeSet<String>,
) -> anyhow::Result<GlobalEnv> {
    let build_config = BuildConfig {
        dev_mode,
        additional_named_addresses,
        architecture: None,
        generate_abis: false,
        generate_docs: false,
        install_dir: None,
        test_mode: false,
        force_recompilation: false,
        fetch_deps_only: false,
        skip_fetch_latest_git_deps: true,
        compiler_config: CompilerConfig {
            bytecode_version,
            compiler_version,
            skip_attribute_checks,
            known_attributes,
        },
    };
    build_config.move_model_for_package(package_path, ModelConfig {
        target_filter,
        all_files_as_targets: false,
    })
}

impl BuiltPackage {
    /// Builds the package and on success delivers a `BuiltPackage`.
    ///
    /// This function currently reports all Move compilation errors and warnings to stdout,
    /// and is not `Ok` if there was an error among those.
    pub fn build(package_path: PathBuf, options: BuildOptions) -> anyhow::Result<Self> {
        let bytecode_version = options.bytecode_version;
        let compiler_version = options.compiler_version;
        let skip_attribute_checks = options.skip_attribute_checks;
        let build_config = BuildConfig {
            dev_mode: options.dev,
            additional_named_addresses: options.named_addresses.clone(),
            architecture: None,
            generate_abis: options.with_abis,
            generate_docs: false,
            install_dir: options.install_dir.clone(),
            test_mode: false,
            force_recompilation: false,
            fetch_deps_only: false,
            skip_fetch_latest_git_deps: options.skip_fetch_latest_git_deps,
            compiler_config: CompilerConfig {
                bytecode_version,
                compiler_version,
                skip_attribute_checks,
                known_attributes: options.known_attributes.clone(),
            },
        };

        eprintln!("Compiling, may take a little while to download git dependencies...");
        let mut package = build_config.compile_package_no_exit(&package_path, &mut stderr())?;

        // Build the Move model for extra processing and run extended checks as well derive
        // runtime metadata
        let model = &build_model(
            options.dev,
            package_path.as_path(),
            options.named_addresses.clone(),
            None,
            bytecode_version,
            compiler_version,
            skip_attribute_checks,
            options.known_attributes.clone(),
        )?;
        let runtime_metadata = extended_checks::run_extended_checks(model);
        if model.diag_count(Severity::Warning) > 0 {
            let mut error_writer = StandardStream::stderr(ColorChoice::Auto);
            model.report_diag(&mut error_writer, Severity::Warning);
            if model.has_errors() {
                bail!("extended checks failed")
            }
        }

        let compiled_pkg_path = package
            .compiled_package_info
            .build_flags
            .install_dir
            .as_ref()
            .unwrap_or(&package_path)
            .join(CompiledPackageLayout::Root.path())
            .join(package.compiled_package_info.package_name.as_str());
        inject_runtime_metadata(
            compiled_pkg_path,
            &mut package,
            runtime_metadata,
            bytecode_version,
        )?;

        // If enabled generate docs.
        if options.with_docs {
            let docgen = if let Some(opts) = options.docgen_options.clone() {
                opts
            } else {
                DocgenOptions::default()
            };
            let dep_paths = package
                .deps_compiled_units
                .iter()
                .map(|(_, u)| {
                    u.source_path
                        .parent()
                        .unwrap()
                        .parent()
                        .unwrap()
                        .join("doc")
                        .display()
                        .to_string()
                })
                .unique()
                .collect::<Vec<_>>();
            docgen.run(package_path.display().to_string(), dep_paths, model)?
        }

        Ok(Self {
            options,
            package_path,
            package,
        })
    }

    /// Returns the name of this package.
    pub fn name(&self) -> &str {
        self.package.compiled_package_info.package_name.as_str()
    }

    pub fn package_path(&self) -> &Path {
        self.package_path.as_path()
    }

    pub fn package_artifacts_path(&self) -> PathBuf {
        self.package_path
            .join(CompiledPackageLayout::Root.path())
            .join(self.name())
    }

    /// Extracts the bytecode for the modules of the built package.
    pub fn extract_code(&self) -> Vec<Vec<u8>> {
        self.package
            .root_modules()
            .map(|unit_with_source| {
                unit_with_source
                    .unit
                    .serialize(self.options.bytecode_version)
            })
            .collect()
    }

    /// Returns the abis for this package, if available.
    pub fn extract_abis(&self) -> Option<Vec<EntryABI>> {
        self.package.compiled_abis.as_ref().map(|abis| {
            abis.iter()
                .map(|(_, bytes)| bcs::from_bytes::<EntryABI>(bytes.as_slice()).unwrap())
                .collect()
        })
    }

    /// Returns an iterator for all compiled proper (non-script) modules.
    pub fn modules(&self) -> impl Iterator<Item = &CompiledModule> {
        self.package
            .root_modules()
            .filter_map(|unit| match &unit.unit {
                CompiledUnit::Module(NamedCompiledModule { module, .. }) => Some(module),
                CompiledUnit::Script(_) => None,
            })
    }

    /// Returns an iterator for all compiled proper (non-script) modules, including
    /// modules that are dependencies of the root modules.
    pub fn all_modules(&self) -> impl Iterator<Item = &CompiledModule> {
        self.package
            .all_modules()
            .filter_map(|unit| match &unit.unit {
                CompiledUnit::Module(NamedCompiledModule { module, .. }) => Some(module),
                CompiledUnit::Script(_) => None,
            })
    }

    /// Returns the number of scripts in the package.
    pub fn script_count(&self) -> usize {
        self.package.scripts().count()
    }

    /// Returns the serialized bytecode of the scripts in the package.
    pub fn extract_script_code(&self) -> Vec<Vec<u8>> {
        self.package
            .scripts()
            .map(|unit_with_source| {
                unit_with_source
                    .unit
                    .serialize(self.options.bytecode_version)
            })
            .collect()
    }

    pub fn is_aptos_package(package_name: &str) -> bool {
        APTOS_PACKAGES.contains(&package_name)
    }

    pub fn compile_aptos_packages(aptos_commons_path: &PathBuf,
                                  compiled_package_map: &mut BTreeMap<(AccountAddress, String, Option<u64>, u32), CompiledPackage>) -> anyhow::Result<()> {
        for package in APTOS_PACKAGES {
            let mut build_options = BuildOptions::default();
            let root_package_dir = aptos_commons_path
                .join(format!("{}", package));
            let compiled_package = BuiltPackage::build(root_package_dir, build_options);
            if let Ok(built_package) = compiled_package {
                compiled_package_map.insert((AccountAddress::ONE, package.to_string(), None, 6), built_package.package);
            } else {
                return Err(anyhow::Error::msg(format!("package {} cannot be compiled", package)));;
            }
        }
        Ok(())
    }

    // step 2: analyzing the manifest file, handle each dependency using depth-first traversal
    // case 1: dependency on aptos related libraries:
    //
    pub fn dump_and_compile_from_package_metadata
    (
     root_dir: PathBuf,
     root_package_name: String,
     root_account_address: AccountAddress,
     upgrade_num: u64,
     dep_map: &HashMap<(AccountAddress, String), PackageMetadata>,
     compiled_package_map: &mut BTreeMap<(AccountAddress, String, Option<u64>, u32), CompiledPackage>,
     compiler_verion: Option<CompilerVersion>,
     bytecode_version: u32) ->
    anyhow::Result<()> {

        let root_package_dir = root_dir
            .join(format!("{}.{}.{}", root_package_name, root_account_address, upgrade_num));
        if root_package_dir.exists() {
            return Ok(());
        }
        std::fs::create_dir_all(root_package_dir.as_path())?;
        let root_package_metadata = dep_map.get(&(root_account_address, root_package_name.clone())).unwrap();
        // step 1: unzip and save the source code into src into corresponding folder: txn_version/package-name
        let sources_dir = root_package_dir.join("sources");
        std::fs::create_dir_all(sources_dir.as_path())?;
        let modules = root_package_metadata.modules.clone();
        for module in modules {
            let module_path = sources_dir.join(format!("{}.move", module.name));
            if !module_path.exists() {
                File::create(module_path.clone())
                    .expect("Error encountered while creating file!");
            };
            let source_str = unzip_metadata_str(&module.source).unwrap();
            std::fs::write(&module_path.clone(), source_str).unwrap();
        }

        // step 2: unzip, parse the manifest file
        let manifest_u8 = root_package_metadata.manifest.clone();
        let manifest_str = unzip_metadata_str(&manifest_u8).unwrap();
        let mut manifest = parse_source_manifest(parse_move_manifest_string(manifest_str.clone()).unwrap()).unwrap();

        let fix_manifest_dep = |dep: &mut Dependency, local_str: &str| {
            dep.git_info = None;
            dep.subst = None;
            dep.version = None;
            dep.digest = None;
            dep.node_info = None;
            dep.local = PathBuf::from("..").join(local_str);// PathBuf::from(local_str);
        };

        // step 3:
        let manifest_deps = &mut manifest.dependencies;
        for manifest_dep in manifest_deps {
            let manifest_dep_name = manifest_dep.0.as_str();
            let dep = manifest_dep.1;
            for pack_dep in &root_package_metadata.deps {
                let pack_dep_address = pack_dep.account;
                let pack_dep_name = pack_dep.clone().package_name;
                if pack_dep_name == manifest_dep_name {
                    if Self::is_aptos_package(&pack_dep_name) {
                        fix_manifest_dep(dep, &format!("{}/{}", APTOS_COMMONS, &pack_dep_name));
                        break;
                    }
                    let dep_metadata_opt = dep_map.get(&(pack_dep_address, pack_dep_name.clone()));
                    if let Some(dep_metadata) = dep_metadata_opt {
                        let pack_dep_upgrade_num = dep_metadata.clone().upgrade_number;
                        let path_str = format!("{}.{}.{}", pack_dep_name, pack_dep_address, pack_dep_upgrade_num);
                        fix_manifest_dep(dep, &path_str);
                        Self::dump_and_compile_from_package_metadata(root_dir.clone(), pack_dep_name.clone(), pack_dep_address,
                                                                     dep_metadata.clone().upgrade_number, dep_map, compiled_package_map,
                                                                     compiler_verion, bytecode_version)?;
                    }
                    break;
                }
            }
        }

        // Dump the fixed manifest file
        let toml_path = root_package_dir.join("Move.toml");

        //let _ = File::create(toml_path)
        //        .expect("Error encountered while creating file!");
        std::fs::write(&toml_path, manifest.to_string()).unwrap();
        if !compiled_package_map.contains_key(&(root_account_address, root_package_name.clone(), Some(upgrade_num), bytecode_version)) {
            let mut build_options = BuildOptions::default();
            build_options.named_addresses.insert(root_package_name.clone(), root_account_address.clone());
            let root_package_dir = PathBuf::from(".")
                .join(format!("{}.{}.{}", root_package_name, root_account_address, upgrade_num));
            let compiled_package = BuiltPackage::build(root_package_dir, build_options);
            if let Ok(built_package) = compiled_package {
                compiled_package_map.insert((root_account_address, root_package_name, Some(upgrade_num), bytecode_version), built_package.package);
            }
        }

        Ok(())
    }

    pub fn unzip_package_metadata(package_meta_data: &PackageMetadata) {
        let package_name = package_meta_data.name.clone();
        let modules = package_meta_data.modules.clone();
        let manifest_u8 = package_meta_data.manifest.clone();
        let deps = package_meta_data.deps.clone();
        let manifest_str = unzip_metadata_str(&manifest_u8).unwrap();
        println!("dependency of package:{} will be downloaded", package_name);
        println!("manifest:{}", manifest_str);
        let mut manifest = parse_source_manifest(parse_move_manifest_string(manifest_str.clone()).unwrap()).unwrap();
        //let temp_path = PathBuf::from(TempDir::new()?.path());
        let mut path = PathBuf::from(".").join(package_name.clone());
        std::fs::create_dir_all(&path).unwrap();

        // write move.toml
        println!("path:{:?}", path);
        let move_toml_path = PathBuf::from(path.clone()).join("Move.toml");
        println!("toml path:{:?}", move_toml_path);
        std::fs::write(move_toml_path, manifest_str).unwrap();
        let config: BuildConfig = BuildConfig::default();
        if !package_name.contains("Aptos") {
            ResolutionGraph::download_dependency_repos(&manifest, &config, &path, &mut std::io::stdout()).unwrap();
        }
        //ResolutionGraph::download_dependency_repos(&manifest, &config, &path, &mut std::io::stdout()).unwrap();
    }

    /*
    pub fn extract_metadata_and_save(&self) -> anyhow::Result<()> {
        let data = self.extract_metadata()?;
        let path = self.package_artifacts_path();
        std::fs::create_dir_all(&path)?;
        std::fs::write(path.join(METADATA_FILE_NAME), bcs::to_bytes(&data)?)?;
        Ok(())
    }
     */

    /// Extracts metadata, as needed for releasing a package, from the built package.
    pub fn extract_metadata(&self) -> anyhow::Result<PackageMetadata> {
        let source_digest = self
            .package
            .compiled_package_info
            .source_digest
            .map(|s| s.to_string())
            .unwrap_or_default();
        let manifest_file = self.package_path.join("Move.toml");
        let manifest = std::fs::read_to_string(manifest_file)?;
        let custom_props = extract_custom_fields(&manifest)?;
        let manifest = zip_metadata_str(&manifest)?;
        let upgrade_policy = if let Some(val) = custom_props.get(UPGRADE_POLICY_CUSTOM_FIELD) {
            str::parse::<UpgradePolicy>(val.as_ref())?
        } else {
            UpgradePolicy::compat()
        };
        let mut modules = vec![];
        for u in self.package.root_modules() {
            let name = u.unit.name().to_string();
            let source = if self.options.with_srcs {
                zip_metadata_str(&std::fs::read_to_string(&u.source_path)?)?
            } else {
                vec![]
            };
            let source_map = if self.options.with_source_maps {
                zip_metadata(&u.unit.serialize_source_map())?
            } else {
                vec![]
            };
            modules.push(ModuleMetadata {
                name,
                source,
                source_map,
                extension: MoveOption::default(),
            })
        }
        let deps = self
            .package
            .deps_compiled_units
            .iter()
            .map(|(name, unit)| {
                let package_name = name.as_str().to_string();
                let account = match &unit.unit {
                    CompiledUnit::Module(m) => AccountAddress::new(m.address.into_bytes()),
                    _ => panic!("script not a dependency"),
                };
                PackageDep {
                    account,
                    package_name,
                }
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Ok(PackageMetadata {
            name: self.name().to_string(),
            upgrade_policy,
            upgrade_number: 0,
            source_digest,
            manifest,
            modules,
            deps,
            extension: MoveOption::none(),
        })
    }

    pub fn extract_metadata_and_save(&self) -> anyhow::Result<()> {
        let data = self.extract_metadata()?;
        let path = self.package_artifacts_path();
        std::fs::create_dir_all(&path)?;
        std::fs::write(path.join(METADATA_FILE_NAME), bcs::to_bytes(&data)?)?;
        Ok(())
    }
}

fn extract_custom_fields(toml: &str) -> anyhow::Result<BTreeMap<String, String>> {
    let manifest = parse_source_manifest(parse_move_manifest_string(toml.to_owned())?)?;
    Ok(manifest
        .package
        .custom_properties
        .iter()
        .map(|(s, v)| (s.to_string(), v.to_string()))
        .collect())
}

fn inject_runtime_metadata(
    package_path: PathBuf,
    pack: &mut CompiledPackage,
    metadata: BTreeMap<ModuleId, RuntimeModuleMetadataV1>,
    bytecode_version: Option<u32>,
) -> anyhow::Result<()> {
    for unit_with_source in pack.root_compiled_units.iter_mut() {
        match &mut unit_with_source.unit {
            CompiledUnit::Module(named_module) => {
                if let Some(module_metadata) = metadata.get(&named_module.module.self_id()) {
                    if !module_metadata.is_empty() {
                        if bytecode_version.unwrap_or(METADATA_V1_MIN_FILE_FORMAT_VERSION)
                            >= METADATA_V1_MIN_FILE_FORMAT_VERSION
                        {
                            let serialized_metadata = bcs::to_bytes(&module_metadata)
                                .expect("BCS for RuntimeModuleMetadata");
                            named_module.module.metadata.push(Metadata {
                                key: APTOS_METADATA_KEY_V1.to_vec(),
                                value: serialized_metadata,
                            });
                        } else {
                            let serialized_metadata =
                                bcs::to_bytes(&module_metadata.clone().downgrade())
                                    .expect("BCS for RuntimeModuleMetadata");
                            named_module.module.metadata.push(Metadata {
                                key: APTOS_METADATA_KEY.to_vec(),
                                value: serialized_metadata,
                            });
                        }

                        // Also need to update the .mv file on disk.
                        let path = package_path
                            .join(CompiledPackageLayout::CompiledModules.path())
                            .join(named_module.name.as_str())
                            .with_extension(MOVE_COMPILED_EXTENSION);
                        if path.is_file() {
                            let bytes = unit_with_source.unit.serialize(bytecode_version);
                            std::fs::write(path, bytes)?;
                        }
                    }
                }
            },
            CompiledUnit::Script(_) => {},
        }
    }
    Ok(())
}
