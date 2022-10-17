use std::{
    collections::HashMap,
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
    time::SystemTime,
};

use anyhow::Result;
use directories_next::ProjectDirs;
use rand::Rng;
use serde_derive::{Deserialize, Serialize};
use sodiumoxide::crypto::sign;

use crate::{
    log,
    password_security::{
        decrypt_str_or_original, decrypt_vec_or_original, encrypt_str_or_original,
        encrypt_vec_or_original,
    },
};

pub const RENDEZVOUS_TIMEOUT: u64 = 12_000;
pub const CONNECT_TIMEOUT: u64 = 18_000;
pub const READ_TIMEOUT: u64 = 30_000;
pub const REG_INTERVAL: i64 = 12_000;
pub const COMPRESS_LEVEL: i32 = 3;
const SERIAL: i32 = 3;
const PASSWORD_ENC_VERSION: &'static str = "00";
// 128x128
#[cfg(target_os = "macos")] // 128x128 on 160x160 canvas, then shrink to 128, mac looks better with padding
pub const ICON: &str = "data:image/png;base64,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";
#[cfg(not(target_os = "macos"))] // 128x128 no padding
pub const ICON: &str = "data:image/png;base64,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";
#[cfg(target_os = "macos")]
lazy_static::lazy_static! {
    pub static ref ORG: Arc<RwLock<String>> = Arc::new(RwLock::new("com.CosmosPro".to_owned()));
}

type Size = (i32, i32, i32, i32);

lazy_static::lazy_static! {
    static ref CONFIG: Arc<RwLock<Config>> = Arc::new(RwLock::new(Config::load()));
    static ref CONFIG2: Arc<RwLock<Config2>> = Arc::new(RwLock::new(Config2::load()));
    static ref LOCAL_CONFIG: Arc<RwLock<LocalConfig>> = Arc::new(RwLock::new(LocalConfig::load()));
    pub static ref ONLINE: Arc<Mutex<HashMap<String, i64>>> = Default::default();
    pub static ref PROD_RENDEZVOUS_SERVER: Arc<RwLock<String>> = Default::default();
    pub static ref APP_NAME: Arc<RwLock<String>> = Arc::new(RwLock::new("RustDesk".to_owned()));
    static ref KEY_PAIR: Arc<Mutex<Option<(Vec<u8>, Vec<u8>)>>> = Default::default();
    static ref HW_CODEC_CONFIG: Arc<RwLock<HwCodecConfig>> = Arc::new(RwLock::new(HwCodecConfig::load()));
}

// #[cfg(any(target_os = "android", target_os = "ios"))]
lazy_static::lazy_static! {
    pub static ref APP_DIR: Arc<RwLock<String>> = Default::default();
    pub static ref APP_HOME_DIR: Arc<RwLock<String>> = Default::default();
}
const CHARS: &'static [char] = &[
    '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
    'm', 'n', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
];

pub const RENDEZVOUS_SERVERS: &'static [&'static str] = &[
    "tempremoteassistance.cosmospro.com.br"
];
pub const RS_PUB_KEY: &'static str = "OeVuKk5nlHiXp+APNn0Y3pC1Iwpwn44JGqrQCsWqmBw=";
pub const RENDEZVOUS_PORT: i32 = 21116;
pub const RELAY_PORT: i32 = 21117;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NetworkType {
    Direct,
    ProxySocks,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq)]
pub struct Config {
    #[serde(default)]
    pub id: String, // use
    #[serde(default)]
    enc_id: String, // store
    #[serde(default)]
    password: String,
    #[serde(default)]
    salt: String,
    #[serde(default)]
    key_pair: (Vec<u8>, Vec<u8>), // sk, pk
    #[serde(default)]
    key_confirmed: bool,
    #[serde(default)]
    keys_confirmed: HashMap<String, bool>,
}

#[derive(Debug, Default, PartialEq, Serialize, Deserialize, Clone)]
pub struct Socks5Server {
    #[serde(default)]
    pub proxy: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
}

// more variable configs
#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq)]
pub struct Config2 {
    #[serde(default)]
    rendezvous_server: String,
    #[serde(default)]
    nat_type: i32,
    #[serde(default)]
    serial: i32,

    #[serde(default)]
    socks: Option<Socks5Server>,

    // the other scalar value must before this
    #[serde(default)]
    pub options: HashMap<String, String>,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq)]
pub struct PeerConfig {
    #[serde(default)]
    pub password: Vec<u8>,
    #[serde(default)]
    pub size: Size,
    #[serde(default)]
    pub size_ft: Size,
    #[serde(default)]
    pub size_pf: Size,
    #[serde(default)]
    pub view_style: String, // original (default), scale
    #[serde(default)]
    pub image_quality: String,
    #[serde(default)]
    pub custom_image_quality: Vec<i32>,
    #[serde(default)]
    pub show_remote_cursor: bool,
    #[serde(default)]
    pub lock_after_session_end: bool,
    #[serde(default)]
    pub privacy_mode: bool,
    #[serde(default)]
    pub port_forwards: Vec<(i32, String, i32)>,
    #[serde(default)]
    pub direct_failures: i32,
    #[serde(default)]
    pub disable_audio: bool,
    #[serde(default)]
    pub disable_clipboard: bool,
    #[serde(default)]
    pub enable_file_transfer: bool,
    #[serde(default)]
    pub show_quality_monitor: bool,

    // the other scalar value must before this
    #[serde(default)]
    pub options: HashMap<String, String>,
    #[serde(default)]
    pub info: PeerInfoSerde,
    #[serde(default)]
    pub transfer: TransferSerde,
}

#[derive(Debug, PartialEq, Default, Serialize, Deserialize, Clone)]
pub struct PeerInfoSerde {
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub platform: String,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq)]
pub struct TransferSerde {
    #[serde(default)]
    pub write_jobs: Vec<String>,
    #[serde(default)]
    pub read_jobs: Vec<String>,
}

fn patch(path: PathBuf) -> PathBuf {
    if let Some(_tmp) = path.to_str() {
        #[cfg(windows)]
        return _tmp
            .replace(
                "system32\\config\\systemprofile",
                "ServiceProfiles\\LocalService",
            )
            .into();
        #[cfg(target_os = "macos")]
        return _tmp.replace("Application Support", "Preferences").into();
        #[cfg(target_os = "linux")]
        {
            if _tmp == "/root" {
                if let Ok(output) = std::process::Command::new("whoami").output() {
                    let user = String::from_utf8_lossy(&output.stdout)
                        .to_string()
                        .trim()
                        .to_owned();
                    if user != "root" {
                        return format!("/home/{}", user).into();
                    }
                }
            }
        }
    }
    path
}

impl Config2 {
    fn load() -> Config2 {
        let mut config = Config::load_::<Config2>("2");
        if let Some(mut socks) = config.socks {
            let (password, _, store) =
                decrypt_str_or_original(&socks.password, PASSWORD_ENC_VERSION);
            socks.password = password;
            config.socks = Some(socks);
            if store {
                config.store();
            }
        }
        config
    }

    pub fn file() -> PathBuf {
        Config::file_("2")
    }

    fn store(&self) {
        let mut config = self.clone();
        if let Some(mut socks) = config.socks {
            socks.password = encrypt_str_or_original(&socks.password, PASSWORD_ENC_VERSION);
            config.socks = Some(socks);
        }
        Config::store_(&config, "2");
    }

    pub fn get() -> Config2 {
        return CONFIG2.read().unwrap().clone();
    }

    pub fn set(cfg: Config2) -> bool {
        let mut lock = CONFIG2.write().unwrap();
        if *lock == cfg {
            return false;
        }
        *lock = cfg;
        lock.store();
        true
    }
}

pub fn load_path<T: serde::Serialize + serde::de::DeserializeOwned + Default + std::fmt::Debug>(
    file: PathBuf,
) -> T {
    let cfg = match confy::load_path(&file) {
        Ok(config) => config,
        Err(err) => {
            log::error!("Failed to load config: {}", err);
            T::default()
        }
    };
    cfg
}

#[inline]
pub fn store_path<T: serde::Serialize>(path: PathBuf, cfg: T) -> crate::ResultType<()> {
    Ok(confy::store_path(path, cfg)?)
}

impl Config {
    fn load_<T: serde::Serialize + serde::de::DeserializeOwned + Default + std::fmt::Debug>(
        suffix: &str,
    ) -> T {
        let file = Self::file_(suffix);
        log::debug!("Configuration path: {}", file.display());
        let cfg = load_path(file);
        if suffix.is_empty() {
            log::trace!("{:?}", cfg);
        }
        cfg
    }

    fn store_<T: serde::Serialize>(config: &T, suffix: &str) {
        let file = Self::file_(suffix);
        if let Err(err) = store_path(file, config) {
            log::error!("Failed to store config: {}", err);
        }
    }

    fn load() -> Config {
        let mut config = Config::load_::<Config>("");
        let mut store = false;
        let (password, _, store1) = decrypt_str_or_original(&config.password, PASSWORD_ENC_VERSION);
        config.password = password;
        store |= store1;
        let mut id_valid = false;
        let (id, encrypted, store2) = decrypt_str_or_original(&config.enc_id, PASSWORD_ENC_VERSION);
        if encrypted {
            config.id = id;
            id_valid = true;
            store |= store2;
        } else {
            if crate::get_modified_time(&Self::file_(""))
                .checked_sub(std::time::Duration::from_secs(30)) // allow modification during installation
                .unwrap_or(crate::get_exe_time())
                < crate::get_exe_time()
            {
                if !config.id.is_empty()
                    && config.enc_id.is_empty()
                    && !decrypt_str_or_original(&config.id, PASSWORD_ENC_VERSION).1
                {
                    id_valid = true;
                    store = true;
                }
            }
        }
        if !id_valid {
            for _ in 0..3 {
                if let Some(id) = Config::get_auto_id() {
                    config.id = id;
                    store = true;
                    break;
                } else {
                    log::error!("Failed to generate new id");
                }
            }
        }
        if store {
            config.store();
        }
        config
    }

    fn store(&self) {
        let mut config = self.clone();
        config.password = encrypt_str_or_original(&config.password, PASSWORD_ENC_VERSION);
        config.enc_id = encrypt_str_or_original(&config.id, PASSWORD_ENC_VERSION);
        config.id = "".to_owned();
        Config::store_(&config, "");
    }

    pub fn file() -> PathBuf {
        Self::file_("")
    }

    fn file_(suffix: &str) -> PathBuf {
        let name = format!("{}{}", *APP_NAME.read().unwrap(), suffix);
        Config::with_extension(Self::path(name))
    }

    pub fn is_empty(&self) -> bool {
        (self.id.is_empty() && self.enc_id.is_empty()) || self.key_pair.0.is_empty()
    }

    pub fn get_home() -> PathBuf {
        #[cfg(any(target_os = "android", target_os = "ios"))]
        return Self::path(APP_HOME_DIR.read().unwrap().as_str());
        if let Some(path) = dirs_next::home_dir() {
            patch(path)
        } else if let Ok(path) = std::env::current_dir() {
            path
        } else {
            std::env::temp_dir()
        }
    }

    pub fn path<P: AsRef<Path>>(p: P) -> PathBuf {
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            let mut path: PathBuf = APP_DIR.read().unwrap().clone().into();
            path.push(p);
            return path;
        }
        #[cfg(not(target_os = "macos"))]
        let org = "";
        #[cfg(target_os = "macos")]
        let org = ORG.read().unwrap().clone();
        // /var/root for root
        if let Some(project) = ProjectDirs::from("", &org, &*APP_NAME.read().unwrap()) {
            let mut path = patch(project.config_dir().to_path_buf());
            path.push(p);
            return path;
        }
        return "".into();
    }

    #[allow(unreachable_code)]
    pub fn log_path() -> PathBuf {
        #[cfg(target_os = "macos")]
        {
            if let Some(path) = dirs_next::home_dir().as_mut() {
                path.push(format!("Library/Logs/{}", *APP_NAME.read().unwrap()));
                return path.clone();
            }
        }
        #[cfg(target_os = "linux")]
        {
            let mut path = Self::get_home();
            path.push(format!(".local/share/logs/{}", *APP_NAME.read().unwrap()));
            std::fs::create_dir_all(&path).ok();
            return path;
        }
        if let Some(path) = Self::path("").parent() {
            let mut path: PathBuf = path.into();
            path.push("log");
            return path;
        }
        "".into()
    }

    pub fn ipc_path(postfix: &str) -> String {
        #[cfg(windows)]
        {
            // \\ServerName\pipe\PipeName
            // where ServerName is either the name of a remote computer or a period, to specify the local computer.
            // https://docs.microsoft.com/en-us/windows/win32/ipc/pipe-names
            format!(
                "\\\\.\\pipe\\{}\\query{}",
                *APP_NAME.read().unwrap(),
                postfix
            )
        }
        #[cfg(not(windows))]
        {
            use std::os::unix::fs::PermissionsExt;
            #[cfg(target_os = "android")]
            let mut path: PathBuf =
                format!("{}/{}", *APP_DIR.read().unwrap(), *APP_NAME.read().unwrap()).into();
            #[cfg(not(target_os = "android"))]
            let mut path: PathBuf = format!("/tmp/{}", *APP_NAME.read().unwrap()).into();
            fs::create_dir(&path).ok();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o0777)).ok();
            path.push(format!("ipc{}", postfix));
            path.to_str().unwrap_or("").to_owned()
        }
    }

    pub fn icon_path() -> PathBuf {
        let mut path = Self::path("icons");
        if fs::create_dir_all(&path).is_err() {
            path = std::env::temp_dir();
        }
        path
    }

    #[inline]
    pub fn get_any_listen_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)
    }

    pub fn get_rendezvous_server() -> String {
        let mut rendezvous_server = Self::get_option("custom-rendezvous-server");
        if rendezvous_server.is_empty() {
            rendezvous_server = PROD_RENDEZVOUS_SERVER.read().unwrap().clone();
        }
        if rendezvous_server.is_empty() {
            rendezvous_server = CONFIG2.read().unwrap().rendezvous_server.clone();
        }
        if rendezvous_server.is_empty() {
            rendezvous_server = Self::get_rendezvous_servers()
                .drain(..)
                .next()
                .unwrap_or("".to_owned());
        }
        if !rendezvous_server.contains(":") {
            rendezvous_server = format!("{}:{}", rendezvous_server, RENDEZVOUS_PORT);
        }
        rendezvous_server
    }

    pub fn get_rendezvous_servers() -> Vec<String> {
        let s = Self::get_option("custom-rendezvous-server");
        if !s.is_empty() {
            return vec![s];
        }
        let s = PROD_RENDEZVOUS_SERVER.read().unwrap().clone();
        if !s.is_empty() {
            return vec![s];
        }
        let serial_obsolute = CONFIG2.read().unwrap().serial > SERIAL;
        if serial_obsolute {
            let ss: Vec<String> = Self::get_option("rendezvous-servers")
                .split(",")
                .filter(|x| x.contains("."))
                .map(|x| x.to_owned())
                .collect();
            if !ss.is_empty() {
                return ss;
            }
        }
        return RENDEZVOUS_SERVERS.iter().map(|x| x.to_string()).collect();
    }

    pub fn reset_online() {
        *ONLINE.lock().unwrap() = Default::default();
    }

    pub fn update_latency(host: &str, latency: i64) {
        ONLINE.lock().unwrap().insert(host.to_owned(), latency);
        let mut host = "".to_owned();
        let mut delay = i64::MAX;
        for (tmp_host, tmp_delay) in ONLINE.lock().unwrap().iter() {
            if tmp_delay > &0 && tmp_delay < &delay {
                delay = tmp_delay.clone();
                host = tmp_host.to_string();
            }
        }
        if !host.is_empty() {
            let mut config = CONFIG2.write().unwrap();
            if host != config.rendezvous_server {
                log::debug!("Update rendezvous_server in config to {}", host);
                log::debug!("{:?}", *ONLINE.lock().unwrap());
                config.rendezvous_server = host;
                config.store();
            }
        }
    }

    pub fn set_id(id: &str) {
        let mut config = CONFIG.write().unwrap();
        if id == config.id {
            return;
        }
        config.id = id.into();
        config.store();
    }

    pub fn set_nat_type(nat_type: i32) {
        let mut config = CONFIG2.write().unwrap();
        if nat_type == config.nat_type {
            return;
        }
        config.nat_type = nat_type;
        config.store();
    }

    pub fn get_nat_type() -> i32 {
        CONFIG2.read().unwrap().nat_type
    }

    pub fn set_serial(serial: i32) {
        let mut config = CONFIG2.write().unwrap();
        if serial == config.serial {
            return;
        }
        config.serial = serial;
        config.store();
    }

    pub fn get_serial() -> i32 {
        std::cmp::max(CONFIG2.read().unwrap().serial, SERIAL)
    }

    fn get_auto_id() -> Option<String> {
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            return Some(
                rand::thread_rng()
                    .gen_range(1_000_000_000..2_000_000_000)
                    .to_string(),
            );
        }
        let mut id = 0u32;
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        if let Ok(Some(ma)) = mac_address::get_mac_address() {
            for x in &ma.bytes()[2..] {
                id = (id << 8) | (*x as u32);
            }
            id = id & 0x1FFFFFFF;
            Some(id.to_string())
        } else {
            None
        }
    }

    pub fn get_auto_password(length: usize) -> String {
        let mut rng = rand::thread_rng();
        (0..length)
            .map(|_| CHARS[rng.gen::<usize>() % CHARS.len()])
            .collect()
    }

    pub fn get_key_confirmed() -> bool {
        CONFIG.read().unwrap().key_confirmed
    }

    pub fn set_key_confirmed(v: bool) {
        let mut config = CONFIG.write().unwrap();
        if config.key_confirmed == v {
            return;
        }
        config.key_confirmed = v;
        if !v {
            config.keys_confirmed = Default::default();
        }
        config.store();
    }

    pub fn get_host_key_confirmed(host: &str) -> bool {
        if let Some(true) = CONFIG.read().unwrap().keys_confirmed.get(host) {
            true
        } else {
            false
        }
    }

    pub fn set_host_key_confirmed(host: &str, v: bool) {
        if Self::get_host_key_confirmed(host) == v {
            return;
        }
        let mut config = CONFIG.write().unwrap();
        config.keys_confirmed.insert(host.to_owned(), v);
        config.store();
    }

    pub fn get_key_pair() -> (Vec<u8>, Vec<u8>) {
        // lock here to make sure no gen_keypair more than once
        // no use of CONFIG directly here to ensure no recursive calling in Config::load because of password dec which calling this function
        let mut lock = KEY_PAIR.lock().unwrap();
        if let Some(p) = lock.as_ref() {
            return p.clone();
        }
        let mut config = Config::load_::<Config>("");
        if config.key_pair.0.is_empty() {
            let (pk, sk) = sign::gen_keypair();
            let key_pair = (sk.0.to_vec(), pk.0.into());
            config.key_pair = key_pair.clone();
            std::thread::spawn(|| {
                let mut config = CONFIG.write().unwrap();
                config.key_pair = key_pair;
                config.store();
            });
        }
        *lock = Some(config.key_pair.clone());
        return config.key_pair;
    }

    pub fn get_id() -> String {
        let mut id = CONFIG.read().unwrap().id.clone();
        if id.is_empty() {
            if let Some(tmp) = Config::get_auto_id() {
                id = tmp;
                Config::set_id(&id);
            }
        }
        id
    }

    pub fn get_id_or(b: String) -> String {
        let a = CONFIG.read().unwrap().id.clone();
        if a.is_empty() {
            b
        } else {
            a
        }
    }

    pub fn get_options() -> HashMap<String, String> {
        CONFIG2.read().unwrap().options.clone()
    }

    pub fn set_options(v: HashMap<String, String>) {
        let mut config = CONFIG2.write().unwrap();
        if config.options == v {
            return;
        }
        config.options = v;
        config.store();
    }

    pub fn get_option(k: &str) -> String {
        if let Some(v) = CONFIG2.read().unwrap().options.get(k) {
            v.clone()
        } else {
            "".to_owned()
        }
    }

    pub fn set_option(k: String, v: String) {
        let mut config = CONFIG2.write().unwrap();
        let v2 = if v.is_empty() { None } else { Some(&v) };
        if v2 != config.options.get(&k) {
            if v2.is_none() {
                config.options.remove(&k);
            } else {
                config.options.insert(k, v);
            }
            config.store();
        }
    }

    pub fn update_id() {
        // to-do: how about if one ip register a lot of ids?
        let id = Self::get_id();
        let mut rng = rand::thread_rng();
        let new_id = rng.gen_range(1_000_000_000..2_000_000_000).to_string();
        Config::set_id(&new_id);
        log::info!("id updated from {} to {}", id, new_id);
    }

    pub fn set_permanent_password(password: &str) {
        let mut config = CONFIG.write().unwrap();
        if password == config.password {
            return;
        }
        config.password = password.into();
        config.store();
    }

    pub fn get_permanent_password() -> String {
        CONFIG.read().unwrap().password.clone()
    }

    pub fn set_salt(salt: &str) {
        let mut config = CONFIG.write().unwrap();
        if salt == config.salt {
            return;
        }
        config.salt = salt.into();
        config.store();
    }

    pub fn get_salt() -> String {
        let mut salt = CONFIG.read().unwrap().salt.clone();
        if salt.is_empty() {
            salt = Config::get_auto_password(6);
            Config::set_salt(&salt);
        }
        salt
    }

    pub fn set_socks(socks: Option<Socks5Server>) {
        let mut config = CONFIG2.write().unwrap();
        if config.socks == socks {
            return;
        }
        config.socks = socks;
        config.store();
    }

    pub fn get_socks() -> Option<Socks5Server> {
        CONFIG2.read().unwrap().socks.clone()
    }

    pub fn get_network_type() -> NetworkType {
        match &CONFIG2.read().unwrap().socks {
            None => NetworkType::Direct,
            Some(_) => NetworkType::ProxySocks,
        }
    }

    pub fn get() -> Config {
        return CONFIG.read().unwrap().clone();
    }

    pub fn set(cfg: Config) -> bool {
        let mut lock = CONFIG.write().unwrap();
        if *lock == cfg {
            return false;
        }
        *lock = cfg;
        lock.store();
        true
    }

    fn with_extension(path: PathBuf) -> PathBuf {
        let ext = path.extension();
        if let Some(ext) = ext {
            let ext = format!("{}.toml", ext.to_string_lossy());
            path.with_extension(&ext)
        } else {
            path.with_extension("toml")
        }
    }
}

const PEERS: &str = "peers";

impl PeerConfig {
    pub fn load(id: &str) -> PeerConfig {
        let _ = CONFIG.read().unwrap(); // for lock
        match confy::load_path(&Self::path(id)) {
            Ok(config) => {
                let mut config: PeerConfig = config;
                let mut store = false;
                let (password, _, store2) =
                    decrypt_vec_or_original(&config.password, PASSWORD_ENC_VERSION);
                config.password = password;
                store = store || store2;
                config.options.get_mut("rdp_password").map(|v| {
                    let (password, _, store2) = decrypt_str_or_original(v, PASSWORD_ENC_VERSION);
                    *v = password;
                    store = store || store2;
                });
                config.options.get_mut("os-password").map(|v| {
                    let (password, _, store2) = decrypt_str_or_original(v, PASSWORD_ENC_VERSION);
                    *v = password;
                    store = store || store2;
                });
                if store {
                    config.store(id);
                }
                config
            }
            Err(err) => {
                log::error!("Failed to load config: {}", err);
                Default::default()
            }
        }
    }

    pub fn store(&self, id: &str) {
        let _ = CONFIG.read().unwrap(); // for lock
        let mut config = self.clone();
        config.password = encrypt_vec_or_original(&config.password, PASSWORD_ENC_VERSION);
        config
            .options
            .get_mut("rdp_password")
            .map(|v| *v = encrypt_str_or_original(v, PASSWORD_ENC_VERSION));
        config
            .options
            .get_mut("os-password")
            .map(|v| *v = encrypt_str_or_original(v, PASSWORD_ENC_VERSION));
        if let Err(err) = store_path(Self::path(id), config) {
            log::error!("Failed to store config: {}", err);
        }
    }

    pub fn remove(id: &str) {
        fs::remove_file(&Self::path(id)).ok();
    }

    fn path(id: &str) -> PathBuf {
        let path: PathBuf = [PEERS, id].iter().collect();
        Config::with_extension(Config::path(path))
    }

    pub fn peers() -> Vec<(String, SystemTime, PeerConfig)> {
        if let Ok(peers) = Config::path(PEERS).read_dir() {
            if let Ok(peers) = peers
                .map(|res| res.map(|e| e.path()))
                .collect::<Result<Vec<_>, _>>()
            {
                let mut peers: Vec<_> = peers
                    .iter()
                    .filter(|p| {
                        p.is_file()
                            && p.extension().map(|p| p.to_str().unwrap_or("")) == Some("toml")
                    })
                    .map(|p| {
                        let t = crate::get_modified_time(&p);
                        let id = p
                            .file_stem()
                            .map(|p| p.to_str().unwrap_or(""))
                            .unwrap_or("")
                            .to_owned();
                        let c = PeerConfig::load(&id);
                        if c.info.platform.is_empty() {
                            fs::remove_file(&p).ok();
                        }
                        (id, t, c)
                    })
                    .filter(|p| !p.2.info.platform.is_empty())
                    .collect();
                peers.sort_unstable_by(|a, b| b.1.cmp(&a.1));
                return peers;
            }
        }
        Default::default()
    }
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct LocalConfig {
    #[serde(default)]
    remote_id: String, // latest used one
    #[serde(default)]
    size: Size,
    #[serde(default)]
    pub fav: Vec<String>,
    #[serde(default)]
    options: HashMap<String, String>,
}

impl LocalConfig {
    fn load() -> LocalConfig {
        Config::load_::<LocalConfig>("_local")
    }

    fn store(&self) {
        Config::store_(self, "_local");
    }

    pub fn get_size() -> Size {
        LOCAL_CONFIG.read().unwrap().size
    }

    pub fn set_size(x: i32, y: i32, w: i32, h: i32) {
        let mut config = LOCAL_CONFIG.write().unwrap();
        let size = (x, y, w, h);
        if size == config.size || size.2 < 300 || size.3 < 300 {
            return;
        }
        config.size = size;
        config.store();
    }

    pub fn set_remote_id(remote_id: &str) {
        let mut config = LOCAL_CONFIG.write().unwrap();
        if remote_id == config.remote_id {
            return;
        }
        config.remote_id = remote_id.into();
        config.store();
    }

    pub fn get_remote_id() -> String {
        LOCAL_CONFIG.read().unwrap().remote_id.clone()
    }

    pub fn set_fav(fav: Vec<String>) {
        let mut lock = LOCAL_CONFIG.write().unwrap();
        if lock.fav == fav {
            return;
        }
        lock.fav = fav;
        lock.store();
    }

    pub fn get_fav() -> Vec<String> {
        LOCAL_CONFIG.read().unwrap().fav.clone()
    }

    pub fn get_option(k: &str) -> String {
        if let Some(v) = LOCAL_CONFIG.read().unwrap().options.get(k) {
            v.clone()
        } else {
            "".to_owned()
        }
    }

    pub fn set_option(k: String, v: String) {
        let mut config = LOCAL_CONFIG.write().unwrap();
        let v2 = if v.is_empty() { None } else { Some(&v) };
        if v2 != config.options.get(&k) {
            if v2.is_none() {
                config.options.remove(&k);
            } else {
                config.options.insert(k, v);
            }
            config.store();
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct DiscoveryPeer {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub platform: String,
    #[serde(default)]
    pub online: bool,
    #[serde(default)]
    pub ip_mac: HashMap<String, String>,
}

impl DiscoveryPeer {
    pub fn is_same_peer(&self, other: &DiscoveryPeer) -> bool {
        self.id == other.id && self.username == other.username
    }
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct LanPeers {
    pub peers: Vec<DiscoveryPeer>,
}

impl LanPeers {
    pub fn load() -> LanPeers {
        let _ = CONFIG.read().unwrap(); // for lock
        match confy::load_path(&Config::file_("_lan_peers")) {
            Ok(peers) => peers,
            Err(err) => {
                log::error!("Failed to load lan peers: {}", err);
                Default::default()
            }
        }
    }

    pub fn store(peers: &Vec<DiscoveryPeer>) {
        let f = LanPeers {
            peers: peers.clone(),
        };
        if let Err(err) = store_path(Config::file_("_lan_peers"), f) {
            log::error!("Failed to store lan peers: {}", err);
        }
    }

    pub fn modify_time() -> crate::ResultType<u64> {
        let p = Config::file_("_lan_peers");
        Ok(fs::metadata(p)?
            .modified()?
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_millis() as _)
    }
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct HwCodecConfig {
    #[serde(default)]
    pub options: HashMap<String, String>,
}

impl HwCodecConfig {
    pub fn load() -> HwCodecConfig {
        Config::load_::<HwCodecConfig>("_hwcodec")
    }

    pub fn store(&self) {
        Config::store_(self, "_hwcodec");
    }

    pub fn remove() {
        std::fs::remove_file(Config::file_("_hwcodec")).ok();
    }

    /// refresh current global HW_CODEC_CONFIG, usually uesd after HwCodecConfig::remove()
    pub fn refresh() {
        *HW_CODEC_CONFIG.write().unwrap() = HwCodecConfig::load();
        log::debug!("HW_CODEC_CONFIG refreshed successfully");
    }

    pub fn get() -> HwCodecConfig {
        return HW_CODEC_CONFIG.read().unwrap().clone();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize() {
        let cfg: Config = Default::default();
        let res = toml::to_string_pretty(&cfg);
        assert!(res.is_ok());
        let cfg: PeerConfig = Default::default();
        let res = toml::to_string_pretty(&cfg);
        assert!(res.is_ok());
    }
}
