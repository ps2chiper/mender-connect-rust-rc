//! Configuration subset needed for the remote terminal.
//!
//! Feature flags for `PortForward`, `FileTransfer` and `MenderClient` are
//! supported as disable toggles. When `Limits.Enabled` is true,
//! [`Config::validate`] compiles the actual file-transfer policy through the
//! trusted NSS resolver and verifies that the configured root directory can be
//! opened read-only. Disabled limits perform no NSS or root work.
//!
//! Go's configuration decoder matches JSON field names case-insensitively.
//! This loader canonicalizes all known key names before typed validation so
//! case variants such as `disable` map to `Disable`. Unknown keys, including
//! misspellings such as `Disabel`, are rejected instead of being ignored, and
//! duplicate keys (including case variants) are rejected in every object.
//!
//! Some known Go fields are accepted as typed, deprecated compatibility data
//! and then ignored: `ReconnectIntervalSeconds`, `ServerURL`, `Servers`,
//! `ClientProtocol`, `HttpsClient`, `SkipVerify` and `ServerCertificate`.
//! `Limits.FileTransfer` is parsed and merged in every case, but it is only
//! compiled and enforced when `Limits.Enabled` is true. Configured shell-command
//! path and executable checks are performed, and the shell must be listed in
//! `/etc/shells`. The configured user is resolved through NSS.

use std::fmt;
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

use crate::limits_config::{LiveNss, RawFileTransferLimits, build_policy};
use crate::limits_fs::RootDir;

pub const DEFAULT_CONF_DIR: &str = "/etc/mender";
pub const DEFAULT_DATA_STORE: &str = "/var/lib/mender";
pub const DEFAULT_SHELL_COMMAND: &str = "/bin/sh";
pub const DEFAULT_SHELL_ARGUMENTS: &[&str] = &["--login"];
pub const DEFAULT_TERMINAL_WIDTH: u16 = 80;
pub const DEFAULT_TERMINAL_HEIGHT: u16 = 40;
pub const DEFAULT_STOP_EXPIRED: bool = true;
pub const DEFAULT_EXPIRE_AFTER_IDLE: u32 = 600;

/// Maximum accepted configuration file size.
pub const MAX_CONFIG_FILE_SIZE: u64 = 1024 * 1024;

/// Maximum accepted JSON nesting depth for configuration files.
const MAX_CONFIG_DEPTH: usize = 128;

const KNOWN_CONFIG_KEYS: &[&str] = &[
    "User",
    "ShellCommand",
    "ShellArguments",
    "Terminal",
    "Width",
    "Height",
    "Disable",
    "Sessions",
    "StopExpired",
    "ExpireAfter",
    "ExpireAfterIdle",
    "MaxPerUser",
    "PortForward",
    "FileTransfer",
    "MenderClient",
    "Limits",
    "Enabled",
    "ReconnectIntervalSeconds",
    "ServerURL",
    "Servers",
    "ClientProtocol",
    "HttpsClient",
    "SkipVerify",
    "ServerCertificate",
    "Certificate",
    "Key",
    "SSLEngine",
    "Chroot",
    "FollowSymLinks",
    "AllowOverwrite",
    "OwnerPut",
    "GroupPut",
    "OwnerGet",
    "GroupGet",
    "Umask",
    "MaxFileSize",
    "Counters",
    "MaxBytesTxPerMinute",
    "MaxBytesRxPerMinute",
    "AllowSuid",
    "RegularFilesOnly",
    "PreserveMode",
    "PreserveOwner",
];

fn canonical_key(key: &str) -> Option<&'static str> {
    KNOWN_CONFIG_KEYS
        .iter()
        .copied()
        .find(|candidate| key.eq_ignore_ascii_case(candidate))
}

fn default_shell_arguments() -> Vec<String> {
    DEFAULT_SHELL_ARGUMENTS
        .iter()
        .map(|argument| (*argument).to_owned())
        .collect()
}

fn deserialize_shell_arguments<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    let arguments = Option::<Vec<String>>::deserialize(deserializer)?;
    Ok(Some(arguments.unwrap_or_else(default_shell_arguments)))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalConfig {
    pub width: u16,
    pub height: u16,
    pub disable: bool,
}

impl Default for TerminalConfig {
    fn default() -> Self {
        Self {
            width: DEFAULT_TERMINAL_WIDTH,
            height: DEFAULT_TERMINAL_HEIGHT,
            disable: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionsConfig {
    pub stop_expired: bool,
    pub expire_after: u32,
    pub expire_after_idle: u32,
    pub max_per_user: u32,
}

impl Default for SessionsConfig {
    fn default() -> Self {
        Self {
            stop_expired: DEFAULT_STOP_EXPIRED,
            expire_after: 0,
            expire_after_idle: DEFAULT_EXPIRE_AFTER_IDLE,
            max_per_user: 0,
        }
    }
}

/// Feature toggle for an upstream protocol handler.
///
/// Upstream features are enabled unless explicitly disabled, so the default
/// is `disable: false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FeatureConfig {
    pub disable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub user: String,
    pub shell_command: String,
    pub shell_arguments: Vec<String>,
    pub terminal: TerminalConfig,
    pub sessions: SessionsConfig,
    pub port_forward: FeatureConfig,
    pub file_transfer: FeatureConfig,
    pub mender_client: FeatureConfig,
    /// Whether the upstream `Limits` policy is enabled.
    ///
    /// When this is `true`, [`Config::validate`] compiles the configured
    /// file-transfer policy and verifies the trusted root. Disabled limits do
    /// not perform NSS lookups or root-directory work.
    pub limits_enabled: bool,
    /// Raw, typed file-transfer limits as parsed from the configuration files.
    ///
    /// Every field is preserved (including explicit `false` values and nested
    /// counters) so the startup adapter can compile it into a
    /// [`crate::limits::LimitsPolicy`] exactly as configured.
    pub limits: RawFileTransferLimits,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct ConfigFile {
    user: Option<String>,
    shell_command: Option<String>,
    #[serde(default, deserialize_with = "deserialize_shell_arguments")]
    shell_arguments: Option<Vec<String>>,
    terminal: Option<TerminalFile>,
    sessions: Option<SessionsFile>,
    port_forward: Option<FeatureFile>,
    file_transfer: Option<FeatureFile>,
    mender_client: Option<FeatureFile>,
    limits: Option<LimitsFile>,
    #[serde(rename = "ReconnectIntervalSeconds")]
    _reconnect_interval_seconds: Option<i64>,
    #[serde(rename = "ServerURL")]
    _server_url: Option<String>,
    #[serde(rename = "Servers")]
    _compat_servers: Option<Vec<Option<DeprecatedServerFile>>>,
    #[serde(rename = "ClientProtocol")]
    _client_protocol: Option<String>,
    #[serde(rename = "HttpsClient")]
    _https_client: Option<DeprecatedHttpsClientFile>,
    #[serde(rename = "SkipVerify")]
    _skip_verify: Option<bool>,
    #[serde(rename = "ServerCertificate")]
    _server_certificate: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct TerminalFile {
    width: Option<u16>,
    height: Option<u16>,
    disable: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct SessionsFile {
    stop_expired: Option<bool>,
    expire_after: Option<u32>,
    expire_after_idle: Option<u32>,
    max_per_user: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct FeatureFile {
    disable: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct LimitsFile {
    enabled: Option<bool>,
    #[serde(rename = "FileTransfer")]
    file_transfer: Option<RawFileTransferLimits>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct DeprecatedServerFile {
    #[serde(rename = "ServerURL")]
    _server_url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct DeprecatedHttpsClientFile {
    #[serde(rename = "Certificate")]
    _certificate: Option<String>,
    #[serde(rename = "Key")]
    _key: Option<String>,
    #[serde(rename = "SSLEngine")]
    _ssl_engine: Option<String>,
}

impl ConfigFile {
    fn merge(&mut self, other: Self) {
        if other.user.is_some() {
            self.user = other.user;
        }
        if other.shell_command.is_some() {
            self.shell_command = other.shell_command;
        }
        if other.shell_arguments.is_some() {
            self.shell_arguments = other.shell_arguments;
        }
        if let Some(terminal) = other.terminal {
            self.terminal
                .get_or_insert_with(TerminalFile::default)
                .merge(terminal);
        }
        if let Some(sessions) = other.sessions {
            self.sessions
                .get_or_insert_with(SessionsFile::default)
                .merge(sessions);
        }
        if let Some(port_forward) = other.port_forward {
            self.port_forward
                .get_or_insert_with(FeatureFile::default)
                .merge(port_forward);
        }
        if let Some(file_transfer) = other.file_transfer {
            self.file_transfer
                .get_or_insert_with(FeatureFile::default)
                .merge(file_transfer);
        }
        if let Some(mender_client) = other.mender_client {
            self.mender_client
                .get_or_insert_with(FeatureFile::default)
                .merge(mender_client);
        }
        if let Some(limits) = other.limits {
            self.limits
                .get_or_insert_with(LimitsFile::default)
                .merge(limits);
        }
    }
}

impl TerminalFile {
    fn merge(&mut self, other: Self) {
        if other.width.is_some() {
            self.width = other.width;
        }
        if other.height.is_some() {
            self.height = other.height;
        }
        if other.disable.is_some() {
            self.disable = other.disable;
        }
    }
}

impl SessionsFile {
    fn merge(&mut self, other: Self) {
        if other.stop_expired.is_some() {
            self.stop_expired = other.stop_expired;
        }
        if other.expire_after.is_some() {
            self.expire_after = other.expire_after;
        }
        if other.expire_after_idle.is_some() {
            self.expire_after_idle = other.expire_after_idle;
        }
        if other.max_per_user.is_some() {
            self.max_per_user = other.max_per_user;
        }
    }
}

impl FeatureFile {
    fn merge(&mut self, other: Self) {
        if other.disable.is_some() {
            self.disable = other.disable;
        }
    }
}

impl LimitsFile {
    fn merge(&mut self, other: Self) {
        if other.enabled.is_some() {
            self.enabled = other.enabled;
        }
        if let Some(file_transfer) = other.file_transfer {
            self.file_transfer
                .get_or_insert_with(RawFileTransferLimits::default)
                .merge(file_transfer);
        }
    }
}

impl Config {
    fn from_file(file: ConfigFile) -> Self {
        let ConfigFile {
            user,
            shell_command,
            shell_arguments,
            terminal,
            sessions,
            port_forward,
            file_transfer,
            mender_client,
            limits,
            ..
        } = file;

        let user = user.unwrap_or_default();
        let shell_command = match shell_command {
            Some(command) if !command.is_empty() => command,
            _ => DEFAULT_SHELL_COMMAND.to_owned(),
        };
        let shell_arguments = shell_arguments.unwrap_or_else(default_shell_arguments);

        let terminal = terminal.unwrap_or_default();
        let terminal = TerminalConfig {
            width: match terminal.width {
                Some(0) | None => DEFAULT_TERMINAL_WIDTH,
                Some(width) => width,
            },
            height: match terminal.height {
                Some(0) | None => DEFAULT_TERMINAL_HEIGHT,
                Some(height) => height,
            },
            disable: terminal.disable.unwrap_or(false),
        };

        let sessions = sessions.unwrap_or_default();
        let stop_expired = sessions.stop_expired.unwrap_or(DEFAULT_STOP_EXPIRED);
        let mut expire_after = sessions.expire_after.unwrap_or(0);
        let mut expire_after_idle = sessions.expire_after_idle.unwrap_or(0);
        if !stop_expired {
            expire_after = 0;
            expire_after_idle = 0;
        } else if expire_after == 0 && expire_after_idle == 0 {
            expire_after_idle = DEFAULT_EXPIRE_AFTER_IDLE;
        }

        let sessions = SessionsConfig {
            stop_expired,
            expire_after,
            expire_after_idle,
            max_per_user: sessions.max_per_user.unwrap_or(0),
        };

        let port_forward = FeatureConfig {
            disable: port_forward.unwrap_or_default().disable.unwrap_or(false),
        };
        let file_transfer = FeatureConfig {
            disable: file_transfer.unwrap_or_default().disable.unwrap_or(false),
        };
        let mender_client = FeatureConfig {
            disable: mender_client.unwrap_or_default().disable.unwrap_or(false),
        };
        let limits = limits.unwrap_or_default();
        let limits_enabled = limits.enabled.unwrap_or(false);
        let limits = limits.file_transfer.unwrap_or_default();

        Self {
            user,
            shell_command,
            shell_arguments,
            terminal,
            sessions,
            port_forward,
            file_transfer,
            mender_client,
            limits_enabled,
            limits,
        }
    }

    /// Validate the settings required when a daemon starts.
    ///
    /// Shells must be absolute, regular files and executable, and must be
    /// listed in `/etc/shells`. The username must be non-empty, free of NUL
    /// bytes, at most [`crate::shell_policy::MAX_USERNAME_LEN`] bytes and
    /// resolvable through NSS. When file-transfer limits are enabled, the
    /// complete policy is compiled with the trusted NSS resolver and the
    /// configured root directory is opened read-only. No staging file is
    /// created here.
    pub fn validate(&self) -> Result<()> {
        if self.limits_enabled {
            build_policy(true, &self.limits, &LiveNss)
                .map_err(|error| anyhow::anyhow!("invalid file-transfer Limits policy: {error}"))?;
            let root_path = match self.limits.chroot.as_deref() {
                Some(path) if !path.is_empty() => PathBuf::from(path),
                _ => PathBuf::from("/"),
            };
            RootDir::open(&root_path).map_err(|error| {
                anyhow::anyhow!("file-transfer Limits root is not usable: {error}")
            })?;
        }

        crate::shell_policy::validate_user(&self.user)?;

        let shell = Path::new(&self.shell_command);
        if !shell.is_absolute() {
            bail!(
                "ShellCommand must be an absolute path: {}",
                self.shell_command
            );
        }

        let metadata = fs::metadata(shell)
            .with_context(|| format!("ShellCommand is not accessible: {}", self.shell_command))?;
        if !metadata.is_file() {
            bail!("ShellCommand is not a regular file: {}", self.shell_command);
        }
        if metadata.permissions().mode() & 0o111 == 0 {
            bail!("ShellCommand is not executable: {}", self.shell_command);
        }

        crate::shell_policy::validate_shell_command(&self.shell_command)?;

        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::from_file(ConfigFile::default())
    }
}

/// Load the optional fallback configuration first, then the primary
/// configuration. Values present in the primary file override the fallback.
///
/// Missing files are allowed. A present but malformed file is always an error;
/// defaults are not silently substituted for malformed JSON. Files larger than
/// [`MAX_CONFIG_FILE_SIZE`] are rejected before their contents are read.
pub fn load_config(
    primary_config_file: impl AsRef<Path>,
    fallback_config_file: impl AsRef<Path>,
) -> Result<Config> {
    let mut file = ConfigFile::default();
    merge_config_file(fallback_config_file.as_ref(), &mut file)?;
    merge_config_file(primary_config_file.as_ref(), &mut file)?;
    Ok(Config::from_file(file))
}

pub fn load_default_config() -> Result<Config> {
    load_config(
        default_primary_config_path(),
        default_fallback_config_path(),
    )
}

pub fn default_primary_config_path() -> PathBuf {
    PathBuf::from(DEFAULT_CONF_DIR).join("mender-connect.conf")
}

pub fn default_fallback_config_path() -> PathBuf {
    PathBuf::from(DEFAULT_DATA_STORE).join("mender-connect.conf")
}

fn merge_config_file(path: &Path, target: &mut ConfigFile) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_NOCTTY)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to open configuration file {}", path.display()));
        }
    };

    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect configuration file {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!(
            "configuration file {} is not a regular file",
            path.display()
        );
    }
    if metadata.len() > MAX_CONFIG_FILE_SIZE {
        bail!(
            "configuration file {} exceeds the {} byte limit",
            path.display(),
            MAX_CONFIG_FILE_SIZE
        );
    }

    let mut data = Vec::new();
    let mut limited = file.take(MAX_CONFIG_FILE_SIZE + 1);
    limited
        .read_to_end(&mut data)
        .with_context(|| format!("failed to read configuration file {}", path.display()))?;
    let data_len = u64::try_from(data.len()).with_context(|| {
        format!(
            "configuration file {} size is out of range for the size limit check",
            path.display()
        )
    })?;
    if data_len > MAX_CONFIG_FILE_SIZE {
        bail!(
            "configuration file {} exceeds the {} byte limit",
            path.display(),
            MAX_CONFIG_FILE_SIZE
        );
    }

    let file = parse_config_file(&data)
        .with_context(|| format!("failed to parse configuration file {}", path.display()))?;
    target.merge(file);
    Ok(())
}

fn parse_config_file(data: &[u8]) -> Result<ConfigFile> {
    let mut deserializer = serde_json::Deserializer::from_slice(data);
    let value = ConfigJsonSeed { depth: 0 }
        .deserialize(&mut deserializer)
        .context("invalid JSON configuration value")?;
    deserializer
        .end()
        .context("trailing tokens after JSON configuration value")?;
    match value {
        Value::Null => Ok(ConfigFile::default()),
        root @ Value::Object(_) => {
            serde_json::from_value(root).context("configuration schema mismatch")
        }
        _ => bail!("configuration root must be a JSON object or null"),
    }
}

struct ConfigJsonSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for ConfigJsonSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(ConfigJsonVisitor { depth: self.depth })
    }
}

struct ConfigJsonVisitor {
    depth: usize,
}

impl ConfigJsonVisitor {
    fn child_depth<E>(&self) -> std::result::Result<usize, E>
    where
        E: de::Error,
    {
        let depth = self
            .depth
            .checked_add(1)
            .ok_or_else(|| E::custom("configuration nesting depth overflow"))?;
        if depth > MAX_CONFIG_DEPTH {
            return Err(E::custom(format!(
                "configuration nesting exceeds {} levels",
                MAX_CONFIG_DEPTH
            )));
        }
        Ok(depth)
    }

    fn validate_field_shape<E>(key: &str, value: &Value) -> std::result::Result<(), E>
    where
        E: de::Error,
    {
        match key {
            "Terminal" | "Sessions" | "PortForward" | "FileTransfer" | "MenderClient"
            | "Limits" | "HttpsClient" | "Counters" => {
                if !matches!(value, Value::Object(_) | Value::Null) {
                    return Err(E::custom(format!(
                        "configuration key `{key}` must be a JSON object or null"
                    )));
                }
            }
            "Servers" => match value {
                Value::Null => {}
                Value::Array(entries) => {
                    for entry in entries {
                        if !matches!(entry, Value::Object(_) | Value::Null) {
                            return Err(E::custom(
                                "configuration key `Servers` entries must be JSON objects or null",
                            ));
                        }
                    }
                }
                _ => {
                    return Err(E::custom(
                        "configuration key `Servers` must be a JSON array or null",
                    ));
                }
            },
            _ => {}
        }
        Ok(())
    }
}

impl<'de> Visitor<'de> for ConfigJsonVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON configuration value")
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        let number = serde_json::Number::from_f64(value)
            .ok_or_else(|| E::custom("non-finite JSON number"))?;
        Ok(Value::Number(number))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::String(value))
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::Null)
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let child_depth = self.child_depth::<A::Error>()?;
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(ConfigJsonSeed { depth: child_depth })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let child_depth = self.child_depth::<A::Error>()?;
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            let canonical = match canonical_key(&key) {
                Some(key) => key.to_owned(),
                None => key,
            };
            if values.contains_key(&canonical) {
                return Err(de::Error::custom(format!(
                    "duplicate configuration key `{}`",
                    canonical
                )));
            }
            let value = map.next_value_seed(ConfigJsonSeed { depth: child_depth })?;
            Self::validate_field_shape::<A::Error>(&canonical, &value)?;
            values.insert(canonical, value);
        }
        Ok(Value::Object(values))
    }
}
