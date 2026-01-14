use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread;

use tracing::Level;
use tracing_subscriber::fmt::SubscriberBuilder;

use crate::config::LoggingConfig;

const LOG_FILENAME: &str = "file-guardian.log";
const LOG_QUEUE_CAPACITY: usize = 8192;

#[derive(Debug, thiserror::Error)]
pub enum LoggingError {
    #[error("invalid log level for {field}: {value}")]
    InvalidLevel { field: &'static str, value: String },

    #[error("logging.max_bytes must be greater than zero when logging.directory is set")]
    InvalidMaxBytes { value: u64 },

    #[error("logging.max_files must be greater than zero when logging.directory is set")]
    InvalidMaxFiles { value: usize },

    #[error("failed to create logging directory {path}: {source}")]
    CreateDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to open log file {path}: {source}")]
    OpenFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to initialize global tracing subscriber: {0}")]
    InitFailed(#[from] Box<dyn std::error::Error + Send + Sync>),
}

#[derive(Debug, Clone)]
pub struct LoggingSettings {
    pub level: Level,
    pub directory: Option<PathBuf>,
    pub max_bytes: u64,
    pub max_files: usize,
    pub console: bool,
}

pub struct LoggingGuards {
    _worker: Option<WorkerGuard>,
}

impl LoggingSettings {
    pub fn from_config(cfg: &LoggingConfig) -> Result<Self, LoggingError> {
        let level = parse_level(&cfg.level).map_err(|value| LoggingError::InvalidLevel {
            field: "logging.level",
            value,
        })?;

        if cfg.directory.is_some() {
            if cfg.max_bytes == 0 {
                return Err(LoggingError::InvalidMaxBytes {
                    value: cfg.max_bytes,
                });
            }
            if cfg.max_files == 0 {
                return Err(LoggingError::InvalidMaxFiles {
                    value: cfg.max_files,
                });
            }
        }

        Ok(LoggingSettings {
            level,
            directory: cfg.directory.clone(),
            max_bytes: cfg.max_bytes,
            max_files: cfg.max_files,
            console: cfg.console,
        })
    }

    pub fn init_tracing(&self) -> Result<LoggingGuards, LoggingError> {
        let builder: SubscriberBuilder = tracing_subscriber::fmt()
            .with_max_level(self.level)
            .with_target(true)
            .with_ansi(false);

        if let Some(directory) = &self.directory {
            fs::create_dir_all(directory).map_err(|source| LoggingError::CreateDir {
                path: directory.clone(),
                source,
            })?;

            let log_path = directory.join(LOG_FILENAME);
            let file_writer =
                RotatingFileWriter::new(log_path.clone(), self.max_bytes, self.max_files).map_err(
                    |source| LoggingError::OpenFile {
                        path: log_path,
                        source,
                    },
                )?;

            let sink: Box<dyn Write + Send> = if self.console {
                Box::new(TeeWriter::new(file_writer, io::stdout()))
            } else {
                Box::new(file_writer)
            };

            let (writer, guard) = NonBlockingWriter::new(sink);
            let writer_factory = move || writer.clone();

            builder
                .with_writer(writer_factory)
                .try_init()
                .map_err(LoggingError::InitFailed)?;

            Ok(LoggingGuards {
                _worker: Some(guard),
            })
        } else if self.console {
            builder
                .with_writer(io::stdout)
                .try_init()
                .map_err(LoggingError::InitFailed)?;

            Ok(LoggingGuards { _worker: None })
        } else {
            builder
                .with_writer(io::sink)
                .try_init()
                .map_err(LoggingError::InitFailed)?;

            Ok(LoggingGuards { _worker: None })
        }
    }
}

enum LogMessage {
    Line(Vec<u8>),
    Shutdown,
}

#[derive(Clone)]
struct NonBlockingWriter {
    sender: SyncSender<LogMessage>,
    shutdown: Arc<AtomicBool>,
}

impl NonBlockingWriter {
    fn new(sink: Box<dyn Write + Send>) -> (Self, WorkerGuard) {
        let (sender, receiver) = mpsc::sync_channel(LOG_QUEUE_CAPACITY);
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_shutdown = shutdown.clone();

        let handle = thread::spawn(move || log_worker(receiver, sink));
        let writer = NonBlockingWriter {
            sender: sender.clone(),
            shutdown: thread_shutdown,
        };

        let guard = WorkerGuard {
            sender,
            shutdown,
            handle: Some(handle),
        };

        (writer, guard)
    }
}

impl Write for NonBlockingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.shutdown.load(Ordering::SeqCst) {
            return Ok(buf.len());
        }

        match self.sender.try_send(LogMessage::Line(buf.to_vec())) {
            Ok(()) => Ok(buf.len()),
            Err(TrySendError::Full(_)) => Ok(buf.len()),
            Err(TrySendError::Disconnected(_)) => Ok(buf.len()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct WorkerGuard {
    sender: SyncSender<LogMessage>,
    shutdown: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = self.sender.send(LogMessage::Shutdown);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn log_worker(receiver: Receiver<LogMessage>, mut sink: Box<dyn Write + Send>) {
    let mut error_reported = false;

    for message in receiver {
        match message {
            LogMessage::Line(buf) => {
                if let Err(err) = sink.write_all(&buf) {
                    if !error_reported {
                        eprintln!("logging write failed: {err}");
                        error_reported = true;
                    }
                }
            }
            LogMessage::Shutdown => break,
        }
    }

    let _ = sink.flush();
}

struct TeeWriter<A, B> {
    primary: A,
    secondary: B,
}

impl<A, B> TeeWriter<A, B> {
    fn new(primary: A, secondary: B) -> Self {
        Self { primary, secondary }
    }
}

impl<A: Write, B: Write> Write for TeeWriter<A, B> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.primary.write_all(buf)?;
        self.secondary.write_all(buf)?;

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.primary.flush()?;
        self.secondary.flush()?;

        Ok(())
    }
}

struct RotatingFileWriter {
    base_path: PathBuf,
    max_bytes: u64,
    max_files: usize,
    file: std::fs::File,
    size: u64,
}

impl RotatingFileWriter {
    fn new(base_path: PathBuf, max_bytes: u64, max_files: usize) -> io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&base_path)?;
        let size = file.metadata().map(|metadata| metadata.len()).unwrap_or(0);

        Ok(Self {
            base_path,
            max_bytes,
            max_files,
            file,
            size,
        })
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.file.flush()?;

        for index in (1..=self.max_files).rev() {
            let destination = self.rotated_path(index);
            let source = if index == 1 {
                self.base_path.clone()
            } else {
                self.rotated_path(index - 1)
            };

            if source.exists() {
                if destination.exists() {
                    fs::remove_file(&destination)?;
                }
                fs::rename(source, destination)?;
            }
        }

        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.base_path)?;
        self.size = 0;

        Ok(())
    }

    fn rotated_path(&self, index: usize) -> PathBuf {
        let mut path = self.base_path.as_os_str().to_os_string();
        path.push(format!(".{index}"));
        PathBuf::from(path)
    }
}

impl Write for RotatingFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.size > 0 && self.size + buf.len() as u64 > self.max_bytes {
            self.rotate()?;
        }

        self.file.write_all(buf)?;
        self.size += buf.len() as u64;

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

fn parse_level(value: &str) -> Result<Level, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "trace" => Ok(Level::TRACE),
        "debug" => Ok(Level::DEBUG),
        "info" => Ok(Level::INFO),
        "warn" | "warning" => Ok(Level::WARN),
        "error" => Ok(Level::ERROR),
        _ => Err(value.to_string()),
    }
}

impl fmt::Display for LoggingSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "level={} directory={:?} max_bytes={} max_files={} console={}",
            self.level, self.directory, self.max_bytes, self.max_files, self.console
        )
    }
}
