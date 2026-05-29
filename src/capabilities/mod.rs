//! "What does this binary do" reporting from the recovered types and
//! itab dispatch tables.
//!
//! The data sources are everything we already recover: type names from
//! `typelinks`, interface-to-concrete pairs from `itablinks`, and the
//! function set. We match curated patterns against those names and emit
//! a list of inferred capabilities.
//!
//! The patterns live in this module rather than an external YAML file
//! for v1. When the curated list grows past ~50 entries we'll move it
//! to a real config file and let users supply their own.

use serde::Serialize;

use crate::itabs::Itab;
use crate::pclntab::Function;
use crate::types::Type;

#[derive(Debug, Clone, Serialize)]
pub struct Capability {
    pub name: &'static str,
    pub category: &'static str,
    /// Stable dot-namespaced identifier for the rule that fired. Treat
    /// as a public contract: rename `name` freely but never an `id`;
    /// deprecate by adding a new id rather than mutating an existing
    /// one. See README for the namespace layout.
    pub rule_id: &'static str,
    /// Concrete evidence: the type names, function names, or itab
    /// concrete-side strings that triggered the match. Truncated to
    /// keep the output scannable.
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CapabilityReport {
    pub capabilities: Vec<Capability>,
}

struct Rule {
    id: &'static str,
    name: &'static str,
    category: &'static str,
    /// Substrings to match against type names. If any matches, the
    /// capability triggers; the matched names go into evidence.
    type_substrings: &'static [&'static str],
    /// Substrings to match against itab concrete names.
    itab_substrings: &'static [&'static str],
    /// Substrings to match against function names.
    function_substrings: &'static [&'static str],
}

const RULES: &[Rule] = &[
    // HTTP / web
    Rule {
        id: "net.http.server",
        name: "HTTP server",
        category: "network",
        type_substrings: &[
            "http.Server",
            "http.ServeMux",
            "*http.Handler",
            "*http.HandlerFunc",
        ],
        itab_substrings: &[],
        function_substrings: &["net/http.ListenAndServe", "net/http.Serve"],
    },
    Rule {
        id: "net.http.client",
        name: "HTTP client",
        category: "network",
        type_substrings: &["http.Client", "http.Transport", "http.Request"],
        itab_substrings: &[],
        function_substrings: &["net/http.Get", "net/http.Post"],
    },
    Rule {
        id: "net.websocket",
        name: "WebSocket",
        category: "network",
        type_substrings: &["websocket.Conn", "websocket.Upgrader"],
        itab_substrings: &[],
        function_substrings: &[],
    },
    Rule {
        id: "net.grpc",
        name: "gRPC",
        category: "network",
        type_substrings: &["grpc.ClientConn", "grpc.Server", "grpc.UnaryServerInfo"],
        itab_substrings: &[],
        function_substrings: &["google.golang.org/grpc."],
    },
    Rule {
        id: "net.dns",
        name: "DNS",
        category: "network",
        type_substrings: &["net.Resolver", "net.DNSConfig", "miekg/dns."],
        itab_substrings: &[],
        function_substrings: &["net.LookupHost", "net.LookupIP"],
    },
    Rule {
        id: "net.tcp",
        name: "raw TCP",
        category: "network",
        type_substrings: &["net.TCPConn", "net.TCPListener", "net.TCPAddr"],
        itab_substrings: &[],
        function_substrings: &["net.Dial", "net.Listen"],
    },
    Rule {
        id: "net.udp",
        name: "raw UDP",
        category: "network",
        type_substrings: &["net.UDPConn", "net.UDPAddr"],
        itab_substrings: &[],
        function_substrings: &["net.DialUDP", "net.ListenUDP"],
    },
    Rule {
        id: "crypto.tls",
        name: "TLS client/server",
        category: "crypto",
        type_substrings: &[
            "tls.Config",
            "tls.Conn",
            "tls.Certificate",
            "tls.ClientHelloInfo",
        ],
        itab_substrings: &[],
        function_substrings: &["crypto/tls.Dial", "crypto/tls.Listen"],
    },
    Rule {
        id: "crypto.x509",
        name: "X.509 / PKI",
        category: "crypto",
        type_substrings: &[
            "x509.Certificate",
            "x509.CertPool",
            "x509.CertificateRequest",
        ],
        itab_substrings: &[],
        function_substrings: &["crypto/x509.ParseCertificate"],
    },
    Rule {
        id: "crypto.rsa",
        name: "RSA",
        category: "crypto",
        type_substrings: &["rsa.PrivateKey", "rsa.PublicKey"],
        itab_substrings: &[],
        function_substrings: &["crypto/rsa.SignPSS", "crypto/rsa.EncryptOAEP"],
    },
    Rule {
        id: "crypto.ecdsa",
        name: "ECDSA",
        category: "crypto",
        type_substrings: &["ecdsa.PrivateKey", "ecdsa.PublicKey"],
        itab_substrings: &[],
        function_substrings: &["crypto/ecdsa.Sign", "crypto/ecdsa.Verify"],
    },
    Rule {
        id: "crypto.aes",
        name: "AES",
        category: "crypto",
        type_substrings: &[],
        itab_substrings: &[],
        function_substrings: &[
            "crypto/aes.NewCipher",
            "crypto/cipher.NewCBC",
            "crypto/cipher.NewGCM",
        ],
    },
    // Cloud SDKs
    Rule {
        id: "cloud.aws.s3",
        name: "AWS SDK: S3",
        category: "cloud",
        type_substrings: &["aws-sdk-go-v2/service/s3.", "aws-sdk-go/service/s3."],
        itab_substrings: &[],
        function_substrings: &[],
    },
    Rule {
        id: "cloud.aws.ec2",
        name: "AWS SDK: EC2",
        category: "cloud",
        type_substrings: &["aws-sdk-go-v2/service/ec2.", "aws-sdk-go/service/ec2."],
        itab_substrings: &[],
        function_substrings: &[],
    },
    Rule {
        id: "cloud.aws.iam",
        name: "AWS SDK: IAM",
        category: "cloud",
        type_substrings: &["aws-sdk-go-v2/service/iam.", "aws-sdk-go/service/iam."],
        itab_substrings: &[],
        function_substrings: &[],
    },
    Rule {
        id: "cloud.aws.sts",
        name: "AWS SDK: STS",
        category: "cloud",
        type_substrings: &["aws-sdk-go-v2/service/sts.", "aws-sdk-go/service/sts."],
        itab_substrings: &[],
        function_substrings: &[],
    },
    Rule {
        id: "cloud.gcp",
        name: "Google Cloud SDK",
        category: "cloud",
        type_substrings: &["cloud.google.com/go/", "google.golang.org/api/"],
        itab_substrings: &[],
        function_substrings: &[],
    },
    Rule {
        id: "cloud.azure",
        name: "Azure SDK",
        category: "cloud",
        type_substrings: &[
            "github.com/Azure/azure-sdk-for-go/",
            "github.com/Azure/go-autorest/",
        ],
        itab_substrings: &[],
        function_substrings: &[],
    },
    Rule {
        id: "cloud.k8s.client",
        name: "Kubernetes client",
        category: "cloud",
        type_substrings: &["k8s.io/client-go/", "k8s.io/api/core/", "k8s.io/api/apps/"],
        itab_substrings: &[],
        function_substrings: &[],
    },
    // Filesystem / process
    Rule {
        id: "fs.file.rw",
        name: "file read/write",
        category: "filesystem",
        type_substrings: &[],
        itab_substrings: &["*os.File"],
        function_substrings: &[
            "os.Open",
            "os.Create",
            "os.WriteFile",
            "os.ReadFile",
            "ioutil.WriteFile",
        ],
    },
    Rule {
        id: "fs.dir.walk",
        name: "directory walk",
        category: "filesystem",
        type_substrings: &[],
        itab_substrings: &[],
        function_substrings: &["filepath.Walk", "filepath.WalkDir", "os.ReadDir"],
    },
    Rule {
        id: "proc.spawn",
        name: "child process spawn",
        category: "process",
        type_substrings: &["exec.Cmd"],
        itab_substrings: &[],
        function_substrings: &[
            "os/exec.Command",
            "os/exec.CommandContext",
            "syscall.ForkExec",
        ],
    },
    Rule {
        id: "proc.syscall",
        name: "syscall direct invocation",
        category: "process",
        type_substrings: &[],
        itab_substrings: &[],
        function_substrings: &[
            "syscall.Syscall",
            "syscall.RawSyscall",
            "golang.org/x/sys/unix.Syscall",
        ],
    },
    Rule {
        id: "proc.signal",
        name: "signal handling",
        category: "process",
        type_substrings: &[],
        itab_substrings: &[],
        function_substrings: &["os/signal.Notify", "os/signal.Reset"],
    },
    // Persistence / databases
    Rule {
        id: "db.sql",
        name: "SQL database client",
        category: "database",
        type_substrings: &["sql.DB", "sql.Tx", "sql.Rows", "sql.Stmt"],
        itab_substrings: &["sql/driver."],
        function_substrings: &["database/sql.Open"],
    },
    Rule {
        id: "db.sqlite",
        name: "SQLite",
        category: "database",
        type_substrings: &["mattn/go-sqlite3", "modernc.org/sqlite"],
        itab_substrings: &[],
        function_substrings: &[],
    },
    Rule {
        id: "db.postgres",
        name: "PostgreSQL driver",
        category: "database",
        type_substrings: &["jackc/pgx", "lib/pq"],
        itab_substrings: &[],
        function_substrings: &[],
    },
    Rule {
        id: "db.redis",
        name: "Redis client",
        category: "database",
        type_substrings: &["go-redis/", "redis.Client", "redigo/redis"],
        itab_substrings: &[],
        function_substrings: &[],
    },
    Rule {
        id: "db.mongo",
        name: "MongoDB driver",
        category: "database",
        type_substrings: &["mongo.Client", "mongo-driver/mongo"],
        itab_substrings: &[],
        function_substrings: &[],
    },
    // Container / orchestration
    Rule {
        id: "container.docker",
        name: "Docker client",
        category: "containers",
        type_substrings: &["docker/docker/client.", "moby/moby/client."],
        itab_substrings: &[],
        function_substrings: &[],
    },
    Rule {
        id: "container.containerd",
        name: "containerd client",
        category: "containers",
        type_substrings: &["containerd.Client", "containerd/containerd"],
        itab_substrings: &[],
        function_substrings: &[],
    },
    // Offensive / C2 / persistence hints
    Rule {
        id: "offensive.shell.exec",
        name: "shell command execution",
        category: "offensive-hint",
        type_substrings: &[],
        itab_substrings: &[],
        function_substrings: &["os/exec.Command", "exec.LookPath"],
    },
    Rule {
        id: "offensive.revshell",
        name: "reverse shell shape",
        category: "offensive-hint",
        type_substrings: &[],
        itab_substrings: &[],
        function_substrings: &["bash", "/bin/sh", "powershell"],
    },
    Rule {
        id: "offensive.rawsock",
        name: "raw socket / ICMP",
        category: "offensive-hint",
        type_substrings: &["icmp.PacketConn", "ipv4.PacketConn", "ipv6.PacketConn"],
        itab_substrings: &[],
        function_substrings: &["net.ListenPacket", "syscall.Socket"],
    },
    // Sliver C2 fingerprint
    Rule {
        id: "offensive.sliver",
        name: "Sliver C2 implant",
        category: "offensive-hint",
        type_substrings: &[
            "bishopfox/sliver",
            "sliver/sliver/transports",
            "sliver/protobuf/sliverpb",
        ],
        itab_substrings: &[],
        function_substrings: &["sliver/sliver/transports.", "sliver/sliver/handlers."],
    },
    // Encoding / serialization
    Rule {
        id: "serde.json",
        name: "JSON encoding",
        category: "serialization",
        type_substrings: &[],
        itab_substrings: &["*json.Decoder", "*json.Encoder"],
        function_substrings: &["encoding/json.Marshal", "encoding/json.Unmarshal"],
    },
    Rule {
        id: "serde.protobuf",
        name: "Protocol Buffers",
        category: "serialization",
        type_substrings: &["proto.Message", "protobuf"],
        itab_substrings: &[],
        function_substrings: &["google.golang.org/protobuf/proto."],
    },
    Rule {
        id: "serde.yaml",
        name: "YAML",
        category: "serialization",
        type_substrings: &["yaml.Decoder", "yaml.Encoder", "yaml.MapSlice"],
        itab_substrings: &[],
        function_substrings: &["gopkg.in/yaml.v"],
    },
    // GUI / terminal
    Rule {
        id: "ui.terminal",
        name: "terminal UI",
        category: "interaction",
        type_substrings: &["bubbletea.Model", "tcell.Screen", "tview.Application"],
        itab_substrings: &[],
        function_substrings: &[],
    },
];

pub fn compute(functions: &[Function], types: &[Type], itabs: &[Itab]) -> CapabilityReport {
    let mut out = Vec::new();
    for rule in RULES {
        let mut evidence: Vec<String> = Vec::new();

        if !rule.type_substrings.is_empty() {
            for t in types {
                if rule.type_substrings.iter().any(|s| t.name.contains(s)) {
                    evidence.push(t.name.clone());
                    if evidence.len() >= 5 {
                        break;
                    }
                }
            }
        }
        if evidence.len() < 5 && !rule.itab_substrings.is_empty() {
            for it in itabs {
                if rule
                    .itab_substrings
                    .iter()
                    .any(|s| it.concrete_name.contains(s))
                {
                    evidence.push(it.concrete_name.clone());
                    if evidence.len() >= 5 {
                        break;
                    }
                }
            }
        }
        if evidence.len() < 5 && !rule.function_substrings.is_empty() {
            for f in functions {
                if rule.function_substrings.iter().any(|s| f.name.contains(s)) {
                    evidence.push(f.name.clone());
                    if evidence.len() >= 5 {
                        break;
                    }
                }
            }
        }

        if !evidence.is_empty() {
            out.push(Capability {
                name: rule.name,
                category: rule.category,
                rule_id: rule.id,
                evidence,
            });
        }
    }

    CapabilityReport { capabilities: out }
}

#[cfg(test)]
mod tests {
    use super::RULES;
    use std::collections::HashSet;

    #[test]
    fn rule_ids_are_unique_and_non_empty() {
        let mut seen = HashSet::new();
        for rule in RULES {
            assert!(!rule.id.is_empty(), "rule {:?} has empty id", rule.name);
            assert!(
                seen.insert(rule.id),
                "duplicate rule id {:?} on rule {:?}",
                rule.id,
                rule.name
            );
        }
    }
}
