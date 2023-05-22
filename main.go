// Command vex is a modest docker registry for projects hosting their own docker images.
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/mjl-/bstore"
	"github.com/mjl-/sconf"
)

var metricPanic = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "vex_panic_total",
		Help: "Number of unhandled panics, by server.",
	},
	[]string{
		"server",
	},
)

var metricRequest = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "vex_request_duration_seconds",
		Help:    "HTTP requests with operation, response code, and duration until response status code is written, in seconds.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.100, 0.5, 1, 5, 30, 120},
	},
	[]string{
		"method", // http method
		"op",     // operation, on registry or web pags
		"code",   // http response code
	},
)

// Where all metadata is stored. Blob contents are in the file system, written to
// the file system before committing inserts, and removed from the file system
// after committing deletes.
var database *bstore.DB

// We store digests lower cased, even though docker digests can be both upper- and
// lowercased.
// In the DB types below, the first field is the (unique) primary key.

// BDRepo is typically a software project that can have manifests (multiplatform
// and images) and tags associated with it. Repo's are automatically created when
// something is pushed to them (config/layer blobs or manifests).
type DBRepo struct {
	Name     string
	Modified time.Time `bstore:"nonzero,default now"`
}

// DBBlob is a blob as used in an image, either as layer or config. The actual data
// is stored in the file system. By default in data/blob/. Clients typically check
// if a blob digest is present before uploading it. But if they upload it when
// already present, we accept and ignore the new file, keeping the one we had. It
// is the same because the data is content-addressed. The blobs are global to the
// instance, not per repo.
type DBBlob struct {
	Digest   string
	Size     int64
	Modified time.Time `bstore:"nonzero,default now"`
}

// DBManifest is a manifest stored by digest. This can be an image manifest or
// multiplatform/list manifest. These are global. A manifest used in a repo is
// represented by DBRepoManifest.
type DBManifest struct {
	Digest    string
	Kind      ManifestKind `bstore:"nonzero"`
	ImageSize int64        // Not set for manifest list, otherwise sum of config and layer blob sizes.
	Data      []byte       `bstore:"nonzero"` // JSON version of manifest
}

// DBManifestBlob is a link between a manifest and its config/layer blobs. Only
// relevant for image manifests, not multiplatform/list manifests.
type DBManifestBlob struct {
	ID             int64
	ManifestDigest string `bstore:"nonzero,ref DBManifest"`
	BlobDigest     string `bstore:"nonzero,ref DBBlob"`
}

// DBManifestListImage has a mapping of a list manifest to its image manifests.
type DBManifestListImage struct {
	ID          int64
	ListDigest  string `bstore:"nonzero,index,ref DBManifest"`
	ImageDigest string `bstore:"nonzero,unique ImageDigest+ListDigest,ref DBManifest"`
}

// DBRepoManifest is a manifest added to a repo, either image or list manifest.
// When a list manifest is added, all its image manifests are added to the repo as
// well.
type DBRepoManifest struct {
	ID       int64
	Repo     string    `bstore:"nonzero,ref DBRepo"`
	Digest   string    `bstore:"nonzero,ref DBManifest,unique Digest+Repo"`
	Modified time.Time `bstore:"nonzero,default now"`
}

// DBTag is a named reference to a manifest for a repository. When removed or
// overwritten, the referenced manifest(s) are also removed if they are no longer
// referenced.
type DBTag struct {
	ID       int64
	Repo     string    `bstore:"nonzero,ref DBRepo"`
	Tag      string    `bstore:"nonzero,unique Tag+Repo"`
	Digest   string    `bstore:"nonzero,ref DBManifest"`
	Modified time.Time `bstore:"nonzero,default now"`
}

// DBUser is a user that can login with (with HTTP basic authentication), and has
// write access to all repositories.
type DBUser struct {
	Username string
	Salt     []byte `bstore:"nonzero"`
	Hash     []byte `bstore:"nonzero"` // sha256 hmac.
}

func xparseConfig() {
	if err := sconf.ParseFile(configFile, &config); err != nil {
		log.Fatalf("%v", err)
	}
}

var configFile string
var config struct {
	DataDir string `sconf-doc:"Directory to store database and config/layer blobs."`
}

// Prints requests and responses.
var debugFlag bool

func main() {
	log.SetFlags(0)
	flag.Usage = func() {
		log.Println("usage: vex serve")
		log.Println("       vex quickstart username [tls-cert-auth-hostname]")
		log.Println("       vex describe >vex.conf")
		log.Println("       vex testconfig vex.conf")
		log.Println("       vex user add username")
		log.Println("       vex user delete username")
		log.Println("       vex version")
		flag.PrintDefaults()
		os.Exit(2)
	}
	flag.StringVar(&configFile, "config", "vex.conf", "path to configuration file")
	flag.BoolVar(&debugFlag, "debug", false, "enable debug logging, e.g. printing HTTP requests and responses")
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
	}

	cmd, args := args[0], args[1:]
	switch cmd {
	case "serve":
		xparseConfig()
		serve(args)
	case "quickstart":
		if len(args) != 1 && len(args) != 2 {
			flag.Usage()
		}
		quickstart(args)
	case "describe":
		if len(args) != 0 {
			flag.Usage()
		}
		if err := sconf.Describe(os.Stdout, config); err != nil {
			log.Fatalf("describing config: %v", err)
		}
	case "testconfig":
		if len(args) != 1 {
			flag.Usage()
		}
		xparseConfig()
	case "user":
		if len(args) != 2 {
			flag.Usage()
		}
		xparseConfig()
		switch args[0] {
		case "add":
			fmt.Print("password (will echo): ")
			pw := make([]byte, 64)
			n, err := os.Stdin.Read(pw)
			if err != nil {
				log.Fatalf("reading password: %v", err)
			}
			pw = pw[:n]
			pw = bytes.TrimRight(pw, "\n")
			pw = bytes.TrimRight(pw, "\r")
			if err := adduser(xdb(), args[1], pw); err != nil {
				log.Fatalf("adding user: %v", err)
			}
		case "delete":
			db := xdb()
			if err := db.Delete(context.Background(), &DBUser{Username: args[1]}); err != nil {
				log.Fatalf("removing user from database: %v", err)
			}
		default:
			flag.Usage()
		}
	case "version":
		if len(args) != 0 {
			flag.Usage()
		}
		fmt.Println(version)
	default:
		flag.Usage()
	}
}

func xdb() *bstore.DB {
	os.MkdirAll("data", 0755)
	db, err := bstore.Open(context.Background(), filepath.Join(config.DataDir, "vex.db"), &bstore.Options{Perm: 0660}, DBRepo{}, DBBlob{}, DBManifest{}, DBManifestBlob{}, DBManifestListImage{}, DBRepoManifest{}, DBTag{}, DBUser{})
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	return db
}

func adduser(db *bstore.DB, username string, password []byte) error {
	salt := make([]byte, 16)
	if _, err := cryptorand.Read(salt); err != nil {
		return fmt.Errorf("generating salt: %v", err)
	}
	hm := hmac.New(sha256.New, salt)
	hm.Write([]byte(password))
	h := hm.Sum(nil)
	if err := db.Insert(context.Background(), &DBUser{username, salt, h}); err != nil {
		return fmt.Errorf("inserting user into database: %v", err)
	}
	return nil
}

func logCheck(err error, format string, args ...any) {
	if err == nil {
		return
	}
	log.Printf("%s: %s", fmt.Sprintf(format, args...), err)
}

func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	var publicAddr, authAddr, adminAddr, authTLSKey, authTLSCert string
	fs.StringVar(&publicAddr, "publicaddr", "localhost:8200", "public address to listen on, read-only without authentication")
	fs.StringVar(&authAddr, "authaddr", "localhost:8201", "address to listen on with authentication, for writing too")
	fs.StringVar(&adminAddr, "adminaddr", "localhost:8202", "address to listen on for metrics")
	fs.StringVar(&authTLSKey, "authtlskey", "", "serve https on auth endpoint with this tls key, instead of plain http")
	fs.StringVar(&authTLSCert, "authtlscert", "", "serve https on auth endpoint with this tls cert, instead of plain http")
	fs.Parse(args)
	args = fs.Args()
	if len(args) != 0 {
		flag.Usage()
	}

	database = xdb()

	publicmux := http.NewServeMux()
	publicmux.Handle("/v2/", registry{auth: false})
	publicmux.HandleFunc("/", serveHTML)

	authmux := http.NewServeMux()
	authmux.Handle("/v2/", registry{auth: true})

	adminmux := http.NewServeMux()
	adminmux.Handle("/metrics", promhttp.Handler())

	log.Printf("vex %s, serving public %s, authenticated/writable %s, admin %s", version, publicAddr, authAddr, adminAddr)
	go func() {
		log.Fatalln(http.ListenAndServe(publicAddr, publicmux))
	}()
	go func() {
		if authTLSKey != "" || authTLSCert != "" {
			log.Fatalln(http.ListenAndServeTLS(authAddr, authTLSCert, authTLSKey, authmux))
		} else {
			log.Fatalln(http.ListenAndServe(authAddr, authmux))
		}
	}()
	log.Fatalln(http.ListenAndServe(adminAddr, adminmux))
}

// internal server error.
type serverErr struct {
	err error
}

func xcheckf(err error, format string, args ...any) {
	if err != nil {
		panic(serverErr{fmt.Errorf("%s: %s", fmt.Sprintf(format, args...), err)})
	}
}

// HTTP status codes, for html.go. Registry has type Errors for a JSON body with details.
type httpErr struct {
	code int
}

// For checking errors when writing HTTP responses, we don't want to log i/o
// errors, but we do want to see other errors, e.g. about template execution.
func isClosed(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) || isRemoteTLSError(err)
}

// A remote TLS client can send a message indicating failure, this makes it back to
// us as a write error.
func isRemoteTLSError(err error) bool {
	var netErr *net.OpError
	return errors.As(err, &netErr) && netErr.Op == "remote error"
}
