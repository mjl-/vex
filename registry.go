package main

/*
https://docs.docker.com/registry/spec/api/
https://docs.docker.com/registry/spec/manifest-v2-2/
https://docs.docker.com/registry/compatibility/
*/

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mjl-/bstore"
)

// Errors is an error as returned in JSON format in HTTP failure responses.
type Errors struct {
	code   int     // HTTP status code.
	Errors []Error `json:"errors"`
}

// Error is one element of Errors.
type Error struct {
	Code    RegistryError `json:"code"`
	Message string        `json:"message"`
	Detail  any           `json:"detail"`
}

// RegistryError is a short error code, typically shown in output of docker
// image pull in case of errors.
type RegistryError string

const (
	ErrorBlobUnknown             RegistryError = "BLOB_UNKNOWN"              // Blob unknown to registry.
	ErrorBlobUploadInvalid       RegistryError = "BLOB_UPLOAD_INVALID"       // Blob upload invalid.
	ErrorBlobUploadUnknown       RegistryError = "BLOB_UPLOAD_UNKNOWN"       // Blob upload unknown to registry.
	ErrorDigestInvalid           RegistryError = "DIGEST_INVALID"            // Provided digest did not match uploaded content.
	ErrorManifestBlobUnknown     RegistryError = "MANIFEST_BLOB_UNKNOWN"     // Blob unknown to registry.
	ErrorManifestInvalid         RegistryError = "MANIFEST_INVALID"          // Manifest invalid.
	ErrorManifestUnknown         RegistryError = "MANIFEST_UNKNOWN"          // Manifest unknown.
	ErrorManifestUnverified      RegistryError = "MANIFEST_UNVERIFIED"       // Manifest failed signature verification.
	ErrorNameInvalid             RegistryError = "NAME_INVALID"              // Invalid repository name.
	ErrorNameUnknown             RegistryError = "NAME_UNKNOWN"              // Repository name not known to registry.
	ErrorPaginationNumberInvalid RegistryError = "PAGINATION_NUMBER_INVALID" // Invalid number of results requested.
	ErrorRangeInvalid            RegistryError = "RANGE_INVALID"             // Invalid content range.
	ErrorSizeInvalid             RegistryError = "SIZE_INVALID"              // Provided length did not match content length.
	ErrorTagInvalid              RegistryError = "TAG_INVALID"               // Manifest tag did not match URI.
	ErrorUnauthorized            RegistryError = "UNAUTHORIZED"              // Authentication required.
	ErrorDenied                  RegistryError = "DENIED"                    // Requested access to the resource is denied.
	ErrorUnsupported             RegistryError = "UNSUPPORTED"               // The operation is unsupported.
)

type ManifestKind byte

const (
	ManifestKindV22     ManifestKind = iota + 1 // Image, with layers.
	ManifestKindListV22                         // Multiplatform, lists image manifests.
)

func (k ManifestKind) ContentType() string {
	switch k {
	case ManifestKindV22:
		return "application/vnd.docker.distribution.manifest.v2+json"
	case ManifestKindListV22:
		return "application/vnd.docker.distribution.manifest.list.v2+json"
	}
	return ""
}

// TagList is the response for /v2/<repo>/tags/list.
type TagList struct {
	Name string   `json:"name"` // Repository name.
	Tags []string `json:"tags"`
}

// Catalog lists repositories, for /v2/_catalog.
type Catalog struct {
	Repositories []string `json:"repositories"`
}

// Digests in docker can have lower and uppercase hexadecimal. We store them
// lowercased in the database, and canonicalize incoming digests..

// ManifestList is a multiplatform manifest list, for one or more platforms. A
// platform can be present multiple times, with different variants/features.
type ManifestList struct {
	SchemaVersion int                `json:"schemaVersion"` // 2
	MediaType     string             `json:"mediaType"`     // "application/vnd.docker.distribution.manifest.list.v2+json"
	Manifests     []ManifestPlatform `json:"manifests"`
}

// ManifestPlatform specifies an image manifest for a platform (e.g.
// linux/amd64, and optional cpu/OS variants/requirements).
type ManifestPlatform struct {
	MediaType string   `json:"mediaType"` // "application/vnd.docker.distribution.manifest.v2+json", no support for legacy application/vnd.docker.distribution.manifest.v1+json.
	Size      int64    `json:"size"`      // Size of the manifest object.
	Digest    string   `json:"digest"`    // Digest of manifest object.
	Platform  Platform `json:"platform"`
}

// Platform is a description/requirement of the cpu architecture and operating system for an image.
type Platform struct {
	Architecture string   `json:"architecture"`          // E.g. amd64, ppc64le
	OS           string   `json:"os"`                    // E.g. linux
	OSVersion    string   `json:"os.version,omitempty"`  // E.g. 10.0.10586
	OSFeatures   []string `json:"os.features,omitempty"` // Required OS features, e.g. win32k
	Variant      string   `json:"variant,omitempty"`     // Of cpu, e.g. "v6" for arm.
	Features     []string `json:"features,omitempty"`    // Required cpu features, e.g. "sse4" or "aes".
}

// ManifestImage represents what is commonly known as a docker image. With file
// system layers, and a config for exposed ports, commands, etc.
type ManifestImage struct {
	SchemaVersion int     `json:"schemaVersion"` // 2
	MediaType     string  `json:"mediaType"`     // "application/vnd.docker.distribution.manifest.v2+json"
	Config        Config  `json:"config"`
	Layers        []Layer `json:"layers"`
}

// Config is a blob with JSON content describing commands, ports for an image.
type Config struct {
	MediaType string `json:"mediaType"` // "application/vnd.docker.container.image.v1+json"
	Size      int64  `json:"size"`
	Digest    string `json:"digest"`
}

// Layer is a blob with a tar.gz with files for a docker image.
type Layer struct {
	MediaType string   `json:"mediaType"` // "application/vnd.docker.image.rootfs.diff.tar.gzip"
	Size      int64    `json:"size"`
	Digest    string   `json:"digest"`
	URLs      []string `json:"urls,omitempty"` // Uncommon, list of urls where content may be fetched from.
}

func respondJSON(w http.ResponseWriter, code int, v any) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetIndent("", "\t")
	err := enc.Encode(v)
	xcheckf(err, "marshal json response")
	buf := b.Bytes()

	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Content-Length", fmt.Sprintf("%d", len(buf)))

	w.WriteHeader(code)
	w.Write(buf)
}

type registryPath struct {
	Name                                string
	Regexp                              *regexp.Regexp
	Head, Get, Post, Put, Patch, Delete func(reg registry, args []string, w http.ResponseWriter, r *http.Request)
}

// Handlers for registry. The first regexp element after /v2/ is a repository
// name. Currently no slash is allowed because of the regexp.
var registryPaths = []registryPath{
	{Name: "registryIndex", Regexp: regexp.MustCompile(`^/v2/$`),
		Head: registry.index,
		Get:  registry.index},

	{Name: "registryCatalog", Regexp: regexp.MustCompile(`^/v2/_catalog$`),
		Get: registry.catalog},

	{Name: "registryTags", Regexp: regexp.MustCompile(`^/v2/([a-z0-9]+(?:[\._-][a-z0-9]+)*)/list/tags$`),
		Get: registry.tags},

	// The element after manifests can be a tag, or a digest.
	{Name: "registryManifest", Regexp: regexp.MustCompile(`^/v2/([a-z0-9]+(?:[\._-][a-z0-9]+)*)/manifests/([A-Za-z0-9_+\.-]+:[a-fA-F0-9]+|[a-zA-Z0-9_][a-zA-Z0-9_\.-]{0,127})$`),
		Head:   registry.manifestFetch,
		Get:    registry.manifestFetch,
		Put:    registry.manifestPut,
		Delete: registry.manifestDelete},

	{Name: "registryBlobUpload", Regexp: regexp.MustCompile(`^/v2/([a-z0-9]+(?:[\._-][a-z0-9]+)*)/blobs/uploads/$`),
		Post: registry.blobUploadPost},

	{Name: "registryBlobUpload", Regexp: regexp.MustCompile(`^/v2/([a-z0-9]+(?:[\._-][a-z0-9]+)*)/blobs/uploads/([^/]+)$`),
		Get:    registry.blobUploadGet,
		Patch:  registry.blobUploadPatch,
		Put:    registry.blobUploadPut,
		Delete: registry.blobUploadDelete},

	{Name: "registryBlob", Regexp: regexp.MustCompile(`^/v2/([a-z0-9]+(?:[\._-][a-z0-9]+)*)/blobs/([A-Za-z0-9_+\.-]+:[a-fA-F0-9]+)$`),
		Head:   registry.blobFetch,
		Get:    registry.blobFetch,
		Delete: registry.blobDelete},
}

type registry struct {
	auth bool
}

func (reg registry) ServeHTTP(xw http.ResponseWriter, r *http.Request) {
	w := &loggingWriter{
		W:     xw,
		Start: time.Now(),
		R:     r,
		Op:    "(registry)",
	}

	defer func() {
		x := recover()
		if x == nil {
			return
		}

		if err, ok := x.(httpErr); ok {
			log.Printf("http error: %d", err.code)
			http.Error(w, fmt.Sprintf("%d - %s", err.code, http.StatusText(err.code)), err.code)
		} else if err, ok := x.(serverErr); ok {
			log.Printf("server error: %#v", err.err)
			http.Error(w, fmt.Sprintf("500 - internal server error - %s", err.err), http.StatusInternalServerError)
		} else if err, ok := x.(Errors); ok {
			if debugFlag {
				log.Printf("request error: %#v", err)
			}
			if err.code == http.StatusUnauthorized {
				h := w.Header()
				h.Set("WWW-Authenticate", `Basic realm="registry"`)
			}
			respondJSON(w, err.code, err)
		} else {
			metricPanic.WithLabelValues("registry").Inc()
			panic(x)
		}
	}()

	if debugFlag {
		log.Printf("registry request %s: %v", r.URL.Path, r)
	}

	// https://docs.docker.com/registry/deploying/#importantrequired-http-headers
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")

	// Each request on the authenticated listener is checked for auth. And we check if
	// are on an authenticated registry again in each function that can make changes or
	// is needed for pushing only.
	if reg.auth {
		auth := r.Header.Get("Authorization")
		auth = strings.TrimSpace(auth)
		if !strings.HasPrefix(auth, "Basic ") {
			xunauthorized()
		}
		s, err := base64.StdEncoding.DecodeString(auth[len("Basic "):])
		if err != nil {
			xunauthorized()
		}
		t := bytes.SplitN(s, []byte{':'}, 2)
		// Require non-empty username for database.Get to succeed. Podman appears to send
		// empty username if no credentials are configured.
		if len(t) != 2 || len(t[0]) == 0 {
			xunauthorized()
		}
		u := DBUser{Username: string(t[0])}
		err = database.Get(r.Context(), &u)
		if err == bstore.ErrAbsent {
			xunauthorized()
		}
		xcheckf(err, "looking up user")

		hm := hmac.New(sha256.New, u.Salt)
		hm.Write(t[1])
		if !hmac.Equal(u.Hash, hm.Sum(nil)) {
			xunauthorized()
		}
	} else {
		switch r.Method {
		case "GET", "HEAD":
		default:
			xerrorf(http.StatusMethodNotAllowed, ErrorDenied, "read-only registry")
		}
	}

	for _, p := range registryPaths {
		t := p.Regexp.FindStringSubmatch(r.URL.Path)
		if t == nil {
			continue
		}

		w.Op = p.Name

		var h func(registry, []string, http.ResponseWriter, *http.Request)
		switch r.Method {
		case "HEAD":
			h = p.Head
		case "GET":
			h = p.Get
		case "POST":
			h = p.Post
		case "PUT":
			h = p.Put
		case "PATCH":
			h = p.Patch
		case "DELETE":
			h = p.Delete
		}
		if h == nil {
			xerrorf(http.StatusMethodNotAllowed, ErrorUnsupported, "method not supported")
		}
		h(reg, t[1:], w, r)
		return
	}
	xnotFound(ErrorUnsupported)
}

func (reg registry) xauth() {
	if !reg.auth {
		xerrorf(http.StatusMethodNotAllowed, ErrorDenied, "read-only registry")
	}
}

// HEAD,GET /v2/
//
// Used to check if registry implements v2 protocol.
func (reg registry) index(args []string, w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// GET /v2/_catalog
//
// List repositories.
func (reg registry) catalog(args []string, w http.ResponseWriter, r *http.Request) {
	repos, err := bstore.QueryDB[DBRepo](r.Context(), database).List()
	xcheckf(err, "listing repositories")
	resp := Catalog{Repositories: []string{}}
	for _, r := range repos {
		resp.Repositories = append(resp.Repositories, r.Name)
	}
	respondJSON(w, http.StatusOK, resp)
}

// Return list of tags for the repository.
func (reg registry) tags(args []string, w http.ResponseWriter, r *http.Request) {
	repo := xrepo(r.Context(), args[0])

	// todo: pagination, when we need it.
	resp := TagList{Name: repo.Name, Tags: []string{}}
	q := bstore.QueryDB[DBTag](r.Context(), database)
	q.FilterNonzero(DBTag{Repo: repo.Name})
	q.SortDesc("Modified")
	tags, err := q.List()
	xcheckf(err, "listing tags")
	for _, t := range tags {
		resp.Tags = append(resp.Tags, t.Tag)
	}
	respondJSON(w, http.StatusOK, resp)
}

func (reg registry) manifestFetch(args []string, w http.ResponseWriter, r *http.Request) {
	repo := xrepo(r.Context(), args[0])
	reference := args[1]
	var m DBManifest
	if istag(reference) {
		t, err := bstore.QueryDB[DBTag](r.Context(), database).FilterNonzero(DBTag{Repo: repo.Name, Tag: reference}).Get()
		if err == bstore.ErrAbsent {
			xnotFound(ErrorManifestUnknown)
		}
		xcheckf(err, "looking up tag")

		m = DBManifest{Digest: t.Digest}
		err = database.Get(r.Context(), &m)
		xcheckf(err, "getting manifest from database")
	} else {
		reference = xdigestcanon(reference)
		_, m = xrepomanifest(r.Context(), repo.Name, reference)
	}

	// todo: should we check the accept header?

	h := w.Header()
	h.Set("Content-Length", fmt.Sprintf("%d", len(m.Data)))
	h.Set("Docker-Content-Digest", m.Digest)
	h.Set("Content-Type", m.Kind.ContentType())
	w.WriteHeader(http.StatusOK)
	if r.Method != "HEAD" {
		w.Write(m.Data)
	}
}

// Delete a manifest from a repository, either by tag or manifest digest.
//
// It appears that docker and podman don't have a command to make this request,
// surprisingly. Skopeo (related to podman?) is a tool for interacting with remote
// registries, it has a delete subcommand. But when deleting a tag, it attempts to
// only delete the manifest digest. It looks like it hopes that the registry will
// then remove the manifest and all tags referencing it. Sounds like a bad idea. We
// let you remove an individual tag, and only let you remove a manifest if no more
// tags reference it. But we will also automatically remove a manifest if the last
// tag referencing it is removed.
func (reg registry) manifestDelete(args []string, w http.ResponseWriter, r *http.Request) {
	reg.xauth()

	repo := xrepo(r.Context(), args[0])
	reference := args[1]
	if !istag(reference) {
		reference = xdigestcanon(reference)
	}

	var removePaths []string

	err := database.Write(r.Context(), func(tx *bstore.Tx) error {
		tag := istag(reference)
		if tag {
			// Remove the tag.
			var tags []DBTag
			n, err := bstore.QueryTx[DBTag](tx).FilterNonzero(DBTag{Tag: reference, Repo: repo.Name}).Gather(&tags).Delete()
			xcheckf(err, "removing tag from database")
			if n == 0 {
				xerrorf(http.StatusNotFound, ErrorManifestUnknown, "no such tag")
			}
			reference = tags[0].Digest
			// We'll continue with an attempt to remove the referenced manifest. But if it is
			// still in use, that's fine.
		}

		// If tag still references this manifest in this repo, refuse removal.
		var tags []DBTag
		tagExists := xmanifestInRepoTag(tx, repo, reference, &tags)
		if tagExists && !tag {
			var names []string
			for _, t := range tags {
				names = append(names, t.Tag)
			}
			xerrorf(http.StatusBadRequest, ErrorDenied, "cannot remove manifest that is still referenced by a tag: %s", strings.Join(names, ", "))
		}

		// If multiplatform manifest still references this image manifest (if it is one) in
		// this repo, refuse removal.
		var repoManifests []DBRepoManifest
		listExists := xmanifestInRepoList(tx, repo, reference, &repoManifests)
		if listExists && !tag {
			var digests []string
			for _, rm := range repoManifests {
				digests = append(digests, rm.Digest)
			}
			xerrorf(http.StatusBadRequest, ErrorDenied, "cannot remove image manifest that is still referenced by a multiplatform manifest: %s", strings.Join(digests, ", "))
		}

		if !tagExists && !listExists {
			n, err := bstore.QueryTx[DBRepoManifest](tx).FilterNonzero(DBRepoManifest{Digest: reference, Repo: repo.Name}).Delete()
			xcheckf(err, "removing manifest for repo in database")
			if n == 0 {
				if tag {
					xcheckf(errors.New("manifest not found"), "removing manifest referenced by tag just removed")
				}
				xnotFound(ErrorManifestUnknown)
			}

			// Remove references of images to this repo if this was a list image and its images
			// aren't referenced elsewhere in this repo.
			xremoveRepoLastListImages(tx, repo, reference)

			// Remove this manifest and its referenced objects itself.
			removePaths = xremoveManifestIfUnused(tx, reference)
		}

		err := tx.Get(&repo)
		xcheckf(err, "get repo from database")
		repo.Modified = time.Now()
		err = tx.Update(&repo)
		xcheckf(err, "storing last modified for repo in database")

		return nil
	})
	xcheckf(err, "transaction")

	// With changes committed, remove blobs.
	for _, p := range removePaths {
		err := os.Remove(p)
		logCheck(err, "removing file")
	}

	w.WriteHeader(http.StatusAccepted)
}

func xmanifestInRepoTag(tx *bstore.Tx, repo DBRepo, manifestDigest string, tags *[]DBTag) bool {
	l, err := bstore.QueryTx[DBTag](tx).FilterNonzero(DBTag{Digest: manifestDigest, Repo: repo.Name}).List()
	xcheckf(err, "checking database if manifest is still referenced by a tag")
	if tags != nil {
		*tags = l
	}
	return len(l) > 0
}

func xmanifestInRepoList(tx *bstore.Tx, repo DBRepo, manifestDigest string, repoManifests *[]DBRepoManifest) bool {
	mli, err := bstore.QueryTx[DBManifestListImage](tx).FilterNonzero(DBManifestListImage{ImageDigest: manifestDigest}).List()
	xcheckf(err, "checking database if image manifest is referenced by multiplatform manifest")
	if len(mli) == 0 {
		return false
	}
	var listDigests []any
	for _, lm := range mli {
		listDigests = append(listDigests, lm.ListDigest)
	}
	l, err := bstore.QueryTx[DBRepoManifest](tx).FilterNonzero(DBRepoManifest{Repo: repo.Name}).FilterEqual("Digest", listDigests...).List()
	xcheckf(err, "checking database if list manifests are used this repo")
	if repoManifests != nil {
		*repoManifests = l
	}
	return len(l) > 0
}

// If this is a list manifest, check if its images are the last reference in this
// repo, and remove them from DBRepoManifest if so.
func xremoveRepoLastListImages(tx *bstore.Tx, repo DBRepo, manifestDigest string) {
	l, err := bstore.QueryTx[DBManifestListImage](tx).FilterNonzero(DBManifestListImage{ListDigest: manifestDigest}).List()
	xcheckf(err, "listing potential image manifests")
	for _, e := range l {
		if xmanifestInRepoTag(tx, repo, e.ImageDigest, nil) || xmanifestInRepoList(tx, repo, e.ImageDigest, nil) {
			// Still referenced through other repo tag or repo list manifest.
			continue
		}

		rml, err := bstore.QueryTx[DBRepoManifest](tx).FilterNonzero(DBRepoManifest{Repo: repo.Name, Digest: e.ImageDigest}).List()
		xcheckf(err, "checking references to image manifest for list manifest in this repo")
		if len(rml) == 1 {
			// This manifest that we are removing is the last reference, so remove the manifest
			// from the repo too.
			err = tx.Delete(&rml[0])
			xcheckf(err, "removing image manifest for repo for this list manifest")
		}
	}
}

// Store manifest by digest or tag for repo.
func (reg registry) manifestPut(args []string, w http.ResponseWriter, r *http.Request) {
	reg.xauth()

	repo := xensurerepo(r.Context(), args[0])
	reference := args[1]
	if !istag(reference) {
		reference = xdigestcanon(reference)
	}

	// Maximum manifest size of 100KB.
	body := http.MaxBytesReader(w, r.Body, 100*1024)
	defer body.Close()

	buf, err := io.ReadAll(body)
	xcheckf(err, "reading manifest json")

	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(buf))
	if !istag(reference) && digest != reference {
		xerrorf(http.StatusBadRequest, ErrorManifestInvalid, "manifest digest mismatch")
	}

	var m ManifestImage
	var ml ManifestList
	var kind ManifestKind
	ct := r.Header.Get("Content-Type")
	switch ct {
	case "application/vnd.docker.distribution.manifest.v2+json":
		kind = ManifestKindV22
		err := json.Unmarshal(buf, &m)
		if err != nil {
			xerrorf(http.StatusBadRequest, ErrorManifestInvalid, fmt.Sprintf("parsing image manifest: %v", err))
		}
	case "application/vnd.docker.distribution.manifest.list.v2+json":
		kind = ManifestKindListV22
		err := json.Unmarshal(buf, &ml)
		if err != nil {
			xerrorf(http.StatusBadRequest, ErrorManifestInvalid, fmt.Sprintf("parsing multiplatform manifest: %v", err))
		}
	default:
		xerrorf(http.StatusBadRequest, ErrorManifestInvalid, fmt.Sprintf("unrecognized manifest content-type %q", ct))
	}

	var removePaths []string

	err = database.Write(r.Context(), func(tx *bstore.Tx) error {
		var imageSize int64
		switch kind {
		case ManifestKindV22:
			// Verify image manifest.
			xneedBlob := func(digest string) DBBlob {
				l := DBBlob{Digest: digest}
				err := tx.Get(&l)
				if err == bstore.ErrAbsent {
					xerrorf(http.StatusBadRequest, ErrorBlobUnknown, fmt.Sprintf("unknown config/layer blob digest %s", digest))
				}
				xcheckf(err, "looking up config/layer blob digest %s", digest)
				return l
			}

			if m.SchemaVersion != 2 {
				xerrorf(http.StatusBadRequest, ErrorManifestInvalid, "schemaVersion %d must be 2", m.SchemaVersion)
			}
			if m.MediaType != "application/vnd.docker.distribution.manifest.v2+json" {
				xerrorf(http.StatusBadRequest, ErrorManifestInvalid, "mediaType %q must be %q", m.MediaType, "application/vnd.docker.distribution.manifest.v2+json")
			}
			configDigest, _, err := digestcanon(m.Config.Digest)
			if err != nil {
				xerrorf(http.StatusBadRequest, ErrorManifestInvalid, "config digest %s in manifest: %v", m.Config.Digest, err)
			}
			config := xneedBlob(configDigest)
			if m.Config.Size != config.Size {
				xerrorf(http.StatusBadRequest, ErrorManifestInvalid, "incorrect size %d for config blob %s", m.Config.Size, m.Config.Digest)
			}
			if m.Config.MediaType != "application/vnd.docker.container.image.v1+json" {
				xerrorf(http.StatusBadRequest, ErrorManifestInvalid, "mediaType %q for config must be %q", m.Config.MediaType, "application/vnd.docker.container.image.v1+json")
			}
			if len(m.Layers) == 0 {
				xerrorf(http.StatusBadRequest, ErrorManifestInvalid, "at least one layer required")
			}
			imageSize = m.Config.Size
			for _, l := range m.Layers {
				if len(l.URLs) != 0 {
					xerrorf(http.StatusBadRequest, ErrorManifestInvalid, "no external URLs for allowed for layers")
				}
				layerDigest, _, err := digestcanon(l.Digest)
				if err != nil {
					xerrorf(http.StatusBadRequest, ErrorManifestInvalid, "layer digest %s in manifest: %v", l.Digest, err)
				}
				xl := xneedBlob(layerDigest)
				if xl.Size != l.Size {
					xerrorf(http.StatusBadRequest, ErrorManifestInvalid, "incorrect size %d for layer blob %s (%d)", l.Size, l.Digest, xl.Size)
				}
				if l.MediaType != "application/vnd.docker.image.rootfs.diff.tar.gzip" {
					xerrorf(http.StatusBadRequest, ErrorManifestInvalid, "mediaType %q for layer must be %q", l.MediaType, "application/vnd.docker.image.rootfs.diff.tar.gzip")
				}
				imageSize += l.Size
			}

		case ManifestKindListV22:
			// Verify multiplatform/list manifest.
			xneedManifest := func(digest string) DBManifest {
				m := DBManifest{Digest: digest}
				err := tx.Get(&m)
				if err == bstore.ErrAbsent {
					xerrorf(http.StatusBadRequest, ErrorManifestInvalid, fmt.Sprintf("unknown manifest digest %s", digest))
				}
				xcheckf(err, "looking up manifest digest %s", digest)
				return m
			}

			if ml.SchemaVersion != 2 {
				xerrorf(http.StatusBadRequest, ErrorManifestInvalid, "schemaVersion %d must be 2", ml.SchemaVersion)
			}
			if ml.MediaType != "application/vnd.docker.distribution.manifest.list.v2+json" {
				xerrorf(http.StatusBadRequest, ErrorManifestInvalid, "mediaType %q must be %q", ml.MediaType, "application/vnd.docker.distribution.manifest.list.v2+json")
			}
			if len(ml.Manifests) == 0 {
				xerrorf(http.StatusBadRequest, ErrorManifestInvalid, "need at least one manifest in list")
			}
			seen := map[string]bool{}
			for _, m := range ml.Manifests {
				mdigest, _, err := digestcanon(m.Digest)
				if err != nil {
					xerrorf(http.StatusBadRequest, ErrorManifestInvalid, "manifest digest %s in manifest list: %v", m.Digest, err)
				}
				im := xneedManifest(mdigest)
				if m.Size != int64(len(im.Data)) {
					xerrorf(http.StatusBadRequest, ErrorManifestInvalid, "incorrect size %d for manifest %s", m.Size, m.Digest)
				}
				if im.Kind != ManifestKindV22 {
					xerrorf(http.StatusBadRequest, ErrorManifestInvalid, "referenced manifest must be an image, %s", m.Digest)
				}
				if seen[mdigest] {
					xerrorf(http.StatusBadRequest, ErrorManifestInvalid, "cannot reference same manifest more than once: %s", m.Digest)
				}
				seen[mdigest] = true
			}

		default:
			panic("other manifest kind, cannot happen")
		}

		// Ensure manifest exists in database, it may already be present.
		err := tx.Get(&DBManifest{Digest: digest})
		if err == bstore.ErrAbsent {
			err := tx.Insert(&DBManifest{Digest: digest, Kind: kind, ImageSize: imageSize, Data: buf})
			xcheckf(err, "inserting manifest in database")

			// Also insert the references from image manifest to config and layers, and from
			// list manifest to image manifests.
			switch kind {
			case ManifestKindV22:
				for _, l := range m.Layers {
					err := tx.Insert(&DBManifestBlob{ManifestDigest: digest, BlobDigest: xdigestcanon(l.Digest)})
					xcheckf(err, "inserting reference from image manifest to layer blob")
				}
				err := tx.Insert(&DBManifestBlob{ManifestDigest: digest, BlobDigest: xdigestcanon(m.Config.Digest)})
				xcheckf(err, "inserting reference from image manifest to to config blob")

			case ManifestKindListV22:
				for _, m := range ml.Manifests {
					imdigest := xdigestcanon(m.Digest)
					err := tx.Insert(&DBManifestListImage{ListDigest: digest, ImageDigest: imdigest})
					xcheckf(err, "inserting reference from list manifest to image manifest")

					// Mark manifest as added to this repo.
					exists, err := bstore.QueryTx[DBRepoManifest](tx).FilterNonzero(DBRepoManifest{Repo: repo.Name, Digest: imdigest}).Exists()
					xcheckf(err, "checking if manifest exists for repo in database")
					if !exists {
						err := tx.Insert(&DBRepoManifest{Repo: repo.Name, Digest: imdigest})
						xcheckf(err, "adding manifest for repo to database")
					}
				}
			default:
				panic("other manifest kind, cannot happen")
			}
		} else {
			xcheckf(err, "checking if manifest exists in database")
		}

		// Ensure manifest exists for repo in database.
		exists, err := bstore.QueryTx[DBRepoManifest](tx).FilterNonzero(DBRepoManifest{Repo: repo.Name, Digest: digest}).Exists()
		xcheckf(err, "checking if manifest exists for repo")
		if !exists {
			err := tx.Insert(&DBRepoManifest{Repo: repo.Name, Digest: digest})
			xcheckf(err, "adding manifest for repo to database")
		}

		// If tag, add it to database, overwriting existing tag if needed.
		if istag(reference) {
			// If existing tag exists, remove it, and below also the manifest if now unused.
			var removed []DBTag
			_, err := bstore.QueryTx[DBTag](tx).FilterNonzero(DBTag{Repo: repo.Name, Tag: reference}).Gather(&removed).Delete()
			xcheckf(err, "removing existing tag for repo")

			err = tx.Insert(&DBTag{Repo: repo.Name, Tag: reference, Digest: digest})
			xcheckf(err, "inserting tag into repo")

			// If we removed a previous tag, and its digest is no longer referenced, remove it.
			if len(removed) == 1 && !xmanifestInRepoTag(tx, repo, removed[0].Digest, nil) && !xmanifestInRepoList(tx, repo, removed[0].Digest, nil) {
				_, err := bstore.QueryTx[DBRepoManifest](tx).FilterNonzero(DBRepoManifest{Digest: removed[0].Digest, Repo: repo.Name}).Delete()
				xcheckf(err, "removing manifest for repo in database")
				xremoveRepoLastListImages(tx, repo, removed[0].Digest)
				removePaths = xremoveManifestIfUnused(tx, removed[0].Digest)
			}
		}

		repo.Modified = time.Now()
		err = tx.Update(&repo)
		xcheckf(err, "updating repo modification time")

		return nil
	})
	xcheckf(err, "adding manifest")

	for _, p := range removePaths {
		err := os.Remove(p)
		logCheck(err, "removing file")
	}

	h := w.Header()
	h.Set("Location", fmt.Sprintf("/v2/%s/manifests/%s", repo.Name, reference))
	h.Set("Content-Length", "0")
	h.Set("Docker-Content-Digest", digest)
	w.WriteHeader(http.StatusCreated)
}

// Start a blob upload for later appending with patch calls, but optionally
// copy a blob from another repo, or optionally immediately finishing the
// upload with data sent along.
func (reg registry) blobUploadPost(args []string, w http.ResponseWriter, r *http.Request) {
	reg.xauth()

	repo := xensurerepo(r.Context(), args[0])

	mount := r.URL.Query().Get("mount")
	if mount != "" {
		// Request to use a blob from another repository. We don't care about the repo, all
		// blobs are public and shared.
		mount = xdigestcanon(mount)
		err := database.Get(r.Context(), &DBBlob{Digest: mount})
		if err == nil {
			h := w.Header()
			h.Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", repo.Name, mount))
			h.Set("Content-Length", "0")
			h.Set("Docker-Content-Digest", mount)
			w.WriteHeader(http.StatusCreated)
			return
		}
		// Otherwise, continue with regular upload.
	}

	// If a digest query string is present, the body is the full blob. If no digest is
	// present, this starts an upload to which later PATCH calls add data, and that is
	// finished with a PUT call.
	digest := r.URL.Query().Get("digest")
	if digest == "" {
		up, err := newUpload()
		xcheckf(err, "starting upload")
		respondAccepted(w, repo, up)
		return
	}

	// Direct full blob as upload, not resumable.
	digest = xdigestcanon(digest)

	// Check digest does not yet exist.
	err := database.Get(r.Context(), &DBBlob{Digest: digest})
	if err != bstore.ErrAbsent {
		xcheckf(err, "checking if digest is already present")
	}

	// Store the file to temporary dir, calculating sha256 hash along the way.
	os.MkdirAll(filepath.Join(config.DataDir, "tmp"), 0755)
	f, err := os.CreateTemp(filepath.Join(config.DataDir, "tmp"), "vex-blob")
	xcheckf(err, "creating temp file")
	defer func() {
		if f != nil {
			err := os.Remove(f.Name())
			logCheck(err, "removing temporary blob file")
			err = f.Close()
			logCheck(err, "closing temporary blob file")
		}
	}()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), r.Body)
	xcheckf(err, "copying blob data")
	ldigest := fmt.Sprintf("sha256:%x", h.Sum(nil))
	if digest != ldigest {
		xerrorf(http.StatusBadRequest, ErrorDigestInvalid, "digest mismatch")
	}

	err = database.Write(context.Background(), func(tx *bstore.Tx) error {
		// Check existence again.
		err := tx.Get(&DBBlob{Digest: digest})
		if err == bstore.ErrAbsent {
			blob := DBBlob{Digest: digest, Size: n}
			err := tx.Insert(&blob)
			xcheckf(err, "inserting blob in database")

			err = setBlobPermissions(f)
			xcheckf(err, "setting file permissions")
			dst := filepath.Join(config.DataDir, "blob", digest)
			os.MkdirAll(filepath.Dir(dst), 0755)
			err = os.Rename(f.Name(), dst)
			xcheckf(err, "moving blob to destination")
		} else {
			xcheckf(err, "checking if blob is exists in database")

			// Blob already exists, we'll reuse that instead of storing again.
			err := os.Remove(f.Name())
			logCheck(err, "removing uploaded temp duplicate blob file")
			err = f.Close()
			logCheck(err, "closing uploaded temp duplicate blob file")
		}

		return nil
	})
	xcheckf(err, "transaction")

	hdr := w.Header()
	hdr.Set("Content-Length", "0")
	hdr.Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", repo.Name, digest))
	hdr.Set("Docker-Upload-UUID", "") // Nothing to put here...
	w.WriteHeader(http.StatusCreated)
}

func respondAccepted(w http.ResponseWriter, repo DBRepo, up *upload) {
	h := w.Header()
	h.Set("Location", fmt.Sprintf("/v2/%s/blobs/uploads/%s", repo.Name, up.UUID))
	h.Set("Range", fmt.Sprintf("0-%d", up.Offset-1))
	h.Set("Content-Length", "0")
	h.Set("Docker-Upload-UUID", up.UUID)
	w.WriteHeader(http.StatusAccepted)
}

func withUpload(uuid string, fn func(*upload)) {
	up := uploadLookup(uuid)
	if up == nil {
		xerrorf(http.StatusNotFound, ErrorBlobUploadUnknown, "no such upload")
	}
	up.Lock()
	defer up.Unlock()
	if up.File == nil {
		xerrorf(http.StatusBadRequest, ErrorBlobUploadInvalid, "upload already canceled or finished")
	}
	fn(up)
}

// Return upload progress status.
func (reg registry) blobUploadGet(args []string, w http.ResponseWriter, r *http.Request) {
	reg.xauth()

	xrepo(r.Context(), args[0])
	withUpload(args[1], func(up *upload) {
		up.SendActivity()
		h := w.Header()
		h.Set("Range", fmt.Sprintf("0-%d", up.Offset-1))
		h.Set("Content-Length", "0")
		h.Set("Docker-Upload-UUID", up.UUID)
		up.SendActivity()
		w.WriteHeader(http.StatusNoContent)
	})
}

// Add a (non-finishing) chunk of data to upload.
func (reg registry) blobUploadPatch(args []string, w http.ResponseWriter, r *http.Request) {
	reg.xauth()

	repo := xrepo(r.Context(), args[0])

	withUpload(args[1], func(up *upload) {
		// We handle and enforce the unnecessarily complicated content-range and
		// content-length requirements. These aren't specified for PUT even though it has
		// this same functionality.
		cr := r.Header.Get("Content-Range")
		var rangeSize int64
		if cr != "" {
			t := strings.Split(cr, "-")
			if len(t) != 2 {
				xerrorf(http.StatusBadRequest, ErrorUnsupported, "unrecognized content-range syntax")
			}
			start, err := strconv.ParseInt(strings.TrimSpace(t[0]), 10, 64)
			if err != nil {
				xerrorf(http.StatusBadRequest, ErrorUnsupported, "unrecognized content-range syntax")
			}
			end, err := strconv.ParseInt(strings.TrimSpace(t[1]), 10, 64)
			if err != nil {
				xerrorf(http.StatusBadRequest, ErrorUnsupported, "unrecognized content-range syntax")
			}
			if start != up.Offset {
				xerrorf(http.StatusBadRequest, ErrorRangeInvalid, "upload is at offset %d, cannot continue at start %d", up.Offset, start)
			}
			rangeSize = end + 1 - start
			if rangeSize <= 0 {
				xerrorf(http.StatusBadRequest, ErrorRangeInvalid, "cannot upload zero bytes")
			}
		}
		n, err := io.Copy(up.Writer, r.Body)
		xcheckf(err, "writing to file")
		if n == 0 {
			xerrorf(http.StatusBadRequest, ErrorUnsupported, "cannot add zero-length data")
		}
		up.Offset += n

		if rangeSize > 0 && rangeSize != n {
			xerrorf(http.StatusBadRequest, ErrorSizeInvalid, "size in content-range header %d does not match uploaded data length %d", rangeSize, n)
		}
		hcl := r.Header.Get("Content-Length")
		if hcl != "" {
			cl, err := strconv.ParseInt(hcl, 10, 64)
			if err != nil {
				xerrorf(http.StatusBadRequest, ErrorUnsupported, "unrecognized content-length syntax")
			}
			if cl != n {
				xerrorf(http.StatusBadRequest, ErrorSizeInvalid, "content-length header %d does not match uploaded data length %d", cl, n)
			}
		}
		up.SendActivity()
		respondAccepted(w, repo, up)
	})
}

// Add final chunk of data, finishing blob upload.
func (reg registry) blobUploadPut(args []string, w http.ResponseWriter, r *http.Request) {
	reg.xauth()

	repo := xrepo(r.Context(), args[0])

	withUpload(args[1], func(up *upload) {
		// Unlike PATCH, content-length and content-range are not specified for the chunk in PUT.

		n, err := io.Copy(up.Writer, r.Body)
		xcheckf(err, "writing to file")
		start := up.Offset
		up.Offset += n
		cl := r.Header.Get("Content-Length")
		if cl != "" && cl != fmt.Sprintf("%d", n) {
			xerrorf(http.StatusBadRequest, ErrorSizeInvalid, "content-length header %s does not match uploaded data length %d", cl, n)
		}
		digest := fmt.Sprintf("sha256:%x", up.Hash.Sum(nil))

		qdigest := r.URL.Query().Get("digest")
		if qdigest != "" && digest != xdigestcanon(qdigest) {
			xerrorf(http.StatusBadRequest, ErrorDigestInvalid, "uploaded blob has digest %s, not %s", digest, qdigest)
		}

		err = database.Write(context.Background(), func(tx *bstore.Tx) error {
			defer func() {
				if up.File != nil {
					up.Cancel()
				}
			}()

			// Check existence again.
			err := tx.Get(&DBBlob{Digest: digest})
			if err == bstore.ErrAbsent {
				blob := DBBlob{Digest: digest, Size: up.Offset}
				err := tx.Insert(&blob)
				xcheckf(err, "adding blob digest to database")

				err = setBlobPermissions(up.File)
				xcheckf(err, "setting file permissions")
				dst := filepath.Join(config.DataDir, "blob", digest)
				os.MkdirAll(filepath.Dir(dst), 0755)
				err = os.Rename(up.File.Name(), dst)
				xcheckf(err, "moving blob to destination")
			} else {
				xcheckf(err, "checking if blob exists in database")

				// Blob already exists, we'll use that, discarding this new copy.
				err := os.Remove(up.File.Name())
				logCheck(err, "removing uploaded temp duplicate blob file")
			}

			// Remove uuid from uploads.
			uploadsLock.Lock()
			delete(uploads, up.UUID)
			uploadsLock.Unlock()

			// Clean up the file and shutdown upload goroutine.
			err = up.File.Close()
			logCheck(err, "closing stored blob")
			up.File = nil
			close(up.Done)

			return nil
		})
		xcheckf(err, "adding blog digest to database")

		h := w.Header()
		h.Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", repo.Name, digest))
		h.Set("Content-Length", "0")
		h.Set("Content-Range", fmt.Sprintf("%d-%d", start, up.Offset-1))
		h.Set("Docker-Content-Digest", digest)
		w.WriteHeader(http.StatusCreated)
	})
}

// Cancel upload.
func (reg registry) blobUploadDelete(args []string, w http.ResponseWriter, r *http.Request) {
	reg.xauth()

	xrepo(r.Context(), args[0])
	withUpload(args[1], func(up *upload) {
		up.Cancel()
	})

	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusNoContent)
}

// Fetch a blob by digest.
func (reg registry) blobFetch(args []string, w http.ResponseWriter, r *http.Request) {
	xrepo(r.Context(), args[0])

	digest := xdigestcanon(args[1])
	b, err := bstore.QueryDB[DBBlob](r.Context(), database).FilterNonzero(DBBlob{Digest: digest}).Get()
	if err == bstore.ErrAbsent {
		xnotFound(ErrorBlobUnknown)
	}
	xcheckf(err, "looking up blob")

	var f *os.File
	if r.Method != "HEAD" {
		var err error
		f, err = os.Open(filepath.Join(config.DataDir, "blob", b.Digest))
		xcheckf(err, "open")
		defer f.Close()
	}
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Docker-Content-Digest", b.Digest)
	if f != nil {
		http.ServeContent(w, r, b.Digest, b.Modified, f)
	} else {
		h.Set("Content-Length", fmt.Sprintf("%d", b.Size))
	}
}

// Delete a blob. We always allow it, just not actually deleting if it is still
// referenced by something (possibly in another repo).
func (reg registry) blobDelete(args []string, w http.ResponseWriter, r *http.Request) {
	reg.xauth()

	xrepo(r.Context(), args[0])
	digest := xdigestcanon(args[1])

	var removePath string
	err := database.Write(r.Context(), func(tx *bstore.Tx) error {
		l := DBBlob{Digest: digest}
		err := tx.Get(&l)
		if err == bstore.ErrAbsent {
			xnotFound(ErrorDigestInvalid)
		} else {
			xcheckf(err, "fetch blob from database")
		}

		exists, err := bstore.QueryTx[DBManifestBlob](tx).FilterNonzero(DBManifestBlob{BlobDigest: l.Digest}).Exists()
		xcheckf(err, "checking if blob is still referenced")
		if !exists {
			err := tx.Delete(&l)
			xcheckf(err, "removing blob from database")
			removePath = filepath.Join(config.DataDir, "blob", l.Digest)
		}

		return nil
	})
	xcheckf(err, "transaction")

	if removePath != "" {
		err := os.Remove(removePath)
		logCheck(err, "removing blob from file system")
	}

	h := w.Header()
	h.Set("Content-Length", "0")
	h.Set("Docker-Content-Digest", digest)
	w.WriteHeader(http.StatusAccepted)
}

func xnotFound(regErr RegistryError) {
	xerrorf(http.StatusNotFound, regErr, "not found")
}

func xunauthorized() {
	xerrorf(http.StatusUnauthorized, ErrorUnauthorized, "valid authorization required")
}

func xerrorf(statuscode int, regErr RegistryError, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	err := Errors{statuscode, []Error{{regErr, msg, ""}}}
	panic(err)
}

func xrepo(ctx context.Context, name string) DBRepo {
	repo := DBRepo{Name: name}
	err := database.Get(ctx, &repo)
	if err == bstore.ErrAbsent {
		xnotFound(ErrorNameUnknown)
	}
	xcheckf(err, "looking up repository")
	return repo
}

var repoNameRegexp = regexp.MustCompile(`^[a-z0-9]+(?:[\._-][a-z0-9]+)*$`)

func xensurerepo(ctx context.Context, name string) (repo DBRepo) {
	err := database.Write(ctx, func(tx *bstore.Tx) error {
		repo = DBRepo{Name: name}
		err := tx.Get(&repo)
		if err == bstore.ErrAbsent {
			if len(name) > 256 || !repoNameRegexp.MatchString(name) {
				xerrorf(http.StatusBadRequest, ErrorNameInvalid, "invalid repository name")
			}
			err := tx.Insert(&repo)
			xcheckf(err, "adding repo to database")
		} else {
			xcheckf(err, "looking up repository")
		}
		return nil
	})
	xcheckf(err, "transaction")
	return
}

func xrepomanifest(ctx context.Context, repo, digest string) (DBRepoManifest, DBManifest) {
	q := bstore.QueryDB[DBRepoManifest](ctx, database)
	rm, err := q.FilterNonzero(DBRepoManifest{Repo: repo, Digest: digest}).Get()
	if err == bstore.ErrAbsent {
		xnotFound(ErrorManifestUnknown)
	}
	xcheckf(err, "looking up manifest for repository")
	m := DBManifest{Digest: digest}
	err = database.Get(ctx, &m)
	xcheckf(err, "getting manifest from database")
	return rm, m
}

var regexpTag = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_\.-]{0,127}$`)

func istag(s string) bool {
	return regexpTag.MatchString(s)
}

// Digests are of the form "algorithm:hex", with the only algorithm currently in
// use "sha256" (unclear if case sensitive, we assume so). Hex is (needlessly
// complicating) case insensitive. When storing the database, we canonicalize the
// digest to lower case.
var regexpDigest = regexp.MustCompile(`^([A-Za-z0-9_+\.-]+):([a-fA-F0-9]+)$`)

func digestcanon(s string) (string, RegistryError, error) {
	m := regexpDigest.FindStringSubmatch(s)
	if m == nil {
		return "", ErrorDigestInvalid, errors.New("digest format not recognized")
	}
	if m[1] != "sha256" {
		return "", ErrorUnsupported, fmt.Errorf("digest algorithm %q not supported", m[1])
	}
	if len(m[2]) != 2*sha256.Size {
		return "", ErrorDigestInvalid, fmt.Errorf("wrong digest length %d, need %d", len(m[2]), 2*sha256.Size)
	}
	return strings.ToLower(s), "", nil
}

func xdigestcanon(s string) string {
	digest, regErr, err := digestcanon(s)
	if err != nil {
		xerrorf(http.StatusBadRequest, regErr, "%s", err)
	}
	return digest
}

// Remove manifest digest (either list or image) if it is unused, and all resources
// it references if they also become unused. Caller must have already removed a
// link from the repository for which the manifest has been removed.
func xremoveManifestIfUnused(tx *bstore.Tx, manifestDigest string) (removePaths []string) {
	// Check if tag references the manifest.
	tagExists, err := bstore.QueryTx[DBTag](tx).FilterNonzero(DBTag{Digest: manifestDigest}).Exists()
	xcheckf(err, "check if manifest is referenced by tag")
	if tagExists {
		return nil
	}

	// Check if a list manifest references this manifest.
	listExists, err := bstore.QueryTx[DBManifestListImage](tx).FilterNonzero(DBManifestListImage{ImageDigest: manifestDigest}).Exists()
	xcheckf(err, "check if manifest is referenced by manifest list")
	if listExists {
		return nil
	}

	// Check if a repo references the manifest. A tag can be removed but the manifest reference left behind.
	repoExists, err := bstore.QueryTx[DBRepoManifest](tx).FilterNonzero(DBRepoManifest{Digest: manifestDigest}).Exists()
	xcheckf(err, "check if manifest is referenced by tag")
	if repoExists {
		return nil
	}

	xremoveDBManifest := func() {
		dbm := DBManifest{Digest: manifestDigest}
		err = tx.Delete(&dbm)
		xcheckf(err, "deleting manifest %s from database", manifestDigest)
	}

	dbm := DBManifest{Digest: manifestDigest}
	err = tx.Get(&dbm)
	xcheckf(err, "fetching manifest from database")

	switch dbm.Kind {
	case ManifestKindV22:
		// Remove links between this manifest and its blobs.
		var links []DBManifestBlob
		q := bstore.QueryTx[DBManifestBlob](tx)
		q.FilterNonzero(DBManifestBlob{ManifestDigest: manifestDigest})
		q.SortAsc("BlobDigest")
		q.Gather(&links)
		_, err = q.Delete()
		xcheckf(err, "removing referenced blobs from database")

		// Gather if blobs are still in use by other manifests.
		var blobDigests []any
		for _, l := range links {
			blobDigests = append(blobDigests, l.BlobDigest)
		}
		used := map[string]bool{}
		err = bstore.QueryTx[DBManifestBlob](tx).FilterEqual("BlobDigest", blobDigests...).ForEach(func(dbml DBManifestBlob) error {
			used[dbml.BlobDigest] = true
			return nil
		})
		xcheckf(err, "looking up if config/layer blobs for image manifest are in still use")

		// Remove unused blobs.
		for _, blobDigest := range blobDigests {
			if used[blobDigest.(string)] {
				continue
			}
			b := DBBlob{Digest: blobDigest.(string)}
			err := tx.Delete(&b)
			xcheckf(err, "removing blob from database")
			path := filepath.Join(config.DataDir, "blob", b.Digest)
			removePaths = append(removePaths, path)
		}

		xremoveDBManifest()
		return removePaths

	case ManifestKindListV22:
		// Remove links between this list and its images.
		var links []DBManifestListImage
		q := bstore.QueryTx[DBManifestListImage](tx)
		q.FilterNonzero(DBManifestListImage{ListDigest: manifestDigest})
		q.SortAsc("ImageDigest")
		q.Gather(&links)
		_, err := q.Delete()
		xcheckf(err, "removing referenced manifest images from database")

		// Now attempt to remove those previously linked images.
		for _, mli := range links {
			paths := xremoveManifestIfUnused(tx, mli.ImageDigest)
			removePaths = append(removePaths, paths...)
		}

		xremoveDBManifest()
		return removePaths

	default:
		panic("missing case for kind")
	}
}
