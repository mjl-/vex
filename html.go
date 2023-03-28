package main

import (
	"encoding/json"
	"fmt"
	htmltemplate "html/template"
	"log"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	_ "embed"

	"github.com/mjl-/bstore"
)

//go:embed index.html
var indexHTML string

//go:embed repo.html
var repoHTML string

//go:embed manifest.html
var manifestHTML string

var funcs = htmltemplate.FuncMap{
	// For displaying image size.
	"formatSize": func(v int64) string {
		return fmt.Sprintf("%.01fMB", float64(v)/(1024*1024))
	},
	// Time between now and last modification.
	"age": func(t time.Time) string {
		const day = 24 * time.Hour
		const week = 7 * day
		const month = 30 * day
		const year = 365 * day
		d := time.Since(t)
		if d < 2*time.Minute {
			return "just now"
		} else if d < 2*time.Hour {
			return fmt.Sprintf("%d minutes ago", int64(math.Round(float64(d)/float64(time.Minute))))
		} else if d < 2*day {
			return fmt.Sprintf("%d hours ago", int64(math.Round(float64(d)/float64(time.Hour))))
		} else if d < 2*week {
			return fmt.Sprintf("%d days ago", int64(math.Round(float64(d)/float64(day))))
		} else if d < 2*month {
			return fmt.Sprintf("%d weeks ago", int64(math.Round(float64(d)/float64(week))))
		} else if d < 2*year {
			return fmt.Sprintf("%d months ago", int64(math.Round(float64(d)/float64(month))))
		}
		return fmt.Sprintf("%d years ago", int64(math.Round(float64(d)/float64(year))))
	},
}

var indexTemplate = htmltemplate.Must(htmltemplate.New("index.html").Funcs(funcs).Parse(indexHTML))
var repoTemplate = htmltemplate.Must(htmltemplate.New("repo.html").Funcs(funcs).Parse(repoHTML))
var manifestTemplate = htmltemplate.Must(htmltemplate.New("manifest.html").Funcs(funcs).Parse(manifestHTML))

type htmlPath struct {
	Name       string
	Regexp     *regexp.Regexp
	HandleFunc func(args []string, w http.ResponseWriter, r *http.Request)
}

var htmlPaths = []htmlPath{
	{"htmlIndex", regexp.MustCompile(`^/$`), htmlIndex},
	{"htmlRepo", regexp.MustCompile(`^/repo/([^/]+)/?$`), htmlRepo},
	{"htmlManifest", regexp.MustCompile(`^/repo/([^/]+)/manifest/([^/]+)/?$`), htmlManifest},
}

func serveHTML(xw http.ResponseWriter, r *http.Request) {
	w := &loggingWriter{
		W:     xw,
		Start: time.Now(),
		R:     r,
		Op:    "(html)",
	}

	defer func() {
		x := recover()
		if x == nil {
			return
		}

		if err, ok := x.(httpErr); ok {
			if debugFlag {
				log.Printf("http error: %d", err.code)
			}
			http.Error(w, fmt.Sprintf("%d - %s", err.code, http.StatusText(err.code)), err.code)
		} else if err, ok := x.(serverErr); ok {
			log.Printf("server error: %#v", err.err)
			http.Error(w, fmt.Sprintf("500 - internal server error - %s", err.err), http.StatusInternalServerError)
		} else {
			metricPanic.WithLabelValues("html").Inc()
			panic(x)
		}
	}()

	if debugFlag {
		log.Printf("html request %s: %v", r.URL.Path, r)
	}

	if r.Method != "GET" {
		panic(httpErr{http.StatusMethodNotAllowed})
	}

	for _, p := range htmlPaths {
		l := p.Regexp.FindStringSubmatch(r.URL.Path)
		if l != nil {
			w.Op = p.Name
			p.HandleFunc(l[1:], w, r)
			return
		}
	}
	panic(httpErr{http.StatusNotFound})
}

func htmlIndex(args []string, w http.ResponseWriter, r *http.Request) {
	repos, err := bstore.QueryDB[DBRepo](database).SortDesc("Modified").List()
	xcheckf(err, "listing repos")
	err = indexTemplate.Execute(w, map[string]any{
		"Repos": repos,
	})
	if err != nil && !isClosed(err) {
		log.Printf("executing template: %v", err)
	}
}

func htmlRepo(args []string, w http.ResponseWriter, r *http.Request) {
	var params map[string]any

	err := database.Read(func(tx *bstore.Tx) error {
		repo := DBRepo{Name: args[0]}
		err := tx.Get(&repo)
		if err == bstore.ErrAbsent {
			panic(httpErr{http.StatusNotFound})
		}
		xcheckf(err, "fetching repo from database")

		if !strings.HasSuffix(r.URL.Path, "/") {
			http.Redirect(w, r, r.URL.Path+"/", http.StatusPermanentRedirect)
			return nil
		}

		tags, err := bstore.QueryTx[DBTag](tx).FilterNonzero(DBTag{Repo: repo.Name}).SortDesc("Modified").List()
		xcheckf(err, "listing tags")

		manifestTags := map[string][]DBTag{} // Digest to tag.
		for _, t := range tags {
			manifestTags[t.Digest] = append(manifestTags[t.Digest], t)
		}
		for _, tags := range manifestTags {
			sort.Slice(tags, func(i, j int) bool {
				a := tags[i].Modified
				b := tags[j].Modified
				if a.Equal(b) {
					return tags[i].Tag < tags[j].Tag
				}
				return a.After(b)
			})
		}

		var digests []any
		for digest := range manifestTags {
			digests = append(digests, digest)
		}
		dbmanifests := map[string]DBManifest{} // digest to DBManifest
		parsedmanifests := map[string]any{}    // digest to Manifest or ManifestList
		if len(digests) > 0 {
			dbml, err := bstore.QueryTx[DBManifest](tx).FilterEqual("Digest", digests...).List()
			xcheckf(err, "fetching manifests from database")
			for _, dbm := range dbml {
				dbmanifests[dbm.Digest] = dbm
				switch dbm.Kind {
				case ManifestKindV22:
					var m ManifestImage
					err := json.Unmarshal(dbm.Data, &m)
					xcheckf(err, "parsing manifest")
					parsedmanifests[dbm.Digest] = m
				case ManifestKindListV22:
					var m ManifestList
					err := json.Unmarshal(dbm.Data, &m)
					xcheckf(err, "parsing manifest list")
					parsedmanifests[dbm.Digest] = m
				default:
					panic("unhandled manifest kind, cannot happen")
				}
			}
		}

		baseAddress := fmt.Sprintf("%s/%s", r.Host, repo.Name)

		params = map[string]any{
			"Repo":                repo,
			"Tags":                tags,
			"ManifestTags":        manifestTags,
			"DBManifests":         dbmanifests,
			"ParsedManifests":     parsedmanifests,
			"ManifestKindV22":     ManifestKindV22,
			"ManifestKindListV22": ManifestKindListV22,
			"BaseAddress":         baseAddress,
		}

		return nil
	})
	xcheckf(err, "read transaction")

	err = repoTemplate.Execute(w, params)
	if err != nil && !isClosed(err) {
		log.Printf("executing template: %v", err)
	}
}

func htmlManifest(args []string, w http.ResponseWriter, r *http.Request) {
	var params map[string]any

	tag := r.URL.Query().Get("tag")

	err := database.Read(func(tx *bstore.Tx) error {
		repo := DBRepo{Name: args[0]}
		err := tx.Get(&repo)
		if err == bstore.ErrAbsent {
			panic(httpErr{http.StatusNotFound})
		}
		xcheckf(err, "fetching repo from database")

		digest := strings.ToLower(args[1])

		qrm := bstore.QueryTx[DBRepoManifest](tx)
		exists, err := qrm.FilterNonzero(DBRepoManifest{Repo: repo.Name, Digest: digest}).Exists()
		xcheckf(err, "finding manifest for repo in database")
		if !exists {
			panic(httpErr{http.StatusNotFound})
		}

		dbmanifest := DBManifest{Digest: digest}
		err = tx.Get(&dbmanifest)
		xcheckf(err, "fetching manifest from database")

		if tag != "" {
			exists, err := bstore.QueryTx[DBTag](tx).FilterNonzero(DBTag{Repo: repo.Name, Tag: tag, Digest: digest}).Exists()
			xcheckf(err, "looking up tag in database")
			if !exists {
				// Could be an image manifest that is part of a list manifest.
				mli, err := bstore.QueryTx[DBManifestListImage](tx).FilterNonzero(DBManifestListImage{ImageDigest: digest}).Get()
				if err == bstore.ErrAbsent {
					panic(httpErr{http.StatusBadRequest})
				}
				xcheckf(err, "looking up multiplatform manifest in database")
				exists, err := bstore.QueryTx[DBTag](tx).FilterNonzero(DBTag{Repo: repo.Name, Tag: tag, Digest: mli.ListDigest}).Exists()
				xcheckf(err, "looking up tag in database")
				if !exists {
					panic(httpErr{http.StatusBadRequest})
				}
			}
		}

		if !strings.HasSuffix(r.URL.Path, "/") {
			url := r.URL.Path + "/"
			if r.URL.RawQuery != "" {
				url += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, url, http.StatusPermanentRedirect)
			return nil
		}

		dbmanifests := map[string]DBManifest{} // For manifests in lists.

		manifestDigests := []any{}
		var manifest any
		switch dbmanifest.Kind {
		case ManifestKindV22:
			var m ManifestImage
			err := json.Unmarshal(dbmanifest.Data, &m)
			xcheckf(err, "parsing manifest")
			manifest = m

			// Get all manifest lists that reference this manifest and are in this repo, add them to manifestDigests.
			q := bstore.QueryTx[DBManifestListImage](tx)
			dbml, err := q.FilterNonzero(DBManifestListImage{ImageDigest: dbmanifest.Digest}).List()
			xcheckf(err, "listing manifest lists referencing this manifest")
			seen := map[string]bool{}
			for _, x := range dbml {
				if seen[x.ListDigest] {
					continue
				}
				seen[x.ListDigest] = true
				qrm := bstore.QueryTx[DBRepoManifest](tx)
				exists, err := qrm.FilterNonzero(DBRepoManifest{Repo: repo.Name, Digest: x.ListDigest}).Exists()
				xcheckf(err, "finding referencing list manifest for repo")
				if exists {
					manifestDigests = append(manifestDigests, x.ListDigest)
				}
			}

		case ManifestKindListV22:
			var m ManifestList
			err := json.Unmarshal(dbmanifest.Data, &m)
			xcheckf(err, "parsing manifest")
			manifest = m

			for _, im := range m.Manifests {
				manifestDigests = append(manifestDigests, strings.ToLower(im.Digest))
			}
			dbml, err := bstore.QueryTx[DBManifest](tx).FilterEqual("Digest", manifestDigests...).List()
			xcheckf(err, "fetching manifests in manifest list from database")
			for _, dbm := range dbml {
				dbmanifests[dbm.Digest] = dbm
			}

		default:
			panic("missing case for kind")
		}

		manifestDigests = append(manifestDigests, digest)
		q := bstore.QueryTx[DBTag](tx)
		tags, err := q.FilterEqual("Digest", manifestDigests...).SortDesc("Modified").List()
		xcheckf(err, "listing tags referencing manifest digest")

		var address string
		if tag == "" {
			address = fmt.Sprintf("%s/%s@%s", r.Host, repo.Name, dbmanifest.Digest)
		} else {
			address = fmt.Sprintf("%s/%s:%s@%s", r.Host, repo.Name, tag, dbmanifest.Digest)
		}

		params = map[string]any{
			"Repo":                repo,
			"ManifestKindV22":     ManifestKindV22,
			"ManifestKindListV22": ManifestKindListV22,
			"DBManifest":          dbmanifest,
			"ParsedManifest":      manifest,
			"Tags":                tags,
			"DBManifests":         dbmanifests,
			"BaseAddress":         r.Host,
			"Address":             address,
			"Tag":                 tag,
		}
		return nil
	})
	xcheckf(err, "read transaction")

	err = manifestTemplate.Execute(w, params)
	if err != nil && !isClosed(err) {
		log.Printf("executing template: %v", err)
	}
}
