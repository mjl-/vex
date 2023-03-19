package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"log"
)

func TestRegistry(t *testing.T) {
	debugFlag = true
	uploadInactivityDuration = time.Second / 2

	os.RemoveAll("testdata/test")
	os.MkdirAll("testdata/test", 0700)

	config.DataDir = "testdata/test"
	database = xdb()
	adduser(database, "vex", []byte("testtest"))

	checkRequest := func(h http.Handler, auth bool, method, path string, headers map[string]string, body []byte, expCode int, expHeaders map[string]string, expErr RegistryError) (respBody []byte, respHeaders http.Header) {
		t.Helper()
		rec := httptest.NewRecorder()
		var reader io.Reader
		if body != nil {
			reader = bytes.NewReader(body)
		}
		req := httptest.NewRequest(method, path, reader)
		for k, v := range headers {
			req.Header.Add(k, v)
		}
		if auth {
			req.Header.Add("Authorization", "Basic dmV4OnRlc3R0ZXN0")
		}
		h.ServeHTTP(rec, req)
		resp := rec.Result()
		if resp.StatusCode != expCode {
			t.Fatalf("got statuscode %d, expected %d, for request %v", resp.StatusCode, expCode, req)
		}
		for k, v := range expHeaders {
			if resp.Header.Get(k) != v {
				t.Fatalf("for response header %s, expected %q, got %q", k, v, resp.Header.Get(k))
			}
		}
		respBody = rec.Body.Bytes()
		if expErr != "" {
			var errors Errors
			err := json.Unmarshal(respBody, &errors)
			if err != nil {
				t.Fatalf("parsing errors json: %v", err)
			}
			if len(errors.Errors) != 1 {
				t.Fatalf("got %d errors, expected 1: %v", len(errors.Errors), errors)
			}
			if errors.Errors[0].Code != expErr {
				t.Fatalf("got error %q, expected %q", errors.Errors[0].Code, expErr)
			}
		}
		return respBody, resp.Header
	}

	reg := registry{auth: true}
	checkRequest(reg, true, "HEAD", "/v2/", nil, nil, http.StatusOK, nil, "")
	checkRequest(reg, true, "GET", "/v2/", nil, nil, http.StatusOK, nil, "")
	checkRequest(reg, true, "GET", "/v2/_catalog", nil, nil, http.StatusOK, nil, "")

	// Bad auth.
	checkRequest(reg, false, "GET", "/v2/", nil, nil, http.StatusUnauthorized, nil, ErrorUnauthorized)
	checkRequest(reg, false, "GET", "/v2/", map[string]string{"Authorization": "bogus"}, nil, http.StatusUnauthorized, nil, ErrorUnauthorized)
	checkRequest(reg, false, "GET", "/v2/", map[string]string{"Authorization": "Digest bogus"}, nil, http.StatusUnauthorized, nil, ErrorUnauthorized)
	checkRequest(reg, false, "GET", "/v2/", map[string]string{"Authorization": "Basic badbase64"}, nil, http.StatusUnauthorized, nil, ErrorUnauthorized)
	checkRequest(reg, false, "GET", "/v2/", map[string]string{"Authorization": "Basic eA=="}, nil, http.StatusUnauthorized, nil, ErrorUnauthorized)                 // Bad base64 content.
	checkRequest(reg, false, "GET", "/v2/", map[string]string{"Authorization": "Basic eDp4Ong="}, nil, http.StatusUnauthorized, nil, ErrorUnauthorized)             // Bad base64 content.
	checkRequest(reg, false, "GET", "/v2/", map[string]string{"Authorization": "Basic b3RoZXI6dGVzdHRlc3Q="}, nil, http.StatusUnauthorized, nil, ErrorUnauthorized) // Unknown user.
	checkRequest(reg, false, "GET", "/v2/", map[string]string{"Authorization": "Basic dmV4OmJhZA=="}, nil, http.StatusUnauthorized, nil, ErrorUnauthorized)         // Bad password.

	// No data yet.
	html := http.HandlerFunc(serveHTML)
	checkRequest(html, false, "GET", "/", nil, nil, http.StatusOK, nil, "")
	checkRequest(html, false, "GET", "/repo/badname/", nil, nil, http.StatusNotFound, nil, "")
	checkRequest(html, false, "GET", "/repo/badname/manifest/sha256:0000000000000000000000000000000000000000000000000000000000000000", nil, nil, http.StatusNotFound, nil, "")

	upper := func(digest string) string {
		t := strings.SplitN(digest, ":", 2)
		return t[0] + ":" + strings.ToUpper(t[1])
	}

	makeDigest := func(buf []byte) string {
		return fmt.Sprintf("sha256:%x", sha256.Sum256(buf))
	}

	makeConfig := func(s string) (Config, []byte) {
		buf := []byte(s)
		c := Config{MediaType: "application/vnd.docker.container.image.v1+json", Size: int64(len(buf)), Digest: makeDigest(buf)}
		return c, buf
	}

	makeLayer := func(s string) (Layer, []byte) {
		buf := []byte(s)
		l := Layer{MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip", Size: int64(len(buf)), Digest: makeDigest(buf)}
		return l, buf
	}

	makeImage := func(config Config, layers ...Layer) ManifestImage {
		return ManifestImage{2, "application/vnd.docker.distribution.manifest.v2+json", config, layers}
	}

	marshalDigest := func(v any) (string, []byte) {
		buf, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal json: %v", err)
		}
		return makeDigest(buf), buf
	}

	// Create some config/layer blobs and manifests.
	bamdc, bamdcBuf := makeConfig("linux/amd64 config")
	bamd0, bamd0Buf := makeLayer("linux/amd64 layer 0")
	bamd1, bamd1Buf := makeLayer("linux/amd64 layer 1")
	mamdDigest, mamdBuf := marshalDigest(makeImage(bamdc, bamd0, bamd1))

	// Two linux/arm's, a v6 and v7, with one layer shared.
	barmv6c, barmv6cBuf := makeConfig("linux/arm v6 config")
	barm0, barm0Buf := makeLayer("linux/arm layer 0")
	barmv61, barmv61Buf := makeLayer("linux/arm v6 layer 1")
	marmv6Digest, marmv6Buf := marshalDigest(makeImage(barmv6c, barm0, barmv61))

	barmv7c, barmv7cBuf := makeConfig("linux/arm v7 config")
	barmv71, barmv71Buf := makeLayer("linux/arm v7 layer 1")
	marmv7Digest, marmv7Buf := marshalDigest(makeImage(barmv7c, barm0, barmv71))

	list0Digest, list0Buf := marshalDigest(ManifestList{
		SchemaVersion: 2,
		MediaType:     "application/vnd.docker.distribution.manifest.list.v2+json",
		Manifests: []ManifestPlatform{
			{
				MediaType: "application/vnd.docker.distribution.manifest.v2+json",
				Size:      int64(len(mamdBuf)),
				Digest:    upper(mamdDigest), // Test canonicalization of digest.
				Platform: Platform{
					Architecture: "amd64",
					OS:           "linux",
				},
			},
			{
				MediaType: "application/vnd.docker.distribution.manifest.v2+json",
				Size:      int64(len(marmv6Buf)),
				Digest:    marmv6Digest,
				Platform: Platform{
					Architecture: "arm",
					OS:           "linux",
					Variant:      "v6",
				},
			},
			{
				MediaType: "application/vnd.docker.distribution.manifest.v2+json",
				Size:      int64(len(marmv7Buf)),
				Digest:    marmv7Digest,
				Platform: Platform{
					Architecture: "amd64",
					OS:           "linux",
					Variant:      "v7",
				},
			},
		},
	})

	bunref0, bunref0Buf := makeLayer("unreferenced blob0")

	checkPushBlob := func(repo string, digest string, buf []byte) {
		t.Helper()
		path := fmt.Sprintf("/v2/%s/blobs/uploads/", repo)
		checkRequest(reg, true, "POST", path+"?digest="+digest, nil, buf, http.StatusCreated, map[string]string{"Docker-Content-Digest": ""}, "")
	}

	checkPushImage := func(repo string, reference, digest string, buf []byte) {
		t.Helper()
		path := fmt.Sprintf("/v2/%s/manifests/%s", repo, reference)
		checkRequest(reg, true, "PUT", path, map[string]string{"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"}, buf, http.StatusCreated, map[string]string{"Docker-Content-Digest": digest}, "")
	}

	checkPushList := func(repo string, reference, digest string, buf []byte) {
		t.Helper()
		path := fmt.Sprintf("/v2/%s/manifests/%s", repo, reference)
		checkRequest(reg, true, "PUT", path, map[string]string{"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"}, buf, http.StatusCreated, map[string]string{"Docker-Content-Digest": digest}, "")
	}

	checkManifestDelete := func(repo string, reference string) {
		t.Helper()
		path := fmt.Sprintf("/v2/%s/manifests/%s", repo, reference)
		checkRequest(reg, true, "DELETE", path, nil, nil, http.StatusAccepted, nil, "")
	}

	checkBlobDelete := func(repo string, digest string) {
		t.Helper()
		path := fmt.Sprintf("/v2/%s/blobs/%s", repo, digest)
		checkRequest(reg, true, "DELETE", path, nil, nil, http.StatusAccepted, nil, "")
	}

	// Push the blobs and manifest.
	checkPushBlob("testrepo", bamdc.Digest, bamdcBuf)
	checkPushBlob("testrepo", bamd0.Digest, bamd0Buf)
	checkPushBlob("testrepo", bamd1.Digest, bamd1Buf)
	checkPushBlob("testrepo", bamd1.Digest, bamd1Buf) // OK to do again.
	checkPushImage("testrepo", mamdDigest, mamdDigest, mamdBuf)
	checkPushImage("testrepo", mamdDigest, mamdDigest, mamdBuf) // OK to do again.
	checkPushImage("testrepo", "image", mamdDigest, mamdBuf)
	checkPushImage("testrepo", "image", mamdDigest, mamdBuf) // OK to do again.

	checkPushBlob("testrepo", barmv6c.Digest, barmv6cBuf)
	checkPushBlob("testrepo", barm0.Digest, barm0Buf)
	checkPushBlob("testrepo", barmv61.Digest, barmv61Buf)
	checkPushImage("testrepo", marmv6Digest, marmv6Digest, marmv6Buf)

	checkPushBlob("testrepo", barmv7c.Digest, barmv7cBuf)
	checkPushBlob("testrepo", barmv71.Digest, barmv71Buf)
	checkPushImage("testrepo", marmv7Digest, marmv7Digest, marmv7Buf)

	checkPushList("testrepo", list0Digest, list0Digest, list0Buf)
	checkPushList("testrepo", "list", list0Digest, list0Buf)
	checkPushImage("testrepo", "imagedup", mamdDigest, mamdBuf)
	checkPushList("testrepo", "listdup", list0Digest, list0Buf)
	checkPushBlob("testrepo", bunref0.Digest, bunref0Buf)

	// Also on another repo.
	checkPushList("repo2", list0Digest, list0Digest, list0Buf)
	checkPushImage("repo2", "image", mamdDigest, mamdBuf)

	// Put manifest with missing config or layer.
	absentLayer, _ := makeLayer("absent")
	mxlayerDigest, mxlayerBuf := marshalDigest(makeImage(bamdc, absentLayer))
	checkRequest(reg, true, "PUT", "/v2/testrepo/manifests/"+mxlayerDigest, nil, mxlayerBuf, http.StatusBadRequest, nil, ErrorManifestInvalid)
	absentConfig, _ := makeConfig("absent")
	mxconfigDigest, mxconfigBuf := marshalDigest(makeImage(absentConfig, bamd0))
	checkRequest(reg, true, "PUT", "/v2/testrepo/manifests/"+mxconfigDigest, nil, mxconfigBuf, http.StatusBadRequest, nil, ErrorManifestInvalid)

	// Put list manifest with missing image manifest.
	mxlistDigest, mxlistBuf := marshalDigest(makeImage(absentConfig, absentLayer))
	xlistDigest, xlistBuf := marshalDigest(ManifestList{
		SchemaVersion: 2,
		MediaType:     "application/vnd.docker.distribution.manifest.list.v2+json",
		Manifests: []ManifestPlatform{
			{
				MediaType: "application/vnd.docker.distribution.manifest.v2+json",
				Size:      int64(len(mxlistBuf)),
				Digest:    mxlistDigest,
				Platform: Platform{
					Architecture: "amd64",
					OS:           "linux",
				},
			},
		},
	})
	checkRequest(reg, true, "PUT", "/v2/testrepo/manifests/"+xlistDigest, nil, xlistBuf, http.StatusBadRequest, nil, ErrorManifestInvalid)

	// Mount from other repo.
	checkRequest(reg, true, "POST", "/v2/repo2/blobs/uploads/?mount="+bamdc.Digest+"&from=testrepo", nil, nil, http.StatusCreated, map[string]string{"Docker-Content-Digest": bamdc.Digest}, "")
	checkRequest(reg, true, "POST", "/v2/repo2/blobs/uploads/?mount=sha256:0000000000000000000000000000000000000000000000000000000000000000&from=testrepo", nil, nil, http.StatusAccepted, nil, "") // Starts a regular upload.

	// Upload in chunks.
	_, uph := checkRequest(reg, true, "POST", "/v2/testrepo/blobs/uploads/", nil, nil, http.StatusAccepted, nil, "")
	uuid := uph.Get("Docker-Upload-UUID")
	checkRequest(reg, true, "GET", "/v2/testrepo/blobs/uploads/"+uuid, nil, nil, http.StatusNoContent, nil, "")
	checkRequest(reg, true, "DELETE", "/v2/testrepo/blobs/uploads/"+uuid, nil, nil, http.StatusNoContent, nil, "")
	time.Sleep(time.Second / 100) // Not great. Give upload goroutine a chance to clean up.
	checkRequest(reg, true, "GET", "/v2/testrepo/blobs/uploads/"+uuid, nil, nil, http.StatusNotFound, nil, ErrorBlobUploadUnknown)

	_, uph = checkRequest(reg, true, "POST", "/v2/testrepo/blobs/uploads/", nil, nil, http.StatusAccepted, nil, "")
	uuid = uph.Get("Docker-Upload-UUID")
	checkRequest(reg, true, "PATCH", "/v2/testrepo/blobs/uploads/"+uuid, nil, bamd0Buf[:1], http.StatusAccepted, map[string]string{"Range": "0-0"}, "")                                                 // Range "end" is inclusive...
	checkRequest(reg, true, "PATCH", "/v2/testrepo/blobs/uploads/"+uuid, nil, nil, http.StatusBadRequest, nil, ErrorUnsupported)                                                                        // Data required.
	checkRequest(reg, true, "PATCH", "/v2/testrepo/blobs/uploads/"+uuid, map[string]string{"Content-Range": "bogus"}, bamd0Buf[1:2], http.StatusBadRequest, nil, ErrorUnsupported)                      // Bad Content-Range
	checkRequest(reg, true, "PATCH", "/v2/testrepo/blobs/uploads/"+uuid, map[string]string{"Content-Range": "0-bogus"}, bamd0Buf[1:2], http.StatusBadRequest, nil, ErrorUnsupported)                    // Bad Content-Range
	checkRequest(reg, true, "PATCH", "/v2/testrepo/blobs/uploads/"+uuid, map[string]string{"Content-Range": "bogus-0"}, bamd0Buf[1:2], http.StatusBadRequest, nil, ErrorUnsupported)                    // Bad Content-Range
	checkRequest(reg, true, "PATCH", "/v2/testrepo/blobs/uploads/"+uuid, map[string]string{"Content-Range": "0-1"}, bamd0Buf[1:2], http.StatusBadRequest, nil, ErrorRangeInvalid)                       // Bad range start.
	checkRequest(reg, true, "PATCH", "/v2/testrepo/blobs/uploads/"+uuid, map[string]string{"Content-Range": "1-0"}, bamd0Buf[1:2], http.StatusBadRequest, nil, ErrorRangeInvalid)                       // Length mismatch.
	checkRequest(reg, true, "PATCH", "/v2/testrepo/blobs/uploads/"+uuid, map[string]string{"Content-Length": "2", "Content-Range": "1-1"}, bamd0Buf[1:2], http.StatusBadRequest, nil, ErrorSizeInvalid) // Content-Length mismatch.
	checkRequest(reg, true, "PATCH", "/v2/testrepo/blobs/uploads/"+uuid, map[string]string{"Content-Range": "2-4"}, bamd0Buf[2:3], http.StatusBadRequest, nil, ErrorSizeInvalid)                        // Size in Content-Range mismatches data.
	checkRequest(reg, true, "PATCH", "/v2/testrepo/blobs/uploads/"+uuid, nil, bamd0Buf[3:4], http.StatusAccepted, map[string]string{"Range": "0-3"}, "")
	checkRequest(reg, true, "PUT", "/v2/testrepo/blobs/uploads/"+uuid, nil, bamd0Buf[4:], http.StatusCreated, map[string]string{"Docker-Content-Digest": bamd0.Digest, "Content-Range": fmt.Sprintf("4-%d", len(bamd0Buf)-1)}, "")
	time.Sleep(time.Second / 100) // Not great. Give upload goroutine a chance to clean up.
	checkRequest(reg, true, "GET", "/v2/testrepo/blobs/uploads/"+uuid, nil, nil, http.StatusNotFound, nil, ErrorBlobUploadUnknown)

	bunref1, bunref1Buf := makeLayer("unreferenced blob1")
	_, uph = checkRequest(reg, true, "POST", "/v2/testrepo/blobs/uploads/", nil, nil, http.StatusAccepted, nil, "")
	uuid = uph.Get("Docker-Upload-UUID")
	checkRequest(reg, true, "PATCH", "/v2/testrepo/blobs/uploads/"+uuid, nil, bunref1Buf[:1], http.StatusAccepted, map[string]string{"Range": "0-0"}, "") // Range "end" is inclusive...
	checkRequest(reg, true, "PATCH", "/v2/testrepo/blobs/uploads/"+uuid, nil, bunref1Buf[1:], http.StatusAccepted, map[string]string{"Range": fmt.Sprintf("0-%d", len(bunref1Buf)-1)}, "")
	checkRequest(reg, true, "PUT", "/v2/testrepo/blobs/uploads/"+uuid, nil, nil, http.StatusCreated, map[string]string{"Docker-Content-Digest": bunref1.Digest, "Content-Range": fmt.Sprintf("%d-%d", len(bunref1Buf), len(bunref1Buf)-1)}, "")
	time.Sleep(time.Second / 100) // Not great. Give upload goroutine a chance to clean up.
	checkRequest(reg, true, "GET", "/v2/testrepo/blobs/uploads/"+uuid, nil, nil, http.StatusNotFound, nil, ErrorBlobUploadUnknown)
	checkRequest(reg, true, "GET", "/v2/testrepo/blobs/"+bunref1.Digest, nil, nil, http.StatusOK, nil, "")

	// Upload with wrong digest.
	checkRequest(reg, true, "POST", "/v2/testrepo/blobs/uploads/?digest=sha256:0000000000000000000000000000000000000000000000000000000000000000", nil, []byte("test"), http.StatusBadRequest, nil, ErrorDigestInvalid)
	_, uph = checkRequest(reg, true, "POST", "/v2/testrepo/blobs/uploads/", nil, nil, http.StatusAccepted, nil, "")
	uuid = uph.Get("Docker-Upload-UUID")
	checkRequest(reg, true, "PUT", "/v2/testrepo/blobs/uploads/"+uuid+"?digest=sha256:0000000000000000000000000000000000000000000000000000000000000000", nil, nil, http.StatusBadRequest, nil, ErrorDigestInvalid)

	checkRequest(reg, true, "PUT", "/v2/testrepo/manifests/sha256:0000000000000000000000000000000000000000000000000000000000000000", nil, []byte("test"), http.StatusBadRequest, nil, ErrorManifestInvalid)

	checkRequest(reg, true, "POST", "/v2/testrepo/blobs/uploads/", nil, nil, http.StatusAccepted, nil, "") // Dangling until reaped.

	checkRequest(reg, true, "GET", "/v2/", nil, nil, http.StatusOK, nil, "")
	checkRequest(reg, true, "GET", "/v2/_catalog", nil, nil, http.StatusOK, nil, "")
	checkRequest(reg, true, "GET", "/v2/testrepo/list/tags", nil, nil, http.StatusOK, nil, "")
	checkRequest(reg, true, "GET", "/v2/testrepo/manifests/image", nil, nil, http.StatusOK, nil, "")
	checkRequest(reg, true, "GET", "/v2/testrepo/manifests/imagedup", nil, nil, http.StatusOK, nil, "")
	checkRequest(reg, true, "GET", "/v2/testrepo/manifests/list", nil, nil, http.StatusOK, nil, "")
	checkRequest(reg, true, "GET", "/v2/testrepo/manifests/listdup", nil, nil, http.StatusOK, nil, "")
	checkRequest(reg, true, "GET", "/v2/testrepo/manifests/"+mamdDigest, nil, nil, http.StatusOK, nil, "")
	checkRequest(reg, true, "GET", "/v2/testrepo/manifests/"+list0Digest, nil, nil, http.StatusOK, nil, "")
	checkRequest(reg, true, "GET", "/v2/testrepo/blobs/"+bamdc.Digest, nil, nil, http.StatusOK, nil, "")
	checkRequest(reg, true, "GET", "/v2/testrepo/blobs/"+bamd0.Digest, nil, nil, http.StatusOK, nil, "")
	checkRequest(reg, true, "GET", "/v2/testrepo/blobs/"+bamd1.Digest, nil, nil, http.StatusOK, nil, "")
	checkRequest(reg, true, "GET", "/v2/testrepo/manifests/"+upper(mamdDigest), nil, nil, http.StatusOK, nil, "")
	checkRequest(reg, true, "GET", "/v2/testrepo/blobs/"+upper(bamd0.Digest), nil, nil, http.StatusOK, nil, "")

	// Attempt removing resources that don't exist.
	checkRequest(reg, true, "DELETE", "/v2/badrepo/manifests/sha256:0000000000000000000000000000000000000000000000000000000000000000", nil, nil, http.StatusNotFound, nil, ErrorNameUnknown)
	checkRequest(reg, true, "DELETE", "/v2/testrepo/manifests/badtag", nil, nil, http.StatusNotFound, nil, ErrorManifestUnknown)
	checkRequest(reg, true, "DELETE", "/v2/testrepo/manifests/sha256:0000000000000000000000000000000000000000000000000000000000000000", nil, nil, http.StatusNotFound, nil, ErrorManifestUnknown)
	checkRequest(reg, true, "DELETE", "/v2/testrepo/blobs/sha256:0000000000000000000000000000000000000000000000000000000000000000", nil, nil, http.StatusNotFound, nil, ErrorDigestInvalid)
	checkRequest(reg, true, "DELETE", "/v2/testrepo/blobs/uploads/bogus", nil, nil, http.StatusNotFound, nil, ErrorBlobUploadUnknown)

	// Attempt to remove resources that are still referenced.
	checkRequest(reg, true, "DELETE", "/v2/testrepo/manifests/"+list0Digest, nil, nil, http.StatusBadRequest, nil, ErrorDenied)
	checkRequest(reg, true, "DELETE", "/v2/testrepo/blobs/"+bamd0.Digest, nil, nil, http.StatusAccepted, nil, "") // Blobs are global, and will only be actually be removed when nothing references it anymore.

	checkManifestDelete("testrepo", "image")
	checkManifestDelete("testrepo", "imagedup")
	checkRequest(reg, true, "DELETE", "/v2/testrepo/manifests/"+mamdDigest, nil, nil, http.StatusBadRequest, nil, ErrorDenied) // Still referenced by list manifest.
	checkPushImage("testrepo", "image", mamdDigest, mamdBuf)                                                                   // Restore.
	checkPushImage("testrepo", "imagedup", mamdDigest, mamdBuf)

	// Unknown algorithm.
	checkRequest(reg, true, "GET", "/v2/testrepo/manifests/sha999:0000000000000000000000000000000000000000000000000000000000000000", nil, nil, http.StatusBadRequest, nil, ErrorUnsupported)
	checkRequest(reg, true, "GET", "/v2/testrepo/manifests/sha256:zzz", nil, nil, http.StatusNotFound, nil, ErrorUnsupported)     // Path regex does not match.
	checkRequest(reg, true, "GET", "/v2/testrepo/manifests/sha256:fff", nil, nil, http.StatusBadRequest, nil, ErrorDigestInvalid) // Bad length.

	// HTML pages, now with data.
	checkRequest(html, false, "GET", "/", nil, nil, http.StatusOK, nil, "")
	checkRequest(html, false, "GET", "/repo/badname/", nil, nil, http.StatusNotFound, nil, "")
	checkRequest(html, false, "GET", "/repo/testrepo/manifest/sha256:0000000000000000000000000000000000000000000000000000000000000000", nil, nil, http.StatusNotFound, nil, "")
	checkRequest(html, false, "GET", "/repo/badname/manifest/"+mamdDigest, nil, nil, http.StatusNotFound, nil, "")
	checkRequest(html, false, "GET", "/repo/badname/manifest/"+list0Digest, nil, nil, http.StatusNotFound, nil, "")
	checkRequest(html, false, "GET", "/repo/testrepo/", nil, nil, http.StatusOK, nil, "")
	checkRequest(html, false, "GET", "/repo/testrepo/manifest/"+mamdDigest+"/", nil, nil, http.StatusOK, nil, "")
	checkRequest(html, false, "GET", "/repo/testrepo/manifest/"+mamdDigest+"/?tag=image", nil, nil, http.StatusOK, nil, "")
	checkRequest(html, false, "GET", "/repo/testrepo/manifest/"+list0Digest+"/", nil, nil, http.StatusOK, nil, "")
	checkRequest(html, false, "GET", "/repo/testrepo/manifest/"+list0Digest+"/?tag=list", nil, nil, http.StatusOK, nil, "")

	// Public, unauthenticated endpoint.
	public := registry{auth: false}
	checkRequest(public, true, "PUT", "/v2/testrepo/manifests/tag", nil, nil, http.StatusMethodNotAllowed, nil, ErrorDenied)
	checkRequest(public, true, "PUT", "/v2/testrepo/manifests/sha256:0000000000000000000000000000000000000000000000000000000000000000", nil, nil, http.StatusMethodNotAllowed, nil, ErrorDenied)
	checkRequest(public, true, "DELETE", "/v2/testrepo/manifests/tag", nil, nil, http.StatusMethodNotAllowed, nil, ErrorDenied)
	checkRequest(public, true, "DELETE", "/v2/testrepo/manifests/sha256:0000000000000000000000000000000000000000000000000000000000000000", nil, nil, http.StatusMethodNotAllowed, nil, ErrorDenied)
	checkRequest(public, true, "POST", "/v2/testrepo/blobs/uploads/", nil, nil, http.StatusMethodNotAllowed, nil, ErrorDenied)
	checkRequest(public, true, "PUT", "/v2/testrepo/blobs/uploads/x", nil, nil, http.StatusMethodNotAllowed, nil, ErrorDenied)
	checkRequest(public, true, "PATCH", "/v2/testrepo/blobs/uploads/x", nil, nil, http.StatusMethodNotAllowed, nil, ErrorDenied)
	checkRequest(public, true, "DELETE", "/v2/testrepo/blobs/uploads/x", nil, nil, http.StatusMethodNotAllowed, nil, ErrorDenied)
	checkRequest(public, true, "GET", "/v2/testrepo/blobs/uploads/x", nil, nil, http.StatusMethodNotAllowed, nil, ErrorDenied)
	checkRequest(public, true, "DELETE", "/v2/testrepo/blobs/sha256:0000000000000000000000000000000000000000000000000000000000000000", nil, nil, http.StatusMethodNotAllowed, nil, ErrorDenied)

	// Remove all tags, we'll end up with an empty blob directory.
	checkManifestDelete("testrepo", "image")
	checkManifestDelete("testrepo", "imagedup")
	checkManifestDelete("testrepo", "list")
	checkManifestDelete("testrepo", "listdup")
	checkManifestDelete("repo2", list0Digest)
	checkManifestDelete("repo2", "image")
	checkBlobDelete("testrepo", bunref0.Digest)
	checkBlobDelete("testrepo", bunref1.Digest)

	checkEmptyDir := func(dir string) {
		t.Helper()
		files, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("reading dir: %v", err)
		}
		if len(files) != 0 {
			t.Fatalf("leftover files, e.g. %s", files[0].Name())
		}
	}
	checkEmptyDir(filepath.Join(config.DataDir, "blob"))

	// Test overwriting tags. Should also remove unreferenced objects.
	bindepc, bindepcBuf := makeConfig("independent config")
	bindepl, bindeplBuf := makeLayer("independent layer")
	mindepDigest, mindepBuf := marshalDigest(makeImage(bindepc, bindepl))

	writeImage := func() {
		checkPushBlob("testrepo", bamdc.Digest, bamdcBuf)
		checkPushBlob("testrepo", bamd0.Digest, bamd0Buf)
		checkPushBlob("testrepo", bamd1.Digest, bamd1Buf)
		checkPushImage("testrepo", mamdDigest, mamdDigest, mamdBuf)
		checkPushImage("testrepo", "shared", mamdDigest, mamdBuf)
	}
	writeIndep := func() {
		checkPushBlob("testrepo", bindepc.Digest, bindepcBuf)
		checkPushBlob("testrepo", bindepl.Digest, bindeplBuf)
		checkPushImage("testrepo", mindepDigest, mindepDigest, mindepBuf)
		checkPushImage("testrepo", "shared", mindepDigest, mindepBuf)
	}
	writeList := func() {
		checkPushBlob("testrepo", bamdc.Digest, bamdcBuf)
		checkPushBlob("testrepo", bamd0.Digest, bamd0Buf)
		checkPushBlob("testrepo", bamd1.Digest, bamd1Buf)
		checkPushImage("testrepo", mamdDigest, mamdDigest, mamdBuf)

		checkPushBlob("testrepo", barmv6c.Digest, barmv6cBuf)
		checkPushBlob("testrepo", barm0.Digest, barm0Buf)
		checkPushBlob("testrepo", barmv61.Digest, barmv61Buf)
		checkPushImage("testrepo", marmv6Digest, marmv6Digest, marmv6Buf)

		checkPushBlob("testrepo", barmv7c.Digest, barmv7cBuf)
		checkPushBlob("testrepo", barmv71.Digest, barmv71Buf)
		checkPushImage("testrepo", marmv7Digest, marmv7Digest, marmv7Buf)

		checkPushList("testrepo", list0Digest, list0Digest, list0Buf)
		checkPushList("testrepo", "shared", list0Digest, list0Buf)
		// Overwrite tag pointing to image with list that contains that image.
	}

	// Overwrite image with list that contains image.
	writeImage()
	writeList()
	checkManifestDelete("testrepo", "shared")
	checkEmptyDir(filepath.Join(config.DataDir, "blob"))

	// Overwrite list with image that list contained.
	writeList()
	writeImage()
	checkManifestDelete("testrepo", "shared")
	checkEmptyDir(filepath.Join(config.DataDir, "blob"))

	// Overwrite image with list that does not contain image.
	writeIndep()
	writeList()
	checkManifestDelete("testrepo", "shared")
	checkEmptyDir(filepath.Join(config.DataDir, "blob"))

	// Overwrite list with image that is not in list.
	writeList()
	writeIndep()
	checkManifestDelete("testrepo", "shared")
	checkEmptyDir(filepath.Join(config.DataDir, "blob"))

	wait := uploadInactivityDuration + uploadInactivityDuration/10
	log.Printf("sleeping for %s for reaping unfinished downloads", wait)
	time.Sleep(wait)
	checkEmptyDir(filepath.Join(config.DataDir, "tmp"))
}
