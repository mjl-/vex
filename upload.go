package main

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	mathrand "math/rand"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Blobs can be uploaded with multiple HTTP PATCH requests, each adding data to the
// upload in progress. Uploads are cleaned up after a timeout after no activity.
type upload struct {
	UUID     string
	Done     chan struct{} // Closed when upload is finished.
	Activity chan struct{} // HTTP handlers send on this channel on activity, for inactivity timer.

	sync.Mutex
	Offset int64
	Writer io.Writer // Multiwriter that writes to both file and hash.
	File   *os.File  // Temporary file.
	Hash   hash.Hash // For sha256 digest.
}

var uploadsLock sync.Mutex
var uploads = map[string]*upload{}
var uuidgen = mathrand.New(mathrand.NewSource(time.Now().UnixNano()))

var uploadInactivityDuration = time.Minute

func newUpload() (*upload, error) {
	os.MkdirAll(filepath.Join(config.DataDir, "tmp"), 0755)
	f, err := os.CreateTemp(filepath.Join(config.DataDir, "tmp"), "vex-blob-upload")
	if err != nil {
		return nil, err
	}

	uploadsLock.Lock()
	defer uploadsLock.Unlock()

	uuidbuf := make([]byte, 8)
	uuidgen.Read(uuidbuf)
	uuid := fmt.Sprintf("%x", uuidbuf)

	up := &upload{
		UUID:     uuid,
		Done:     make(chan struct{}),
		Activity: make(chan struct{}, 1),
		File:     f,
		Hash:     sha256.New(),
	}
	up.Writer = io.MultiWriter(f, up.Hash)
	uploads[uuid] = up

	go func() {
		timer := time.NewTimer(uploadInactivityDuration)
		defer timer.Stop()

		for {
			select {
			case <-up.Done:
				return

			case <-up.Activity:
				timer.Reset(uploadInactivityDuration)

			case <-timer.C:
				up.Lock()
				defer up.Unlock()
				up.Cancel()
				return
			}
		}
	}()

	return up, nil
}

func uploadLookup(uuid string) *upload {
	uploadsLock.Lock()
	defer uploadsLock.Unlock()
	up := uploads[uuid]
	return up
}

// Called with up lock held.
func (up *upload) Cancel() {
	uploadsLock.Lock()
	delete(uploads, up.UUID)
	uploadsLock.Unlock()

	if up.File == nil {
		return
	}

	err := os.Remove(up.File.Name())
	logCheck(err, "removing uploaded file after failure to store")
	err = up.File.Close()
	logCheck(err, "closing uploaded file after failure to store")
	up.File = nil
	close(up.Done)
}

func (up *upload) SendActivity() {
	select {
	case up.Activity <- struct{}{}:
	default:
	}
}
