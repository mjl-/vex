Vex is a basic docker container image registry.

- Images, including multiplatform (list) manifests can be pushed to the
  authenticated, writable endpoint.
- All pushed data (repositories, images and blobs/layers) are public
  and can be pulled from the read-only endpoint.
- Serves on three HTTP(s) ports: 1. public read-only, for downloading
  images. 2. read-write, with authentication, for adding/removing
  images (manifests, tags, blobs/layers). 3. internal, for metrics.
- Authenticated users have full control over all repositories.
  Repositories are automatically created on first write operation on
  them (e.g. blob/layer upload).
- The public endpoint has a Web interface for browsing repositories,
  tags, manifests (images and multiplatform images).
- Data (images and their config/layer blobs) are kept consistent, and
  automatically removed when the last reference to them is removed.
  I.e. manifests will always have all their blobs available as well.
- Metadata is stored with a builtin transactional database, for fast
  and consistent data.
- Vex is a standalone static binary, easily reproducibly built, also
  when cross-compiled.

License: MIT


# Quickstart

Create user to run as (optional) and run quickstart:

	useradd -d /home/vex vex
	mkdir /home/vex
	cd /home/vex

	# [...] download vex binary, see below.

	# generate config files. optionally replace localhost with an internal
	# host name, for self-signed tls certificate for pushing images.
	./vex quickstart <username-for-pushing-images> localhost

The quickstart creates files and prints commands to start vex, optionally enable
it as a service, and example commands to push and pull docker images.


# Download

You can easily (cross) compile if you have a recent Go toolchain installed
(see "go version", it must be >= 1.19; otherwise, see https://go.dev/dl/ or
https://go.dev/doc/manage-install and $HOME/go/bin):

	GOBIN=$PWD CGO_ENABLED=0 go install github.com/mjl-/vex@latest

Or you can download a binary built with the latest Go toolchain from
https://beta.gobuilds.org/github.com/mjl-/vex, and symlink or rename it to
"vex".

Verify you have a working binary:

	./vex version


# Caveats

- Repository names cannot currently contain a slash.
- Only application/vnd.docker.distribution.manifest.v2+json and
  application/vnd.docker.distribution.manifest.list.v2+json
  content-types are supported. The OCI copies are not currently recognized, i.e.
  application/vnd.oci.image.manifest.v1+json and
  application/vnd.oci.image.index.v1+json.


# Docker registries

Data is stored sha256 content-addressed. A docker image consist of a JSON
manifest (hashed to a digest) that references a JSON config blob (hashed to a
blob digest) and layer blobs (also hashed to blob digests). A tag is a name for
a manifest digest. Docker also has multiplatform ("list") manifests, which is a
JSON document referencing multiple image manifests, for each supported
os/architecture (platform). A tag can also point to a multiplatform/list
manifest.

Uploading an image starts with uploading blobs, resulting in digests that the
uploading tool verifies. Next the manifest is uploaded, also resulting in a
digest. For multiplatform images, multiple manifests and their blobs are
uploaded, and finally the multiplatform manifest itself, again resulting in a
digest. Finally, a tag is created (or overwritten, e.g. "latest") pointing to
the digest of the manifest.

Downloading an image typically starts with looking up a tag, resulting in a
manifest digest. Then the manifest JSON is downloaded for that digest. And next
the referenced blobs. The downloading tool will verify all digests. Only the
initial tag is often not verified in practice, but it is if the pull address
includes a digest, i.e. ending with "@sha256:...".

Blobs can be uploaded, and then never used in a manifest. This would result in
storage waste. These layers can be cleaned up after a while.

We only allow objects to be removed when they are no longer referenced: a blob
no longer referenced by an image manifest. An image manifest no longer
referenced by a tag and multiplatform/list manifests. When the last reference to
an object is removed, the object is automatically removed. So when an image
manifest is removed, its blobs are automatically removed if no other image
manifest references the image. And when a multiplatform/list manifest is
removed, its now unreferenced image manifests (and their blobs) are
automatically removed. I.e. we keep data consistent, and clean up automatically.


# FAQ

## Why a new registry?

Vex was created after the "docker free teams sunset" announcement (which they
sunrose again again shortly after).

Vex is more basic, simpler, smaller, and more limited in functionality than
popular registry software. For example, the user permission/authorization model
is very basic: any authenticated user has full control of the registry
(convenient for small/medium-sized projects/organizations, internal registries
and for testing/developing). Another example: popular registries typically
depend on external components, e.g. PostgreSQL, redis, more... Vex is very
self-contained: a statically compiled binary with no further dependencies. A
final example: popular registries typically support pluggable or configurable
storage backends (e.g. to AWS S3). Vex always stores files in the file system.

Popular registries are typically run using docker, and instructions assume that
Vex doesn't assume docker and has instructions for running without docker.
Useful if your users expect docker images but you haven't fully bought into the
docker ecosystem.
