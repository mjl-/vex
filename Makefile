default: build
	./vex -debug -config local/vex.conf serve

build:
	./gendoc.sh
	CGO_ENABLED=0 go build
	CGO_ENABLED=0 go vet

https: build
	./vex -debug -config local/vex.conf serve -authtlscert local/tls.pem -authtlskey local/tls-key.pem

httpsfresh: build
	-rm -r data
	echo testtest | ./vex -config local/vex.conf user add vex
	./vex -debug -config local/vex.conf serve -authtlscert local/tls.pem -authtlskey local/tls-key.pem

check:
	staticcheck

test:
	CGO_ENABLED=0 go test -shuffle=on -coverprofile cover.out ./...
	go tool cover -html=cover.out -o cover.html

test-race:
	go test -race -shuffle=on -coverprofile cover.out ./...

# having "err" shadowed is common, best to not have others
check-shadow:
	go vet -vettool=$$(which shadow) ./... 2>&1 | grep -v '"err"'

dump:
	-mkdir tmp
	for name in DBRepo DBBlob DBManifest DBManifestBlob DBManifestListImage DBRepoManifest DBTag DBUser; do bstore exportcsv data/vex.db $$name >tmp/$$name.csv; done


fmt:
	gofmt -w -s *.go
