package trust

import (
	"crypto/x509"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/docker/docker/pkg/log"
	"github.com/docker/libtrust/trustapi/client"
	"github.com/docker/libtrust/trustgraph"
)

type TrustStore struct {
	path       string
	caPool     *x509.CertPool
	graph      trustgraph.TrustGraph
	expiration time.Time
	fetcher    *time.Timer
	fetchTime  time.Duration
	client     *client.TrustClient

	sync.RWMutex
}

const defaultFetchtime = 45 * time.Second
const rootCA string = `-----BEGIN CERTIFICATE-----
MIIBnzCCAUSgAwIBAgIBADAKBggqhkjOPQQDAjBGMUQwQgYDVQQDEztHVzRGOkdT
N1A6MjJLWTpTUVhNOkZJNzQ6U1FCUzpLUlhSOlY0VFI6SUc2UTo3TkxMOk9KSVM6
M1hYSjAeFw0xNDA5MDUyMzA3NTRaFw0yNDA5MDkyMzA3NTRaMEYxRDBCBgNVBAMT
O0dXNEY6R1M3UDoyMktZOlNRWE06Rkk3NDpTUUJTOktSWFI6VjRUUjpJRzZROjdO
TEw6T0pJUzozWFhKMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEB23slGpLr16M
TAJ3MaGVZK6QYEb/l5EZkpnrPcdX6JTGCSuDy7jpEYtsAyp6Du1jEwZuwR2nF1ni
WI39XxM1lKMjMCEwDgYDVR0PAQH/BAQDAgAEMA8GA1UdEwEB/wQFMAMBAf8wCgYI
KoZIzj0EAwIDSQAwRgIhAOFl3YnbPAPd7hRbh2Wpe0RrtZ0KAZGpjKk3C1ZhQEG4
AiEAh6R8OVclkFNXFbQML8X5uEL+3d7wB+osNU0OlHFaiiQ=
-----END CERTIFICATE-----
`

var baseGraphs = []string{"official"}

func NewTrustStore(path string) (*TrustStore, error) {
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM([]byte(rootCA))

	abspath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	// Load grant files
	t := &TrustStore{
		path:      abspath,
		caPool:    caPool,
		client:    client.NewTrustClient("localhost:8092", caPool),
		fetchTime: time.Millisecond,
	}

	err = t.reload()
	if err != nil {
		return nil, err
	}

	return t, nil
}

func (t *TrustStore) reload() error {
	t.Lock()
	defer t.Unlock()

	matches, err := filepath.Glob(filepath.Join(t.path, "*.json"))
	if err != nil {
		return err
	}
	statements := make([]*trustgraph.Statement, len(matches))
	for i, match := range matches {
		f, err := os.Open(match)
		if err != nil {
			return err
		}
		statements[i], err = trustgraph.LoadStatement(f, t.caPool)
		if err != nil {
			f.Close()
			return err
		}
		f.Close()

	}
	if len(statements) == 0 {
		log.Debugf("No grants, fetching")
		t.fetcher = time.AfterFunc(t.fetchTime, t.fetch)
		return nil
	}

	grants, expiration, err := trustgraph.CollapseStatements(statements, true)
	if err != nil {
		return err
	}

	t.expiration = expiration
	t.graph = trustgraph.NewMemoryGraph(grants)
	log.Debugf("Reloaded graph with %d grants expiring at %s", len(grants), expiration)

	nextFetch := expiration.Sub(time.Now())
	if nextFetch < 0 {
		nextFetch = defaultFetchtime
	} else {
		nextFetch = time.Duration(0.8 * (float64)(nextFetch))
	}
	t.fetcher = time.AfterFunc(nextFetch, t.fetch)

	return nil
}

// fetch retrieves updated base graphs.  This function cannot error, it
// should only log errors
func (t *TrustStore) fetch() {
	t.Lock()
	defer t.Unlock()

	if t.fetcher == nil {
		// Do nothing ??
		return
	}

	fetchCount := 0
	for _, bg := range baseGraphs {
		statement, err := t.client.GetBaseGraph(bg)
		if err != nil {
			log.Infof("Trust graph fetch failed: %s", err)
			continue
		}
		b, err := statement.Bytes()
		if err != nil {
			log.Infof("Bad trust graph statement: %s", err)
			continue
		}
		// TODO check if value differs
		err = ioutil.WriteFile(path.Join(t.path, bg+".json"), b, 0600)
		if err != nil {
			log.Infof("Error writing trust graph statement: %s", err)
		}
		fetchCount++
	}
	log.Debugf("Fetched %d base graphs at %s", fetchCount, time.Now())

	if fetchCount > 0 {
		t.fetchTime = defaultFetchtime
		go func() {
			err := t.reload()
			if err != nil {
				// TODO log
				log.Infof("Reload of trust graph failed: %s", err)
			}
		}()
		t.fetcher = nil
	} else {
		maxTime := 10 * defaultFetchtime
		t.fetchTime = time.Duration(1.5 * (float64)(t.fetchTime+time.Second))
		if t.fetchTime > maxTime {
			t.fetchTime = maxTime
		}
		t.fetcher = time.AfterFunc(t.fetchTime, t.fetch)
	}
}
