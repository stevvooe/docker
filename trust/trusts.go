package trust

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/docker/libtrust/trustgraph"
)

type TrustStore struct {
	path          string
	caPool        *x509.CertPool
	graph         trustgraph.TrustGraph
	expiration    time.Time
	httpClient    *http.Client
	graphEndpoint *url.URL

	sync.RWMutex
}

var graphEndpoint = "http://localhost:8048/graph"

func NewTrustStore(path string) (*TrustStore, error) {
	abspath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	u, err := url.Parse(graphEndpoint)
	if err != nil {
		return nil, err
	}

	// Load grant files
	t := &TrustStore{
		path:          abspath,
		caPool:        nil,
		httpClient:    &http.Client{},
		graphEndpoint: u,
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
		statements[i], err = trustgraph.LoadStatement(f, nil)
		if err != nil {
			f.Close()
			return err
		}
		f.Close()
	}
	if len(statements) == 0 {
		return nil
	}

	grants, expiration, err := trustgraph.CollapseStatements(statements, true)
	if err != nil {
		return err
	}

	t.expiration = expiration
	t.graph = trustgraph.NewMemoryGraph(grants)
	log.Debugf("Reloaded graph with %d grants expiring at %s", len(grants), expiration)

	return nil
}

func (t *TrustStore) getGraph() trustgraph.TrustGraph {
	t.RLock()
	defer t.RUnlock()
	return t.graph
}

func (t *TrustStore) fetchGraph(signature []byte) error {
	h := crypto.MD5.New()
	h.Write(signature)
	statementFile := path.Join(t.path, fmt.Sprintf("%s.json", hex.EncodeToString(h.Sum(nil))))

	// TODO Check if statementFile already exists and not expired

	req := &http.Request{
		Method:     "POST",
		URL:        t.graphEndpoint,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       ioutil.NopCloser(bytes.NewReader(signature)),
		Host:       t.graphEndpoint.Host,
	}

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode == 404 {
		return errors.New("base graph does not exist")
	}

	defer resp.Body.Close()

	statement, err := trustgraph.LoadStatement(resp.Body, t.caPool)
	if err != nil {
		return err
	}

	// Save statement
	b, err := statement.Bytes()
	if err != nil {
		log.Infof("Bad trust graph statement: %s", err)
		return err
	}
	err = ioutil.WriteFile(statementFile, b, 0600)
	if err != nil {
		log.Infof("Error writing trust graph statement: %s", err)
		return err
	}

	return t.reload()
}
