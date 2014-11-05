package trust

import (
	"fmt"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/docker/docker/engine"
	"github.com/docker/libtrust"
)

func (t *TrustStore) Install(eng *engine.Engine) error {
	for name, handler := range map[string]engine.Handler{
		"trust_verify_signature": t.CmdCheckSignature,
	} {
		if err := eng.Register(name, handler); err != nil {
			return fmt.Errorf("Could not register %q: %v", name, err)
		}
	}
	return nil
}

func (t *TrustStore) CmdCheckSignature(job *engine.Job) engine.Status {
	var (
		signatureBytes = job.Getenv("JWS")
	)
	if signatureBytes == "" {
		return job.Errorf("Missing Signature")
	}

	sig, err := libtrust.ParseJWS([]byte(signatureBytes))
	if err != nil {
		return job.Error(err)
	}

	// Verify based on signatures, use chain if passed
	keys, err := sig.Verify()
	if err != nil {
		return job.Error(err)
	}

	err = t.fetchGraph([]byte(signatureBytes))
	if err != nil {
		// TODO check if err should be ignored and key check you be made anyway
		return job.Error(err)
	}

	subject, action, err := sig.ExtractSubject()
	if err != nil {
		return job.Error(err)
	}

	// Check local graph
	graph := t.getGraph()
	if graph == nil {
		job.Stdout.Write([]byte("no graph"))
		return engine.StatusOK
	}

	var expired bool
	var verified bool
	for _, key := range keys {
		// Check if any expired grants
		verifiedSignature, err := graph.Verify(key, subject, action)
		if err != nil {
			return job.Errorf("Error verifying key to namespace: %s", subject)
		}
		if !verifiedSignature {
			log.Debugf("Verification failed for %s using key %s", subject, key.KeyID())
		} else if t.expiration.Before(time.Now()) {
			expired = true
		} else {
			verified = true
		}
	}

	if verified {
		job.Stdout.Write([]byte("verified"))
	} else if expired {
		job.Stdout.Write([]byte("expired"))
	} else {
		job.Stdout.Write([]byte("not verified"))
	}

	return engine.StatusOK
}
