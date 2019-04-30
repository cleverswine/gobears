package gobears

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_signingKeyCache_getSigningKey(t *testing.T) {
	skc := newSigningKeyCache(time.Minute * 5)
	// sample kid value pulled from "https://login.microsoftonline.com/common/discovery/v2.0/keys"
	sk, err := skc.getSigningKey("https://login.microsoftonline.com/common/v2.0", "iBjL1Rcqzhiy4fpxIxdZqohM2Yk")
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.NotEmpty(t, sk) {
		t.FailNow()
	}
}
