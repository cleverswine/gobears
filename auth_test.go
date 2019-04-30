package gobears

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_tokenFromHeader(t *testing.T) {
	r := &http.Request{}
	r.Header = http.Header{}
	r.Header.Add("Authorization", "Bearer 1234567890abcdef")
	tok := tokenFromHeader(r)
	assert.Equal(t, "1234567890abcdef", tok)
}
