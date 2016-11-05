package nosurf

import (
	"net/http"
	"net/url"
)

// enforce referrer check for https to prevent MITM of http->https requests
func validateReferer(r *http.Request) error {
	if r.URL.Scheme == "https" {
		referer, err := url.Parse(r.Header.Get("Referer"))

		if err != nil || referer.String() == "" {
			return ErrNoReferer
		}

		if !sameOrigin(referer, r.URL) {
			return ErrBadReferer
		}
	}

	return nil
}
