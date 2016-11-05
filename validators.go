package nosurf

import (
	"net/http"
	"net/url"
)

func validateReferer(r *http.Request) error {
	referer, err := url.Parse(r.Header.Get("Referer"))

	if err != nil || referer.String() == "" {
		return ErrNoReferer
	}

	if !sameOrigin(referer, r.URL) {
		return ErrBadReferer
	}

	return nil
}
