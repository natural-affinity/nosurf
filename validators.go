package nosurf

import (
	"net/http"
	"net/url"
)

// enforce origin/referrer check for https to prevent MITM of http->https requests
func validateOrigin(r *http.Request) error {
	if r.URL.Scheme == "https" {
		origin, e1 := url.Parse(r.Header.Get("Origin"))
		referer, e2 := url.Parse(r.Header.Get("Referer"))

		if e1 != nil || origin.String() == "" {
			if e2 != nil || referer.String() == "" {
				return ErrNoReferer
			} // ensure at least one header is present (origin or referer)

			if !sameOrigin(referer, r.URL) {
				return ErrBadReferer
			} // ensure Referer Header is valid
		}

		if !sameOrigin(origin, r.URL) {
			return ErrBadReferer
		} // ensure origin header is valid (if present)
	}

	return nil
}
