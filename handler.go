// Package nosurf implements an HTTP handler that
// mitigates Cross-Site Request Forgery Attacks.
package nosurf

import (
	"context"
	"net/http"
	"net/url"
)

func defaultFailureHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "", http.StatusBadRequest)
}

func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r = addNosurfContext(r)
	defer ctxClear(r)
	w.Header().Add("Vary", "Cookie")

	var realToken []byte

	tokenCookie, err := r.Cookie(m.Options.baseCookie.Name)
	if err == nil {
		realToken = b64decode(tokenCookie.Value)
	}

	// If the length of the real token isn't what it should be,
	// it has either been tampered with,
	// or we're migrating onto a new algorithm for generating tokens,
	// or it hasn't ever been set so far.
	// In any case of those, we should regenerate it.
	//
	// As a consequence, CSRF check will fail when comparing the tokens later on,
	// so we don't have to fail it just yet.
	if len(realToken) != m.Options.TokenLength {
		m.RegenerateToken(w, r)
	} else {
		ctxSetToken(r, realToken, m.Options.TokenLength)
	}

	if sContains(m.Options.SafeMethods, r.Method) {
		// short-circuit with a success for safe methods
		m.Options.successHandler.ServeHTTP(w, r)
		return
	}

	// if the request is secure, we enforce origin check
	// for referer to prevent MITM of http->https requests
	if r.URL.Scheme == "https" {
		referer, err := url.Parse(r.Header.Get("Referer"))

		// if we can't parse the referer or it's empty,
		// we assume it's not specified
		if err != nil || referer.String() == "" {
			ctxSetReason(r, ErrNoReferer)
			m.Options.failureHandler.ServeHTTP(w, r)
			return
		}

		// if the referer doesn't share origin with the request URL,
		// we have another error for that
		if !sameOrigin(referer, r.URL) {
			ctxSetReason(r, ErrBadReferer)
			m.Options.failureHandler.ServeHTTP(w, r)
			return
		}
	}

	// Finally, we check the token itself.
	sentToken := extractToken(r, m.Options.HeaderName, m.Options.FormFieldName)

	if !verifyToken(realToken, sentToken, m.Options.TokenLength) {
		ctxSetReason(r, ErrBadToken)
		m.Options.failureHandler.ServeHTTP(w, r)
		return
	}

	// Everything else passed, handle the success.
	m.Options.successHandler.ServeHTTP(w, r)
}

// Generates a new token, sets it on the given request and returns it
func (m *Middleware) RegenerateToken(w http.ResponseWriter, r *http.Request) string {
	token := generateToken(m.Options.TokenLength)
	m.setTokenCookie(w, r, token)

	return Token(r)
}

func (m *Middleware) setTokenCookie(w http.ResponseWriter, r *http.Request, token []byte) {
	// ctxSetToken() does the masking for us
	ctxSetToken(r, token, m.Options.TokenLength)

	// Copy baseCookie (de-reference: shallow copy)
	cookie := *m.Options.baseCookie
	cookie.Value = b64encode(token)

	http.SetCookie(w, &cookie)
}

func addNosurfContext(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), nosurfKey, &csrfContext{}))
}
