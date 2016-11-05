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

// Handler for middleware
func (m *Middleware) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = addNosurfContext(r)
		defer ctxClear(r)
		w.Header().Add("Vary", "Cookie")

		if err := m.Validate(w, r); err != nil {
			m.Options.failureHandler.ServeHTTP(w, r)
			return
		}

		h.ServeHTTP(w, r)
	})
}

// Validate CSRF Token
func (m *Middleware) Validate(w http.ResponseWriter, r *http.Request) error {
	realToken := FromCookie(r, m.Options.baseCookie.Name)

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
		return nil
	} // short-circuit with a success for safe methods

	// if the request is secure, we enforce origin check
	// for referer to prevent MITM of http->https requests
	if r.URL.Scheme == "https" {
		referer, err := url.Parse(r.Header.Get("Referer"))

		// if we can't parse the referer or it's empty,
		// we assume it's not specified
		if err != nil || referer.String() == "" {
			ctxSetReason(r, ErrNoReferer)
			return ErrNoReferer
		}

		// if the referer doesn't share origin with the request URL,
		// we have another error for that
		if !sameOrigin(referer, r.URL) {
			ctxSetReason(r, ErrBadReferer)
			return ErrBadReferer
		}
	}

	// Finally, we check the token itself.
	sentToken := extractToken(r, m.Options.HeaderName, m.Options.FormFieldName)

	if !verifyToken(realToken, sentToken, m.Options.TokenLength) {
		ctxSetReason(r, ErrBadToken)
		return ErrBadToken
	}

	return nil
}

// RegenerateToken creates a new base token on cookie
func (m *Middleware) RegenerateToken(w http.ResponseWriter, r *http.Request) string {
	token := generateToken(m.Options.TokenLength)
	ctxSetToken(r, token, m.Options.TokenLength)

	// Copy baseCookie (de-reference: shallow copy)
	cookie := *m.Options.baseCookie
	cookie.Value = b64encode(token)
	http.SetCookie(w, &cookie)

	return Token(r)
}

func addNosurfContext(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), nosurfKey, &csrfContext{}))
}
