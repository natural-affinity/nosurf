// Package nosurf implements an HTTP handler that
// mitigates Cross-Site Request Forgery Attacks.
package nosurf

import "net/http"

func defaultFailureHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "", http.StatusBadRequest)
}

// Handler for middleware
func (m *Middleware) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = ctxCreate(r)
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
	sentToken := m.Options.TokenExtractor(r, m.Options.TokenField)

	// Always: Update Masked Token in Context
	// Regenerate: New Visitor, Tampered, or Migration
	if len(realToken) != m.Options.TokenLength {
		m.RegenerateToken(w, r)
	} else {
		ctxSetToken(r, realToken, m.Options.TokenLength)
	}

	if m.Options.WriteResponseHeader {
		w.Header().Set(m.Options.TokenField, Token(r))
	} // ensure token is set on response header (if requested)

	if sContains(m.Options.SafeMethods, r.Method) {
		return nil
	} // short-circuit with a success for safe methods

	if err := validateOrigin(r); err != nil {
		return ctxSetReason(r, err)
	} // ensure referrer is valid for HTTPS

	if !verifyToken(realToken, sentToken, m.Options.TokenLength) {
		return ctxSetReason(r, ErrBadToken)
	} // ensure token is valid

	return nil
}

// RegenerateToken creates a new base token on cookie, sets context (returns masked)
func (m *Middleware) RegenerateToken(w http.ResponseWriter, r *http.Request) string {
	token := generateToken(m.Options.TokenLength)
	ctxSetToken(r, token, m.Options.TokenLength)

	// Copy baseCookie (de-reference: shallow copy)
	cookie := *m.Options.baseCookie
	cookie.Value = b64encode(token)
	http.SetCookie(w, &cookie)

	return Token(r)
}
