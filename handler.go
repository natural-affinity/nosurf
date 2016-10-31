// Package nosurf implements an HTTP handler that
// mitigates Cross-Site Request Forgery Attacks.
package nosurf

import (
	"net/http"
	"net/url"
)

func defaultFailureHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "", http.StatusBadRequest)
}

// Extracts the "sent" token from the request
// and returns an unmasked version of it
func extractToken(r *http.Request, headerName string, formFieldName string) []byte {
	var sentToken string

	// Prefer the header over form value
	sentToken = r.Header.Get(headerName)

	// Then POST values
	if len(sentToken) == 0 {
		sentToken = r.PostFormValue(formFieldName)
	}

	// If all else fails, try a multipart value.
	// PostFormValue() will already have called ParseMultipartForm()
	if len(sentToken) == 0 && r.MultipartForm != nil {
		vals := r.MultipartForm.Value[formFieldName]
		if len(vals) != 0 {
			sentToken = vals[0]
		}
	}

	return b64decode(sentToken)
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
	if len(realToken) != tokenLength {
		m.RegenerateToken(w, r)
	} else {
		ctxSetToken(r, realToken)
	}

	if sContains(m.Options.SafeMethods, r.Method) {
		// short-circuit with a success for safe methods
		m.handleSuccess(w, r)
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
			m.handleFailure(w, r)
			return
		}

		// if the referer doesn't share origin with the request URL,
		// we have another error for that
		if !sameOrigin(referer, r.URL) {
			ctxSetReason(r, ErrBadReferer)
			m.handleFailure(w, r)
			return
		}
	}

	// Finally, we check the token itself.
	sentToken := extractToken(r, m.Options.HeaderName, m.Options.FormFieldName)

	if !verifyToken(realToken, sentToken) {
		ctxSetReason(r, ErrBadToken)
		m.handleFailure(w, r)
		return
	}

	// Everything else passed, handle the success.
	m.handleSuccess(w, r)
}

// handleSuccess simply calls the successHandler.
// Everything else, like setting a token in the context
// is taken care of by h.ServeHTTP()
func (m *Middleware) handleSuccess(w http.ResponseWriter, r *http.Request) {
	m.Options.successHandler.ServeHTTP(w, r)
}

// Same applies here: h.ServeHTTP() sets the failure reason, the token,
// and only then calls handleFailure()
func (m *Middleware) handleFailure(w http.ResponseWriter, r *http.Request) {
	m.Options.failureHandler.ServeHTTP(w, r)
}

// Generates a new token, sets it on the given request and returns it
func (m *Middleware) RegenerateToken(w http.ResponseWriter, r *http.Request) string {
	token := generateToken()
	m.setTokenCookie(w, r, token)

	return Token(r)
}

func (m *Middleware) setTokenCookie(w http.ResponseWriter, r *http.Request, token []byte) {
	// ctxSetToken() does the masking for us
	ctxSetToken(r, token)

	cookie := m.Options.baseCookie
	cookie.Value = b64encode(token)

	http.SetCookie(w, cookie)

}

// Sets the handler to call in case the CSRF check
// fails. By default it's defaultFailureHandler.
func (m *Middleware) SetFailureHandler(handler http.Handler) {
	m.Options.failureHandler = handler
}

// Sets the base cookie to use when building a CSRF token cookie
// This way you can specify the Domain, Path, HttpOnly, Secure, etc.
func (m *Middleware) SetBaseCookie(cookie *http.Cookie) {
	m.Options.baseCookie = cookie
}
