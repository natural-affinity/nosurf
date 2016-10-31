package nosurf

import (
	"errors"
	"net/http"
)

const (
	// the name of CSRF cookie
	CookieName = "csrf_token"
	// the name of the form field
	FormFieldName = "csrf_token"
	// the name of CSRF header
	HeaderName = "X-CSRF-Token"
	// the HTTP status code for the default failure handler
	FailureCode = 400

	// Max-Age in seconds for the default base cookie. 365 days.
	MaxAge = 365 * 24 * 60 * 60
)

var safeMethods = []string{"GET", "HEAD", "OPTIONS", "TRACE"}

// reasons for CSRF check failures
var (
	ErrNoReferer  = errors.New("A secure request contained no Referer or its value was malformed")
	ErrBadReferer = errors.New("A secure request's Referer comes from a different Origin" +
		" from the request's URL")
	ErrBadToken = errors.New("The CSRF token in the cookie doesn't match the one" +
		" received in a form/header.")
)

type CSRFHandler struct {
	// Handlers that CSRFHandler wraps.
	successHandler http.Handler

	failureHandler http.Handler

	// The base cookie that CSRF cookies will be built upon.
	// This should be a better solution of customizing the options
	// than a bunch of methods SetCookieExpiration(), etc.
	baseCookie http.Cookie
}

// Options is a struct for specifying configuration options for the middleware.
type Options struct {
	successHandler http.Handler
}

// Constructs a new CSRFHandler that calls
// the specified handler if the CSRF check succeeds.
func New(options ...Options) *CSRFHandler {
	var opts Options
	if len(options) == 0 {
		opts = Options{}
	} else {
		opts = options[0]
	}

	baseCookie := http.Cookie{}
	baseCookie.MaxAge = MaxAge

	csrf := &CSRFHandler{successHandler: opts.successHandler,
		failureHandler: http.HandlerFunc(defaultFailureHandler),
		baseCookie:     baseCookie,
	}

	return csrf
}
