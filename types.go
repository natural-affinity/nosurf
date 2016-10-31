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

// Middleware for CSRF Protection
type Middleware struct {
	Options Options
}

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
	SafeMethods    []string
	successHandler http.Handler
	failureHandler http.Handler
	baseCookie     *http.Cookie
}

// Constructs a new CSRFHandler that calls
// the specified handler if the CSRF check succeeds.
func New(options ...Options) *Middleware {
	var opts Options
	if len(options) == 0 {
		opts = Options{}
	} else {
		opts = options[0]
	}

	if len(opts.SafeMethods) == 0 {
		opts.SafeMethods = []string{"GET", "HEAD", "OPTIONS", "TRACE"}
	}

	if opts.failureHandler == nil {
		opts.failureHandler = http.HandlerFunc(defaultFailureHandler)
	}

	if opts.baseCookie == nil {
		opts.baseCookie = &http.Cookie{}
		opts.baseCookie.MaxAge = MaxAge
	}

	return &Middleware{Options: opts}
}
