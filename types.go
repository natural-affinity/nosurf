package nosurf

import (
	"errors"
	"net/http"
)

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

// Options is a struct for specifying configuration options for the middleware.
type Options struct {
	SafeMethods    []string
	TokenLength    int
	HeaderName     string
	FormFieldName  string
	successHandler http.Handler
	failureHandler http.Handler
	baseCookie     *http.Cookie
}

// New Constructs a configurable CSRF Middleware that calls desired handler
func New(options ...Options) *Middleware {
	var opts Options
	if len(options) == 0 {
		opts = Options{}
	} else {
		opts = options[0]
	}

	if len(opts.SafeMethods) == 0 {
		opts.SafeMethods = []string{"GET", "HEAD", "OPTIONS", "TRACE"}
	} // default safe methods

	if opts.TokenLength == 0 {
		opts.TokenLength = 32
	} // default token length (32 bytes)

	if opts.HeaderName == "" {
		opts.HeaderName = "X-CSRF-Token"
	} // default header name

	if opts.FormFieldName == "" {
		opts.FormFieldName = "csrf_token"
	} // default form field name

	if opts.failureHandler == nil {
		opts.failureHandler = http.HandlerFunc(defaultFailureHandler)
	} // default failure handler

	if opts.baseCookie == nil {
		opts.baseCookie = &http.Cookie{}
		opts.baseCookie.Name = "csrf_token"
		opts.baseCookie.MaxAge = 365 * 24 * 60 * 60
	} // default cookie (duration)

	return &Middleware{Options: opts}
}
