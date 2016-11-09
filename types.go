package nosurf

import (
	"errors"
	"net/http"
)

// reasons for CSRF check failures
var (
	ErrNoReferer  = errors.New("A secure request contained no Referer or its value was malformed")
	ErrBadReferer = errors.New("A secure request's Referer comes from a different Origin from the request's URL")
	ErrBadToken   = errors.New("The CSRF token in the cookie doesn't match the one received in a form/header.")
)

// Extractor type for getting field value from request
type Extractor func(r *http.Request, name string) []byte

// Middleware for CSRF Protection
type Middleware struct {
	Options Options
}

// Options is a struct for specifying configuration options for the middleware.
type Options struct {
	SafeMethods         []string
	TokenLength         int
	TokenField          string
	TokenExtractor      Extractor
	failureHandler      http.Handler
	baseCookie          *http.Cookie
	WriteResponseHeader bool
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

	if opts.TokenExtractor == nil {
		opts.TokenExtractor = FromHeader
	} // default extractor (from header)

	if opts.TokenField == "" {
		opts.TokenField = "X-CSRF-Token"
	} // default field (from header)

	if opts.failureHandler == nil {
		opts.failureHandler = http.HandlerFunc(defaultFailureHandler)
	} // default failure handler

	if opts.baseCookie == nil {
		opts.baseCookie = &http.Cookie{}
		opts.baseCookie.Name = "csrf_token"
		opts.baseCookie.MaxAge = 365 * 24 * 60 * 60
		opts.baseCookie.Secure = true
		opts.baseCookie.HttpOnly = true
	} // default cookie (duration)

	return &Middleware{Options: opts}
}
