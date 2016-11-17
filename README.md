# nosurf

[![Build Status](https://travis-ci.org/justinas/nosurf.svg?branch=master)](https://travis-ci.org/justinas/nosurf)

`nosurf` is an HTTP middleware package for Go
that helps prevent Cross-Site Request Forgery (CSRF) attacks.

## Prerequisites
* Go 1.7+

## Installing
```bash
go get github.com/natural-affinity/nosurf
```

## Features
* Customizable Options
* Supports Go 1.7+ context
* Supports any `http.Handler` framework
* Supports masked tokens to mitigate the BREACH attack.
* Uses Double-Submit Cookie Method by-default
* Supports JavaScript SPA via HTTP Header
* Origin and Referrer Check as per [OWASP Guidelines](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Checking_the_Referer_Header)

# Usage

### Options

The Options struct is used to configure the middleware.

```go
type Options struct {
  // Methods for which token validation will not be performed
  // Default: GET, HEAD, OPTIONS, TRACE
  SafeMethods         []string

  // Length of the base token
  // Default: 32 (bytes)
  TokenLength         int

  // Name of the form field or header to use for extraction
  // Default: X-CSRF (header)
  TokenField          string

  // Function that extracts token from request (FromHeader, FromForm, or Custom)
  // Default: FromHeader (i.e. X-CSRF TokenField)
  TokenExtractor      Extractor

  // Function to be called post-validation errors
  // Default: http.Error(w, "", http.StatusBadRequest)
  FailureHandler      http.Handler

  // Base Cookie properties to use for response
  // Default: Name (csrf_token), MaxAge: 1 Day, Secure, HttpOnly
  BaseCookie          *http.Cookie

  // Flag indicating if token should be written to Header Automatically
  // Default: False
  WriteResponseHeader bool
}
```

### Example 1: Single Page Applications (Recommended)
```go
package main

import (
  "net/http"
  "github.com/natural-affinity/nosurf"
)

func CSRFMiddleware() func(http.handler) http.Handler {
  options := nosurf.Options{
    WriteResponseHeader: true,
  } // ensure masked token automatically written to header

  // return middleware handler for chaining
  csrf := nosurf.New(options)
  return csrf.Handler
}

// final handler for example
func final(w http.ResponseWriter, r *http.Request) {
  log.Println("Executing finalHandler")
  w.Write([]byte("OK"))
}

func main() {
  finalHandler := http.HandlerFunc(final)
  protect := CSRFMiddleware()

  // run csrf middleware then handler on success
  http.Handle("/", protect(finalHandler))
  http.ListenAndServe(":3000", nil)
}

```

### Example 2: Traditional Apps
```go
package main

import (
  "net/http"
  "github.com/natural-affinity/nosurf"
)

func CSRFMiddleware() func(http.handler) http.Handler {
  options := nosurf.Options{
    TokenField: "csrf_token",
    TokenExtractor: FromForm,
  } // ensure form-based extraction is used

  // return middleware handler for chaining
  csrf := nosurf.New(options)
  return csrf.Handler
}

var templateString string = `
<!doctype html>
<html>
<body>
{{ if .name }}
<p>Your name: {{ .name }}</p>
{{ end }}
<form action="/" method="POST">
<input type="text" name="name">
<input type="hidden" name="csrf_token" value="{{ .token }}">
<input type="submit" value="Send">
</form>
</body>
</html>
`
var templ = template.Must(template.New("t1").Parse(templateString))

func myFunc(w http.ResponseWriter, r *http.Request) {
  context := make(map[string]string)
  context["token"] = nosurf.Token(r)
  if r.Method == "POST" {
    context["name"] = r.FormValue("name")
  }

  templ.Execute(w, context)
}

func main() {
  myHandler := http.HandlerFunc(myFunc)
  protect := CSRFMiddleware()

  fmt.Println("Listening on http://127.0.0.1:8000/")
  http.ListenAndServe(":8000", protect(myHandler))
}

```


# Special Thanks
Justin Stankevičius ([@justinas](https://github.com/justinas) for the original library).

# License
Released under the MIT License.
