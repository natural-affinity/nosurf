package nosurf

import "net/http"

// FromHeader (extract from header)
func FromHeader(r *http.Request, name string) []byte {
	token := r.Header.Get(name)
	return b64decode(token)
}

// FromForm (extract from form)
func FromForm(r *http.Request, name string) []byte {
	token := r.PostFormValue(name)
	return b64decode(token)
}

// FromMultiForm (extract from multi-part form)
func FromMultiForm(r *http.Request, name string) []byte {
	var token string
	if r.MultipartForm != nil {
		values := r.MultipartForm.Value[name]
		if len(values) != 0 {
			token = values[0]
		}
	}

	return b64decode(token)
}

// Extracts the "sent" token from the request
// and returns an unmasked version of it
func extractToken(r *http.Request, headerName string, formFieldName string) []byte {
	var sentToken []byte

	// Prefer the header over form value
	sentToken = FromHeader(r, headerName)

	// Then POST values
	if len(sentToken) == 0 {
		sentToken = FromForm(r, formFieldName)
	}

	if len(sentToken) == 0 {
		sentToken = FromMultiForm(r, formFieldName)
	}

	return sentToken
}
