package nosurf

import "net/http"

// FromCookie (extract from cookie)
func FromCookie(r *http.Request, name string) []byte {
	cookie, err := r.Cookie(name)
	if err != nil {
		return nil
	}

	return b64decode(cookie.Value)
}

// FromHeader (extract from header)
func FromHeader(r *http.Request, name string) []byte {
	token := r.Header.Get(name)
	return b64decode(token)
}

// FromForm (extract from form)
func FromForm(r *http.Request, name string) []byte {
	token := r.PostFormValue(name)

	if len(token) == 0 && r.MultipartForm != nil {
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

	return sentToken
}
