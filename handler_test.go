package nosurf

import (
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/justinas/alice"
)

func TestDefaultFailureHandler(t *testing.T) {
	writer := httptest.NewRecorder()
	req := dummyGet()

	defaultFailureHandler(writer, req)

	if writer.Code != http.StatusBadRequest {
		t.Errorf("Wrong status code for defaultFailure Handler: "+
			"expected %d, got %d", http.StatusBadRequest, writer.Code)
	}
}

func TestSafeMethodsPass(t *testing.T) {
	handler := New()

	for _, method := range handler.Options.SafeMethods {
		req, err := http.NewRequest(method, "http://dummy.us", nil)

		if err != nil {
			t.Fatal(err)
		}

		writer := httptest.NewRecorder()
		chain := alice.New(handler.Handler).Then(http.HandlerFunc(succHand))
		chain.ServeHTTP(writer, req)

		expected := 200

		if writer.Code != expected {
			t.Errorf("A safe method didn't pass the CSRF check."+
				"Expected HTTP status %d, got %d", expected, writer.Code)
		}

		writer.Flush()
	}
}

// Tests that the token/reason context is accessible
// in the success/failure handlers
func TestContextIsAccessible(t *testing.T) {
	// case 1: success
	succHand := func(w http.ResponseWriter, r *http.Request) {
		token := Token(r)
		if token == "" {
			t.Errorf("Token is inaccessible in the success handler")
		}
	}

	hand := New()

	// we need a request that passes. Let's just use a safe method for that.
	req := dummyGet()
	writer := httptest.NewRecorder()

	chain := alice.New(hand.Handler).Then(http.HandlerFunc(succHand))
	chain.ServeHTTP(writer, req)
}

func TestEmptyOriginAndRefererFails(t *testing.T) {
	opts := Options{
		FailureHandler: correctReason(t, ErrNoReferer),
	}
	hand := New(opts)

	req, err := http.NewRequest("POST", "https://dummy.us/", strings.NewReader("a=b"))
	if err != nil {
		t.Fatal(err)
	}
	writer := httptest.NewRecorder()
	chain := alice.New(hand.Handler).Then(http.HandlerFunc(succHand))
	chain.ServeHTTP(writer, req)

	if writer.Code != http.StatusBadRequest {
		t.Errorf("A POST request with no Referer should have failed with the code %d, but it didn't.",
			writer.Code)
	}
}

func TestDifferentRefererFails(t *testing.T) {
	opts := Options{
		FailureHandler: correctReason(t, ErrBadReferer),
	}

	hand := New(opts)
	req, err := http.NewRequest("POST", "https://dummy.us/", strings.NewReader("a=b"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Referer", "http://attack-on-golang.com")
	writer := httptest.NewRecorder()

	chain := alice.New(hand.Handler).Then(http.HandlerFunc(succHand))
	chain.ServeHTTP(writer, req)

	if writer.Code != http.StatusBadRequest {
		t.Errorf("A POST request with a Referer from a different origin"+
			"should have failed with the code %d, but it didn't.", writer.Code)
	}
}

func TestDifferentOriginFails(t *testing.T) {
	opts := Options{
		FailureHandler: correctReason(t, ErrBadReferer),
	}

	hand := New(opts)
	req, err := http.NewRequest("POST", "https://dummy.us/", strings.NewReader("a=b"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", "http://attack-on-golang.com")
	writer := httptest.NewRecorder()

	chain := alice.New(hand.Handler).Then(http.HandlerFunc(succHand))
	chain.ServeHTTP(writer, req)

	if writer.Code != http.StatusBadRequest {
		t.Errorf("A POST request with a Referer from a different origin"+
			"should have failed with the code %d, but it didn't.", writer.Code)
	}
}

func TestNoTokenFails(t *testing.T) {
	opts := Options{
		FailureHandler: correctReason(t, ErrBadToken),
	}
	hand := New(opts)

	vals := [][]string{
		{"name", "Jolene"},
	}

	req, err := http.NewRequest("POST", "http://dummy.us", formBodyR(vals))
	if err != nil {
		panic(err)
	}
	writer := httptest.NewRecorder()

	chain := alice.New(hand.Handler).Then(http.HandlerFunc(succHand))
	chain.ServeHTTP(writer, req)

	if writer.Code != http.StatusBadRequest {
		t.Errorf("The check should've failed with the code %d, but instead, it"+
			" returned code %d", http.StatusBadRequest, writer.Code)
	}

	expectedContentType := "text/plain; charset=utf-8"
	actualContentType := writer.Header().Get("Content-Type")
	if actualContentType != expectedContentType {
		t.Errorf("The check should've failed with content type %s, but instead, it"+
			" returned content type %s", expectedContentType, actualContentType)
	}
}

func TestWrongTokenFails(t *testing.T) {
	opts := Options{
		FailureHandler:      correctReason(t, ErrBadToken),
		TokenField:          "csrf_token",
		TokenExtractor:      FromForm,
		WriteResponseHeader: false,
	}
	hand := New(opts)

	vals := [][]string{
		{"name", "Jolene"},
		// this won't EVER be a valid value with the current scheme
		{hand.Options.TokenField, "$#%^&"},
	}

	req, err := http.NewRequest("POST", "http://dummy.us", formBodyR(vals))
	if err != nil {
		panic(err)
	}
	writer := httptest.NewRecorder()

	chain := alice.New(hand.Handler).Then(http.HandlerFunc(succHand))
	chain.ServeHTTP(writer, req)

	if writer.Code != http.StatusBadRequest {
		t.Errorf("The check should've failed with the code %d, but instead, it"+
			" returned code %d", http.StatusBadRequest, writer.Code)
	}

	expectedContentType := "text/plain; charset=utf-8"
	actualContentType := writer.Header().Get("Content-Type")
	if actualContentType != expectedContentType {
		t.Errorf("The check should've failed with content type %s, but instead, it"+
			" returned content type %s", expectedContentType, actualContentType)
	}
}

// For this and similar tests we start a test server
// Since it's much easier to get the cookie
// from a normal http.Response than from the recorder
func TestCorrectTokenPasses(t *testing.T) {
	opts := Options{
		FailureHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("Test failed. Reason: %v", Reason(r))
		}),
		TokenLength:         32,
		TokenField:          "csrf_token",
		TokenExtractor:      FromForm,
		WriteResponseHeader: false,
	}
	hand := New(opts)

	chain := alice.New(hand.Handler).Then(http.HandlerFunc(succHand))

	server := httptest.NewServer(chain)
	defer server.Close()

	// issue the first request to get the token
	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	cookie := getRespCookie(resp, hand.Options.BaseCookie.Name)
	if cookie == nil {
		t.Fatal("Cookie was not found in the response.")
	}

	finalToken := b64encode(maskToken(b64decode(cookie.Value), opts.TokenLength))

	vals := [][]string{
		{"name", "Jolene"},
		{hand.Options.TokenField, finalToken},
	}

	// Test multipart
	{
		prd, pwr := io.Pipe()
		wr := multipart.NewWriter(pwr)
		go func() {

			for _, v := range vals {
				wr.WriteField(v[0], v[1])
			}

			err := wr.Close()
			if err != nil {
				t.Fatal(err)
			}
			err = pwr.Close()
			if err != nil {
				t.Fatal(err)
			}
		}()

		// Prepare a multipart request
		req, err := http.NewRequest("POST", server.URL, prd)
		if err != nil {
			t.Fatal(err)
		}

		req.Header.Add("Content-Type", wr.FormDataContentType())
		req.AddCookie(cookie)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			t.Errorf("The request should have succeeded, but it didn't. Instead, the code was %d",
				resp.StatusCode)
		}
	}
}

func TestUseHeaderOverFormValue(t *testing.T) {
	// Let's do a nice trick to find out this:
	// We'll set the correct token in the header
	// And a wrong one in the form.
	// That way, if it succeeds,
	// it will mean that it prefered the header.

	opts := Options{
		TokenLength: 32,
		TokenField:  "X-CSRF",
	}
	hand := New(opts)
	chain := alice.New(hand.Handler).Then(http.HandlerFunc(succHand))

	server := httptest.NewServer(chain)
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	cookie := getRespCookie(resp, hand.Options.BaseCookie.Name)
	if cookie == nil {
		t.Fatal("Cookie was not found in the response.")
	}

	finalToken := b64encode(maskToken(b64decode(cookie.Value), opts.TokenLength))

	vals := [][]string{
		{"name", "Jolene"},
		{hand.Options.TokenField, "a very wrong value"},
	}

	req, err := http.NewRequest("POST", server.URL, formBodyR(vals))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(hand.Options.TokenField, finalToken)
	req.AddCookie(cookie)

	resp, err = http.DefaultClient.Do(req)

	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("The request should have succeeded, but it didn't. Instead, the code was %d",
			resp.StatusCode)
	}
}

func TestAddsVaryCookieHeader(t *testing.T) {
	hand := New()
	writer := httptest.NewRecorder()
	req := dummyGet()

	chain := alice.New(hand.Handler).Then(http.HandlerFunc(succHand))
	chain.ServeHTTP(writer, req)

	if !sContains(writer.Header()["Vary"], "Cookie") {
		t.Errorf("CSRFHandler didn't add a `Vary: Cookie` header.")
	}
}

func TestAddsTokenResponseHeader(t *testing.T) {
	opts := Options{
		TokenLength:         32,
		WriteResponseHeader: true,
	}
	handler := New(opts)
	chain := alice.New(handler.Handler).Then(http.HandlerFunc(succHand))

	server := httptest.NewServer(chain)
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	cookie := getRespCookie(resp, handler.Options.BaseCookie.Name)
	if cookie == nil {
		t.Fatal("Cookie was not found in the response.")
	}

	header := getRespHeader(resp, handler.Options.TokenField)
	if header == "" {
		t.Fatal("Response header field not found")
	}
}

// Confusing test name. Tests that nosurf's context is accessible
// when a request with golang's context is passed into Token().
func TestContextIsAccessibleWithGo17Context(t *testing.T) {
	succHand := func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), "dummykey", "dummyval"))
		token := Token(r)
		if token == "" {
			t.Errorf("Token is inaccessible in the success handler")
		}
	}

	hand := New()
	chain := alice.New(hand.Handler).Then(http.HandlerFunc(succHand))

	// we need a request that passes. Let's just use a safe method for that.
	req := dummyGet()
	writer := httptest.NewRecorder()

	chain.ServeHTTP(writer, req)
}
