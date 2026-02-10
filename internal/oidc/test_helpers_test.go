package oidc

import (
	"encoding/json"
)

type fakeContext struct {
	query      map[string]string
	form       map[string]string
	headers    map[string]string
	statusCode int
	jsonBody   any
	redirect   string
	bindBody   []byte
}

func (f *fakeContext) Query(key string) string {
	if f.query == nil {
		return ""
	}
	return f.query[key]
}

func (f *fakeContext) PostForm(key string) string {
	if f.form == nil {
		return ""
	}
	return f.form[key]
}

func (f *fakeContext) Header(key string) string {
	if f.headers == nil {
		return ""
	}
	return f.headers[key]
}

func (f *fakeContext) JSON(status int, value any) {
	f.statusCode = status
	f.jsonBody = value
}

func (f *fakeContext) Redirect(status int, location string) {
	f.statusCode = status
	f.redirect = location
}

func (f *fakeContext) Status(status int) {
	f.statusCode = status
}

func (f *fakeContext) BindJSON(value any) error {
	if len(f.bindBody) == 0 {
		return nil
	}
	return json.Unmarshal(f.bindBody, value)
}

func mustOAuthError(value any) OAuthError {
	errBody, _ := value.(OAuthError)
	return errBody
}
