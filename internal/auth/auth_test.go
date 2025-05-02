package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey_noHeader(t *testing.T) {
	tests := map[string]struct {
		header        http.Header
		key           string
		error_message error
	}{
		"Good API Key": {
			header: http.Header{
				"Authorization": []string{"ApiKey 12345-API"},
			},
			key:           "12345-API",
			error_message: nil,
		},
		"No Auth header": {
			header:        http.Header{},
			key:           "",
			error_message: ErrNoAuthHeaderIncluded,
		},
		"Malformed Auth": {
			header: http.Header{
				"Authorization": []string{"1234356"},
			},
			key:           "",
			error_message: errors.New("malformed authorization header"),
		},
	}

	for test, tc := range tests {
		t.Run(test, func(t *testing.T) {
			api_key, err := GetAPIKey(tc.header)

			if api_key != tc.key {
				t.Errorf("Key does not match expected. Got %s, expected %s", api_key, tc.key)
			}

			if (tc.error_message == nil) != (err == nil) {
				t.Errorf("Error mismatch. Was expecting no error but got %v instead", err)
			}
		})
	}

}
