package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name           string
		headers        http.Header
		expectedKey    string
		expectedErrMsg string
	}{
		{
			name:           "no authorization header",
			headers:        http.Header{},
			expectedKey:    "",
			expectedErrMsg: "no authorization header included",
		},
		{
			name:           "empty authorization header",
			headers:        http.Header{"Authorization": []string{""}},
			expectedKey:    "",
			expectedErrMsg: "no authorization header included",
		},
		{
			name:           "wrong prefix",
			headers:        http.Header{"Authorization": []string{"Bearer abc123"}},
			expectedKey:    "",
			expectedErrMsg: "malformed authorization header",
		},
		{
			name:           "missing key",
			headers:        http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey:    "",
			expectedErrMsg: "malformed authorization header",
		},
		{
			name:           "valid api key",
			headers:        http.Header{"Authorization": []string{"ApiKey abc123"}},
			expectedKey:    "abc123",
			expectedErrMsg: "",
		},
		{
			name:           "key with spaces",
			headers:        http.Header{"Authorization": []string{"ApiKey abc 123"}},
			expectedKey:    "abc",
			expectedErrMsg: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			// Check key
			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}

			// Check error
			if tt.expectedErrMsg == "" {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error %q, got nil", tt.expectedErrMsg)
				} else if err.Error() != tt.expectedErrMsg {
					t.Errorf("expected error %q, got %q", tt.expectedErrMsg, err.Error())
				}
			}
		})
	}
}

func TestGetAPIKeyWithErrVariable(t *testing.T) {
	headers := http.Header{}
	_, err := GetAPIKey(headers)

	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("expected error to be ErrNoAuthHeaderIncluded, got %v", err)
	}
}
