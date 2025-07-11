package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetApiKey(t *testing.T) {
	tests := []struct {
		name    string
		header  http.Header
		wantKey string
		wantErr error
	}{
		{
			name:    "no header",
			header:  http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "malformed header - missing prefix",
			header:  headerWith("Authorization", "Bearer abc123"),
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "malformed header - missing key",
			header:  headerWith("Authorization", "ApiKey"),
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "valid header",
			header:  headerWith("Authorization", "ApiKey my_real_key"),
			wantKey: "my_real_key",
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.header)
			if gotKey != tt.wantKey {
				t.Errorf("expected key '%s', got '%s'", tt.wantKey, gotKey)
			}
			if (err != nil && tt.wantErr == nil) ||
				(err == nil && tt.wantErr != nil) ||
				(err != nil && tt.wantErr != nil && err.Error() != tt.wantErr.Error()) {
				t.Errorf("expected error '%v', got '%v'", tt.wantErr, err)
			}
		})
	}
}

// helper to create headers
func headerWith(key, value string) http.Header {
	h := http.Header{}
	h.Set(key, value)
	return h
}
