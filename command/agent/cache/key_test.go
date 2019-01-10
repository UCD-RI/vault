package cache

import (
	"net/http"
	"net/url"
	"reflect"
	"testing"
)

func TestParseRequestKey(t *testing.T) {
	type args struct {
		req *http.Request
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			"basic",
			args{
				req: &http.Request{
					URL: &url.URL{
						Path: "test",
					},
				},
			},
			[]byte{202, 161, 193, 171, 22, 115, 187, 213, 107, 94, 211, 203, 48, 158, 80, 4, 88, 107, 161, 44, 32, 239, 155, 25, 165, 68, 189, 6, 63, 216, 65, 27},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRequestKey(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRequestKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseRequestKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
