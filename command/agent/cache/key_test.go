package cache

import (
	"net/http"
	"net/url"
	"reflect"
	"testing"
)

func TestComputeRequestKey(t *testing.T) {
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
			[]byte{46, 220, 126, 150, 92, 62, 27, 220, 227, 177, 213, 247, 154, 82, 146, 120, 66, 86, 156, 7, 52, 168, 101, 68, 210, 34, 117, 63, 17, 174, 72, 71},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ComputeCacheKey(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRequestKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, string(tt.want)) {
				t.Errorf("ParseRequestKey() = %v, want %v", got, string(tt.want))
			}
		})
	}
}
