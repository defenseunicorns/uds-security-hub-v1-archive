package docker

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateConfigText(t *testing.T) {
	type args struct {
		credentialsMap map[string]RegistryCredentials
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "single credential",
			args: args{
				credentialsMap: map[string]RegistryCredentials{
					"example.com": {
						Username: "user",
						Password: "pass",
					},
				},
			},
			want:    `{"auths":{"example.com":{"username":"user","password":"pass"}}}`,
			wantErr: false,
		},
		{
			name: "multiple credentials",
			args: args{
				credentialsMap: map[string]RegistryCredentials{
					"example.com": {
						Username: "user1",
						Password: "pass1",
					},
					"example.org": {
						Username: "user2",
						Password: "pass2",
					},
				},
			},
			want:    `{"auths":{"example.com":{"username":"user1","password":"pass1"},"example.org":{"username":"user2","password":"pass2"}}}`,
			wantErr: false,
		},
		{
			name: "empty credentials map",
			args: args{
				credentialsMap: map[string]RegistryCredentials{},
			},
			want:    `{"auths":{}}`,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateConfigText(tt.args.credentialsMap)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateConfigText() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GenerateConfigText() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWriteConfigToTempDir(t *testing.T) {
	type args struct {
		configText string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "valid config text",
			args: args{
				configText: `{"auths":{"example.com":{"username":"user","password":"pass"}}}`,
			},
			wantErr: false,
		},
		{
			name: "empty config text",
			args: args{
				configText: "",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := WriteConfigToTempDir(tt.args.configText)
			if (err != nil) != tt.wantErr {
				t.Errorf("WriteConfigToTempDir() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if _, err := os.Stat(got); os.IsNotExist(err) {
				t.Errorf("WriteConfigToTempDir() file does not exist: %v", got)
			}
			// Clean up
			defer os.RemoveAll(filepath.Dir(got))
		})
	}
}
