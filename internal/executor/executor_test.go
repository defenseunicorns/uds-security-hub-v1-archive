package executor

import (
	"context"
	"testing"
)

// TestRealCommandExecutor_ExecuteCommand tests the ExecuteCommand method of the RealCommandExecutor.
func TestRealCommandExecutor_ExecuteCommand(t *testing.T) {
	type fields struct {
		ctx context.Context
	}
	type args struct {
		name string
		args []string
		env  []string
	}
	tests := []struct {
		name       string
		wantStdout string
		wantStderr string
		fields     fields
		args       args
		wantErr    bool
	}{
		{
			name: "echo command without error",
			fields: fields{
				ctx: context.Background(),
			},
			args: args{
				name: "echo",
				args: []string{"hello world"},
				env:  []string{},
			},
			wantStdout: "hello world\n",
			wantStderr: "",
			wantErr:    false,
		},
		{
			name: "echo command with env var",
			fields: fields{
				ctx: context.Background(),
			},
			args: args{
				name: "bash",
				args: []string{"-c", "echo $TEST_VAR"},
				env:  []string{"TEST_VAR=hello"},
			},
			wantStdout: "hello\n",
			wantStderr: "",
			wantErr:    false,
		},
		{
			name: "non-existent command",
			fields: fields{
				ctx: context.Background(),
			},
			args: args{
				name: "nonexistentcmd",
				args: []string{},
				env:  []string{},
			},
			wantStdout: "",
			wantStderr: "",
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewCommandExecutor(context.TODO())
			gotStdout, gotStderr, err := r.ExecuteCommand(tt.args.name, tt.args.args, tt.args.env)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExecuteCommand() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotStdout != tt.wantStdout {
				t.Errorf("ExecuteCommand() gotStdout = %v, want %v", gotStdout, tt.wantStdout)
			}
			if gotStderr != tt.wantStderr {
				t.Errorf("ExecuteCommand() gotStderr = %v, want %v", gotStderr, tt.wantStderr)
			}
		})
	}
}
