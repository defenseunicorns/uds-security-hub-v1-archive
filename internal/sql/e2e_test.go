package sql

import (
	"context"
	"fmt"
	"testing"
)

func TestE2E(t *testing.T) {

}

func TestCreateDBConnector(t *testing.T) {
	tests := []struct {
		name                   string
		host                   string
		port                   string
		user                   string
		password               string
		dbname                 string
		instanceConnectionName string
		expectedType           string
	}{
		{
			name:                   "StandardDBConnector",
			host:                   "localhost",
			port:                   "5432",
			user:                   "user",
			password:               "password",
			dbname:                 "dbname",
			instanceConnectionName: "",
			expectedType:           "*sql.StandardDBConnector",
		},
		{
			name:                   "CloudSQLConnector",
			host:                   "localhost",
			port:                   "5432",
			user:                   "user",
			password:               "password",
			dbname:                 "dbname",
			instanceConnectionName: "instance-connection-name",
			expectedType:           "*sql.CloudSQLConnector",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			connector := CreateDBConnector(tt.host, tt.port, tt.user, tt.password, tt.dbname, tt.instanceConnectionName)
			if gotType := fmt.Sprintf("%T", connector); gotType != tt.expectedType {
				t.Errorf("CreateDBConnector() = %v, want %v", gotType, tt.expectedType)
			}
		})
	}
}
func TestConnect(t *testing.T) {
	tests := []struct {
		name      string
		connector *StandardDBConnector
		expectErr bool
	}{
		{
			name: "Success",
			connector: &StandardDBConnector{
				host:     "localhost",
				port:     "5432",
				user:     "test_user",
				password: "test_password",
				dbname:   "test_db",
			},
			expectErr: false,
		},
		{
			name: "Failure",
			connector: &StandardDBConnector{
				host:     "invalid_host",
				port:     "5432",
				user:     "test_user",
				password: "test_password",
				dbname:   "test_db",
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := tt.connector.Connect(context.Background())
			if (err != nil) != tt.expectErr {
				t.Fatalf("Connect() error = %v, expectErr %v", err, tt.expectErr)
			}
			if tt.expectErr {
				return
			}

			sqlDB, err := db.DB()
			if err != nil {
				t.Fatalf("db.DB() error = %v", err)
			}
			defer sqlDB.Close()

			if err := sqlDB.Ping(); err != nil {
				t.Fatalf("sqlDB.Ping() error = %v", err)
			}
		})
	}
}
