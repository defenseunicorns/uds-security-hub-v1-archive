package sql

import (
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
