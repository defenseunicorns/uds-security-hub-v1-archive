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
		dbType                 string
		dbPath                 string
		instanceConnectionName string
		user                   string
		password               string
		dbname                 string
		expectedType           string
	}{
		{
			name:                   "SQLiteConnector",
			dbType:                 "sqlite",
			dbPath:                 "test.db",
			instanceConnectionName: "",
			user:                   "",
			password:               "",
			dbname:                 "",
			expectedType:           "*sql.SQLiteConnector",
		},
		{
			name:                   "CloudSQLConnector",
			dbType:                 "cloudsql",
			dbPath:                 "",
			instanceConnectionName: "instance-connection-name",
			user:                   "user",
			password:               "password",
			dbname:                 "dbname",
			expectedType:           "*sql.CloudSQLConnector",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			connector := CreateDBConnector(tt.dbType, tt.dbPath, tt.instanceConnectionName, tt.user, tt.password, tt.dbname)
			if gotType := fmt.Sprintf("%T", connector); gotType != tt.expectedType {
				t.Errorf("CreateDBConnector() = %v, want %v", gotType, tt.expectedType)
			}
		})
	}
}
