package sql

import (
	"context"
	"fmt"
	"net"

	"cloud.google.com/go/cloudsqlconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// DBConnector is an interface for database connections.
type DBConnector interface {
	Connect(ctx context.Context) (*gorm.DB, error)
}

// SQLiteConnector implements DBConnector for SQLite connections.
type SQLiteConnector struct {
	dbPath string
}

// Connect connects to the SQLite database.
func (c *SQLiteConnector) Connect(ctx context.Context) (*gorm.DB, error) {
	database, err := gorm.Open(sqlite.Open(c.dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SQLite database: %w", err)
	}
	return database, nil
}

// CloudSQLConnector implements DBConnector for Cloud SQL connections.
type CloudSQLConnector struct {
	instanceConnectionName string
	user                   string
	password               string
	dbname                 string
}

// Connect connects to the database using the Cloud SQL connection.
func (c *CloudSQLConnector) Connect(ctx context.Context) (*gorm.DB, error) {
	dialer, err := cloudsqlconn.NewDialer(ctx, cloudsqlconn.WithIAMAuthN())
	if err != nil {
		// Fallback to using password if IAMAuthN fails
		dialer, err = cloudsqlconn.NewDialer(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create dialer: %w", err)
		}
	}

	config, err := pgxpool.ParseConfig(fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable",
		c.user, c.password, c.dbname))
	if err != nil {
		return nil, fmt.Errorf("failed to parse configuration: %w", err)
	}

	config.ConnConfig.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dialer.Dial(ctx, c.instanceConnectionName)
		if err != nil {
			return nil, fmt.Errorf("failed to dial Cloud SQL instance: %w", err)
		}
		return conn, nil
	}

	dbpool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to the database: %w", err)
	}
	defer dbpool.Close()

	conn, err := dbpool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire connection: %w", err)
	}
	defer conn.Release()

	pgxConn := conn.Conn()
	gormDB, err := gorm.Open(postgres.New(postgres.Config{
		Conn: stdlib.OpenDB(*pgxConn.Config()),
	}), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Gorm with pgx connection: %w", err)
	}
	return gormDB, nil
}

// CreateDBConnector is a factory function that returns the appropriate DBConnector.
func CreateDBConnector(dbType, dbPath, instanceConnectionName, user, password, dbname string) DBConnector {
	if dbType == "sqlite" {
		return &SQLiteConnector{
			dbPath: dbPath,
		}
	}
	return &CloudSQLConnector{
		instanceConnectionName: instanceConnectionName,
		user:                   user,
		password:               password,
		dbname:                 dbname,
	}
}
