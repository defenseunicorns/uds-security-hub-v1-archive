package sql

import (
	"context"
	"fmt"
	"net"

	"cloud.google.com/go/cloudsqlconn"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/jackc/pgx/v4/stdlib"
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

// StandardDBConnector implements DBConnector for standard PostgreSQL connections.
type StandardDBConnector struct {
	host     string
	port     string
	user     string
	password string
	dbname   string
}

// Connect connects to the database using the standard PostgreSQL connection.
func (c *StandardDBConnector) Connect(ctx context.Context) (*gorm.DB, error) {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		c.host, c.port, c.user, c.password, c.dbname)
	database, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
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

	dbpool, err := pgxpool.ConnectConfig(ctx, config)
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

type DatabaseConfig struct {
	DBType                   string
	DBHost                   string
	DBPort                   string
	DBName                   string
	DBPath                   string
	DBUser                   string
	DBPassword               string
	DBInstanceConnectionName string
}

// CreateDBConnector is a factory function that returns the appropriate DBConnector.
func CreateDBConnector(config *DatabaseConfig) DBConnector {
	if config.DBType == "sqlite" {
		return &SQLiteConnector{
			dbPath: config.DBPath,
		}
	}
	if config.DBType == "local" {
		port := config.DBPort
		if port == "" {
			port = "5432"
		}
		host := config.DBHost
		if host == "" {
			host = "localhost"
		}
		return &StandardDBConnector{
			host:     host,
			port:     port,
			user:     config.DBUser,
			password: config.DBPassword,
			dbname:   config.DBName,
		}
	}
	return &CloudSQLConnector{
		instanceConnectionName: config.DBInstanceConnectionName,
		user:                   config.DBUser,
		password:               config.DBPassword,
		dbname:                 config.DBName,
	}
}
