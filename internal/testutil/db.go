package testutil

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestDB holds a connection pool for integration tests
type TestDB struct {
	Pool *pgxpool.Pool
}

// GetTestDBConfig returns database connection config for tests
func GetTestDBConfig() string {
	host := os.Getenv("TEST_DB_HOST")
	if host == "" {
		host = "localhost"
	}
	port := os.Getenv("TEST_DB_PORT")
	if port == "" {
		port = "5433"
	}
	user := os.Getenv("TEST_DB_USER")
	if user == "" {
		user = "ztnms"
	}
	password := os.Getenv("TEST_DB_PASSWORD")
	if password == "" {
		password = "ztnms_test"
	}
	dbname := os.Getenv("TEST_DB_NAME")
	if dbname == "" {
		dbname = "ztnms_test"
	}
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		user, password, host, port, dbname)
}

// NewTestDB creates a new test database connection
func NewTestDB(t *testing.T) *TestDB {
	t.Helper()

	connString := GetTestDBConfig()
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		t.Skipf("Skipping integration test: cannot connect to test database: %v", err)
		return nil
	}

	// Verify connection
	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		t.Skipf("Skipping integration test: cannot ping test database: %v", err)
		return nil
	}

	return &TestDB{Pool: pool}
}

// Close closes the database connection
func (db *TestDB) Close() {
	if db.Pool != nil {
		db.Pool.Close()
	}
}

// CleanupTable truncates a table for test isolation
func (db *TestDB) CleanupTable(t *testing.T, tableName string) {
	t.Helper()
	_, err := db.Pool.Exec(context.Background(), fmt.Sprintf("TRUNCATE TABLE %s CASCADE", tableName))
	if err != nil {
		t.Logf("Warning: could not truncate table %s: %v", tableName, err)
	}
}

// IsAvailable checks if the test database is available
func IsAvailable() bool {
	connString := GetTestDBConfig()
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		return false
	}
	defer pool.Close()
	return pool.Ping(context.Background()) == nil
}
