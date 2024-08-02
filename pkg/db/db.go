package db

import (
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"golang.org/x/xerrors"

	"github.com/hardenCN/trivy-java-db/pkg/types"
)

const (
	dbFileName    = "trivy-java.db"
	SchemaVersion = 1
)

type DB struct {
	Client *sql.DB
	DBDir  string
}

func path(cacheDir string) string {
	return filepath.Join(cacheDir, dbFileName)
}

func Reset(cacheDir string) error {
	return os.RemoveAll(path(cacheDir))
}

func New(cacheDir string) (DB, error) {
	dbPath := path(cacheDir)
	dbDir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dbDir, 0700); err != nil {
		return DB{}, xerrors.Errorf("failed to mkdir: %w", err)
	}

	// open db
	var err error
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return DB{}, xerrors.Errorf("can't open db: %w", err)
	}

	if _, err = db.Exec("PRAGMA foreign_keys=true"); err != nil {
		return DB{}, xerrors.Errorf("failed to enable 'foreign_keys': %w", err)
	}

	return DB{
		Client: db,
		DBDir:  dbDir,
	}, nil
}

func (db *DB) Init() error {
	if _, err := db.Client.Exec("CREATE TABLE artifacts(id INTEGER PRIMARY KEY, group_id TEXT, artifact_id TEXT)"); err != nil {
		return xerrors.Errorf("unable to create 'artifacts' table: %w", err)
	}
	if _, err := db.Client.Exec("CREATE TABLE indices(artifact_id INTEGER, version TEXT, sha1 BLOB, archive_type TEXT, foreign key (artifact_id) references artifacts(id))"); err != nil {
		return xerrors.Errorf("unable to create 'indices' table: %w", err)
	}

	if _, err := db.Client.Exec("CREATE UNIQUE INDEX artifacts_idx ON artifacts(artifact_id, group_id)"); err != nil {
		return xerrors.Errorf("unable to create 'artifacts_idx' index: %w", err)
	}
	if _, err := db.Client.Exec("CREATE INDEX indices_artifact_idx ON indices(artifact_id)"); err != nil {
		return xerrors.Errorf("unable to create 'indices_artifact_idx' index: %w", err)
	}
	if _, err := db.Client.Exec("CREATE UNIQUE INDEX indices_sha1_idx ON indices(sha1)"); err != nil {
		return xerrors.Errorf("unable to create 'indices_sha1_idx' index: %w", err)
	}
	return nil
}

func (db *DB) Dir() string {
	return db.DBDir
}

func (db *DB) VacuumDB() error {
	if _, err := db.Client.Exec("VACUUM"); err != nil {
		return xerrors.Errorf("vacuum database error: %w", err)
	}
	return nil
}

func (db *DB) Close() error {
	return db.Client.Close()
}

//////////////////////////////////////
// functions to interaction with DB //
//////////////////////////////////////

func (db *DB) InsertIndexes(indexes []types.Index) error {
	if len(indexes) == 0 {
		return nil
	}
	tx, err := db.Client.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err = db.insertArtifacts(tx, indexes); err != nil {
		return xerrors.Errorf("insert error: %w", err)
	}

	for _, index := range indexes {
		_, err = tx.Exec(`
			INSERT INTO indices(artifact_id, version, sha1, archive_type)
			VALUES (
			        (SELECT id FROM artifacts 
			            WHERE group_id=? AND artifact_id=?), 
			        ?, ?, ?
			) ON CONFLICT(sha1) DO NOTHING`,
			index.GroupID, index.ArtifactID, index.Version, index.SHA1, index.ArchiveType)
		if err != nil {
			return xerrors.Errorf("unable to insert to 'indices' table: %w", err)
		}
	}

	return tx.Commit()
}

func (db *DB) insertArtifacts(tx *sql.Tx, indexes []types.Index) error {
	query := `INSERT OR IGNORE INTO artifacts(group_id, artifact_id) VALUES `
	query += strings.Repeat("(?, ?), ", len(indexes))
	query = strings.TrimSuffix(query, ", ")

	var values []any
	for _, index := range indexes {
		values = append(values, index.GroupID, index.ArtifactID)
	}
	if _, err := tx.Exec(query, values...); err != nil {
		return xerrors.Errorf("unable to insert to 'artifacts' table: %w", err)
	}
	return nil
}

func (db *DB) SelectIndexBySha1(sha1 string) (types.Index, error) {
	var exeSql string
	switch driverName(db.Client) {
	case "*stdlib.Driver":
		exeSql = `
		SELECT a.group_id, a.artifact_id, i.version, i.sha1, i.archive_type 
		FROM indices i
		JOIN artifacts a ON a.id = i.artifact_id
        WHERE i.sha1 = $1`
	case "*godror.drv":
		exeSql = `
		SELECT a.group_id, a.artifact_id, i.version, i.sha1, i.archive_type 
		FROM indices i
		JOIN artifacts a ON a.id = i.artifact_id
        WHERE i.sha1 = :1`
	default:
		exeSql = `
		SELECT a.group_id, a.artifact_id, i.version, i.sha1, i.archive_type 
		FROM indices i
		JOIN artifacts a ON a.id = i.artifact_id
        WHERE i.sha1 = ?`
	}
	var index types.Index
	sha1b, err := hex.DecodeString(sha1)
	if err != nil {
		return index, xerrors.Errorf("sha1 decode error: %w", err)
	}
	row := db.Client.QueryRow(exeSql, sha1b)
	err = row.Scan(&index.GroupID, &index.ArtifactID, &index.Version, &index.SHA1, &index.ArchiveType)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return index, xerrors.Errorf("select index error: %w", err)
	}
	return index, nil
}

func (db *DB) SelectIndexByArtifactIDAndGroupID(artifactID, groupID string) (types.Index, error) {
	var exeSql string
	switch driverName(db.Client) {
	case "*stdlib.Driver":
		exeSql = `
		SELECT a.group_id, a.artifact_id, i.version, i.sha1, i.archive_type
		FROM indices i 
		JOIN artifacts a ON a.id = i.artifact_id
        WHERE a.group_id = $1 AND a.artifact_id = $2`
	case "*godror.drv":
		exeSql = `
		SELECT a.group_id, a.artifact_id, i.version, i.sha1, i.archive_type
		FROM indices i 
		JOIN artifacts a ON a.id = i.artifact_id
        WHERE a.group_id = :1 AND a.artifact_id = :2`
	default:
		exeSql = `
		SELECT a.group_id, a.artifact_id, i.version, i.sha1, i.archive_type
		FROM indices i 
		JOIN artifacts a ON a.id = i.artifact_id
        WHERE a.group_id = ? AND a.artifact_id = ?`
	}
	var index types.Index
	row := db.Client.QueryRow(exeSql, groupID, artifactID)
	err := row.Scan(&index.GroupID, &index.ArtifactID, &index.Version, &index.SHA1, &index.ArchiveType)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return index, xerrors.Errorf("select index error: %w", err)
	}
	return index, nil
}

// SelectIndexesByArtifactIDAndFileType returns all indexes for `artifactID` + `fileType` if `version` exists for them
func (db *DB) SelectIndexesByArtifactIDAndFileType(artifactID, version string, fileType types.ArchiveType) ([]types.Index, error) {
	var exeSql string
	switch driverName(db.Client) {
	case "*stdlib.Driver":
		exeSql = `
		SELECT f_id.group_id, f_id.artifact_id, i.version, i.sha1, i.archive_type
		FROM indices i
		JOIN (SELECT a.id, a.group_id, a.artifact_id
      	      FROM indices i
        	  JOIN artifacts a on a.id = i.artifact_id
      	      WHERE a.artifact_id = $1 AND i.version = $2 AND i.archive_type = $3) f_id ON f_id.id = i.artifact_id`
	case "*godror.drv":
		exeSql = `
		SELECT f_id.group_id, f_id.artifact_id, i.version, i.sha1, i.archive_type
		FROM indices i
		JOIN (SELECT a.id, a.group_id, a.artifact_id
      	      FROM indices i
        	  JOIN artifacts a on a.id = i.artifact_id
      	      WHERE a.artifact_id = :1 AND i.version = :2 AND i.archive_type = :3) f_id ON f_id.id = i.artifact_id`
	default:
		exeSql = `
		SELECT f_id.group_id, f_id.artifact_id, i.version, i.sha1, i.archive_type
		FROM indices i
		JOIN (SELECT a.id, a.group_id, a.artifact_id
      	      FROM indices i
        	  JOIN artifacts a on a.id = i.artifact_id
      	      WHERE a.artifact_id = ? AND i.version = ? AND i.archive_type = ?) f_id ON f_id.id = i.artifact_id`
	}
	var indexes []types.Index
	rows, err := db.Client.Query(exeSql, artifactID, version, fileType)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, xerrors.Errorf("select indexes error: %w", err)
	}
	for rows.Next() {
		var index types.Index
		if err = rows.Scan(&index.GroupID, &index.ArtifactID, &index.Version, &index.SHA1, &index.ArchiveType); err != nil {
			return nil, xerrors.Errorf("scan row error: %w", err)
		}
		indexes = append(indexes, index)
	}
	return indexes, nil
}

func driverName(sqldb *sql.DB) string {
	driver := sqldb.Driver()
	a := reflect.TypeOf(driver)
	return a.String()
}
