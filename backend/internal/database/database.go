package database

import (
	"context"
	"embed"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrations embed.FS

func Open(ctx context.Context, dsn string)(*pgxpool.Pool,error){
	cfg,e:=pgxpool.ParseConfig(dsn);if e!=nil{return nil,fmt.Errorf("parse database URL: %w",e)}
	cfg.MaxConns=20;cfg.MinConns=2;cfg.MaxConnLifetime=time.Hour
	p,e:=pgxpool.NewWithConfig(ctx,cfg);if e!=nil{return nil,e};if e=p.Ping(ctx);e!=nil{p.Close();return nil,e};return p,nil
}

func Migrate(ctx context.Context,p *pgxpool.Pool)error{
	if _,e:=p.Exec(ctx,`CREATE TABLE IF NOT EXISTS schema_migrations(version text PRIMARY KEY,applied_at timestamptz NOT NULL DEFAULT now())`);e!=nil{return e}
	es,e:=migrations.ReadDir("migrations");if e!=nil{return e}; names:=[]string{}
	for _,x:=range es{if !x.IsDir()&&strings.HasSuffix(x.Name(),".sql"){names=append(names,x.Name())}};sort.Strings(names)
	for _,n:=range names{var done bool;if e=p.QueryRow(ctx,`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)`,n).Scan(&done);e!=nil{return e};if done{continue};sql,e:=migrations.ReadFile("migrations/"+n);if e!=nil{return e};tx,e:=p.Begin(ctx);if e!=nil{return e};if _,e=tx.Exec(ctx,string(sql));e!=nil{tx.Rollback(ctx);return fmt.Errorf("migration %s: %w",n,e)};if _,e=tx.Exec(ctx,`INSERT INTO schema_migrations(version) VALUES($1)`,n);e!=nil{tx.Rollback(ctx);return e};if e=tx.Commit(ctx);e!=nil{return e}}
	return nil
}
