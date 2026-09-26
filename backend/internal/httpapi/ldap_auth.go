package httpapi

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/chmajster/OpenSSO/backend/internal/security"
	"github.com/jackc/pgx/v5"
)

type primaryAuthResult struct {
	UserID   string
	Username string
	Valid    bool
	Local    bool
}

func (s *Server) authenticatePrimary(ctx context.Context, login, password string) (primaryAuthResult, error) {
	var uid, username, hash string
	var active bool
	var locked *time.Time
	err := s.db.QueryRow(ctx, "SELECT u.id,u.username,u.active,u.locked_until,p.password_hash FROM users u JOIN password_credentials p ON p.user_id=u.id WHERE lower(u.username)=lower($1) OR lower(u.email)=lower($1)", strings.TrimSpace(login)).Scan(&uid, &username, &active, &locked, &hash)
	if err == nil && active && (locked == nil || locked.Before(time.Now())) && security.VerifyPassword(hash, password) {
		return primaryAuthResult{UserID: uid, Username: username, Valid: true, Local: true}, nil
	}
	// A local account with a password is authoritative. Do not silently fall
	// through to LDAP for the same identifier after a bad local password.
	if err == nil {
		return primaryAuthResult{UserID: uid, Username: username, Local: true}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return primaryAuthResult{}, err
	}
	return s.authenticateLDAP(ctx, login, password)
}

func (s *Server) authenticateLDAP(ctx context.Context, login, password string) (primaryAuthResult, error) {
	if password == "" {
		return primaryAuthResult{}, nil
	}
	rows, err := s.db.Query(ctx, `SELECT id FROM ldap_providers WHERE enabled=true ORDER BY name`)
	if err != nil {
		return primaryAuthResult{}, err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil { return primaryAuthResult{}, err }
		ids = append(ids,id)
	}
	for _, id := range ids {
		p, secret, e := s.loadLDAPProvider(ctx, id)
		if e != nil { continue }
		service, e := s.ldapServiceConnection(ctx, p, secret)
		if e != nil { continue }
		identity, e := findLDAPUser(service, p, login)
		service.Close()
		if e != nil { continue }
		userConn, e := dialLDAP(ctx, p)
		if e != nil { continue }
		e = userConn.Bind(identity.DN, password)
		userConn.Close()
		if e != nil { continue }
		uid, username, e := s.upsertLDAPIdentity(ctx, p.ID, identity)
		if e != nil { return primaryAuthResult{}, e }
		return primaryAuthResult{UserID:uid,Username:username,Valid:true,Local:false},nil
	}
	return primaryAuthResult{},nil
}

func (s *Server) upsertLDAPIdentity(ctx context.Context, providerID string, identity ldapIdentity)(string,string,error){
	tx,err:=s.db.Begin(ctx);if err!=nil{return "","",err};defer tx.Rollback(ctx)
	var uid,username string
	err=tx.QueryRow(ctx,`SELECT u.id,u.username FROM ldap_identity_links l JOIN users u ON u.id=l.user_id WHERE l.provider_id=$1 AND l.external_id=$2`,providerID,identity.ExternalID).Scan(&uid,&username)
	if errors.Is(err,pgx.ErrNoRows){
		// Link an existing passwordless/federated account only by exact unique
		// username/email. Never take over a local password-backed account.
		err=tx.QueryRow(ctx,`SELECT u.id,u.username FROM users u LEFT JOIN password_credentials p ON p.user_id=u.id WHERE p.user_id IS NULL AND (lower(u.username)=lower($1) OR lower(u.email)=lower($2)) LIMIT 1`,identity.Username,identity.Email).Scan(&uid,&username)
		if errors.Is(err,pgx.ErrNoRows){
			err=tx.QueryRow(ctx,`INSERT INTO users(username,email,display_name,active,must_change_password) VALUES($1,$2,$3,true,false) RETURNING id,username`,identity.Username,identity.Email,identity.DisplayName).Scan(&uid,&username)
		}
	}
	if err!=nil{return "","",err}
	if _,err=tx.Exec(ctx,`INSERT INTO ldap_identity_links(provider_id,external_id,user_id,distinguished_name,last_synced_at) VALUES($1,$2,$3,$4,now()) ON CONFLICT(provider_id,external_id) DO UPDATE SET distinguished_name=EXCLUDED.distinguished_name,last_synced_at=now()`,providerID,identity.ExternalID,uid,identity.DN);err!=nil{return "","",err}
	if _,err=tx.Exec(ctx,`UPDATE users SET username=$1,email=$2,display_name=$3,active=true,updated_at=now() WHERE id=$4`,identity.Username,identity.Email,identity.DisplayName,uid);err!=nil{return "","",err}
	if err=tx.Commit(ctx);err!=nil{return "","",err};return uid,username,nil
}
