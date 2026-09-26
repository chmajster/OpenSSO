package httpapi

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/chmajster/OpenSSO/backend/internal/security"
	"github.com/go-ldap/ldap/v3"
)

type ldapProvider struct {
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	Enabled              bool   `json:"enabled"`
	Host                 string `json:"host"`
	Port                 int    `json:"port"`
	TLSMode              string `json:"tls_mode"`
	SkipTLSVerify        bool   `json:"skip_tls_verify"`
	BindDN               string `json:"bind_dn"`
	UserBaseDN           string `json:"user_base_dn"`
	UserFilter           string `json:"user_filter"`
	UserIDAttribute      string `json:"user_id_attribute"`
	UsernameAttribute    string `json:"username_attribute"`
	EmailAttribute       string `json:"email_attribute"`
	DisplayNameAttribute string `json:"display_name_attribute"`
	GroupBaseDN          string `json:"group_base_dn"`
	GroupFilter          string `json:"group_filter"`
	GroupNameAttribute   string `json:"group_name_attribute"`
}

type ldapProviderInput struct {
	ldapProvider
	BindPassword string `json:"bind_password"`
}

func validateLDAPProvider(in ldapProviderInput) error {
	in.Host = strings.TrimSpace(in.Host)
	if in.Name == "" || in.Host == "" || in.Port < 1 || in.Port > 65535 || in.UserBaseDN == "" {
		return errors.New("name, host, valid port and user_base_dn are required")
	}
	if in.TLSMode != "ldaps" && in.TLSMode != "starttls" {
		return errors.New("tls_mode must be ldaps or starttls")
	}
	if !strings.Contains(in.UserFilter, "{username}") {
		return errors.New("user_filter must contain {username}")
	}
	for _, v := range []string{in.UserIDAttribute, in.UsernameAttribute, in.EmailAttribute, in.DisplayNameAttribute} {
		if strings.TrimSpace(v) == "" {
			return errors.New("LDAP user attribute mappings are required")
		}
	}
	return nil
}

func (s *Server) listLDAPProviders(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(r.Context(), `SELECT id,name,enabled,host,port,tls_mode,skip_tls_verify,bind_dn,user_base_dn,user_filter,user_id_attribute,username_attribute,email_attribute,display_name_attribute,group_base_dn,group_filter,group_name_attribute FROM ldap_providers ORDER BY name`)
	if err != nil { problem(w,500,"database error"); return }
	defer rows.Close()
	items:=[]ldapProvider{}
	for rows.Next(){ var x ldapProvider; if rows.Scan(&x.ID,&x.Name,&x.Enabled,&x.Host,&x.Port,&x.TLSMode,&x.SkipTLSVerify,&x.BindDN,&x.UserBaseDN,&x.UserFilter,&x.UserIDAttribute,&x.UsernameAttribute,&x.EmailAttribute,&x.DisplayNameAttribute,&x.GroupBaseDN,&x.GroupFilter,&x.GroupNameAttribute)!=nil {problem(w,500,"database error");return};items=append(items,x)}
	writeJSON(w,200,map[string]any{"items":items})
}

func (s *Server) createLDAPProvider(w http.ResponseWriter,r *http.Request){
	var in ldapProviderInput
	if decodeJSON(w,r,&in)!=nil{return}
	if err:=validateLDAPProvider(in);err!=nil{problem(w,400,err.Error());return}
	var encrypted []byte
	var err error
	if in.BindPassword!="" { encrypted,err=security.EncryptSecret(s.cfg.MasterKey,[]byte(in.BindPassword));if err!=nil{problem(w,500,"secret encryption failed");return}}
	var id string
	err=s.db.QueryRow(r.Context(),`INSERT INTO ldap_providers(name,enabled,host,port,tls_mode,skip_tls_verify,bind_dn,encrypted_bind_password,user_base_dn,user_filter,user_id_attribute,username_attribute,email_attribute,display_name_attribute,group_base_dn,group_filter,group_name_attribute) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) RETURNING id`,strings.TrimSpace(in.Name),in.Enabled,strings.TrimSpace(in.Host),in.Port,in.TLSMode,in.SkipTLSVerify,strings.TrimSpace(in.BindDN),encrypted,strings.TrimSpace(in.UserBaseDN),in.UserFilter,in.UserIDAttribute,in.UsernameAttribute,in.EmailAttribute,in.DisplayNameAttribute,in.GroupBaseDN,in.GroupFilter,in.GroupNameAttribute).Scan(&id)
	if err!=nil{problem(w,409,"LDAP provider already exists or configuration is invalid");return}
	p:=r.Context().Value(principalKey).(principal);_=s.audit(r.Context(),&p.UserID,"LDAP_PROVIDER_CREATED","ldap_provider",id,"success",r)
	writeJSON(w,201,map[string]any{"id":id})
}

func (s *Server) updateLDAPProvider(w http.ResponseWriter,r *http.Request){
	var in ldapProviderInput;if decodeJSON(w,r,&in)!=nil{return};if err:=validateLDAPProvider(in);err!=nil{problem(w,400,err.Error());return}
	id:=r.PathValue("id")
	var encrypted []byte
	if in.BindPassword!="" {var err error;encrypted,err=security.EncryptSecret(s.cfg.MasterKey,[]byte(in.BindPassword));if err!=nil{problem(w,500,"secret encryption failed");return}}
	tag,err:=s.db.Exec(r.Context(),`UPDATE ldap_providers SET name=$1,enabled=$2,host=$3,port=$4,tls_mode=$5,skip_tls_verify=$6,bind_dn=$7,encrypted_bind_password=CASE WHEN $8::bytea IS NULL OR octet_length($8::bytea)=0 THEN encrypted_bind_password ELSE $8::bytea END,user_base_dn=$9,user_filter=$10,user_id_attribute=$11,username_attribute=$12,email_attribute=$13,display_name_attribute=$14,group_base_dn=$15,group_filter=$16,group_name_attribute=$17,updated_at=now() WHERE id=$18`,strings.TrimSpace(in.Name),in.Enabled,strings.TrimSpace(in.Host),in.Port,in.TLSMode,in.SkipTLSVerify,strings.TrimSpace(in.BindDN),encrypted,strings.TrimSpace(in.UserBaseDN),in.UserFilter,in.UserIDAttribute,in.UsernameAttribute,in.EmailAttribute,in.DisplayNameAttribute,in.GroupBaseDN,in.GroupFilter,in.GroupNameAttribute,id)
	if err!=nil{problem(w,409,"LDAP provider update failed");return};if tag.RowsAffected()==0{problem(w,404,"LDAP provider not found");return}
	p:=r.Context().Value(principalKey).(principal);_=s.audit(r.Context(),&p.UserID,"LDAP_PROVIDER_UPDATED","ldap_provider",id,"success",r);w.WriteHeader(204)
}

func (s *Server) deleteLDAPProvider(w http.ResponseWriter,r *http.Request){id:=r.PathValue("id");tag,err:=s.db.Exec(r.Context(),"DELETE FROM ldap_providers WHERE id=$1",id);if err!=nil{problem(w,500,"database error");return};if tag.RowsAffected()==0{problem(w,404,"LDAP provider not found");return};p:=r.Context().Value(principalKey).(principal);_=s.audit(r.Context(),&p.UserID,"LDAP_PROVIDER_DELETED","ldap_provider",id,"success",r);w.WriteHeader(204)}

func (s *Server) loadLDAPProvider(ctx context.Context,id string)(ldapProvider,[]byte,error){
	var x ldapProvider;var encrypted []byte
	err:=s.db.QueryRow(ctx,`SELECT id,name,enabled,host,port,tls_mode,skip_tls_verify,bind_dn,encrypted_bind_password,user_base_dn,user_filter,user_id_attribute,username_attribute,email_attribute,display_name_attribute,group_base_dn,group_filter,group_name_attribute FROM ldap_providers WHERE id=$1`,id).Scan(&x.ID,&x.Name,&x.Enabled,&x.Host,&x.Port,&x.TLSMode,&x.SkipTLSVerify,&x.BindDN,&encrypted,&x.UserBaseDN,&x.UserFilter,&x.UserIDAttribute,&x.UsernameAttribute,&x.EmailAttribute,&x.DisplayNameAttribute,&x.GroupBaseDN,&x.GroupFilter,&x.GroupNameAttribute)
	return x,encrypted,err
}

func dialLDAP(ctx context.Context,p ldapProvider)(*ldap.Conn,error){
	dialer:=&net.Dialer{Timeout:5*time.Second}
	addr:=fmt.Sprintf("%s:%d",p.Host,p.Port)
	tlsConfig:=&tls.Config{ServerName:p.Host,MinVersion:tls.VersionTLS12,InsecureSkipVerify:p.SkipTLSVerify} // #nosec G402 -- explicit administrator setting, surfaced in configuration.
	var conn net.Conn;var err error
	if p.TLSMode=="ldaps"{conn,err=tls.DialWithDialer(dialer,"tcp",addr,tlsConfig)}else{conn,err=dialer.DialContext(ctx,"tcp",addr)}
	if err!=nil{return nil,err}
	l:=ldap.NewConn(conn,p.TLSMode=="ldaps");l.Start()
	if p.TLSMode=="starttls"{if err=l.StartTLS(tlsConfig);err!=nil{l.Close();return nil,err}}
	l.SetTimeout(8*time.Second)
	return l,nil
}

func (s *Server) ldapServiceConnection(ctx context.Context,p ldapProvider,encrypted []byte)(*ldap.Conn,error){
	l,err:=dialLDAP(ctx,p);if err!=nil{return nil,err}
	if p.BindDN!="" {plain,e:=security.DecryptSecret(s.cfg.MasterKey,encrypted);if e!=nil{l.Close();return nil,e};defer func(){for i:=range plain{plain[i]=0}}();if e=l.Bind(p.BindDN,string(plain));e!=nil{l.Close();return nil,e}}
	return l,nil
}

func (s *Server) testLDAPProvider(w http.ResponseWriter,r *http.Request){p,secret,err:=s.loadLDAPProvider(r.Context(),r.PathValue("id"));if err!=nil{problem(w,404,"LDAP provider not found");return};l,err:=s.ldapServiceConnection(r.Context(),p,secret);if err!=nil{problem(w,502,"LDAP connection or bind failed");return};defer l.Close();req:=ldap.NewSearchRequest(p.UserBaseDN,ldap.ScopeBaseObject,ldap.NeverDerefAliases,1,5,false,"(objectClass=*)",[]string{"dn"},nil);if _,err=l.Search(req);err!=nil{problem(w,502,"LDAP base DN search failed");return};writeJSON(w,200,map[string]any{"status":"ok"})}

type ldapIdentity struct{ExternalID,DN,Username,Email,DisplayName string}

func findLDAPUser(l *ldap.Conn,p ldapProvider,login string)(ldapIdentity,error){
	filter:=strings.ReplaceAll(p.UserFilter,"{username}",ldap.EscapeFilter(strings.TrimSpace(login)))
	req:=ldap.NewSearchRequest(p.UserBaseDN,ldap.ScopeWholeSubtree,ldap.NeverDerefAliases,2,8,false,filter,[]string{p.UserIDAttribute,p.UsernameAttribute,p.EmailAttribute,p.DisplayNameAttribute},nil)
	res,err:=l.Search(req);if err!=nil{return ldapIdentity{},err};if len(res.Entries)!=1{return ldapIdentity{},errors.New("directory identity is missing or ambiguous")}
	e:=res.Entries[0];rawID:=e.GetRawAttributeValue(p.UserIDAttribute);external:=e.GetAttributeValue(p.UserIDAttribute);if len(rawID)>0{external=base64.RawURLEncoding.EncodeToString(rawID)}
	out:=ldapIdentity{ExternalID:external,DN:e.DN,Username:strings.ToLower(strings.TrimSpace(e.GetAttributeValue(p.UsernameAttribute))),Email:strings.ToLower(strings.TrimSpace(e.GetAttributeValue(p.EmailAttribute))),DisplayName:strings.TrimSpace(e.GetAttributeValue(p.DisplayNameAttribute))}
	if out.ExternalID==""||out.Username==""||!strings.Contains(out.Email,"@"){return ldapIdentity{},errors.New("directory identity is missing required mapped attributes")};return out,nil
}
