package httpapi

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/chmajster/OpenSSO/backend/internal/security"
	"github.com/jackc/pgx/v5"
)

const scimUserSchema = "urn:ietf:params:scim:schemas:core:2.0:User"
const scimGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"

type scimUser struct {
	Schemas []string `json:"schemas"`
	ID string `json:"id,omitempty"`
	ExternalID string `json:"externalId,omitempty"`
	UserName string `json:"userName"`
	DisplayName string `json:"displayName,omitempty"`
	Active bool `json:"active"`
	Emails []struct { Value string `json:"value"`; Primary bool `json:"primary,omitempty"` } `json:"emails,omitempty"`
	Meta map[string]any `json:"meta,omitempty"`
}
type scimGroup struct {
	Schemas []string `json:"schemas"`
	ID string `json:"id,omitempty"`
	ExternalID string `json:"externalId,omitempty"`
	DisplayName string `json:"displayName"`
	Members []struct { Value string `json:"value"`; Display string `json:"display,omitempty"` } `json:"members,omitempty"`
	Meta map[string]any `json:"meta,omitempty"`
}
type scimPrincipal struct{ TokenID string; Scopes map[string]bool }

func (s *Server) scimAuth(r *http.Request, scope string) (scimPrincipal, bool) {
	h:=strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(h,"Bearer ") { return scimPrincipal{},false }
	raw:=strings.TrimSpace(strings.TrimPrefix(h,"Bearer "))
	if len(raw)<32 { return scimPrincipal{},false }
	hash:=security.SHA256String(raw)
	var id string; var scopes []string
	err:=s.db.QueryRow(r.Context(),`SELECT id,scopes FROM scim_tokens WHERE token_hash=$1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>now())`,hash).Scan(&id,&scopes)
	if err!=nil { return scimPrincipal{},false }
	m:=map[string]bool{}; for _,v:=range scopes {m[v]=true}
	if !m[scope] { return scimPrincipal{},false }
	_,_=s.db.Exec(r.Context(),`UPDATE scim_tokens SET last_used_at=now() WHERE id=$1`,id)
	return scimPrincipal{TokenID:id,Scopes:m},true
}
func scimError(w http.ResponseWriter,status int,detail string) {
	w.Header().Set("Content-Type","application/scim+json")
	writeJSON(w,status,map[string]any{"schemas":[]string{"urn:ietf:params:scim:api:messages:2.0:Error"},"status":strconv.Itoa(status),"detail":detail})
}
func (s *Server) scimConfig(w http.ResponseWriter,r *http.Request){
	if _,ok:=s.scimAuth(r,"users.read"); !ok { scimError(w,401,"invalid or insufficient SCIM bearer token"); return }
	w.Header().Set("Content-Type","application/scim+json")
	writeJSON(w,200,map[string]any{"schemas":[]string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},"patch":map[string]bool{"supported":true},"bulk":map[string]any{"supported":false,"maxOperations":0,"maxPayloadSize":0},"filter":map[string]any{"supported":true,"maxResults":200},"changePassword":map[string]bool{"supported":false},"sort":map[string]bool{"supported":false},"etag":map[string]bool{"supported":false},"authenticationSchemes":[]map[string]any{{"type":"oauthbearertoken","name":"Bearer Token","description":"Opaque scoped SCIM bearer token","primary":true}}})
}
func scimEmail(u scimUser) string { for _,e:=range u.Emails {if e.Primary && strings.Contains(e.Value,"@"){return strings.ToLower(strings.TrimSpace(e.Value))}}; for _,e:=range u.Emails {if strings.Contains(e.Value,"@"){return strings.ToLower(strings.TrimSpace(e.Value))}}; return "" }
func (s *Server) scimUsers(w http.ResponseWriter,r *http.Request){
	scope:="users.read"; if r.Method=="POST"{scope="users.write"}; p,ok:=s.scimAuth(r,scope); if !ok {scimError(w,401,"invalid or insufficient SCIM bearer token");return}; _=p
	if r.Method=="POST" {
		var in scimUser; if decodeJSON(w,r,&in)!=nil{return}; in.UserName=strings.ToLower(strings.TrimSpace(in.UserName)); email:=scimEmail(in)
		if len(in.UserName)<3 || email=="" {scimError(w,400,"userName and a valid email are required");return}
		tx,e:=s.db.Begin(r.Context()); if e!=nil{scimError(w,500,"database error");return}; defer tx.Rollback(r.Context())
		var id string; e=tx.QueryRow(r.Context(),`INSERT INTO users(username,email,display_name,active,must_change_password) VALUES($1,$2,$3,$4,false) RETURNING id`,in.UserName,email,strings.TrimSpace(in.DisplayName),in.Active).Scan(&id)
		if e!=nil{scimError(w,409,"userName or email already exists");return}
		if _,e=tx.Exec(r.Context(),`INSERT INTO scim_user_links(user_id,external_id) VALUES($1,NULLIF($2,''))`,id,strings.TrimSpace(in.ExternalID));e!=nil{scimError(w,409,"externalId already exists");return}
		if e=tx.Commit(r.Context());e!=nil{scimError(w,500,"database error");return}
		out:=in; out.ID=id; out.Schemas=[]string{scimUserSchema}; out.Meta=map[string]any{"resourceType":"User","location":s.cfg.PublicURL+"/scim/v2/Users/"+id}; w.Header().Set("Location",fmt.Sprint(out.Meta["location"])); w.Header().Set("Content-Type","application/scim+json"); writeJSON(w,201,out); return
	}
	start,count:=scimPage(r); filter:=strings.TrimSpace(r.URL.Query().Get("filter")); args:=[]any{}; where:=""
	if filter!="" { parts:=strings.SplitN(filter," eq ",2); if len(parts)!=2 {scimError(w,400,"only eq filters are supported");return}; v:=strings.Trim(parts[1]," \""); switch strings.TrimSpace(parts[0]) {case "userName":args=append(args,strings.ToLower(v));where=" WHERE u.username=$1";case "externalId":args=append(args,v);where=" WHERE l.external_id=$1";default:scimError(w,400,"unsupported filter attribute");return}}
	var total int; if e:=s.db.QueryRow(r.Context(),`SELECT count(*) FROM users u LEFT JOIN scim_user_links l ON l.user_id=u.id`+where,args...).Scan(&total);e!=nil{scimError(w,500,"database error");return}; args=append(args,count,start-1); rows,e:=s.db.Query(r.Context(),`SELECT u.id,u.username,u.email,u.display_name,u.active,COALESCE(l.external_id,'') FROM users u LEFT JOIN scim_user_links l ON l.user_id=u.id`+where+fmt.Sprintf(" ORDER BY u.username LIMIT $%d OFFSET $%d",len(args)-1,len(args)),args...); if e!=nil{scimError(w,500,"database error");return}; defer rows.Close()
	res:=[]scimUser{}; for rows.Next(){var x scimUser;var email string;if rows.Scan(&x.ID,&x.UserName,&email,&x.DisplayName,&x.Active,&x.ExternalID)!=nil{scimError(w,500,"database error");return};x.Schemas=[]string{scimUserSchema};x.Emails=[]struct{Value string `json:"value"`;Primary bool `json:"primary,omitempty"`}{{email,true}};x.Meta=map[string]any{"resourceType":"User","location":s.cfg.PublicURL+"/scim/v2/Users/"+x.ID};res=append(res,x)}
	w.Header().Set("Content-Type","application/scim+json");writeJSON(w,200,map[string]any{"schemas":[]string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},"totalResults":total,"startIndex":start,"itemsPerPage":len(res),"Resources":res})
}
func scimPage(r *http.Request)(int,int){start,_:=strconv.Atoi(r.URL.Query().Get("startIndex"));if start<1{start=1};count,_:=strconv.Atoi(r.URL.Query().Get("count"));if count<1{count=100};if count>200{count=200};return start,count}
func (s *Server) scimUserResource(w http.ResponseWriter,r *http.Request){
	scope:="users.read";if r.Method!="GET"{scope="users.write"};if _,ok:=s.scimAuth(r,scope);!ok{scimError(w,401,"invalid or insufficient SCIM bearer token");return};id:=r.PathValue("id")
	if r.Method=="DELETE"{tag,e:=s.db.Exec(r.Context(),`UPDATE users SET active=false,updated_at=now() WHERE id=$1`,id);if e!=nil||tag.RowsAffected()==0{scimError(w,404,"user not found");return};_,_=s.db.Exec(r.Context(),`UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`,id);w.WriteHeader(204);return}
	if r.Method=="GET"{var x scimUser;var email string;e:=s.db.QueryRow(r.Context(),`SELECT u.id,u.username,u.email,u.display_name,u.active,COALESCE(l.external_id,'') FROM users u LEFT JOIN scim_user_links l ON l.user_id=u.id WHERE u.id=$1`,id).Scan(&x.ID,&x.UserName,&email,&x.DisplayName,&x.Active,&x.ExternalID);if e!=nil{scimError(w,404,"user not found");return};x.Schemas=[]string{scimUserSchema};x.Emails=[]struct{Value string `json:"value"`;Primary bool `json:"primary,omitempty"`}{{email,true}};x.Meta=map[string]any{"resourceType":"User","location":s.cfg.PublicURL+"/scim/v2/Users/"+id};w.Header().Set("Content-Type","application/scim+json");writeJSON(w,200,x);return}
	if r.Method=="PUT"{var in scimUser;if decodeJSON(w,r,&in)!=nil{return};email:=scimEmail(in);if len(strings.TrimSpace(in.UserName))<3||email==""{scimError(w,400,"userName and email are required");return};tag,e:=s.db.Exec(r.Context(),`UPDATE users SET username=lower($1),email=lower($2),display_name=$3,active=$4,updated_at=now() WHERE id=$5`,in.UserName,email,in.DisplayName,in.Active,id);if e!=nil{scimError(w,409,"conflicting user attributes");return};if tag.RowsAffected()==0{scimError(w,404,"user not found");return};_,_=s.db.Exec(r.Context(),`INSERT INTO scim_user_links(user_id,external_id) VALUES($1,NULLIF($2,'')) ON CONFLICT(user_id) DO UPDATE SET external_id=EXCLUDED.external_id`,id,in.ExternalID);in.ID=id;in.Schemas=[]string{scimUserSchema};in.Meta=map[string]any{"resourceType":"User","location":s.cfg.PublicURL+"/scim/v2/Users/"+id};w.Header().Set("Content-Type","application/scim+json");writeJSON(w,200,in);return}
	scimError(w,405,"method not allowed")
}
func (s *Server) scimTokens(w http.ResponseWriter,r *http.Request){
	if r.Method=="GET"{rows,e:=s.db.Query(r.Context(),`SELECT id,name,scopes,created_at,last_used_at,expires_at,revoked_at FROM scim_tokens ORDER BY created_at DESC`);if e!=nil{problem(w,500,"database error");return};defer rows.Close();items:=[]map[string]any{};for rows.Next(){var id,name string;var scopes []string;var created time.Time;var last,exp,rev *time.Time;if rows.Scan(&id,&name,&scopes,&created,&last,&exp,&rev)!=nil{problem(w,500,"database error");return};items=append(items,map[string]any{"id":id,"name":name,"scopes":scopes,"created_at":created,"last_used_at":last,"expires_at":exp,"revoked_at":rev})};writeJSON(w,200,map[string]any{"items":items});return}
	var in struct{Name string `json:"name"`;Scopes []string `json:"scopes"`;ExpiresAt *time.Time `json:"expires_at"`};if decodeJSON(w,r,&in)!=nil{return};if strings.TrimSpace(in.Name)==""{problem(w,400,"name is required");return};allowed:=map[string]bool{"users.read":true,"users.write":true,"groups.read":true,"groups.write":true};if len(in.Scopes)==0{problem(w,400,"at least one scope is required");return};for _,v:=range in.Scopes{if !allowed[v]{problem(w,400,"invalid SCIM scope");return}}
	raw,e:=security.RandomToken(32);if e!=nil{problem(w,500,"entropy failure");return};hash:=security.SHA256String(raw);p:=r.Context().Value(principalKey).(principal);var id string;e=s.db.QueryRow(r.Context(),`INSERT INTO scim_tokens(name,token_hash,scopes,created_by,expires_at) VALUES($1,$2,$3,$4,$5) RETURNING id`,strings.TrimSpace(in.Name),hash,in.Scopes,p.UserID,in.ExpiresAt).Scan(&id);if e!=nil{problem(w,409,"SCIM token name already exists");return};writeJSON(w,201,map[string]any{"id":id,"name":strings.TrimSpace(in.Name),"token":raw,"scopes":in.Scopes,"expires_at":in.ExpiresAt})
}
func (s *Server) revokeSCIMToken(w http.ResponseWriter,r *http.Request){tag,e:=s.db.Exec(r.Context(),`UPDATE scim_tokens SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL`,r.PathValue("id"));if e!=nil{problem(w,500,"database error");return};if tag.RowsAffected()==0{problem(w,404,"active token not found");return};w.WriteHeader(204)}
var _ = subtle.ConstantTimeCompare
var _ = pgx.ErrNoRows
