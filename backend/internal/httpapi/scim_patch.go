package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
)

const scimPatchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

type scimPatchRequest struct {
	Schemas []string `json:"schemas"`
	Operations []struct {
		Op string `json:"op"`
		Path string `json:"path,omitempty"`
		Value json.RawMessage `json:"value,omitempty"`
	} `json:"Operations"`
}

func decodeSCIMPatch(w http.ResponseWriter,r *http.Request)(scimPatchRequest,bool){
	var in scimPatchRequest;if decodeJSON(w,r,&in)!=nil{return in,false}
	if len(in.Schemas)!=1||in.Schemas[0]!=scimPatchSchema||len(in.Operations)==0||len(in.Operations)>100{scimError(w,400,"invalid SCIM PatchOp document");return in,false};return in,true
}

func (s *Server) scimUserPatch(w http.ResponseWriter,r *http.Request){
	if _,ok:=s.scimAuth(r,"users.write");!ok{scimError(w,401,"invalid or insufficient SCIM bearer token");return}
	in,ok:=decodeSCIMPatch(w,r);if !ok{return};id:=r.PathValue("id")
	tx,err:=s.db.Begin(r.Context());if err!=nil{scimError(w,500,"database error");return};defer tx.Rollback(r.Context())
	for _,op:=range in.Operations{
		verb:=strings.ToLower(op.Op);path:=strings.TrimSpace(op.Path);if verb!="replace"&&verb!="add"{scimError(w,400,"unsupported user PATCH operation");return}
		switch strings.ToLower(path){
		case "active":var v bool;if json.Unmarshal(op.Value,&v)!=nil{scimError(w,400,"active must be boolean");return};if _,err=tx.Exec(r.Context(),"UPDATE users SET active=$1,updated_at=now() WHERE id=$2",v,id);err!=nil{scimError(w,500,"database error");return}
		case "displayname":var v string;if json.Unmarshal(op.Value,&v)!=nil{scimError(w,400,"displayName must be string");return};if _,err=tx.Exec(r.Context(),"UPDATE users SET display_name=$1,updated_at=now() WHERE id=$2",strings.TrimSpace(v),id);err!=nil{scimError(w,500,"database error");return}
		case "externalid":var v string;if json.Unmarshal(op.Value,&v)!=nil{scimError(w,400,"externalId must be string");return};if _,err=tx.Exec(r.Context(),"INSERT INTO scim_user_links(user_id,external_id) VALUES($1,NULLIF($2,'')) ON CONFLICT(user_id) DO UPDATE SET external_id=EXCLUDED.external_id",id,strings.TrimSpace(v));err!=nil{scimError(w,409,"externalId already exists");return}
		default:scimError(w,400,"unsupported user PATCH path");return
		}
	}
	if err=tx.Commit(r.Context());err!=nil{scimError(w,500,"database error");return}
	req:=r.Clone(r.Context());req.Method=http.MethodGet;s.scimUserResource(w,req)
}

func (s *Server) scimGroupPatch(w http.ResponseWriter,r *http.Request){
	if _,ok:=s.scimAuth(r,"groups.write");!ok{scimError(w,401,"invalid or insufficient SCIM bearer token");return}
	in,ok:=decodeSCIMPatch(w,r);if !ok{return};id:=r.PathValue("id")
	tx,err:=s.db.Begin(r.Context());if err!=nil{scimError(w,500,"database error");return};defer tx.Rollback(r.Context())
	for _,op:=range in.Operations{
		verb:=strings.ToLower(op.Op);path:=strings.TrimSpace(op.Path)
		switch {
		case strings.EqualFold(path,"displayName")&&(verb=="replace"||verb=="add"):
			var v string;if json.Unmarshal(op.Value,&v)!=nil||strings.TrimSpace(v)==""{scimError(w,400,"displayName must be non-empty string");return};if _,err=tx.Exec(r.Context(),"UPDATE groups SET name=$1 WHERE id=$2",strings.TrimSpace(v),id);err!=nil{scimError(w,409,"group displayName already exists");return}
		case strings.EqualFold(path,"externalId")&&(verb=="replace"||verb=="add"):
			var v string;if json.Unmarshal(op.Value,&v)!=nil{scimError(w,400,"externalId must be string");return};if _,err=tx.Exec(r.Context(),"INSERT INTO scim_group_links(group_id,external_id) VALUES($1,NULLIF($2,'')) ON CONFLICT(group_id) DO UPDATE SET external_id=EXCLUDED.external_id",id,strings.TrimSpace(v));err!=nil{scimError(w,409,"externalId already exists");return}
		case strings.EqualFold(path,"members")&&(verb=="replace"):
			var members []struct{Value string `json:"value"`};if json.Unmarshal(op.Value,&members)!=nil{scimError(w,400,"members must be an array");return};if _,err=tx.Exec(r.Context(),"DELETE FROM group_memberships WHERE group_id=$1",id);err!=nil{scimError(w,500,"database error");return};for _,m:=range members{tag,e:=tx.Exec(r.Context(),"INSERT INTO group_memberships(group_id,user_id) SELECT $1,id FROM users WHERE id=$2 ON CONFLICT DO NOTHING",id,m.Value);if e!=nil||tag.RowsAffected()==0{scimError(w,400,"unknown member");return}}
		default:scimError(w,400,"unsupported group PATCH operation or path");return
		}
	}
	if err=tx.Commit(r.Context());err!=nil{scimError(w,500,"database error");return};out,err:=s.loadSCIMGroup(r,id);if err!=nil{scimError(w,404,"group not found");return};w.Header().Set("Content-Type","application/scim+json");writeJSON(w,200,out)
}
