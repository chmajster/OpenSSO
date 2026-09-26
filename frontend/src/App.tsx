import { FormEvent, useEffect, useMemo, useState } from "react";
import { api } from "./http";
import { MFAChallenge, MFASettings } from "./mfa";

type Item = Record<string, unknown>;
type View =
  | "my-apps" | "my-sessions" | "profile" | "mfa"
  | "dashboard" | "users" | "groups" | "roles" | "applications"
  | "sessions" | "security" | "audit" | "provisioning";

type Me = {
  UserID?: string;
  Username?: string;
  MustChangePassword?: boolean;
  user_id?: string;
  username?: string;
  must_change_password?: boolean;
  mfa_verified?: boolean;
  mfa_required?: boolean;
  mfa_enrollment_required?: boolean;
};

type Access = { roles:string[]; permissions:string[] };

async function continueAuthorization(){
  const params=new URLSearchParams(window.location.search);
  const samlRequestId=params.get("saml_request_id");
  if(samlRequestId){
    const result=await api("/api/v1/saml/continue",{method:"POST",body:JSON.stringify({request_id:samlRequestId})});
    window.location.assign(String(result.callback_url));
    return true;
  }
  const returnTo=params.get("return_to");
  if(returnTo && (returnTo==="/oauth2/authorize" || returnTo.startsWith("/oauth2/authorize?"))){
    window.location.assign(returnTo);
    return true;
  }
  return false;
}

const adminResourceEndpoints: Partial<Record<View,string>> = {
  users:"/api/v1/users",
  groups:"/api/v1/groups",
  roles:"/api/v1/roles",
  applications:"/api/v1/applications",
  sessions:"/api/v1/sessions",
};

function hasPermission(access:Access|null, permission:string){
  return Boolean(access?.permissions.includes(permission));
}

function defaultView(access:Access):View{
  return access.permissions.length>0?"dashboard":"my-apps";
}

export default function App(){
  const [initialized,setInitialized]=useState<boolean|null>(null);
  const [me,setMe]=useState<Me|null>(null);
  const [access,setAccess]=useState<Access|null>(null);
  const [error,setError]=useState("");
  const [view,setView]=useState<View>("my-apps");
  const [items,setItems]=useState<Item[]>([]);
  const [dashboard,setDashboard]=useState<Item>({});
  const [policy,setPolicy]=useState<Item>({});
  const [profile,setProfile]=useState<Item>({});
  const [loading,setLoading]=useState(false);
  const [reloadKey,setReloadKey]=useState(0);

  const refreshSession=async()=>{
    const status=await api("/api/v1/setup/status");
    setInitialized(Boolean(status.initialized));
    if(!status.initialized)return;
    try{
      const current:Me=await api("/api/v1/me");
      setMe(current);
      const forceMFA=new URLSearchParams(window.location.search).get("mfa")==="required";
      if(current.must_change_password || ((current.mfa_required || forceMFA) && !current.mfa_verified)){
        setAccess(null);
        return;
      }
      const currentAccess:Access=await api("/api/v1/me/access");
      setAccess(currentAccess);
      setView(v=>v==="my-apps"?defaultView(currentAccess):v);
    }catch{
      setMe(null);
      setAccess(null);
    }
  };

  useEffect(()=>{refreshSession().catch(e=>setError(e.message));},[]);

  useEffect(()=>{
    if(!me || Boolean(me.MustChangePassword ?? me.must_change_password))return;
    if(new URLSearchParams(window.location.search).get("saml_request_id")){
      void continueAuthorization().catch(e=>setError(e.message));
    }
  },[me]);

  useEffect(()=>{
    if(!me)return;
    setLoading(true);
    setError("");
    let request:Promise<any>;
    if(view==="dashboard") request=api("/api/v1/dashboard");
    else if(view==="security") request=api("/api/v1/security/policy");
    else if(view==="profile") request=api("/api/v1/me/profile");
    else if(view==="my-apps") request=api("/api/v1/me/applications");
    else if(view==="my-sessions") request=api("/api/v1/me/sessions");
    else {
      const endpoint=adminResourceEndpoints[view];
      request=endpoint?api(endpoint):Promise.resolve({items:[]});
    }
    request.then(data=>{
      if(view==="dashboard")setDashboard(data||{});
      else if(view==="security")setPolicy(data||{});
      else if(view==="profile")setProfile(data||{});
      else setItems(data?.items||[]);
    }).catch(e=>setError(e.message)).finally(()=>setLoading(false));
  },[me,view,reloadKey]);

  if(initialized===null)return <Centered><p>Checking OpenSSO status…</p>{error&&<ErrorBox text={error}/>}</Centered>;
  if(!initialized)return <Bootstrap onDone={refreshSession}/>;
  if(!me)return <Login onDone={refreshSession}/>;
  if(Boolean(me.MustChangePassword ?? me.must_change_password))return <ChangePassword onDone={refreshSession}/>;
  const forceMFA=new URLSearchParams(window.location.search).get("mfa")==="required";
  if((Boolean(me.mfa_required)||forceMFA) && !Boolean(me.mfa_verified))return <MFAChallenge onDone={async()=>{await refreshSession();continueAuthorization()}}/>;

  const logout=async()=>{await api("/api/v1/auth/logout",{method:"POST"});setMe(null);setAccess(null)};
  const reload=()=>setReloadKey(x=>x+1);
  const username=String(me.Username ?? me.username ?? "");
  const nav=navigation(access);

  return <div className="shell">
    <aside>
      <div className="brand">OpenSSO</div>
      <div className="identity">{username}</div>
      <nav>
        {nav.map(v=><button key={v} className={view===v?"active":""} onClick={()=>setView(v)}>{label(v)}</button>)}
      </nav>
      <div className="roleLine">{access?.roles.join(" · ")||"User"}</div>
      <button className="secondary logout" onClick={()=>void logout()}>Sign out</button>
    </aside>
    <main>
      <header><div><h1>{label(view)}</h1><p>{subtitle(view)}</p></div></header>
      {error&&<ErrorBox text={error}/>}
      {view==="dashboard"?<Dashboard data={dashboard} loading={loading}/>:
       view==="security"?<SecurityPolicy data={policy} loading={loading} onSaved={reload}/>:
       view==="profile"?<ProfileView data={profile} loading={loading} onSaved={reload}/>:
       view==="mfa"?<MFASettings/>:
       view==="audit"?<AuditView/>:
       view==="provisioning"?<ProvisioningView access={access} reload={reload}/>:
       view==="my-apps"?<MyApplications items={items} loading={loading}/>:
       view==="my-sessions"?<MySessions items={items} loading={loading} reload={reload}/>:
       <ResourceView view={view} items={items} loading={loading} reload={reload} access={access} canMFARead={hasPermission(access,"mfa.read")} canMFAWrite={hasPermission(access,"mfa.write")}/>}
    </main>
  </div>;
}

function navigation(access:Access|null):View[]{
  const result:View[]=["my-apps","mfa","my-sessions","profile"];
  if(hasPermission(access,"users.read"))result.push("dashboard","users");
  if(hasPermission(access,"groups.read"))result.push("groups");
  if(hasPermission(access,"users.read"))result.push("roles");
  if(hasPermission(access,"applications.read"))result.push("applications");
  if(hasPermission(access,"sessions.read"))result.push("sessions");
  if(hasPermission(access,"policies.read"))result.push("security");
  if(hasPermission(access,"audit.read"))result.push("audit");
  if(hasPermission(access,"scim.read")||hasPermission(access,"ldap.read"))result.push("provisioning");
  return [...new Set(result)];
}

function Bootstrap({onDone}:{onDone:()=>Promise<void>}){
  const [busy,setBusy]=useState(false),[error,setError]=useState("");
  const submit=async(e:FormEvent<HTMLFormElement>)=>{
    e.preventDefault();setBusy(true);setError("");const f=new FormData(e.currentTarget);
    try{
      await api("/api/v1/setup/bootstrap",{method:"POST",headers:{Authorization:`Bearer ${f.get("token")}`},body:JSON.stringify({
        username:f.get("username"),email:f.get("email"),display_name:f.get("display_name"),password:f.get("password")
      })});
      await onDone();
    }catch(x){setError((x as Error).message)}finally{setBusy(false)}
  };
  return <Centered><section className="card auth"><h1>Initialize OpenSSO</h1><p>Create the first Super Admin. The bootstrap token is accepted only before initialization.</p>{error&&<ErrorBox text={error}/>}<form onSubmit={submit}><Field name="token" label="Bootstrap token" type="password"/><Field name="username" label="Username"/><Field name="email" label="Email" type="email"/><Field name="display_name" label="Display name"/><Field name="password" label="Password (upper/lower/digit/symbol)" type="password" minLength={12}/><button disabled={busy}>{busy?"Creating…":"Create installation"}</button></form></section></Centered>
}

function Login({onDone}:{onDone:()=>Promise<void>}){
  const [busy,setBusy]=useState(false),[error,setError]=useState("");
  const submit=async(e:FormEvent<HTMLFormElement>)=>{
    e.preventDefault();setBusy(true);setError("");const f=new FormData(e.currentTarget);
    try{
      await api("/api/v1/auth/login",{method:"POST",body:JSON.stringify({username:f.get("username"),password:f.get("password")})});
      await onDone();
      await continueAuthorization();
    }catch(x){setError((x as Error).message)}finally{setBusy(false)}
  };
  return <Centered><section className="card auth"><h1>Sign in</h1><p>Use your OpenSSO local account.</p>{error&&<ErrorBox text={error}/>}<form onSubmit={submit}><Field name="username" label="Username or email"/><Field name="password" label="Password" type="password"/><button disabled={busy}>{busy?"Signing in…":"Sign in"}</button></form></section></Centered>
}

function ChangePassword({onDone}:{onDone:()=>Promise<void>}){
  const [busy,setBusy]=useState(false),[error,setError]=useState("");
  const submit=async(e:FormEvent<HTMLFormElement>)=>{
    e.preventDefault();setBusy(true);setError("");const f=new FormData(e.currentTarget);
    try{
      await api("/api/v1/me/password",{method:"POST",body:JSON.stringify({current_password:f.get("current_password"),new_password:f.get("new_password")})});
      await onDone();
      continueAuthorization();
    }catch(x){setError((x as Error).message)}finally{setBusy(false)}
  };
  return <Centered><section className="card auth"><h1>Password change required</h1><p>Your administrator requires a new password before normal access is granted.</p>{error&&<ErrorBox text={error}/>}<form onSubmit={submit}><Field name="current_password" label="Current password" type="password"/><Field name="new_password" label="New password" type="password" minLength={12}/><button disabled={busy}>{busy?"Changing…":"Change password"}</button></form></section></Centered>
}

function Dashboard({data,loading}:{data:Item;loading:boolean}){
  if(loading)return <section className="card"><p>Loading dashboard…</p></section>;
  const cards=[
    ["Users",data.users],["Active users",data.active_users],["Locked users",data.locked_users],
    ["Applications",data.applications],["Active sessions",data.active_sessions],
    ["Logins / 24h",data.logins_24h],["Failed / 24h",data.failed_logins_24h]
  ];
  return <div className="metrics">{cards.map(([name,value])=><section className="card metric" key={String(name)}><span>{String(name)}</span><strong>{String(value??0)}</strong></section>)}</div>;
}

function SecurityPolicy({data,loading,onSaved}:{data:Item;loading:boolean;onSaved:()=>void}){
  const [error,setError]=useState(""),[busy,setBusy]=useState(false);
  if(loading)return <section className="card"><p>Loading security policy…</p></section>;
  const submit=async(e:FormEvent<HTMLFormElement>)=>{
    e.preventDefault();setBusy(true);setError("");const f=new FormData(e.currentTarget);
    try{
      await api("/api/v1/security/policy",{method:"PUT",body:JSON.stringify({
        password_min_length:Number(f.get("password_min_length")),
        password_require_upper:f.get("password_require_upper")==="on",
        password_require_lower:f.get("password_require_lower")==="on",
        password_require_digit:f.get("password_require_digit")==="on",
        password_require_symbol:f.get("password_require_symbol")==="on",
        lockout_threshold:Number(f.get("lockout_threshold")),
        lockout_minutes:Number(f.get("lockout_minutes")),session_ttl_minutes:Number(f.get("session_ttl_minutes")),
        mfa_required:f.get("mfa_required")==="on"
      })});
      onSaved();
    }catch(x){setError((x as Error).message)}finally{setBusy(false)}
  };
  return <section className="card"><h2>Authentication policy</h2>{error&&<ErrorBox text={error}/>}<form onSubmit={submit} className="inlineForm">
    <NumberField name="password_min_length" label="Minimum password length" value={Number(data.password_min_length??12)} min={12} max={128}/>
    <CheckField name="password_require_upper" label="Require uppercase letter" checked={Boolean(data.password_require_upper)}/>
    <CheckField name="password_require_lower" label="Require lowercase letter" checked={Boolean(data.password_require_lower)}/>
    <CheckField name="password_require_digit" label="Require digit" checked={Boolean(data.password_require_digit)}/>
    <CheckField name="password_require_symbol" label="Require symbol" checked={Boolean(data.password_require_symbol)}/>
    <NumberField name="lockout_threshold" label="Failed attempts before lockout" value={Number(data.lockout_threshold??10)} min={3} max={100}/>
    <NumberField name="lockout_minutes" label="Lockout minutes" value={Number(data.lockout_minutes??15)} min={1} max={1440}/>
    <NumberField name="session_ttl_minutes" label="Session TTL minutes" value={Number(data.session_ttl_minutes??720)} min={5} max={10080}/>
    <CheckField name="mfa_required" label="Require MFA globally" checked={Boolean(data.mfa_required)}/>
    <button disabled={busy}>{busy?"Saving…":"Save policy"}</button>
  </form></section>
}

function ProfileView({data,loading,onSaved}:{data:Item;loading:boolean;onSaved:()=>void}){
  const [busy,setBusy]=useState(false),[error,setError]=useState("");
  if(loading)return <section className="card"><p>Loading profile…</p></section>;
  const submit=async(e:FormEvent<HTMLFormElement>)=>{
    e.preventDefault();setBusy(true);setError("");const f=new FormData(e.currentTarget);
    try{
      await api("/api/v1/me/profile",{method:"PATCH",body:JSON.stringify({email:f.get("email"),display_name:f.get("display_name")})});
      onSaved();
    }catch(x){setError((x as Error).message)}finally{setBusy(false)}
  };
  return <div className="grid">
    <section className="card"><h2>Profile</h2>{error&&<ErrorBox text={error}/>}<form onSubmit={submit} className="stack">
      <label><span>Username</span><input disabled value={String(data.username??"")}/></label>
      <Field name="email" label="Email" type="email" defaultValue={String(data.email??"")}/>
      <Field name="display_name" label="Display name" defaultValue={String(data.display_name??"")}/>
      <button disabled={busy}>{busy?"Saving…":"Save profile"}</button>
    </form></section>
    <ChangePasswordInline/>
  </div>;
}

function ChangePasswordInline(){
  const [busy,setBusy]=useState(false),[error,setError]=useState(""),[done,setDone]=useState("");
  const submit=async(e:FormEvent<HTMLFormElement>)=>{
    e.preventDefault();setBusy(true);setError("");setDone("");const f=new FormData(e.currentTarget);
    try{
      await api("/api/v1/me/password",{method:"POST",body:JSON.stringify({current_password:f.get("current_password"),new_password:f.get("new_password")})});
      e.currentTarget.reset();setDone("Password changed.");
    }catch(x){setError((x as Error).message)}finally{setBusy(false)}
  };
  return <section className="card"><h2>Change password</h2>{error&&<ErrorBox text={error}/>} {done&&<div className="success">{done}</div>}<form onSubmit={submit} className="stack">
    <Field name="current_password" label="Current password" type="password"/>
    <Field name="new_password" label="New password" type="password" minLength={12}/>
    <button disabled={busy}>{busy?"Changing…":"Change password"}</button>
  </form></section>
}

function MyApplications({items,loading}:{items:Item[];loading:boolean}){
  if(loading)return <section className="card"><p>Loading applications…</p></section>;
  if(items.length===0)return <section className="card"><h2>No assigned applications</h2><p>Your account or groups do not currently have application assignments.</p></section>;
  return <div className="appGrid">{items.map(app=><section className="card appTile" key={String(app.id)}>
    <h2>{String(app.name)}</h2><span className="protocolBadge">{String(app.protocol).toUpperCase()}</span><code>{String(app.identifier??app.client_id)}</code>
    {app.launch_url?<a className="buttonLink" href={String(app.launch_url)} rel="noreferrer">Launch application</a>:<span className="muted">No launch URL configured</span>}
  </section>)}</div>;
}

function MySessions({items,loading,reload}:{items:Item[];loading:boolean;reload:()=>void}){
  if(loading)return <section className="card"><p>Loading sessions…</p></section>;
  return <section className="card tableCard">{items.length===0?<p>No active sessions.</p>:<table><thead><tr>{["ip","user_agent","created_at","last_seen_at","expires_at","actions"].map(x=><th key={x}>{x}</th>)}</tr></thead><tbody>{items.map(x=><tr key={String(x.id)}>
    {["ip","user_agent","created_at","last_seen_at","expires_at"].map(c=><td key={c}>{render(x[c])}</td>)}
    <td><button className="danger" onClick={()=>window.confirm("Revoke this session?")&&void api(`/api/v1/me/sessions/${x.id}`,{method:"DELETE"}).then(reload)}>Revoke</button></td>
  </tr>)}</tbody></table>}</section>;
}

function AuditView(){
  const [items,setItems]=useState<Item[]>([]);
  const [loading,setLoading]=useState(false);
  const [error,setError]=useState("");
  const [filters,setFilters]=useState({user_id:"",application_id:"",event:"",ip:"",result:""});

  const load=async(next=filters)=>{
    setLoading(true);setError("");
    try{
      const q=new URLSearchParams();
      Object.entries(next).forEach(([k,v])=>{if(v.trim())q.set(k,v.trim())});
      const data=await api(`/api/v1/audit?${q.toString()}`);
      setItems(data.items||[]);
    }catch(e){setError((e as Error).message)}finally{setLoading(false)}
  };
  useEffect(()=>{void load()},[]);

  const submit=(e:FormEvent<HTMLFormElement>)=>{e.preventDefault();void load()};
  const clear=()=>{const empty={user_id:"",application_id:"",event:"",ip:"",result:""};setFilters(empty);void load(empty)};

  return <>
    <section className="card create"><h2>Audit filters</h2>{error&&<ErrorBox text={error}/>}<form className="inlineForm" onSubmit={submit}>
      <label><span>User ID</span><input value={filters.user_id} onChange={e=>setFilters({...filters,user_id:e.target.value})}/></label>
      <label><span>Application ID</span><input value={filters.application_id} onChange={e=>setFilters({...filters,application_id:e.target.value})}/></label>
      <label><span>Event</span><input value={filters.event} onChange={e=>setFilters({...filters,event:e.target.value})}/></label>
      <label><span>IP</span><input value={filters.ip} onChange={e=>setFilters({...filters,ip:e.target.value})}/></label>
      <label><span>Result</span><select value={filters.result} onChange={e=>setFilters({...filters,result:e.target.value})}><option value="">Any</option><option value="success">success</option><option value="failure">failure</option></select></label>
      <div className="actions"><button disabled={loading}>Apply</button><button type="button" className="secondary" onClick={clear}>Clear</button></div>
    </form></section>
    <section className="card tableCard">{loading?<p>Loading…</p>:items.length===0?<p>No audit events match the filters.</p>:<table><thead><tr>{columns("audit").map(x=><th key={x}>{x}</th>)}<th>request_id</th></tr></thead><tbody>{items.map(x=><tr key={String(x.id)}>{columns("audit").map(k=><td key={k}>{render(x[k])}</td>)}<td>{render(x.request_id)}</td></tr>)}</tbody></table>}</section>
  </>;
}

function ResourceView({view,items,loading,reload,access,canMFARead,canMFAWrite}:{view:View;items:Item[];loading:boolean;reload:()=>void;access:Access|null;canMFARead:boolean;canMFAWrite:boolean}){
  const [query,setQuery]=useState("");
  const [page,setPage]=useState(1);
  const pageSize=25;
  const filtered=useMemo(()=>{
    const q=query.trim().toLowerCase();
    if(!q)return items;
    return items.filter(item=>JSON.stringify(item).toLowerCase().includes(q));
  },[items,query]);
  const pageCount=Math.max(1,Math.ceil(filtered.length/pageSize));
  const pageItems=filtered.slice((page-1)*pageSize,page*pageSize);
  useEffect(()=>{if(page>pageCount)setPage(pageCount)},[page,pageCount]);

  const canWriteApplications=hasPermission(access,"applications.write");
  const canWriteSAML=hasPermission(access,"saml.write");
  return <>
    {view!=="applications"&&<CreateForm view={view} onCreated={reload}/>}
    {view==="applications"&&canWriteApplications&&<CreateForm view={view} onCreated={reload}/>}
    {view==="applications"&&canWriteSAML&&<SAMLCreateForm onCreated={reload}/>}
    {view==="applications"&&hasPermission(access,"saml.read")&&<SAMLCertificatePanel canRotate={hasPermission(access,"saml.rotate")}/>} 
    {view==="sessions"&&<section className="toolbar"><button className="danger" onClick={()=>window.confirm("Revoke every active OpenSSO browser session?")&&void api("/api/v1/sessions/revoke-all",{method:"POST"}).then(reload)}>Revoke all sessions</button></section>}
    <section className="card tableCard">
      <div className="tableTools"><input placeholder="Search…" value={query} onChange={e=>{setQuery(e.target.value);setPage(1)}}/><span>{filtered.length} records</span></div>
      {loading?<p>Loading…</p>:filtered.length===0?<p>No records.</p>:<>
        <table><thead><tr>{columns(view).map(c=><th key={c}>{c}</th>)}{["users","groups","applications","sessions"].includes(view)&&<th>actions</th>}</tr></thead><tbody>{pageItems.map((x,i)=><tr key={String(x.id||i)}>
          {columns(view).map(c=><td key={c}>{render(x[c])}</td>)}
          {view==="users"&&<td><UserActions user={x} reload={reload} canMFARead={canMFARead} canMFAWrite={canMFAWrite}/></td>}
          {view==="groups"&&<td><GroupActions group={x} reload={reload} canMFARead={canMFARead} canMFAWrite={canMFAWrite}/></td>}
          {view==="applications"&&<td><ApplicationActions app={x} reload={reload} canMFARead={canMFARead} canMFAWrite={canMFAWrite}/></td>}
          {view==="sessions"&&<td><SessionActions session={x} reload={reload}/></td>}
        </tr>)}</tbody></table>
        <div className="pager"><button className="secondary" disabled={page<=1} onClick={()=>setPage(p=>p-1)}>Previous</button><span>Page {page} / {pageCount}</span><button className="secondary" disabled={page>=pageCount} onClick={()=>setPage(p=>p+1)}>Next</button></div>
      </>}
    </section>
  </>;
}

function UserActions({user,reload,canMFARead,canMFAWrite}:{user:Item;reload:()=>void;canMFARead:boolean;canMFAWrite:boolean}){
  const [busy,setBusy]=useState(false);
  const [mfaInfo,setMFAInfo]=useState<any|null>(null);
  const id=String(user.id);
  const run=async(fn:()=>Promise<unknown>)=>{setBusy(true);try{await fn();reload()}catch(e){window.alert((e as Error).message)}finally{setBusy(false)}};
  const toggle=()=>run(()=>api(`/api/v1/users/${id}`,{method:"PATCH",body:JSON.stringify({email:user.email,display_name:user.display_name,active:!Boolean(user.active)})}));
  const reset=()=>{const password=window.prompt("Temporary password (minimum policy length):");if(!password)return;if(!window.confirm("Reset password and revoke all sessions for this user?"))return;void run(()=>api(`/api/v1/users/${id}/reset-password`,{method:"POST",body:JSON.stringify({password})}))};
  const loadMFA=async()=>{try{setMFAInfo(await api("/api/v1/users/"+id+"/mfa"))}catch(e){window.alert((e as Error).message)}};
  const resetMFA=async()=>{if(!window.confirm("Reset all MFA factors and revoke active sessions for this user?"))return;await run(()=>api("/api/v1/users/"+id+"/mfa/reset",{method:"POST"}));setMFAInfo(null)};
  return <div className="actionPanel"><div className="actions"><button disabled={busy} className="secondary" onClick={toggle}>{user.active?"Disable":"Enable"}</button><button disabled={busy} className="secondary" onClick={()=>void run(()=>api(`/api/v1/users/${id}/unlock`,{method:"POST"}))}>Unlock</button><button disabled={busy} className="secondary" onClick={reset}>Reset password</button><button disabled={busy} className="danger" onClick={()=>window.confirm("Revoke all sessions for this user?")&&void run(()=>api(`/api/v1/users/${id}/sessions/revoke-all`,{method:"POST"}))}>Revoke sessions</button>{canMFARead&&<button className="secondary" onClick={()=>void loadMFA()}>MFA status</button>}{canMFAWrite&&<button disabled={busy} className="danger" onClick={()=>void resetMFA()}>Reset MFA</button>}</div>
    {mfaInfo&&<div className="details"><strong>MFA status</strong><span>Required: {mfaInfo.status?.required?"Yes":"No"}</span><span>TOTP: {mfaInfo.status?.totp_enabled?"Enabled":"Disabled"}</span><span>WebAuthn credentials: {String(mfaInfo.status?.webauthn_credentials??0)}</span><span>Recovery codes: {String(mfaInfo.status?.recovery_codes_remaining??0)}</span></div>}
  </div>;
}

function GroupActions({group,reload,canMFARead,canMFAWrite}:{group:Item;reload:()=>void;canMFARead:boolean;canMFAWrite:boolean}){
  const [busy,setBusy]=useState(false),[members,setMembers]=useState<Item[]|null>(null),[mfaRequired,setMFARequired]=useState<boolean|null>(null);
  const id=String(group.id);
  const run=async(fn:()=>Promise<unknown>)=>{setBusy(true);try{await fn();reload()}catch(e){window.alert((e as Error).message)}finally{setBusy(false)}};
  const edit=()=>{const name=window.prompt("Group name:",String(group.name??""));if(!name)return;const description=window.prompt("Description:",String(group.description??""))??"";void run(()=>api(`/api/v1/groups/${id}`,{method:"PATCH",body:JSON.stringify({name,description})}))};
  const add=()=>{const userId=window.prompt("User ID to add:");if(userId)void run(()=>api(`/api/v1/groups/${id}/members`,{method:"POST",body:JSON.stringify({user_id:userId})}))};
  const loadMembers=async()=>{try{const data=await api(`/api/v1/groups/${id}/members`);setMembers(data.items||[])}catch(e){window.alert((e as Error).message)}};
  const remove=async(userId:string)=>{if(!window.confirm("Remove this user from the group?"))return;await run(()=>api(`/api/v1/groups/${id}/members/${userId}`,{method:"DELETE"}));await loadMembers()};
  const loadMFAPolicy=async()=>{try{const data=await api("/api/v1/groups/"+id+"/mfa-policy");setMFARequired(Boolean(data.required))}catch(e){window.alert((e as Error).message)}};
  const toggleMFA=async()=>{let current=mfaRequired;if(current===null){const data=await api("/api/v1/groups/"+id+"/mfa-policy");current=Boolean(data.required)}await run(()=>api("/api/v1/groups/"+id+"/mfa-policy",{method:"PUT",body:JSON.stringify({required:!current})}));setMFARequired(!current)};
  return <div className="actionPanel"><div className="actions"><button disabled={busy} className="secondary" onClick={edit}>Edit</button><button disabled={busy} className="secondary" onClick={add}>Add member</button><button className="secondary" onClick={()=>void loadMembers()}>Members</button>{canMFARead&&<button className="secondary" onClick={()=>void loadMFAPolicy()}>MFA policy{mfaRequired===null?"":mfaRequired?" (required)":" (optional)"}</button>}{canMFAWrite&&<button disabled={busy} className="secondary" onClick={()=>void toggleMFA()}>Toggle MFA</button>}<button disabled={busy} className="danger" onClick={()=>window.confirm("Delete this group?")&&void run(()=>api(`/api/v1/groups/${id}`,{method:"DELETE"}))}>Delete</button></div>
    {members&&<div className="details"><strong>Members</strong>{members.length===0?<span>None</span>:members.map(m=><div className="detailRow" key={String(m.id)}><span>{String(m.username)} · {String(m.email)}</span><button className="danger compact" onClick={()=>void remove(String(m.id))}>Remove</button></div>)}</div>}
  </div>;
}

function ApplicationActions({app,reload,canMFARead,canMFAWrite}:{app:Item;reload:()=>void;canMFARead:boolean;canMFAWrite:boolean}){
  const [busy,setBusy]=useState(false),[details,setDetails]=useState<Item|null>(null),[assignments,setAssignments]=useState<{users:Item[];groups:Item[]}|null>(null),[mfaRequired,setMFARequired]=useState<boolean|null>(null);
  const id=String(app.id);
  const protocol=String(app.protocol||"oidc");
  const integrationURL=protocol==="saml"?`/api/v1/saml/applications/${id}/integration`:`/api/v1/applications/${id}/integration`;
  const loadDetails=async()=>{try{setDetails(await api(integrationURL))}catch(e){window.alert((e as Error).message)}};
  const loadAssignments=async()=>{try{setAssignments(await api(`/api/v1/applications/${id}/assignments`))}catch(e){window.alert((e as Error).message)}};
  const run=async(fn:()=>Promise<unknown>)=>{setBusy(true);try{await fn();reload()}catch(e){window.alert((e as Error).message)}finally{setBusy(false)}};
  const rotate=async()=>{if(!window.confirm("Rotate this client secret? Existing integrations using the old secret will stop working."))return;setBusy(true);try{const data=await api(`/api/v1/applications/${id}/rotate-secret`,{method:"POST"});window.alert(`New client secret — copy now:\n\n${data.client_secret}`)}catch(e){window.alert((e as Error).message)}finally{setBusy(false)}};
  const assignUser=()=>{const userId=window.prompt("User ID to assign:");if(userId)void run(()=>api(`/api/v1/applications/${id}/assign/users`,{method:"POST",body:JSON.stringify({user_id:userId})})).then(loadAssignments)};
  const assignGroup=()=>{const groupId=window.prompt("Group ID to assign:");if(groupId)void run(()=>api(`/api/v1/applications/${id}/assign/groups`,{method:"POST",body:JSON.stringify({group_id:groupId})})).then(loadAssignments)};
  const removeUser=async(userId:string)=>{await run(()=>api(`/api/v1/applications/${id}/assign/users/${userId}`,{method:"DELETE"}));await loadAssignments()};
  const removeGroup=async(groupId:string)=>{await run(()=>api(`/api/v1/applications/${id}/assign/groups/${groupId}`,{method:"DELETE"}));await loadAssignments()};

  const editOIDC=async(toggleOnly=false)=>{
    const d=details??await api(integrationURL);
    const name=toggleOnly?String(app.name):window.prompt("Application name:",String(app.name??""));
    if(!name)return;
    const initiate=toggleOnly?String(app.initiate_login_uri??""):window.prompt("Initiate login URI:",String(d.initiate_login_uri??""))??"";
    await run(()=>api(`/api/v1/applications/${id}`,{method:"PUT",body:JSON.stringify({
      name,enabled:toggleOnly?!Boolean(app.enabled):Boolean(app.enabled),initiate_login_uri:initiate,
      redirect_uris:d.redirect_uris||[],post_logout_redirect_uris:d.post_logout_redirect_uris||[],allowed_scopes:d.scopes||[]
    })}));
  };

  const editSAML=async(toggleOnly=false)=>{
    const d=details??await api(integrationURL);
    const name=toggleOnly?String(app.name):window.prompt("Application name:",String(app.name??""));
    if(!name)return;
    const initiate=toggleOnly?String(app.initiate_login_uri??""):window.prompt("Launch / initiate-login URI:",String(d.initiate_login_uri??""))??"";
    const metadata=toggleOnly?String(d.sp_metadata_xml??""):window.prompt("Service Provider metadata XML:",String(d.sp_metadata_xml??""));
    if(metadata===null||metadata==="")return;
    await run(()=>api(`/api/v1/saml/applications/${id}`,{method:"PUT",body:JSON.stringify({
      name,enabled:toggleOnly?!Boolean(app.enabled):Boolean(app.enabled),
      initiate_login_uri:initiate,metadata_xml:metadata,
      require_signed_authn_request:Boolean(d.require_signed_authn_request)
    })}));
  };

  const loadMFAPolicy=async()=>{try{const data=await api("/api/v1/applications/"+id+"/mfa-policy");setMFARequired(Boolean(data.required))}catch(e){window.alert((e as Error).message)}};
  const toggleMFA=async()=>{let current=mfaRequired;if(current===null){const data=await api("/api/v1/applications/"+id+"/mfa-policy");current=Boolean(data.required)}await run(()=>api("/api/v1/applications/"+id+"/mfa-policy",{method:"PUT",body:JSON.stringify({required:!current})}));setMFARequired(!current)};
  const edit=(toggleOnly=false)=>protocol==="saml"?editSAML(toggleOnly):editOIDC(toggleOnly);

  return <div className="actionPanel"><div className="actions">
    <button className="secondary" onClick={()=>void loadDetails()}>Integration</button>
    <button className="secondary" onClick={()=>void edit(false)}>Edit</button>
    <button className="secondary" onClick={()=>void edit(true)}>{app.enabled?"Disable":"Enable"}</button>
    {protocol==="oidc"&&!app.public_client&&<button disabled={busy} className="secondary" onClick={()=>void rotate()}>Rotate secret</button>}
    <button className="secondary" onClick={assignUser}>Assign user</button>
    <button className="secondary" onClick={assignGroup}>Assign group</button>
    <button className="secondary" onClick={()=>void loadAssignments()}>Assignments</button>
    {canMFARead&&<button className="secondary" onClick={()=>void loadMFAPolicy()}>MFA policy{mfaRequired===null?"":mfaRequired?" (required)":" (optional)"}</button>}
    {canMFAWrite&&<button disabled={busy} className="secondary" onClick={()=>void toggleMFA()}>Toggle MFA</button>}
  </div>
    {details&&protocol==="oidc"&&<div className="details"><strong>OIDC integration</strong><code>Issuer: {String(details.issuer)}</code><code>Client ID: {String(details.client_id)}</code><code>Authorize: {String(details.authorization_url)}</code><code>Token: {String(details.token_url)}</code><code>JWKS: {String(details.jwks_url)}</code><code>Redirects: {render(details.redirect_uris)}</code><code>Scopes: {render(details.scopes)}</code><span>Client secret is never retrievable after creation or rotation.</span></div>}
    {details&&protocol==="saml"&&<div className="details"><strong>SAML integration</strong><code>IdP Entity ID: {String(details.idp_entity_id)}</code><code>IdP metadata: {String(details.idp_metadata_url)}</code><code>SSO URL: {String(details.sso_url)}</code><code>SP Entity ID: {String(details.sp_entity_id)}</code><code>NameID: {String(details.name_id_format)}</code><code>Request binding: {String(details.request_binding)}</code><code>Response binding: {String(details.response_binding)}</code><span>AuthnRequest signature required: {String(details.require_signed_authn_request)}</span></div>}
    {assignments&&<div className="details"><strong>Assignments</strong>{assignments.users.map(u=><div className="detailRow" key={String(u.id)}><span>User: {String(u.username)}</span><button className="danger compact" onClick={()=>void removeUser(String(u.id))}>Remove</button></div>)}{assignments.groups.map(g=><div className="detailRow" key={String(g.id)}><span>Group: {String(g.name)}</span><button className="danger compact" onClick={()=>void removeGroup(String(g.id))}>Remove</button></div>)}</div>}
  </div>;
}

function SAMLCreateForm({onCreated}:{onCreated:()=>void}){
  const [busy,setBusy]=useState(false),[error,setError]=useState("");
  const submit=async(e:FormEvent<HTMLFormElement>)=>{
    e.preventDefault();setBusy(true);setError("");const f=new FormData(e.currentTarget);
    try{
      await api("/api/v1/saml/applications",{method:"POST",body:JSON.stringify({
        name:f.get("saml_name"),
        initiate_login_uri:f.get("saml_initiate_login_uri"),
        metadata_xml:f.get("saml_metadata_xml"),
        require_signed_authn_request:f.get("saml_require_signed")==="on"
      })});
      e.currentTarget.reset();onCreated();
    }catch(x){setError((x as Error).message)}finally{setBusy(false)}
  };
  return <section className="card create"><h2>Create SAML application</h2><p>Paste the Service Provider metadata. OpenSSO validates the Entity ID and requires an HTTP-POST ACS endpoint.</p>{error&&<ErrorBox text={error}/>}<form onSubmit={submit} className="stack">
    <Field name="saml_name" label="Application name"/>
    <Field name="saml_initiate_login_uri" label="Launch / initiate-login URI" required={false}/>
    <TextArea name="saml_metadata_xml" label="Service Provider metadata XML" rows={10}/>
    <label className="check"><input name="saml_require_signed" type="checkbox"/> Require signed AuthnRequests</label>
    <button disabled={busy}>{busy?"Saving…":"Create SAML application"}</button>
  </form></section>;
}

function SAMLCertificatePanel({canRotate}:{canRotate:boolean}){
  const [items,setItems]=useState<Item[]>([]),[error,setError]=useState(""),[busy,setBusy]=useState(false);
  const load=async()=>{try{const data=await api("/api/v1/saml/certificates");setItems(data.items||[])}catch(e){setError((e as Error).message)}};
  useEffect(()=>{void load()},[]);
  const rotate=async()=>{if(!window.confirm("Rotate the active SAML signing certificate? Existing metadata consumers must refresh the IdP metadata."))return;setBusy(true);setError("");try{const data=await api("/api/v1/saml/certificates/rotate",{method:"POST"});setItems(data.items||[])}catch(e){setError((e as Error).message)}finally{setBusy(false)}};
  const active=items.find(x=>Boolean(x.active));
  return <section className="card create"><h2>SAML signing certificate</h2>{error&&<ErrorBox text={error}/>}<p>{active?`Active certificate ${active.kid}, expires ${active.not_after}`:"No certificate metadata loaded."}</p>{canRotate&&<button className="secondary" disabled={busy} onClick={()=>void rotate()}>{busy?"Rotating…":"Rotate certificate"}</button>}</section>;
}

function SessionActions({session,reload}:{session:Item;reload:()=>void}){
  const [busy,setBusy]=useState(false);const id=String(session.id);
  const revoke=async()=>{if(!window.confirm("Revoke this session?"))return;setBusy(true);try{await api(`/api/v1/sessions/${id}`,{method:"DELETE"});reload()}catch(e){window.alert((e as Error).message)}finally{setBusy(false)}};
  return <button className="danger" disabled={busy} onClick={()=>void revoke()}>Revoke</button>;
}

function CreateForm({view,onCreated}:{view:View;onCreated:()=>void}){
  const [error,setError]=useState(""),[busy,setBusy]=useState(false),[secret,setSecret]=useState("");
  if(["audit","sessions","security"].includes(view))return null;
  const submit=async(e:FormEvent<HTMLFormElement>)=>{
    e.preventDefault();setBusy(true);setError("");setSecret("");const f=new FormData(e.currentTarget);
    try{
      let result:any=null;
      if(view==="users")result=await api("/api/v1/users",{method:"POST",body:JSON.stringify({username:f.get("username"),email:f.get("email"),display_name:f.get("display_name"),password:f.get("password")})});
      if(view==="groups")result=await api("/api/v1/groups",{method:"POST",body:JSON.stringify({name:f.get("name"),description:f.get("description")})});
      if(view==="roles")result=await api(`/api/v1/users/${f.get("user_id")}/roles`,{method:"POST",body:JSON.stringify({role_id:f.get("role_id")})});
      if(view==="applications")result=await api("/api/v1/applications",{method:"POST",body:JSON.stringify({
        name:f.get("name"),public_client:f.get("public_client")==="on",
        redirect_uris:[f.get("redirect_uri")],
        post_logout_redirect_uris:f.get("post_logout_redirect_uri")?[f.get("post_logout_redirect_uri")]:[],
        allowed_scopes:String(f.get("allowed_scopes")||"openid profile email groups").split(/\s+/).filter(Boolean),
        initiate_login_uri:String(f.get("initiate_login_uri")||"")
      })});
      if(result?.client_secret)setSecret(result.client_secret);
      e.currentTarget.reset();onCreated();
    }catch(x){setError((x as Error).message)}finally{setBusy(false)}
  };
  return <section className="card create"><h2>{view==="roles"?"Assign role":view==="applications"?"Create OIDC application":`Create ${view.slice(0,-1)}`}</h2>{error&&<ErrorBox text={error}/>}
    {secret&&<div className="secret"><strong>Client secret — copy now</strong><code>{secret}</code><span>It will not be shown again.</span></div>}
    <form onSubmit={submit} className="inlineForm">
      {view==="users"&&<><Field name="username" label="Username"/><Field name="email" label="Email" type="email"/><Field name="display_name" label="Display name"/><Field name="password" label="Temporary password (must meet policy)" type="password" minLength={12}/></>}
      {view==="groups"&&<><Field name="name" label="Name"/><Field name="description" label="Description"/></>}
      {view==="roles"&&<><Field name="user_id" label="User ID"/><Field name="role_id" label="Role ID"/></>}
      {view==="applications"&&<><Field name="name" label="Application name"/><Field name="redirect_uri" label="Exact redirect URI"/><Field name="post_logout_redirect_uri" label="Post-logout redirect URI" required={false}/><Field name="initiate_login_uri" label="Launch / initiate-login URI" required={false}/><Field name="allowed_scopes" label="Allowed scopes" defaultValue="openid profile email groups"/><label className="check"><input name="public_client" type="checkbox"/> Public client</label></>}
      <button disabled={busy}>{busy?"Saving…":"Save"}</button>
    </form>
  </section>;
}

function Field({name,label,type="text",minLength,required=true,defaultValue}:{name:string;label:string;type?:string;minLength?:number;required?:boolean;defaultValue?:string}){return <label><span>{label}</span><input required={required} name={name} type={type} minLength={minLength} defaultValue={defaultValue}/></label>}
function TextArea({name,label,rows=6}:{name:string;label:string;rows?:number}){return <label><span>{label}</span><textarea required name={name} rows={rows}/></label>}
function NumberField({name,label,value,min,max}:{name:string;label:string;value:number;min:number;max:number}){return <label><span>{label}</span><input required name={name} type="number" defaultValue={value} min={min} max={max}/></label>}
function CheckField({name,label,checked}:{name:string;label:string;checked:boolean}){return <label className="check policyCheck"><input name={name} type="checkbox" defaultChecked={checked}/><span>{label}</span></label>}
function ErrorBox({text}:{text:string}){return <div className="error" role="alert">{text}</div>}
function Centered({children}:{children:React.ReactNode}){return <div className="centered">{children}</div>}
function render(v:unknown){if(Array.isArray(v))return v.join(", ");if(typeof v==="boolean")return v?"Yes":"No";if(v==null||v==="")return "—";return String(v)}
function ProvisioningView({access,reload}:{access:Access|null;reload:()=>void}){
  const [tokens,setTokens]=useState<Item[]>([]),[providers,setProviders]=useState<Item[]>([]),[message,setMessage]=useState(""),[error,setError]=useState("");
  const load=async()=>{setError("");try{if(hasPermission(access,"scim.read"))setTokens((await api("/api/v1/scim/tokens")).items||[]);if(hasPermission(access,"ldap.read"))setProviders((await api("/api/v1/ldap/providers")).items||[])}catch(e){setError((e as Error).message)}};
  useEffect(()=>{void load()},[]);
  const createToken=async(e:FormEvent<HTMLFormElement>)=>{e.preventDefault();const f=new FormData(e.currentTarget);try{const x=await api("/api/v1/scim/tokens",{method:"POST",body:JSON.stringify({name:f.get("name"),scopes:["users.read","users.write","groups.read","groups.write"]})});setMessage("SCIM token (shown once): "+String(x.token));await load()}catch(x){setError((x as Error).message)}};
  const createProvider=async(e:FormEvent<HTMLFormElement>)=>{e.preventDefault();const f=new FormData(e.currentTarget);try{await api("/api/v1/ldap/providers",{method:"POST",body:JSON.stringify({name:f.get("name"),enabled:true,host:f.get("host"),port:Number(f.get("port")),tls_mode:f.get("tls_mode"),skip_tls_verify:false,bind_dn:f.get("bind_dn"),bind_password:f.get("bind_password"),user_base_dn:f.get("user_base_dn"),user_filter:"(&(objectClass=person)(sAMAccountName={username}))",user_id_attribute:"objectGUID",username_attribute:"sAMAccountName",email_attribute:"mail",display_name_attribute:"displayName",group_base_dn:"",group_filter:"(objectClass=group)",group_name_attribute:"cn"})});e.currentTarget.reset();await load();reload()}catch(x){setError((x as Error).message)}};
  return <div className="stack">{error&&<ErrorBox text={error}/>} {message&&<section className="card"><code>{message}</code></section>}
    {hasPermission(access,"scim.read")&&<section className="card"><h2>SCIM 2.0</h2><p>Endpoint: <code>/scim/v2</code>. Tokens are stored hashed and the clear value is returned only at creation.</p>{hasPermission(access,"scim.write")&&<form onSubmit={createToken} className="inlineForm"><input name="name" required placeholder="Token name"/><button>Create token</button></form>}<table><thead><tr><th>Name</th><th>Scopes</th><th>Last used</th><th>Status</th></tr></thead><tbody>{tokens.map(x=><tr key={String(x.id)}><td>{String(x.name)}</td><td>{Array.isArray(x.scopes)?x.scopes.join(", "):""}</td><td>{String(x.last_used_at||"Never")}</td><td>{x.revoked_at?"Revoked":"Active"}</td></tr>)}</tbody></table></section>}
    {hasPermission(access,"ldap.read")&&<section className="card"><h2>LDAP / Active Directory</h2>{hasPermission(access,"ldap.write")&&<form onSubmit={createProvider} className="formGrid"><input name="name" required placeholder="Provider name"/><input name="host" required placeholder="ldap.example.com"/><input name="port" type="number" defaultValue="636" required/><select name="tls_mode" defaultValue="ldaps"><option value="ldaps">LDAPS</option><option value="starttls">StartTLS</option></select><input name="bind_dn" placeholder="CN=svc,OU=Service,DC=example,DC=com"/><input name="bind_password" type="password" placeholder="Bind password"/><input name="user_base_dn" required placeholder="OU=Users,DC=example,DC=com"/><button>Create provider</button></form>}<table><thead><tr><th>Name</th><th>Host</th><th>TLS</th><th>Enabled</th><th>Actions</th></tr></thead><tbody>{providers.map(x=><tr key={String(x.id)}><td>{String(x.name)}</td><td>{String(x.host)}:{String(x.port)}</td><td>{String(x.tls_mode)}</td><td>{String(x.enabled)}</td><td>{hasPermission(access,"ldap.write")&&<button onClick={()=>void api("/api/v1/ldap/providers/"+x.id+"/test",{method:"POST"}).then(()=>setMessage("LDAP connection successful")).catch(e=>setError(e.message))}>Test</button>}</td></tr>)}</tbody></table></section>}
  </div>
}


function label(v:View){return ({dashboard:"Dashboard",users:"Users",groups:"Groups",roles:"Roles & RBAC",applications:"Applications",sessions:"Sessions",security:"Security policy",audit:"Audit log","my-apps":"My applications","my-sessions":"My sessions",profile:"My profile",mfa:"MFA",provisioning:"Provisioning"})[v]}
function subtitle(v:View){return ({dashboard:"System overview",users:"Local identities",groups:"Group directory",roles:"Assign administrative roles",applications:"OIDC and SAML applications and assignments",sessions:"Active browser sessions",security:"Password, lockout and session policy",audit:"Security and administrative events","my-apps":"Applications assigned directly or through your groups","my-sessions":"Manage your active OpenSSO sessions",profile:"Self-service profile and credentials",mfa:"Authenticator, passkeys, security keys and recovery codes",provisioning:"SCIM provisioning and LDAP/Active Directory federation"})[v]}
function columns(v:View){return ({
  users:["id","username","email","display_name","active","must_change_password","locked_until","created_at"],
  groups:["id","name","description","created_at"],
  roles:["id","name","description"],
  applications:["id","name","protocol","client_id","entity_id","enabled","initiate_login_uri","created_at"],
  sessions:["id","username","ip","user_agent","last_seen_at","expires_at"],
  audit:["occurred_at","event","result","target_type","target_id","actor_user_id","ip"],
  dashboard:[],security:[],profile:[],mfa:[],provisioning:[],"my-apps":[],"my-sessions":[]
})[v]||[]}
