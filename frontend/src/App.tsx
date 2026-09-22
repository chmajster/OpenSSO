import { FormEvent, useEffect, useState } from "react";

type Item = Record<string, unknown>;
type View = "dashboard" | "users" | "groups" | "roles" | "applications" | "sessions" | "security" | "audit";
type Me = { UserID?: string; Username?: string; MustChangePassword?: boolean; user_id?: string; username?: string; must_change_password?: boolean };

function cookie(name:string){
  const prefix=name+"=";
  const value=document.cookie.split("; ").find(x=>x.startsWith(prefix));
  return value?decodeURIComponent(value.slice(prefix.length)):"";
}

async function api(path:string, init:RequestInit={}) {
  const method=(init.method||"GET").toUpperCase();
  const headers:Record<string,string>={"Content-Type":"application/json",...(init.headers as Record<string,string>||{})};
  if(!["GET","HEAD","OPTIONS"].includes(method)){
    const csrf=cookie("opensso_csrf");
    if(csrf)headers["X-CSRF-Token"]=csrf;
  }
  const r=await fetch(path,{credentials:"include",...init,headers});
  if(r.status===204)return null;
  const body=await r.json().catch(()=>({detail:"Invalid server response"}));
  if(!r.ok)throw new Error(body.detail||body.error||`HTTP ${r.status}`);
  return body;
}

const resourceEndpoints: Partial<Record<View,string>> = {
  users:"/api/v1/users",
  groups:"/api/v1/groups",
  roles:"/api/v1/roles",
  applications:"/api/v1/applications",
  sessions:"/api/v1/sessions",
  audit:"/api/v1/audit",
};

export default function App(){
  const [initialized,setInitialized]=useState<boolean|null>(null);
  const [me,setMe]=useState<Me|null>(null);
  const [error,setError]=useState("");
  const [view,setView]=useState<View>("dashboard");
  const [items,setItems]=useState<Item[]>([]);
  const [dashboard,setDashboard]=useState<Item>({});
  const [policy,setPolicy]=useState<Item>({});
  const [loading,setLoading]=useState(false);
  const [reloadKey,setReloadKey]=useState(0);

  const refreshSession=async()=>{
    const s=await api("/api/v1/setup/status");
    setInitialized(Boolean(s.initialized));
    if(s.initialized){try{setMe(await api("/api/v1/me"));}catch{setMe(null)}}
  };
  useEffect(()=>{refreshSession().catch(e=>setError(e.message));},[]);

  useEffect(()=>{
    if(!me)return;
    setLoading(true);setError("");
    const endpoint=resourceEndpoints[view];
    const request=view==="dashboard"?api("/api/v1/dashboard"):view==="security"?api("/api/v1/security/policy"):endpoint?api(endpoint):Promise.resolve({items:[]});
    request.then(data=>{
      if(view==="dashboard")setDashboard(data||{});
      else if(view==="security")setPolicy(data||{});
      else setItems(data?.items||[]);
    }).catch(e=>setError(e.message)).finally(()=>setLoading(false));
  },[me,view,reloadKey]);

  if(initialized===null)return <Centered><p>Checking OpenSSO status…</p>{error&&<ErrorBox text={error}/>}</Centered>;
  if(!initialized)return <Bootstrap onDone={refreshSession}/>;
  if(!me)return <Login onDone={refreshSession}/>;
  if(Boolean(me.MustChangePassword ?? me.must_change_password))return <ChangePassword onDone={refreshSession}/>;

  const logout=async()=>{await api("/api/v1/auth/logout",{method:"POST"});setMe(null)};
  const reload=()=>setReloadKey(x=>x+1);
  const username=String(me.Username ?? me.username ?? "");

  return <div className="shell">
    <aside>
      <div className="brand">OpenSSO</div>
      <div className="identity">{username}</div>
      <nav>
        {(["dashboard","users","groups","roles","applications","sessions","security","audit"] as View[]).map(v=><button key={v} className={view===v?"active":""} onClick={()=>setView(v)}>{label(v)}</button>)}
      </nav>
      <button className="secondary logout" onClick={()=>void logout()}>Sign out</button>
    </aside>
    <main>
      <header><div><h1>{label(view)}</h1><p>{subtitle(view)}</p></div></header>
      {error&&<ErrorBox text={error}/>}
      {view==="dashboard"?<Dashboard data={dashboard} loading={loading}/>:
       view==="security"?<SecurityPolicy data={policy} loading={loading} onSaved={reload}/>:
       <ResourceView view={view} items={items} loading={loading} reload={reload}/>}
    </main>
  </div>;
}

function Bootstrap({onDone}:{onDone:()=>Promise<void>}){
  const [busy,setBusy]=useState(false),[error,setError]=useState("");
  const submit=async(e:FormEvent<HTMLFormElement>)=>{
    e.preventDefault();setBusy(true);setError("");const f=new FormData(e.currentTarget);
    try{await api("/api/v1/setup/bootstrap",{method:"POST",headers:{Authorization:`Bearer ${f.get("token")}`},body:JSON.stringify({username:f.get("username"),email:f.get("email"),display_name:f.get("display_name"),password:f.get("password")})});await onDone()}catch(x){setError((x as Error).message)}finally{setBusy(false)}
  };
  return <Centered><section className="card auth"><h1>Initialize OpenSSO</h1><p>Create the first Super Admin. The bootstrap token is accepted only before initialization.</p>{error&&<ErrorBox text={error}/>}<form onSubmit={submit}><Field name="token" label="Bootstrap token" type="password"/><Field name="username" label="Username"/><Field name="email" label="Email" type="email"/><Field name="display_name" label="Display name"/><Field name="password" label="Password" type="password" minLength={12}/><button disabled={busy}>{busy?"Creating…":"Create installation"}</button></form></section></Centered>
}

function Login({onDone}:{onDone:()=>Promise<void>}){
  const [busy,setBusy]=useState(false),[error,setError]=useState("");
  const submit=async(e:FormEvent<HTMLFormElement>)=>{e.preventDefault();setBusy(true);setError("");const f=new FormData(e.currentTarget);try{await api("/api/v1/auth/login",{method:"POST",body:JSON.stringify({username:f.get("username"),password:f.get("password")})});await onDone()}catch(x){setError((x as Error).message)}finally{setBusy(false)}};
  return <Centered><section className="card auth"><h1>Sign in</h1><p>Use your OpenSSO local account.</p>{error&&<ErrorBox text={error}/>}<form onSubmit={submit}><Field name="username" label="Username or email"/><Field name="password" label="Password" type="password"/><button disabled={busy}>{busy?"Signing in…":"Sign in"}</button></form></section></Centered>
}

function ChangePassword({onDone}:{onDone:()=>Promise<void>}){
  const [busy,setBusy]=useState(false),[error,setError]=useState("");
  const submit=async(e:FormEvent<HTMLFormElement>)=>{e.preventDefault();setBusy(true);setError("");const f=new FormData(e.currentTarget);try{await api("/api/v1/me/password",{method:"POST",body:JSON.stringify({current_password:f.get("current_password"),new_password:f.get("new_password")})});await onDone()}catch(x){setError((x as Error).message)}finally{setBusy(false)}};
  return <Centered><section className="card auth"><h1>Password change required</h1><p>Your administrator requires a new password before administrative access is granted.</p>{error&&<ErrorBox text={error}/>}<form onSubmit={submit}><Field name="current_password" label="Current password" type="password"/><Field name="new_password" label="New password" type="password" minLength={12}/><button disabled={busy}>{busy?"Changing…":"Change password"}</button></form></section></Centered>
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
  const submit=async(e:FormEvent<HTMLFormElement>)=>{e.preventDefault();setBusy(true);setError("");const f=new FormData(e.currentTarget);try{await api("/api/v1/security/policy",{method:"PUT",body:JSON.stringify({
    password_min_length:Number(f.get("password_min_length")),lockout_threshold:Number(f.get("lockout_threshold")),
    lockout_minutes:Number(f.get("lockout_minutes")),session_ttl_minutes:Number(f.get("session_ttl_minutes"))
  })});onSaved()}catch(x){setError((x as Error).message)}finally{setBusy(false)}};
  return <section className="card"><h2>Authentication policy</h2>{error&&<ErrorBox text={error}/>}<form onSubmit={submit} className="inlineForm">
    <NumberField name="password_min_length" label="Minimum password length" value={Number(data.password_min_length??12)} min={12} max={128}/>
    <NumberField name="lockout_threshold" label="Failed attempts before lockout" value={Number(data.lockout_threshold??10)} min={3} max={100}/>
    <NumberField name="lockout_minutes" label="Lockout minutes" value={Number(data.lockout_minutes??15)} min={1} max={1440}/>
    <NumberField name="session_ttl_minutes" label="Session TTL minutes" value={Number(data.session_ttl_minutes??720)} min={5} max={10080}/>
    <button disabled={busy}>{busy?"Saving…":"Save policy"}</button>
  </form></section>
}

function ResourceView({view,items,loading,reload}:{view:View;items:Item[];loading:boolean;reload:()=>void}){
  return <><CreateForm view={view} onCreated={reload}/><section className="card tableCard">{loading?<p>Loading…</p>:items.length===0?<p>No records.</p>:<table><thead><tr>{columns(view).map(c=><th key={c}>{c}</th>)}{["users","sessions"].includes(view)&&<th>actions</th>}</tr></thead><tbody>{items.map((x,i)=><tr key={String(x.id||i)}>{columns(view).map(c=><td key={c}>{render(x[c])}</td>)}{view==="users"&&<td><UserActions user={x} reload={reload}/></td>}{view==="sessions"&&<td><SessionActions session={x} reload={reload}/></td>}</tr>)}</tbody></table>}</section></>
}

function UserActions({user,reload}:{user:Item;reload:()=>void}){
  const [busy,setBusy]=useState(false);
  const id=String(user.id);
  const run=async(fn:()=>Promise<unknown>)=>{setBusy(true);try{await fn();reload()}catch(e){alert((e as Error).message)}finally{setBusy(false)}};
  const toggle=()=>run(()=>api(`/api/v1/users/${id}`,{method:"PATCH",body:JSON.stringify({email:user.email,display_name:user.display_name,active:!Boolean(user.active)})}));
  const reset=()=>{const password=window.prompt("Temporary password (minimum policy length):");if(!password)return;if(!window.confirm("Reset password and revoke all sessions for this user?"))return;void run(()=>api(`/api/v1/users/${id}/reset-password`,{method:"POST",body:JSON.stringify({password})}))};
  return <div className="actions"><button disabled={busy} className="secondary" onClick={toggle}>{user.active?"Disable":"Enable"}</button><button disabled={busy} className="secondary" onClick={()=>void run(()=>api(`/api/v1/users/${id}/unlock`,{method:"POST"}))}>Unlock</button><button disabled={busy} className="secondary" onClick={reset}>Reset password</button><button disabled={busy} className="danger" onClick={()=>window.confirm("Revoke all sessions for this user?")&&void run(()=>api(`/api/v1/users/${id}/sessions/revoke-all`,{method:"POST"}))}>Revoke sessions</button></div>
}

function SessionActions({session,reload}:{session:Item;reload:()=>void}){
  const [busy,setBusy]=useState(false);const id=String(session.id);
  const revoke=async()=>{if(!window.confirm("Revoke this session?"))return;setBusy(true);try{await api(`/api/v1/sessions/${id}`,{method:"DELETE"});reload()}catch(e){alert((e as Error).message)}finally{setBusy(false)}};
  return <button className="danger" disabled={busy} onClick={()=>void revoke()}>Revoke</button>
}

function CreateForm({view,onCreated}:{view:View;onCreated:()=>void}){
  const [error,setError]=useState(""),[busy,setBusy]=useState(false),[secret,setSecret]=useState("");
  if(["audit","sessions","security"].includes(view))return null;
  const submit=async(e:FormEvent<HTMLFormElement>)=>{e.preventDefault();setBusy(true);setError("");setSecret("");const f=new FormData(e.currentTarget);try{
    let result:any=null;
    if(view==="users")result=await api("/api/v1/users",{method:"POST",body:JSON.stringify({username:f.get("username"),email:f.get("email"),display_name:f.get("display_name"),password:f.get("password")})});
    if(view==="groups")result=await api("/api/v1/groups",{method:"POST",body:JSON.stringify({name:f.get("name"),description:f.get("description")})});
    if(view==="roles")result=await api(`/api/v1/users/${f.get("user_id")}/roles`,{method:"POST",body:JSON.stringify({role_id:f.get("role_id")})});
    if(view==="applications")result=await api("/api/v1/applications",{method:"POST",body:JSON.stringify({name:f.get("name"),public_client:f.get("public_client")==="on",redirect_uris:[f.get("redirect_uri")]})});
    if(result?.client_secret)setSecret(result.client_secret);
    e.currentTarget.reset();onCreated();
  }catch(x){setError((x as Error).message)}finally{setBusy(false)}};
  return <section className="card create"><h2>{view==="roles"?"Assign role":`Create ${view.slice(0,-1)}`}</h2>{error&&<ErrorBox text={error}/>}
    {secret&&<div className="secret"><strong>Client secret — copy now</strong><code>{secret}</code><span>It will not be shown again.</span></div>}
    <form onSubmit={submit} className="inlineForm">
      {view==="users"&&<><Field name="username" label="Username"/><Field name="email" label="Email" type="email"/><Field name="display_name" label="Display name"/><Field name="password" label="Temporary password" type="password" minLength={12}/></>}
      {view==="groups"&&<><Field name="name" label="Name"/><Field name="description" label="Description"/></>}
      {view==="roles"&&<><Field name="user_id" label="User ID"/><Field name="role_id" label="Role ID"/></>}
      {view==="applications"&&<><Field name="name" label="Application name"/><Field name="redirect_uri" label="Exact redirect URI"/><label className="check"><input name="public_client" type="checkbox"/> Public client</label></>}
      <button disabled={busy}>{busy?"Saving…":"Save"}</button>
    </form>
  </section>
}

function Field({name,label,type="text",minLength}:{name:string;label:string;type?:string;minLength?:number}){return <label><span>{label}</span><input required name={name} type={type} minLength={minLength}/></label>}
function NumberField({name,label,value,min,max}:{name:string;label:string;value:number;min:number;max:number}){return <label><span>{label}</span><input required name={name} type="number" defaultValue={value} min={min} max={max}/></label>}
function ErrorBox({text}:{text:string}){return <div className="error" role="alert">{text}</div>}
function Centered({children}:{children:React.ReactNode}){return <div className="centered">{children}</div>}
function render(v:unknown){if(typeof v==="boolean")return v?"Yes":"No";if(v==null||v==="")return "—";return String(v)}
function label(v:View){return ({dashboard:"Dashboard",users:"Users",groups:"Groups",roles:"Roles & RBAC",applications:"Applications",sessions:"Sessions",security:"Security policy",audit:"Audit log"})[v]}
function subtitle(v:View){return ({dashboard:"System overview",users:"Local identities",groups:"Group directory",roles:"Assign administrative roles",applications:"Registered relying parties",sessions:"Active browser sessions",security:"Password, lockout and session policy",audit:"Security and administrative events"})[v]}
function columns(v:View){return ({
  users:["id","username","email","display_name","active","must_change_password","locked_until","created_at"],
  groups:["id","name","description","created_at"],
  roles:["id","name","description"],
  applications:["name","client_id","public_client","require_pkce","created_at"],
  sessions:["id","username","ip","user_agent","last_seen_at","expires_at"],
  audit:["occurred_at","event","result","target_type","target_id","actor_user_id","ip"],
  dashboard:[],security:[]
})[v]||[]}
