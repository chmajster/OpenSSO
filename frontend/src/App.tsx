import { FormEvent, useEffect, useMemo, useState } from "react";

type Item = Record<string, unknown>;
type View = "dashboard" | "users" | "groups" | "roles" | "applications" | "audit";

async function api(path:string, init:RequestInit={}) {
  const r=await fetch(path,{credentials:"include",headers:{"Content-Type":"application/json",...(init.headers||{})},...init});
  if(r.status===204)return null;
  const body=await r.json().catch(()=>({detail:"Invalid server response"}));
  if(!r.ok)throw new Error(body.detail||body.error||`HTTP ${r.status}`);
  return body;
}

export default function App(){
  const [initialized,setInitialized]=useState<boolean|null>(null);
  const [me,setMe]=useState<Item|null>(null);
  const [error,setError]=useState("");
  const [view,setView]=useState<View>("dashboard");
  const [items,setItems]=useState<Item[]>([]);
  const [loading,setLoading]=useState(false);

  const refreshSession=async()=>{
    const s=await api("/api/v1/setup/status");setInitialized(Boolean(s.initialized));
    if(s.initialized){try{setMe(await api("/api/v1/me"));}catch{setMe(null)}}
  };
  useEffect(()=>{refreshSession().catch(e=>setError(e.message));},[]);

  const endpoint=useMemo(()=>({users:"/api/v1/users",groups:"/api/v1/groups",roles:"/api/v1/roles",applications:"/api/v1/applications",audit:"/api/v1/audit",dashboard:""}[view]),[view]);
  useEffect(()=>{if(!me||!endpoint){setItems([]);return}setLoading(true);setError("");api(endpoint).then(x=>setItems(x.items||[])).catch(e=>setError(e.message)).finally(()=>setLoading(false));},[me,endpoint]);

  if(initialized===null)return <Centered><p>Checking OpenSSO status…</p>{error&&<ErrorBox text={error}/>}</Centered>;
  if(!initialized)return <Bootstrap onDone={refreshSession}/>;
  if(!me)return <Login onDone={refreshSession}/>;

  const logout=async()=>{await api("/api/v1/auth/logout",{method:"POST"});setMe(null)};
  return <div className="shell">
    <aside>
      <div className="brand">OpenSSO</div>
      <div className="identity">{String(me.username)}</div>
      <nav>
        {(["dashboard","users","groups","roles","applications","audit"] as View[]).map(v=><button key={v} className={view===v?"active":""} onClick={()=>setView(v)}>{label(v)}</button>)}
      </nav>
      <button className="secondary logout" onClick={()=>void logout()}>Sign out</button>
    </aside>
    <main>
      <header><div><h1>{label(view)}</h1><p>{subtitle(view)}</p></div></header>
      {error&&<ErrorBox text={error}/>}
      {view==="dashboard"?<Dashboard/>:<ResourceView view={view} items={items} loading={loading} reload={()=>{setView("dashboard");setTimeout(()=>setView(view),0)}}/>}
    </main>
  </div>;
}

function Bootstrap({onDone}:{onDone:()=>Promise<void>}){
  const [busy,setBusy]=useState(false),[error,setError]=useState("");
  const submit=async(e:FormEvent<HTMLFormElement>)=>{
    e.preventDefault();setBusy(true);setError("");const f=new FormData(e.currentTarget);
    try{await api("/api/v1/setup/bootstrap",{method:"POST",headers:{Authorization:`Bearer ${f.get("token")}`},body:JSON.stringify({username:f.get("username"),email:f.get("email"),display_name:f.get("display_name"),password:f.get("password")})});await onDone()}catch(x){setError((x as Error).message)}finally{setBusy(false)}
  };
  return <Centered><section className="card auth"><h1>Initialize OpenSSO</h1><p>Create the first Super Admin. The bootstrap token comes from deployment configuration and is accepted only before initialization.</p>{error&&<ErrorBox text={error}/>}<form onSubmit={submit}><Field name="token" label="Bootstrap token" type="password"/><Field name="username" label="Username"/><Field name="email" label="Email" type="email"/><Field name="display_name" label="Display name"/><Field name="password" label="Password" type="password" minLength={12}/><button disabled={busy}>{busy?"Creating…":"Create installation"}</button></form></section></Centered>
}
function Login({onDone}:{onDone:()=>Promise<void>}){
  const [busy,setBusy]=useState(false),[error,setError]=useState("");
  const submit=async(e:FormEvent<HTMLFormElement>)=>{e.preventDefault();setBusy(true);setError("");const f=new FormData(e.currentTarget);try{await api("/api/v1/auth/login",{method:"POST",body:JSON.stringify({username:f.get("username"),password:f.get("password")})});await onDone()}catch(x){setError((x as Error).message)}finally{setBusy(false)}};
  return <Centered><section className="card auth"><h1>Sign in</h1><p>Use your OpenSSO local account.</p>{error&&<ErrorBox text={error}/>}<form onSubmit={submit}><Field name="username" label="Username or email"/><Field name="password" label="Password" type="password"/><button disabled={busy}>{busy?"Signing in…":"Sign in"}</button></form></section></Centered>
}
function Dashboard(){return <div className="grid"><section className="card"><h2>Foundation active</h2><p>Local authentication, server-side RBAC, users, groups, applications, sessions and audit are backed by PostgreSQL. Redis provides distributed login throttling.</p></section><section className="card"><h2>Security posture</h2><p>Passwords use Argon2id. Session tokens and client secrets are stored as hashes. OIDC protocol endpoints are intentionally not exposed until the complete standards-compliant flow is implemented.</p></section></div>}
function ResourceView({view,items,loading,reload}:{view:View;items:Item[];loading:boolean;reload:()=>void}){
  return <><CreateForm view={view} onCreated={reload}/><section className="card tableCard">{loading?<p>Loading…</p>:items.length===0?<p>No records.</p>:<table><thead><tr>{columns(view).map(c=><th key={c}>{c}</th>)}</tr></thead><tbody>{items.map((x,i)=><tr key={String(x.id||i)}>{columns(view).map(c=><td key={c}>{render(x[c])}</td>)}</tr>)}</tbody></table>}</section></>
}
function CreateForm({view,onCreated}:{view:View;onCreated:()=>void}){
  const [error,setError]=useState(""),[busy,setBusy]=useState(false);
  if(view==="audit")return null;
  const submit=async(e:FormEvent<HTMLFormElement>)=>{e.preventDefault();setBusy(true);setError("");const f=new FormData(e.currentTarget);try{
    if(view==="users")await api("/api/v1/users",{method:"POST",body:JSON.stringify({username:f.get("username"),email:f.get("email"),display_name:f.get("display_name"),password:f.get("password")})});
    if(view==="groups")await api("/api/v1/groups",{method:"POST",body:JSON.stringify({name:f.get("name"),description:f.get("description")})});
    if(view==="roles")await api(`/api/v1/users/${f.get("user_id")}/roles`,{method:"POST",body:JSON.stringify({role_id:f.get("role_id")})});
    if(view==="applications")await api("/api/v1/applications",{method:"POST",body:JSON.stringify({name:f.get("name"),public_client:f.get("public_client")==="on",redirect_uris:[f.get("redirect_uri")]})});
    e.currentTarget.reset();onCreated();
  }catch(x){setError((x as Error).message)}finally{setBusy(false)}};
  return <section className="card create"><h2>Create {view.slice(0,-1)}</h2>{error&&<ErrorBox text={error}/>}<form onSubmit={submit} className="inlineForm">
    {view==="users"&&<><Field name="username" label="Username"/><Field name="email" label="Email" type="email"/><Field name="display_name" label="Display name"/><Field name="password" label="Initial password" type="password" minLength={12}/></>}
    {view==="groups"&&<><Field name="name" label="Name"/><Field name="description" label="Description"/></>}
    {view==="roles"&&<><Field name="user_id" label="User ID"/><Field name="role_id" label="Role ID"/></>}
    {view==="applications"&&<><Field name="name" label="Application name"/><Field name="redirect_uri" label="Exact redirect URI"/><label className="check"><input name="public_client" type="checkbox"/> Public client</label></>}
    <button disabled={busy}>{busy?"Saving…":"Create"}</button>
  </form></section>
}
function Field({name,label,type="text",minLength}:{name:string;label:string;type?:string;minLength?:number}){return <label><span>{label}</span><input required name={name} type={type} minLength={minLength}/></label>}
function ErrorBox({text}:{text:string}){return <div className="error" role="alert">{text}</div>}
function Centered({children}:{children:React.ReactNode}){return <div className="centered">{children}</div>}
function render(v:unknown){if(typeof v==="boolean")return v?"Yes":"No";if(v==null)return "—";return String(v)}
function label(v:View){return ({dashboard:"Dashboard",users:"Users",groups:"Groups",roles:"Roles & RBAC",applications:"Applications",audit:"Audit log"})[v]}
function subtitle(v:View){return ({dashboard:"System overview",users:"Local identities",groups:"Group directory",roles:"Assign administrative roles",applications:"Registered relying parties",audit:"Security and administrative events"})[v]}
function columns(v:View){return ({users:["username","email","display_name","active","created_at"],groups:["name","description","created_at"],roles:["id","name","description"],applications:["name","client_id","public_client","require_pkce","created_at"],audit:["occurred_at","event","result","target_type","target_id","actor_user_id","ip"]})[v]||[]}
