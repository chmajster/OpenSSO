import { FormEvent, useEffect, useState } from "react";
import { api } from "./http";

type WebAuthnCredentialInfo={
  id:string;
  display_name:string;
  discoverable:boolean;
  created_at:string;
  last_used_at?:string|null;
};

type MFAStatus={
  required:boolean;
  session_verified:boolean;
  totp_enabled:boolean;
  webauthn_credentials:WebAuthnCredentialInfo[];
  passkeys:number;
  recovery_codes_remaining:number;
  has_primary_factor:boolean;
};

type TOTPSetup={
  secret:string;
  otpauth_url:string;
  qr_code_data_url:string;
};

function b64urlToBuffer(value:string):ArrayBuffer{
  const normalized=value.replace(/-/g,"+").replace(/_/g,"/");
  const padded=normalized+"=".repeat((4-normalized.length%4)%4);
  const binary=atob(padded);
  const bytes=new Uint8Array(binary.length);
  for(let i=0;i<binary.length;i++)bytes[i]=binary.charCodeAt(i);
  return bytes.buffer;
}

function bufferToB64url(value:ArrayBuffer|null):string|null{
  if(value===null)return null;
  const bytes=new Uint8Array(value);
  let binary="";
  for(const b of bytes)binary+=String.fromCharCode(b);
  return btoa(binary).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}

function normalizeCreationOptions(raw:any):PublicKeyCredentialCreationOptions{
  return {
    ...raw,
    challenge:b64urlToBuffer(raw.challenge),
    user:{...raw.user,id:b64urlToBuffer(raw.user.id)},
    excludeCredentials:(raw.excludeCredentials||[]).map((item:any)=>({...item,id:b64urlToBuffer(item.id)})),
  } as PublicKeyCredentialCreationOptions;
}

function normalizeRequestOptions(raw:any):PublicKeyCredentialRequestOptions{
  return {
    ...raw,
    challenge:b64urlToBuffer(raw.challenge),
    allowCredentials:(raw.allowCredentials||[]).map((item:any)=>({...item,id:b64urlToBuffer(item.id)})),
  } as PublicKeyCredentialRequestOptions;
}

function serializeRegistrationCredential(credential:PublicKeyCredential){
  const response=credential.response as AuthenticatorAttestationResponse;
  return {
    id:credential.id,
    rawId:bufferToB64url(credential.rawId),
    type:credential.type,
    response:{
      clientDataJSON:bufferToB64url(response.clientDataJSON),
      attestationObject:bufferToB64url(response.attestationObject),
      transports:typeof (response as any).getTransports==="function"?(response as any).getTransports():[],
    },
    clientExtensionResults:credential.getClientExtensionResults(),
    authenticatorAttachment:(credential as any).authenticatorAttachment??null,
  };
}

function serializeAssertionCredential(credential:PublicKeyCredential){
  const response=credential.response as AuthenticatorAssertionResponse;
  return {
    id:credential.id,
    rawId:bufferToB64url(credential.rawId),
    type:credential.type,
    response:{
      clientDataJSON:bufferToB64url(response.clientDataJSON),
      authenticatorData:bufferToB64url(response.authenticatorData),
      signature:bufferToB64url(response.signature),
      userHandle:bufferToB64url(response.userHandle),
    },
    clientExtensionResults:credential.getClientExtensionResults(),
    authenticatorAttachment:(credential as any).authenticatorAttachment??null,
  };
}

function requireWebAuthn(){
  if(!window.PublicKeyCredential || !navigator.credentials)throw new Error("WebAuthn is not available in this browser.");
}

async function registerWebAuthn(kind:"security_key"|"passkey",displayName:string){
  requireWebAuthn();
  const begin=await api("/api/v1/me/mfa/webauthn/register/begin",{
    method:"POST",body:JSON.stringify({kind})
  });
  const credential=await navigator.credentials.create({
    publicKey:normalizeCreationOptions(begin.options.publicKey)
  });
  if(!(credential instanceof PublicKeyCredential))throw new Error("WebAuthn registration was cancelled.");
  return api(
    "/api/v1/me/mfa/webauthn/register/finish?ceremony="+encodeURIComponent(begin.ceremony)+"&display_name="+encodeURIComponent(displayName),
    {method:"POST",body:JSON.stringify(serializeRegistrationCredential(credential))}
  );
}

async function verifyWebAuthn(){
  requireWebAuthn();
  const begin=await api("/api/v1/auth/mfa/webauthn/begin",{method:"POST",body:"{}"});
  const credential=await navigator.credentials.get({
    publicKey:normalizeRequestOptions(begin.options.publicKey)
  });
  if(!(credential instanceof PublicKeyCredential))throw new Error("WebAuthn verification was cancelled.");
  return api(
    "/api/v1/auth/mfa/webauthn/finish?ceremony="+encodeURIComponent(begin.ceremony),
    {method:"POST",body:JSON.stringify(serializeAssertionCredential(credential))}
  );
}

function ErrorBox({text}:{text:string}){return <div className="error" role="alert">{text}</div>}
function Field({name,label}:{name:string;label:string}){return <label><span>{label}</span><input required name={name}/></label>}

function RecoveryCodes({codes,onConfirmed}:{codes:string[];onConfirmed?:()=>void}){
  const copy=async()=>navigator.clipboard?.writeText(codes.join("\n"));
  return <section className="card recoveryCard">
    <h2>Recovery codes</h2>
    <p>Store these codes now. Each code works once and this set will not be shown again.</p>
    <div className="recoveryCodes">{codes.map(code=><code key={code}>{code}</code>)}</div>
    <div className="actions">
      <button className="secondary" onClick={()=>void copy()}>Copy codes</button>
      {onConfirmed&&<button onClick={onConfirmed}>I saved these codes</button>}
    </div>
  </section>;
}

function MFAVerifyControls({status,onVerified}:{status:MFAStatus;onVerified:()=>Promise<void>|void}){
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState("");
  const verifyCode=async(method:"totp"|"recovery",code:string)=>{
    setBusy(true);setError("");
    try{
      await api("/api/v1/auth/mfa/verify",{method:"POST",body:JSON.stringify({method,code})});
      await onVerified();
    }catch(e){setError((e as Error).message)}finally{setBusy(false)}
  };
  const submit=(method:"totp"|"recovery")=>(e:FormEvent<HTMLFormElement>)=>{
    e.preventDefault();
    const form=new FormData(e.currentTarget);
    void verifyCode(method,String(form.get("code")||""));
  };
  const webauthn=async()=>{
    setBusy(true);setError("");
    try{
      await verifyWebAuthn();
      await onVerified();
    }catch(e){setError((e as Error).message)}finally{setBusy(false)}
  };
  return <div className="mfaVerify">
    {error&&<ErrorBox text={error}/>}
    {status.totp_enabled&&<form className="inlineForm" onSubmit={submit("totp")}><Field name="code" label="Authenticator code"/><button disabled={busy}>Verify TOTP</button></form>}
    {status.webauthn_credentials.length>0&&<button disabled={busy} onClick={()=>void webauthn()}>Use passkey / security key</button>}
    {status.recovery_codes_remaining>0&&<form className="inlineForm" onSubmit={submit("recovery")}><Field name="code" label="Recovery code"/><button disabled={busy} className="secondary">Use recovery code</button></form>}
  </div>;
}

function TOTPEnroll({onEnrolled}:{onEnrolled:(codes:string[])=>Promise<void>|void}){
  const [setup,setSetup]=useState<TOTPSetup|null>(null);
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState("");
  const begin=async()=>{
    setBusy(true);setError("");
    try{
      setSetup(await api("/api/v1/me/mfa/totp/begin",{method:"POST",body:"{}"}));
    }catch(e){setError((e as Error).message)}finally{setBusy(false)}
  };
  const confirm=async(e:FormEvent<HTMLFormElement>)=>{
    e.preventDefault();setBusy(true);setError("");
    const form=new FormData(e.currentTarget);
    try{
      const result=await api("/api/v1/me/mfa/totp/confirm",{method:"POST",body:JSON.stringify({code:form.get("code")})});
      await onEnrolled(result.recovery_codes||[]);
    }catch(x){setError((x as Error).message)}finally{setBusy(false)}
  };
  if(!setup)return <section className="card">
    <h2>Authenticator app</h2>
    <p>Enroll a TOTP authenticator compatible with RFC 6238.</p>
    {error&&<ErrorBox text={error}/>}
    <button disabled={busy} onClick={()=>void begin()}>Set up authenticator</button>
  </section>;
  return <section className="card">
    <h2>Scan authenticator QR</h2>
    {error&&<ErrorBox text={error}/>}
    <img className="totpQr" src={setup.qr_code_data_url} alt="TOTP enrollment QR code"/>
    <label><span>Manual secret</span><code className="copyValue">{setup.secret}</code></label>
    <details><summary>OTPAuth URI</summary><code className="copyValue">{setup.otpauth_url}</code></details>
    <form className="inlineForm" onSubmit={confirm}><Field name="code" label="6-digit code"/><button disabled={busy}>Confirm authenticator</button></form>
  </section>;
}

function WebAuthnEnroll({onEnrolled}:{onEnrolled:(codes:string[])=>Promise<void>|void}){
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState("");
  const enroll=async(kind:"security_key"|"passkey")=>{
    const defaultName=kind==="passkey"?"My passkey":"My security key";
    const name=window.prompt(kind==="passkey"?"Passkey name:":"Security key name:",defaultName);
    if(!name)return;
    setBusy(true);setError("");
    try{
      const result=await registerWebAuthn(kind,name);
      await onEnrolled(result.recovery_codes||[]);
    }catch(e){setError((e as Error).message)}finally{setBusy(false)}
  };
  return <section className="card">
    <h2>Passkeys and security keys</h2>
    <p>Use a platform passkey or a FIDO2/WebAuthn security key.</p>
    {error&&<ErrorBox text={error}/>}
    <div className="actions"><button disabled={busy} onClick={()=>void enroll("passkey")}>Add passkey</button><button disabled={busy} className="secondary" onClick={()=>void enroll("security_key")}>Add security key</button></div>
  </section>;
}

export function MFAChallenge({onDone}:{onDone:()=>Promise<void>}){
  const [status,setStatus]=useState<MFAStatus|null>(null);
  const [error,setError]=useState("");
  const [recoveryCodes,setRecoveryCodes]=useState<string[]>([]);
  const load=async()=>{
    try{setStatus(await api("/api/v1/me/mfa/status"))}catch(e){setError((e as Error).message)}
  };
  useEffect(()=>{void load()},[]);
  const complete=async()=>{await onDone()};
  const enrolled=async(codes:string[])=>{
    setRecoveryCodes(codes);
    await load();
    if(codes.length===0)await complete();
  };
  if(recoveryCodes.length>0)return <div className="centered"><RecoveryCodes codes={recoveryCodes} onConfirmed={()=>void complete()}/></div>;
  if(!status)return <div className="centered"><section className="card auth"><h1>Multi-factor authentication</h1>{error?<ErrorBox text={error}/>:<p>Loading MFA state…</p>}</section></div>;
  if(!status.has_primary_factor)return <div className="centered"><div className="mfaEnrollment"><section className="card"><h1>MFA enrollment required</h1><p>Enroll at least one primary factor before continuing.</p></section><TOTPEnroll onEnrolled={enrolled}/><WebAuthnEnroll onEnrolled={enrolled}/></div></div>;
  return <div className="centered"><section className="card auth"><h1>Verify multi-factor authentication</h1><p>Complete one enrolled factor to continue.</p><MFAVerifyControls status={status} onVerified={complete}/></section></div>;
}

export function MFASettings(){
  const [status,setStatus]=useState<MFAStatus|null>(null);
  const [error,setError]=useState("");
  const [busy,setBusy]=useState(false);
  const [recoveryCodes,setRecoveryCodes]=useState<string[]>([]);
  const load=async()=>{
    try{setStatus(await api("/api/v1/me/mfa/status"))}catch(e){setError((e as Error).message)}
  };
  useEffect(()=>{void load()},[]);
  if(!status)return <section className="card">{error?<ErrorBox text={error}/>:<p>Loading MFA settings…</p>}</section>;
  const afterEnroll=async(codes:string[])=>{setRecoveryCodes(codes);await load()};
  if(status.has_primary_factor&&!status.session_verified)return <section className="card"><h2>Verify MFA to manage factors</h2><p>Factor changes and recovery-code regeneration require an MFA-verified session.</p><MFAVerifyControls status={status} onVerified={load}/></section>;

  const disableTOTP=async()=>{
    if(!window.confirm("Remove the authenticator app from your account?"))return;
    setBusy(true);setError("");
    try{await api("/api/v1/me/mfa/totp",{method:"DELETE"});await load()}catch(e){setError((e as Error).message)}finally{setBusy(false)}
  };
  const removeCredential=async(id:string)=>{
    if(!window.confirm("Remove this WebAuthn credential?"))return;
    setBusy(true);setError("");
    try{await api("/api/v1/me/mfa/webauthn/"+encodeURIComponent(id),{method:"DELETE"});await load()}catch(e){setError((e as Error).message)}finally{setBusy(false)}
  };
  const regenerate=async()=>{
    if(!window.confirm("Generate a new recovery-code set? Existing unused recovery codes will stop working."))return;
    setBusy(true);setError("");
    try{
      const result=await api("/api/v1/me/mfa/recovery/regenerate",{method:"POST",body:"{}"});
      setRecoveryCodes(result.recovery_codes||[]);
      await load();
    }catch(e){setError((e as Error).message)}finally{setBusy(false)}
  };

  return <div className="mfaSettings">
    {error&&<ErrorBox text={error}/>}
    <section className="card"><h2>MFA status</h2><div className="statusGrid"><span>Required by policy</span><strong>{status.required?"Yes":"No"}</strong><span>Current session verified</span><strong>{status.session_verified?"Yes":"No"}</strong><span>Recovery codes remaining</span><strong>{status.recovery_codes_remaining}</strong></div></section>
    {recoveryCodes.length>0&&<RecoveryCodes codes={recoveryCodes}/>}
    {status.totp_enabled?<section className="card"><h2>Authenticator app</h2><p>TOTP is active.</p><button disabled={busy} className="danger" onClick={()=>void disableTOTP()}>Remove authenticator</button></section>:<TOTPEnroll onEnrolled={afterEnroll}/>}
    <WebAuthnEnroll onEnrolled={afterEnroll}/>
    <section className="card"><h2>Registered passkeys / security keys</h2>{status.webauthn_credentials.length===0?<p>No WebAuthn credentials.</p>:<div className="credentialList">{status.webauthn_credentials.map(item=><div className="detailRow" key={item.id}><div><strong>{item.display_name}</strong><span>{item.discoverable?"Passkey":"Security key"} · added {new Date(item.created_at).toLocaleString()}</span></div><button disabled={busy} className="danger compact" onClick={()=>void removeCredential(item.id)}>Remove</button></div>)}</div>}</section>
    <section className="card"><h2>Recovery codes</h2><p>{status.recovery_codes_remaining} unused codes remain.</p><button disabled={busy||!status.has_primary_factor} className="secondary" onClick={()=>void regenerate()}>Regenerate recovery codes</button></section>
  </div>;
}
