function cookie(name:string){
  const prefix=name+"=";
  const value=document.cookie.split("; ").find(x=>x.startsWith(prefix));
  return value?decodeURIComponent(value.slice(prefix.length)):"";
}

export async function api(path:string, init:RequestInit={}) {
  const method=(init.method||"GET").toUpperCase();
  const headers:Record<string,string>={"Content-Type":"application/json",...(init.headers as Record<string,string>||{})};
  if(!["GET","HEAD","OPTIONS"].includes(method)){
    const csrf=cookie("opensso_csrf");
    if(csrf)headers["X-CSRF-Token"]=csrf;
  }
  const response=await fetch(path,{credentials:"include",...init,headers});
  if(response.status===204)return null;
  const body=await response.json().catch(()=>({detail:"Invalid server response"}));
  if(!response.ok)throw new Error(body.detail||body.error||`HTTP ${response.status}`);
  return body;
}
