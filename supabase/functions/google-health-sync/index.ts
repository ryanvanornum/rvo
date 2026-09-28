import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders={"Access-Control-Allow-Origin":"*","Access-Control-Allow-Headers":"authorization, x-client-info, apikey, content-type"};
const TYPES=[
  ["steps","steps"],["active-minutes","active_minutes"],["active-zone-minutes","active_zone_minutes"],
  ["distance","distance"],["active-energy-burned","active_energy_burned"],["total-calories","total_calories"],
  ["daily-resting-heart-rate","daily_resting_heart_rate"],["daily-heart-rate-variability","daily_heart_rate_variability"],
  ["daily-oxygen-saturation","daily_oxygen_saturation"],["daily-respiratory-rate","daily_respiratory_rate"],
  ["daily-vo2-max","daily_vo2_max"],["sleep","sleep"]
] as const;

function ab(b:Uint8Array):ArrayBuffer{return b.buffer.slice(b.byteOffset,b.byteOffset+b.byteLength) as ArrayBuffer}
function hex(s:string){const b=new Uint8Array(s.length/2);for(let i=0;i<s.length;i+=2)b[i/2]=parseInt(s.slice(i,i+2),16);return b}
function bytesToHex(bytes:Uint8Array){return [...bytes].map((b)=>b.toString(16).padStart(2,"0")).join("")}
async function encrypt(value:string,secret:string){const d=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(secret.trim()));const k=await crypto.subtle.importKey("raw",d,"AES-GCM",false,["encrypt"]);const iv=crypto.getRandomValues(new Uint8Array(12));const cipher=await crypto.subtle.encrypt({name:"AES-GCM",iv},k,new TextEncoder().encode(value));const combined=new Uint8Array(iv.length+cipher.byteLength);combined.set(iv);combined.set(new Uint8Array(cipher),iv.length);return bytesToHex(combined)}
async function decrypt(value:string,secret:string){const d=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(secret.trim()));const k=await crypto.subtle.importKey("raw",d,"AES-GCM",false,["decrypt"]);const b=hex(value);const plain=await crypto.subtle.decrypt({name:"AES-GCM",iv:b.slice(0,12)},k,ab(b.slice(12)));return new TextDecoder().decode(plain)}
async function refresh(refreshToken:string,clientId:string,clientSecret:string){
 const r=await fetch("https://oauth2.googleapis.com/token",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:new URLSearchParams({refresh_token:refreshToken,client_id:clientId,client_secret:clientSecret,grant_type:"refresh_token"})});
 const j=await r.json(); if(!r.ok||!j.access_token)throw new Error("refresh_failed"); return j as any;
}
function isoDate(d:Date){return d.toISOString().slice(0,10)}
function n(v:any):number|null{const x=Number(v);return Number.isFinite(x)?x:null}
function firstNumber(o:any,keys:string[]):number|null{for(const k of keys){const parts=k.split(".");let v=o;for(const p of parts)v=v?.[p];const x=n(v);if(x!==null)return x}return null}
function dataPoints(j:any){return j?.dataPoints||j?.data_points||j?.items||[]}

Deno.serve(async(req)=>{
 if(req.method==="OPTIONS")return new Response(null,{headers:corsHeaders});
 const requestId=crypto.randomUUID();
 try{
  const auth=req.headers.get("Authorization"); if(!auth?.startsWith("Bearer "))return json({error:"Unauthorized",requestId},401);
  const url=Deno.env.get("SUPABASE_URL")!, anon=Deno.env.get("SUPABASE_ANON_KEY")!, serviceKey=Deno.env.get("APP_SERVICE_ROLE_KEY")||Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")||"";
  const userClient=createClient(url,anon,{global:{headers:{Authorization:auth}}}); const {data:{user}}=await userClient.auth.getUser(); if(!user)return json({error:"Unauthorized",requestId},401);
  const service=createClient(url,serviceKey); const body=await req.json().catch(()=>({}));
  const days=Math.max(1,Math.min(Number(body.days)||7,90)); const end=new Date(); const start=new Date(end); start.setUTCDate(start.getUTCDate()-days+1);
  const {data:conn,error:ce}=await service.from("health_connections").select("*").eq("user_id",user.id).eq("provider","google_health").eq("status","connected").order("updated_at",{ascending:false}).limit(1).maybeSingle();
  if(ce||!conn)return json({error:"No connected Google Health account",requestId},409);
  const key=Deno.env.get("TOKEN_ENCRYPTION_KEY"), clientId=Deno.env.get("GOOGLE_HEALTH_CLIENT_ID"), clientSecret=Deno.env.get("GOOGLE_HEALTH_CLIENT_SECRET"); if(!key||!clientId||!clientSecret)throw new Error("server_configuration_missing");
  let access=await decrypt(conn.access_token,key);
  if(!conn.token_expires_at||new Date(conn.token_expires_at).getTime()<Date.now()+60000){
   if(!conn.refresh_token)throw new Error("refresh_token_missing");
   const tok=await refresh(await decrypt(conn.refresh_token,key),clientId,clientSecret); access=tok.access_token;
   const encryptedAccess=await encrypt(tok.access_token,key);
   const update:any={access_token:encryptedAccess,token_expires_at:new Date(Date.now()+Number(tok.expires_in||3600)*1000).toISOString(),updated_at:new Date().toISOString()};
   if(tok.refresh_token) update.refresh_token=await encrypt(tok.refresh_token,key);
   await service.from("health_connections").update(update).eq("id",conn.id);
  }
  const requested=TYPES.map(([p])=>p); const {data:run}=await service.from("health_sync_runs").insert({user_id:user.id,connection_id:conn.id,status:"running",range_start:isoDate(start),range_end:isoDate(end),metrics_requested:requested}).select("id").single();
  const payloads:Record<string,any>={}; const ok:string[]=[]; const errors:any[]=[];
  for(const [path,filterName] of TYPES){
   try{
    let endpoint:string;
    if(path.startsWith("daily-")){
      const filter=`${filterName}.date >= "${isoDate(start)}" AND ${filterName}.date <= "${isoDate(end)}"`;
      endpoint=`https://health.googleapis.com/v4/users/me/dataTypes/${path}/dataPoints?filter=${encodeURIComponent(filter)}`;
    }else if(path==="sleep"){
      const filter=`sleep.interval.civil_end_time >= "${isoDate(start)}T00:00:00" AND sleep.interval.civil_end_time <= "${isoDate(end)}T23:59:59"`;
      endpoint=`https://health.googleapis.com/v4/users/me/dataTypes/sleep/dataPoints?filter=${encodeURIComponent(filter)}`;
    }else{
      const filter=`${filterName}.interval.civil_start_time >= "${isoDate(start)}T00:00:00" AND ${filterName}.interval.civil_start_time <= "${isoDate(end)}T23:59:59"`;
      endpoint=`https://health.googleapis.com/v4/users/me/dataTypes/${path}/dataPoints?filter=${encodeURIComponent(filter)}`;
    }
    const r=await fetch(endpoint,{headers:{Authorization:`Bearer ${access}`}}); const j=await r.json(); if(!r.ok)throw new Error(`${r.status}:${j?.error?.message||"api_error"}`); payloads[path]=j; ok.push(path);
   }catch(e){errors.push({metric:path,error:e instanceof Error?e.message:"unknown"});}
  }
  // Store a lossless raw snapshot per day first. Normalized columns are populated where
  // Google's response exposes a stable scalar; Phase 2 parser tests will harden each mapping.
  for(let d=new Date(start);d<=end;d.setUTCDate(d.getUTCDate()+1)){
   const date=isoDate(d); const raw:Record<string,any>={};
   for(const [path] of TYPES) raw[path]=dataPoints(payloads[path]).filter((p:any)=>JSON.stringify(p).includes(date));
   const row:any={user_id:user.id,connection_id:conn.id,metric_date:date,source_payload:raw,synced_at:new Date().toISOString()};
   const scalar=(path:string,keys:string[])=>{const p=raw[path]?.[0];return p?firstNumber(p,keys):null};
   row.resting_heart_rate_bpm=scalar("daily-resting-heart-rate",["value","restingHeartRate","dailyRestingHeartRate.bpm"]);
   row.hrv_rmssd_ms=scalar("daily-heart-rate-variability",["value","rmssd","dailyHeartRateVariability.rmssd"]);
   row.oxygen_saturation_percent=scalar("daily-oxygen-saturation",["value","percentage","dailyOxygenSaturation.percentage"]);
   row.respiratory_rate_bpm=scalar("daily-respiratory-rate",["value","rate","dailyRespiratoryRate.breathsPerMinute"]);
   row.vo2_max=scalar("daily-vo2-max",["value","vo2Max","dailyVo2Max.value"]);
   await service.from("health_daily_metrics").upsert(row,{onConflict:"connection_id,metric_date"});
  }
  const status=errors.length===0?"success":ok.length?"partial":"failure";
  if(run?.id)await service.from("health_sync_runs").update({status,metrics_succeeded:ok,errors,finished_at:new Date().toISOString()}).eq("id",run.id);
  await service.from("health_connections").update({last_synced_at:new Date().toISOString(),last_error:errors.length?JSON.stringify(errors):null}).eq("id",conn.id);
  return json({status,range:{start:isoDate(start),end:isoDate(end)},metricsSucceeded:ok,errors,requestId});
 }catch(e){console.error("[google-health-sync]",requestId,e);return json({error:e instanceof Error?e.message:"sync_failed",requestId},500)}
});
function json(body:unknown,status=200){return new Response(JSON.stringify(body),{status,headers:{...corsHeaders,"Content-Type":"application/json"}})}
