"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";
const nav = [["Dashboard","/","▦"],["Investigation","/investigations","⌕"],["Threat Graph","/threat-graph","◇"],["Geolocation","/threat-intelligence","◈"],["AI Help","/ai-investigator","✦"],["Reports","/reports","▤"],["Help","/help","?"]];

type MailboxStatus={ingestion?:{state?:string;provider?:string;provider_status?:{configured?:boolean;connected?:boolean;missing_config?:string[]};last_error?:string}};
type MailMessage={email_id:string;provider:string;provider_message_id:string;case_id?:string;received_at:string;status:string;risk_score?:number;risk_level?:string;classification?:string};
type EventItem={type?:string;message?:{provider_message_id?:string};result?:{email?:{case_id?:string}}};

function levelClass(level="LOW"){const v=level.toUpperCase();return v==="CRITICAL"?"text-red-300":v==="HIGH"?"text-orange-300":v==="MEDIUM"?"text-yellow-300":"text-emerald-300";}

export default function MailboxPage(){
  const [status,setStatus]=useState<MailboxStatus|null>(null);
  const [messages,setMessages]=useState<MailMessage[]>([]);
  const [events,setEvents]=useState<string[]>([]);
  const [provider,setProvider]=useState("gmail");
  const [address,setAddress]=useState("");
  const [username,setUsername]=useState("");
  const [password,setPassword]=useState("");
  const [host,setHost]=useState("imap.gmail.com");
  const [port,setPort]=useState("993");
  const [tls,setTls]=useState(true);
  const [error,setError]=useState("");
  const [connecting,setConnecting]=useState(false);
  const [syncing,setSyncing]=useState(false);

  async function refresh(){
    try{
      const a=await fetch(API_BASE+"/api/mailbox/status",{cache:"no-store"});
      const b=await fetch(API_BASE+"/api/mailbox/messages",{cache:"no-store"});
      const ad=await a.json(); const bd=await b.json();
      if(!a.ok) throw new Error(ad?.detail || "Mailbox status unavailable.");
      setStatus(ad); setMessages(bd.messages||[]); setError("");
    }catch(err){setError(err instanceof Error?err.message:"Unable to reach mailbox service.");}
  }

  useEffect(()=>{
    const query=new URLSearchParams(window.location.search);
    const initialLoad=window.setTimeout(()=>{
      if(query.get("oauth")==="connected") setError("Mailbox connected. Automatic analysis is running.");
      if(query.get("oauth")==="error") setError(query.get("message") || "Mailbox OAuth was not completed.");
      void refresh();
    },0);
    const timer=window.setInterval(()=>void refresh(),10000);
    let stream:EventSource|null=null;
    try{
      stream=new EventSource(API_BASE+"/api/mailbox/feed");
      stream.onmessage=(event)=>{
        try{
          const data=JSON.parse(event.data) as EventItem;
          const label=data.type || "EVENT";
          const id=data.message?.provider_message_id || data.result?.email?.case_id || "processed";
          setEvents(cur=>[(label+" · "+id),...cur].slice(0,12));
          void refresh();
        }catch{}
      };
    }catch{}
    return()=>{window.clearTimeout(initialLoad);window.clearInterval(timer);stream?.close();};
  },[]);
  async function connect(){
    setConnecting(true); setError("");
    try{
      if(provider==="gmail"||provider==="microsoft_graph"){
        const oauth=await fetch(API_BASE+"/api/mailbox/oauth/"+provider+"/start",{cache:"no-store"});
        const data=await oauth.json();
        if(!oauth.ok) throw new Error(data?.detail || "OAuth is not configured on the backend.");
        if(!data.authorization_url) throw new Error("The backend did not return an OAuth authorization URL.");
        window.location.assign(data.authorization_url);
        return;
      }
      const response=await fetch(API_BASE+"/api/mailbox/connect",{
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({
          provider:provider,
          address:address,
          username:username||address,
          password:password,
          host:host,
          port:Number(port)||993,
          tls:tls,
          permissions:["read","quarantine"]
        })
      });
      const data=await response.json();
      if(!response.ok) throw new Error(data?.detail || "Unable to connect mailbox.");
      setPassword("");
      await refresh();
    }catch(err){setError(err instanceof Error?err.message:"Unable to connect mailbox.");}
    finally{setConnecting(false);}
  }

  async function syncNow(){
    setSyncing(true); setError("");
    try{
      const response=await fetch(API_BASE+"/api/mailbox/sync",{method:"POST"});
      const data=await response.json();
      if(!response.ok) throw new Error(data?.detail || "Unable to sync mailbox.");
      await refresh();
    }catch(err){setError(err instanceof Error?err.message:"Unable to sync mailbox.");}
    finally{setSyncing(false);}
  }

  const worker=status?.ingestion;
  const configured=worker?.provider_status?.configured;
  const connected=worker?.provider_status?.connected;
  const missingConfig=worker?.provider_status?.missing_config?.join(", ");

  return <main className="min-h-screen bg-[#080c14] text-white">
    <aside className="fixed left-0 top-0 z-30 flex h-screen w-64 flex-col border-r border-slate-800 bg-[#0b101a]">
      <div className="border-b border-slate-800 px-6 py-6"><div className="text-xl font-bold">MailTrace <span className="text-blue-500">AI</span></div><div className="mt-1 text-[10px] uppercase tracking-[0.22em] text-slate-500">Email Forensics Platform</div></div>
      <nav className="flex-1 space-y-1 px-3 py-5">{nav.map(item=><Link key={item[0]} href={item[1]} className={item[0]==="Mailbox Live"?"flex items-center gap-3 rounded-lg bg-blue-500/10 px-3 py-3 text-sm text-blue-300":"flex items-center gap-3 rounded-lg px-3 py-3 text-sm text-slate-400 hover:bg-white/5 hover:text-white"}><span className="w-5 text-center">{item[2]}</span>{item[0]}</Link>)}</nav>
    </aside>
    <section className="ml-64 min-h-screen p-8"><div className="mx-auto max-w-7xl">
      <p className="text-xs uppercase tracking-[0.2em] text-blue-400">Near-real-time defensive ingestion</p>
      <h1 className="mt-2 text-3xl font-bold">Mailbox Live</h1>
      <div className="flex flex-wrap items-center justify-between gap-4"><p className="mt-2 text-sm text-slate-500">Connect a mailbox, capture new mail, analyze it automatically, and surface the forensic result here.</p><div className="flex gap-3"><button onClick={()=>document.getElementById("mailbox-connection")?.scrollIntoView({behavior:"smooth"})} className="rounded-lg border border-slate-700 px-4 py-2 text-sm font-semibold text-slate-200">Connect Mailbox</button><button disabled={syncing} onClick={()=>void syncNow()} className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold disabled:opacity-50">{syncing?"Syncing...":"Sync Mail Now"}</button></div></div>
      {error&&<div className="mt-6 rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">{error}</div>}

      <div className="mt-8 grid gap-4 md:grid-cols-4">
        <div className="rounded-xl border border-slate-800 bg-[#0d1420] p-5"><p className="text-xs uppercase text-slate-500">Worker state</p><p className="mt-3 text-2xl font-bold">{worker?.state||"STARTING"}</p><p className="mt-2 text-xs text-slate-500">{worker?.last_error||"Polling and SSE are available."}</p></div>
        <div className="rounded-xl border border-slate-800 bg-[#0d1420] p-5"><p className="text-xs uppercase text-slate-500">Provider</p><p className="mt-3 text-2xl font-bold">{worker?.provider||"gmail"}</p><p className="mt-2 text-xs text-slate-500">{configured?"Configured":missingConfig?"Missing: "+missingConfig:"Credentials not configured"}</p></div>
        <div className="rounded-xl border border-slate-800 bg-[#0d1420] p-5"><p className="text-xs uppercase text-slate-500">Analyzed mail</p><p className="mt-3 text-2xl font-bold">{messages.length}</p><p className="mt-2 text-xs text-slate-500">{connected?"Live mailbox worker":"Waiting for mailbox"}</p></div>
        <div className="rounded-xl border border-slate-800 bg-[#0d1420] p-5"><p className="text-xs uppercase text-slate-500">Quarantine</p><p className="mt-3 text-2xl font-bold text-emerald-300">OFF</p><p className="mt-2 text-xs text-slate-500">Safe default for testing</p></div>
      </div>
      <div className="mt-6 grid gap-6 lg:grid-cols-[1fr_360px]">
        <section id="mailbox-connection" className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6">
          <div className="flex items-center justify-between"><div><h2 className="font-semibold">Mailbox connection</h2><p className="mt-1 text-xs text-slate-500">Credentials are sent only to your local backend and kept in memory for this session.</p></div><button onClick={()=>void refresh()} className="rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-300">Refresh</button></div>
          <div className="mt-5 grid gap-3 md:grid-cols-2">
            <select value={provider} onChange={e=>setProvider(e.target.value)} className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm"><option value="imap">Generic IMAP — Gmail / other</option><option value="gmail">Gmail OAuth</option><option value="microsoft_graph">Microsoft Graph OAuth</option></select>
            <input value={address} onChange={e=>setAddress(e.target.value)} placeholder="Mailbox address, e.g. test@gmail.com" className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm"/>
            {provider==="imap"&&<>
              <input value={username} onChange={e=>setUsername(e.target.value)} placeholder="IMAP username (usually email)" className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm"/>
              <input type="password" value={password} onChange={e=>setPassword(e.target.value)} placeholder="Google App Password" className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm"/>
              <input value={host} onChange={e=>setHost(e.target.value)} placeholder="IMAP host" className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm"/>
              <input value={port} onChange={e=>setPort(e.target.value)} placeholder="Port" className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm"/>
              <label className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm"><input type="checkbox" checked={tls} onChange={e=>setTls(e.target.checked)}/> TLS / SSL</label>
            </>}
            <button disabled={connecting} onClick={()=>void connect()} className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold disabled:opacity-50">{connecting?"Opening connection...":provider==="imap"?"Connect & Start Worker":"Connect "+(provider==="gmail"?"Gmail":"Microsoft")}</button>
          </div>
          <p className="mt-3 text-xs text-slate-500">Gmail OAuth opens Google consent securely. For local IMAP, use imap.gmail.com, port 993, TLS, and a Google App Password—never your normal Gmail password.</p>

          <h2 className="mt-8 font-semibold">Live inbox risk feed</h2>
          <div className="mt-4 space-y-3">
            {messages.length?messages.map(item=><div key={item.email_id} className="rounded-xl border border-slate-800 bg-[#0a111c] p-4"><div className="flex items-center justify-between gap-3"><span className="font-mono text-xs text-blue-300">{item.email_id}</span><span className={"text-xs font-semibold "+levelClass(item.risk_level)}>{item.risk_level||"PENDING"} · {item.risk_score??"—"}/100</span></div><p className="mt-2 text-sm">{item.classification||"Processing"}</p><p className="mt-1 text-xs text-slate-500">{item.provider} · {item.provider_message_id} · {item.status}</p>{item.case_id&&<Link className="mt-2 inline-block text-xs text-blue-400" href={"/investigations?case_id="+encodeURIComponent(item.case_id)}>Open forensic investigation →</Link>}</div>):<p className="rounded-lg border border-dashed border-slate-700 p-8 text-center text-sm text-slate-500">No mailbox messages yet. Connect a mailbox above and then send a test email.</p>}
          </div>
        </section>
        <section className="rounded-2xl border border-slate-800 bg-[#0d1420] p-6"><h2 className="font-semibold">Processing events</h2><p className="mt-1 text-xs text-slate-500">SSE with polling fallback.</p><div className="mt-4 space-y-2">{events.length?events.map((event,index)=><div key={event+index} className="rounded-lg border border-slate-800 bg-[#0a111c] p-3 text-xs text-slate-400">{event}</div>):<p className="mt-5 text-sm text-slate-600">Waiting for mailbox activity.</p>}</div><div className="mt-8 border-t border-slate-800 pt-5"><h3 className="text-sm font-semibold">Safety controls</h3><p className="mt-3 text-xs leading-5 text-slate-500">Original email evidence is hashed. Attachments are never executed. Automatic quarantine stays OFF until explicitly enabled.</p></div></section>
      </div>
    </div></section>
  </main>;
}
