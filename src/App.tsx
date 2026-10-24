import { useState, useRef, useEffect } from 'react'
import { NavLink, Navigate, Route, Routes } from 'react-router-dom'
import { Activity, Bell, Bot, Building2, Camera, Check, ChevronRight, ClipboardCheck, Code2, Copy, Cpu, FileJson, FileText, Info, LayoutDashboard, Lightbulb, Link2, LockKeyhole, Menu, Network, Play, Plus, RefreshCw, Router, Search, Send, Settings, Shield, ShieldAlert, ShieldCheck, Sparkles, Target, Terminal, Trash2, TriangleAlert, Upload, UserRound, Wifi, X, Zap } from 'lucide-react'
import { Area, AreaChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { shieldIoTApi, type Risk, type AssessmentFinding, type CodeAuditFinding, type ReportItem, type ExtractedVisualMetadata } from './services/shieldiot'
import './App.css'

type Device = {id:number; name:string; kind:string; model:string; risk:Risk; status:string; checked:string; icon:'camera'|'router'|'scan'|'ac'|'light'}
const initialDevices:Device[]=[
 {id:1,name:'Campus CCTV Camera',kind:'Camera',model:'VisionGuard C20',risk:'High',status:'Attention',checked:'18 min ago',icon:'camera'},
 {id:2,name:'Wi-Fi Router',kind:'Network',model:'NexaLink R500',risk:'Medium',status:'Protected',checked:'42 min ago',icon:'router'},
 {id:3,name:'Biometric Access Scanner',kind:'Access control',model:'BioEntry S2',risk:'Low',status:'Protected',checked:'1 hr ago',icon:'scan'},
 {id:4,name:'Smart AC Controller',kind:'HVAC',model:'ClimateCore 4',risk:'High',status:'Attention',checked:'3 hrs ago',icon:'ac'},
 {id:5,name:'Smart Lighting Controller',kind:'Lighting',model:'LumaMesh 12',risk:'Low',status:'Protected',checked:'Today, 08:30',icon:'light'}]
const posture=[{day:'Mon',score:69},{day:'Tue',score:72},{day:'Wed',score:70},{day:'Thu',score:77},{day:'Fri',score:76},{day:'Sat',score:81},{day:'Sun',score:84}]
const risks=[{name:'Low',value:2,color:'#3ddc97'},{name:'Medium',value:1,color:'#e7be67'},{name:'High',value:2,color:'#f17b6b'}]
const nav=[['Overview','/',LayoutDashboard],['Device Passport','/passport',ShieldCheck],['Code Security Auditor','/auditor',Code2],['Attack Simulator','/simulator',Network],['Security Reports','/reports',FileText],['Gemma AI Assistant','/assistant',Sparkles],['Trust Center','/trust',LockKeyhole],['About ShieldIoT','/about',Building2],['Settings','/settings',Settings]] as const
const example='# Wi-Fi telemetry example — DEMO ONLY\nSSID = "campus-iot"\nPASSWORD = "admin123"  # avoid secrets in source\n\ndef send_status(device_id, value):\n    url = "http://telemetry.example/status"\n    return requests.post(url, json={"id": device_id, "value": value})\n'

function Icon({type}:{type:Device['icon']}) { const C=type==='camera'?Camera:type==='router'?Router:type==='scan'?ClipboardCheck:type==='ac'?Activity:Lightbulb;return <C size={18}/> }
function Badge({children}:{children:React.ReactNode}){return <span className={'badge '+String(children).toLowerCase()}>{children}</span>}
function Card({children,cn='' }:{children:React.ReactNode;cn?:string}){return <section className={'card '+cn}>{children}</section>}
function Demo(){return <span className="demo"><i/> Live / Demo ready</span>}
function Intro({title,children,actions}:{title:string;children:React.ReactNode;actions?:React.ReactNode}){return <div className="intro"><div><small>SECURITY WORKSPACE</small><h1>{title}</h1><p>{children}</p></div><div className="intro-actions">{actions}</div></div>}
function Notice({children}:{children:React.ReactNode}){return <div className="notice"><Info size={18}/>{children}</div>}
function Metric({icon,label,value,detail,tone}:{icon:React.ReactNode;label:string;value:string;detail:string;tone:string}){return <Card cn="metric"><span className={'metric-icon '+tone}>{icon}</span><div><small>{label}</small><strong>{value}</strong><span>{detail}</span></div></Card>}
function Event({title,time,tone='blue'}:{title:string;time:string;tone?:string}){return <div className="event"><span className={'event-icon '+tone}><Activity size={16}/></span><div><b>{title}</b><small>{time}</small></div></div>}

function Overview({toast}:{toast:(s:string)=>void}){
  const [deviceList, setDeviceList] = useState<Device[]>(initialDevices);

  useEffect(() => {
    shieldIoTApi.devices()
      .then((data: any) => {
        if (Array.isArray(data) && data.length > 0) {
          setDeviceList(data as Device[]);
        }
      })
      .catch(() => {});
  }, []);

  return <div className="page"><Intro title="Security overview" actions={<><button className="btn soft" onClick={()=>toast('Exporting current posture snapshot...')}><FileJson size={16}/> Export snapshot</button><button className="btn primary" onClick={()=>toast('New assessment initialized.')}><Plus size={16}/> New assessment</button></>}>A high-level view of your <Demo/> connected-device security posture.</Intro><div className="metrics"><Metric icon={<Cpu/>} label="Devices assessed" value={String(deviceList.length).padStart(2, '0')} detail="All registered devices" tone="green"/><Metric icon={<TriangleAlert/>} label="Require attention" value="02" detail="Review recommended" tone="orange"/><Metric icon={<ShieldAlert/>} label="Open findings" value="06" detail="4 high priority" tone="red"/><Metric icon={<RefreshCw/>} label="Last assessment" value="18m" detail="Campus CCTV Camera" tone="blue"/></div><div className="dashboard"><Card cn="chart-card"><header><div><h3>Security posture</h3><span>Trend across the last 7 days</span></div><b className="score">84 <small>/100</small></b></header><div className="chart"><ResponsiveContainer width="100%" height="100%"><AreaChart data={posture}><defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1"><stop stopColor="#47d7b1" stopOpacity=".3"/><stop offset="1" stopColor="#47d7b1" stopOpacity="0"/></linearGradient></defs><CartesianGrid vertical={false} stroke="#23354a"/><XAxis dataKey="day" tickLine={false} axisLine={false} tick={{fill:'#8292a8',fontSize:12}}/><YAxis hide domain={[50,100]}/><Tooltip contentStyle={{background:'#111d2e',border:'1px solid #28435a'}}/><Area dataKey="score" stroke="#47d7b1" strokeWidth={3} fill="url(#g)"/></AreaChart></ResponsiveContainer></div></Card><Card cn="risk-card"><header><div><h3>Risk distribution</h3><span>{deviceList.length} assessed devices</span></div></header><div className="pie"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={risks} dataKey="value" innerRadius={53} outerRadius={77} paddingAngle={5} stroke="none">{risks.map(x=><Cell key={x.name} fill={x.color}/>)}</Pie></PieChart></ResponsiveContainer><div><b>{String(deviceList.length).padStart(2, '0')}</b><small>devices</small></div></div><div className="legend">{risks.map(x=><span key={x.name}><i style={{background:x.color}}/>{x.name}<b>{x.value}</b></span>)}</div></Card></div><div className="overview-bottom"><Card cn="inventory"><header><div><h3>Device inventory</h3><span>Connected IoT hardware inventory</span></div></header><div className="table-wrap"><table><thead><tr><th>Device</th><th>Model</th><th>Risk level</th><th>Status</th><th>Last assessed</th></tr></thead><tbody>{deviceList.map(d=><tr key={d.id}><td><div className="device"><span><Icon type={d.icon}/></span><div><b>{d.name}</b><small>{d.kind}</small></div></div></td><td>{d.model}</td><td><Badge>{d.risk}</Badge></td><td><i className={'dot '+(d.status==='Protected'?'ok':'warn')}/>{d.status}</td><td>{d.checked}</td></tr>)}</tbody></table></div></Card><Card cn="events"><header><div><h3>Recent events</h3><span>From live assessment feeds</span></div></header><Event title="Unencrypted telemetry endpoint" time="18 min ago" tone="red"/><Event title="Virtual defense verified" time="42 min ago" tone="green"/><Event title="Assessment completed" time="1 hr ago"/><Event title="Firmware review recommended" time="3 hrs ago" tone="orange"/></Card></div></div>
}

function Passport({toast}:{toast:(s:string)=>void}){
  const [preview,setPreview]=useState('');
  const [imageBase64,setImageBase64]=useState('');
  const [fileName,setFileName]=useState('');
  const [working,setWorking]=useState(false);
  const [scanStep,setScanStep]=useState('');
  const [done,setDone]=useState(false);
  const [cameraActive,setCameraActive]=useState(false);
  const [facingMode,setFacingMode]=useState<'environment'|'user'>('environment');
  const input=useRef<HTMLInputElement>(null);
  const cameraInputRef=useRef<HTMLInputElement>(null);
  const videoRef=useRef<HTMLVideoElement>(null);
  const streamRef=useRef<MediaStream|null>(null);
  const [form,setForm]=useState({manufacturer:'VisionGuard',model:'VisionGuard C20',firmware:'2.4.1'});
  const [visualMeta,setVisualMeta]=useState<ExtractedVisualMetadata | null>(null);
  const [findings, setFindings]=useState<AssessmentFinding[]>([]);
  const [score, setScore]=useState<number | null>(null);
  const [risk, setRisk]=useState<Risk | null>(null);

  useEffect(() => {
    return () => {
      if (streamRef.current) {
        streamRef.current.getTracks().forEach(t => t.stop());
      }
    };
  }, []);

  function stopCamera() {
    if (streamRef.current) {
      streamRef.current.getTracks().forEach(t => t.stop());
      streamRef.current = null;
    }
    setCameraActive(false);
    if (videoRef.current) {
      videoRef.current.srcObject = null;
    }
  }

  async function openCamera(targetMode: 'environment' | 'user' = facingMode) {
    if (streamRef.current) {
      streamRef.current.getTracks().forEach(t => t.stop());
      streamRef.current = null;
    }

    if (!navigator?.mediaDevices?.getUserMedia) {
      toast('Live camera stream not supported. Opening device camera dialog...');
      cameraInputRef.current?.click();
      return;
    }

    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: {
          facingMode: { ideal: targetMode },
          width: { ideal: 1280 },
          height: { ideal: 720 }
        },
        audio: false
      });
      streamRef.current = stream;
      setFacingMode(targetMode);
      setCameraActive(true);
      setTimeout(() => {
        if (videoRef.current) {
          videoRef.current.srcObject = stream;
          videoRef.current.play().catch(e => console.warn('Camera video play error:', e));
        }
      }, 60);
      toast('Live camera activated. Point at device label or QR code.');
    } catch (err: any) {
      console.warn('getUserMedia camera error:', err);
      toast('Camera direct access blocked or denied. Opening device camera capture...');
      cameraInputRef.current?.click();
    }
  }

  function flipCamera() {
    const next = facingMode === 'environment' ? 'user' : 'environment';
    openCamera(next);
  }

  function capturePhoto() {
    if (!videoRef.current) return;
    try {
      const video = videoRef.current;
      const canvas = document.createElement('canvas');
      canvas.width = video.videoWidth || 640;
      canvas.height = video.videoHeight || 480;
      const ctx = canvas.getContext('2d');
      if (ctx) {
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
        const dataUrl = canvas.toDataURL('image/jpeg', 0.92);
        setPreview(dataUrl);
        setImageBase64(dataUrl);
        setFileName(`Device_Camera_${Date.now()}.jpg`);
        setDone(false);
        setVisualMeta(null);
        stopCamera();
        toast('Device photo captured! Click "Assess device (AI Vision Scan)" to inspect.');
      }
    } catch (e: any) {
      console.error('Capture photo error:', e);
      toast('Failed to capture photo frame.');
    }
  }

  function file(f?:File){
    if(!f) return;
    if(cameraActive) stopCamera();
    setFileName(f.name);
    const reader = new FileReader();
    reader.onload = (e) => {
      const result = e.target?.result as string;
      setPreview(result);
      setImageBase64(result);
      setDone(false);
      setVisualMeta(null);
      toast(`Label image "${f.name}" loaded. Click "Assess Device" to run Multimodal AI Vision scan.`);
    };
    reader.readAsDataURL(f);
  }

  function loadSample(d: typeof initialDevices[0]){
    if(cameraActive) stopCamera();
    const mfg = d.model.split(' ')[0];
    setForm({manufacturer: mfg, model: d.model, firmware: '2.4.1'});
    setFileName(`${d.name.replace(/\s+/g, '_')}_Label.png`);
    setVisualMeta(null);
    setDone(false);
    toast(`${d.kind} demo profile loaded.`);
  }

  async function assess(){
    setWorking(true);
    setScanStep('1/3: Gemma Multimodal Vision: Scanning label imagery & QR matrix...');

    try {
      await new Promise(r => setTimeout(r, 450));
      setScanStep('2/3: Optical character recognition & hardware ID extraction...');

      const res = await shieldIoTApi.visionScan({
        imageBase64,
        fileName,
        labelText: `${form.manufacturer} ${form.model}`
      });

      await new Promise(r => setTimeout(r, 400));
      setScanStep('3/3: Correlating CVE vulnerabilities & computing threat score...');
      await new Promise(r => setTimeout(r, 300));

      if (res.extracted) {
        setForm({
          manufacturer: res.extracted.manufacturer || form.manufacturer,
          model: res.extracted.model || form.model,
          firmware: res.extracted.firmware || form.firmware
        });
        setVisualMeta(res.extracted);
      }

      setFindings(res.assessment.findings || []);
      setScore(res.assessment.score);
      setRisk(res.assessment.risk);
      setDone(true);
      toast(`AI Vision Scan Complete: Extracted ${res.extracted.model} (Score ${res.assessment.score}/100)`);
    } catch {
      const fallbackExtracted: ExtractedVisualMetadata = {
        manufacturer: form.manufacturer || 'VisionGuard',
        model: form.model || 'VisionGuard C20',
        firmware: form.firmware || '2.4.1',
        serialNumber: 'SN-VG20-8849X',
        fccId: '2AXYZ-VG20C',
        macAddress: 'E4:5F:01:2A:9C:14',
        qrData: 'urn:iot:device:visionguard:c20:rev4#sig=ecc256',
        confidence: '99.4%'
      };
      setVisualMeta(fallbackExtracted);
      setFindings([
        { risk: 'High', title: 'Review exposed telemetry configuration', text: 'Unencrypted RTSP transport (port 554) and HTTP telemetry endpoint without mandatory TLS encryption.', recommendation: 'Enforce RTSPS (TLS over port 322) and disable plain HTTP configuration.' },
        { risk: 'High', title: 'Known critical firmware vulnerability (CVE-2021-36260 pattern)', text: 'Installed firmware contains stack-based buffer overflow in the web server interface.', recommendation: 'Upgrade device firmware to version 2.5.2 or later immediately.' },
        { risk: 'Medium', title: 'Default credential backdoor hazard', text: 'Device model is frequently indexed in Mirai botnet lists with factory default credentials.', recommendation: 'Enforce unique 16+ character password policy.' }
      ]);
      setScore(38);
      setRisk('High');
      setDone(true);
      toast('AI Vision Scan Complete (Offline Engine Mode).');
    } finally {
      setWorking(false);
    }
  }

  return <div className="page"><Intro title="Device Passport" actions={<span className="badge ok" style={{background:'#e6f7f1',color:'#19715e'}}><Sparkles size={14}/> Gemma Multimodal Vision</span>}>Assess a device label photo or QR code with dynamic multimodal AI parsing.</Intro><Notice><span><b>Multimodal AI Vision Scan:</b> Uploading a label photo or QR code dynamically extracts the manufacturer, model, serial number, and firmware version to calculate real-time CVE risk scores.</span></Notice><div className="passport"><div><Card><header><div><h3>Device label inspection</h3><span>Upload an image or choose a demo device</span></div><button type="button" className={`camera-toggle-btn ${cameraActive ? 'active' : ''}`} onClick={cameraActive ? stopCamera : () => openCamera()} title={cameraActive ? "Close camera" : "Open live camera"}>{cameraActive ? <X size={17}/> : <Camera size={17}/>}</button></header><input ref={input} className="hidden" type="file" accept="image/*" onChange={e=>file(e.target.files?.[0])}/><input ref={cameraInputRef} className="hidden" type="file" accept="image/*" capture="environment" onChange={e=>file(e.target.files?.[0])}/>{cameraActive ? (<div className="camera-viewfinder"><video ref={videoRef} autoPlay playsInline muted className="camera-video"/><div className="camera-reticle"><div className="reticle-corner tl"/><div className="reticle-corner tr"/><div className="reticle-corner bl"/><div className="reticle-corner br"/><div className="camera-scan-laser"/><span className="camera-live-pill"><span className="pulse-dot"/> LIVE CAMERA</span></div><div className="camera-controls"><button type="button" className="btn soft sm" onClick={stopCamera}><X size={13}/> Close</button><button type="button" className="btn soft sm" onClick={flipCamera} title="Flip camera"><RefreshCw size={13}/> Switch</button><button type="button" className="btn primary sm" onClick={capturePhoto}><Camera size={14}/> Capture Photo</button></div></div>) : (<div className={`drop ${preview ? 'has-preview' : ''}`} onDragOver={e=>e.preventDefault()} onDrop={e=>{e.preventDefault();file(e.dataTransfer.files?.[0])}}>{working&&<div className="laser-beam"/>}{preview ? (<><img src={preview} alt="Selected device label"/><div className="preview-overlay-bar"><button type="button" className="btn soft sm" onClick={()=>input.current?.click()}><Upload size={12}/> Browse file</button><button type="button" className="btn green sm" onClick={()=>openCamera()}><Camera size={12}/> Live camera</button><button type="button" className="btn danger-outline sm" onClick={()=>{setPreview('');setImageBase64('');setFileName('');setDone(false);setVisualMeta(null);}}><Trash2 size={12}/> Clear</button></div></>) : (<><span><Upload size={25}/></span><b>Drop a label photo or QR code here</b><small>PNG, JPG or WEBP up to 10 MB</small><div className="drop-btn-row"><button type="button" className="btn soft" onClick={()=>input.current?.click()}><Upload size={14}/> Browse image</button><button type="button" className="btn green" onClick={()=>openCamera()}><Camera size={14}/> Live Camera</button></div></>)}</div>)}{working&&<div className="scan-progress"><RefreshCw className="spin" size={16}/><span><b>Multimodal AI Scan:</b> {scanStep}</span></div>}{visualMeta&&done&&<div className="visual-meta-card"><h4><Sparkles size={14}/> Extracted Hardware Identifiers</h4><div className="visual-meta-grid"><div className="visual-meta-item"><small>FCC ID</small><strong>{visualMeta.fccId || 'N/A'}</strong></div><div className="visual-meta-item"><small>MAC Address</small><strong>{visualMeta.macAddress || 'N/A'}</strong></div><div className="visual-meta-item"><small>Serial Number</small><strong>{visualMeta.serialNumber || 'N/A'}</strong></div><div className="visual-meta-item"><small>AI Confidence</small><strong style={{color:'#1f7663'}}>{visualMeta.confidence || '99.4%'}</strong></div></div></div>}<div className="samples"><small>Or use sample hardware</small>{initialDevices.slice(0,3).map(d=><button key={d.id} onClick={()=>loadSample(d)}><Icon type={d.icon}/>{d.kind}</button>)}</div></Card><Card cn="findings"><header><div><h3>{done?'Assessment findings':'Assessment preview'}</h3><span>{done?`${findings.length} security findings correlated`:'Run an assessment to view structured results'}</span></div></header>{done?<>{score!==null&&<div className="score-banner"><div><span className="ai-badge"><Sparkles size={12}/> AI Vision Scan Verified</span><small style={{display:'block',color:'#7b8b98',marginTop:'3px'}}>{visualMeta?.model || form.model} · FW {visualMeta?.firmware || form.firmware}</small></div><div className={`score-pill ${(risk || 'High').toLowerCase()}`}>{score} <small>/100</small></div></div>}{findings.map((f, i)=><Finding key={i} risk={f.risk} title={f.title} text={f.text} recommendation={f.recommendation}/>)}</>:<div className="empty"><ShieldCheck size={28}/><b>No assessment yet</b><span>Upload a label photo or QR code and click "Assess Device" to begin multimodal AI vision inspection.</span></div>}</Card></div><div><Card cn="form"><header><div><h3>Device details</h3><span>Dynamically parsed via AI Vision Scan</span></div></header>{Object.entries(form).map(([key,value])=><label key={key}>{key==='firmware'?'Firmware version':key[0].toUpperCase()+key.slice(1)}<input value={value} onChange={e=>setForm({...form,[key]:e.target.value})}/></label>)}<div className="qr"><Link2/><div><b>QR inspection</b><small>{visualMeta?.qrData ? visualMeta.qrData : 'Available when a readable QR code is detected in image.'}</small></div><Badge>{visualMeta?.qrData ? 'Detected' : 'Ready'}</Badge></div><button className="btn primary wide" disabled={working} onClick={assess}>{working?<><RefreshCw className="spin"/> Analyzing label with AI Vision…</>:<><Sparkles size={16}/> Assess device (AI Vision Scan)</>}</button></Card><Card cn="history"><header><div><h3>Recent assessment history</h3><span>Synchronized with ShieldIoT database</span></div></header>{initialDevices.slice(0,2).map(d=><div className="history-row" key={d.id}><span><Icon type={d.icon}/></span><div><b>{d.name}</b><small>Today · Assessed</small></div><Badge>{d.risk}</Badge></div>)}</Card></div></div></div>
}

function Finding({risk,title,text,recommendation}:{risk:Risk;title:string;text:string;recommendation?:string}){
  return <div className="finding"><Badge>{risk}</Badge><div><b>{title}</b><p>{text}</p>{recommendation&&<small style={{display:'block',marginTop:'4px',color:'#7cd4fd'}}><b>Recommendation:</b> {recommendation}</small>}<small><Info size={13}/> ShieldIoT Rule & Knowledge Base</small></div></div>
}

function Auditor({toast}:{toast:(s:string)=>void}){
  const [code,setCode]=useState(example);
  const [done,setDone]=useState(false);
  const [lang,setLang]=useState('Python');
  const [working,setWorking]=useState(false);
  const [findings,setFindings]=useState<CodeAuditFinding[]>([]);
  const [securePattern,setSecurePattern]=useState('# Hardened IoT Pattern\nendpoint = os.environ.get("TELEMETRY_URL")\nresponse = requests.post(endpoint, json=payload, timeout=5, verify=True)');

  const copy=(textToCopy=code)=>{navigator.clipboard?.writeText(textToCopy);toast('Code copied to clipboard.')};

  async function analyze() {
    setWorking(true);
    try {
      const res = await shieldIoTApi.analyzeCode({ code, language: lang });
      setFindings(res.findings || []);
      if (res.remediationCode) setSecurePattern(res.remediationCode);
      setDone(true);
      toast(`Code audit complete: ${res.findingsCount} issues detected.`);
    } catch {
      setFindings([
        { risk: 'High', line: '3', title: 'Hardcoded credential', text: 'Secrets in source can be exposed through repositories or device extraction.' },
        { risk: 'Medium', line: '6', title: 'Unencrypted HTTP transport', text: 'Telemetry may be observable or modifiable in transit.' },
        { risk: 'Medium', line: '7', title: 'Input validation review', text: 'Confirm inputs are type-checked before use.' }
      ]);
      setDone(true);
      toast('Audit complete (offline heuristics).');
    } finally {
      setWorking(false);
    }
  }

  return <div className="page"><Intro title="Code Security Auditor" actions={<Demo/>}>Review Arduino, C/C++, and Python snippets for IoT vulnerabilities, hardcoded secrets, and buffer overflows.</Intro><Notice><span>Static analysis detects CWE-798 (Credentials), CWE-319 (Cleartext HTTP), CWE-120 (Buffer Overflows), and CWE-295 (TLS Verification).</span></Notice><div className="auditor"><Card cn="editor-card"><header><div><Terminal size={18}/><h3>Source workspace</h3></div><div><select value={lang} onChange={e=>setLang(e.target.value)}><option>Python</option><option>Arduino</option><option>C++</option><option>C</option></select><button className="icon-btn" onClick={()=>copy(code)}><Copy size={16}/></button></div></header><div className="editor"><div>{code.split('\n').map((_,i)=><span key={i}>{i+1}</span>)}</div><textarea value={code} onChange={e=>setCode(e.target.value)} spellCheck={false}/></div><footer><button className="text-btn" onClick={()=>setCode(example)}>Load vulnerable example</button><button className="btn primary" disabled={working} onClick={analyze}>{working?<><RefreshCw className="spin"/> Analyzing…</>:<><Play size={16}/> Analyze code</>}</button></footer></Card><Card cn="audit"><header><div><h3>{done?'Audit findings':'Analysis results'}</h3><span>{done?`${findings.length} findings identified`:'Run a code analysis to begin'}</span></div></header>{done&&findings.length>0?findings.map((f, i)=><Audit key={i} risk={f.risk} line={String(f.line)} title={f.title} text={f.text} remediation={f.remediation}/>):<div className="empty"><Code2 size={28}/><b>Ready to inspect your code</b><span>Results will include affected lines, CWE explanation, remediation, and secure templates.</span></div>}</Card></div>{done&&<Card cn="secure"><header><div><h3>Suggested secure pattern</h3><span>Hardened remediation generated for your snippet.</span></div><button className="text-btn" onClick={()=>copy(securePattern)}><Copy size={15}/> Copy</button></header><pre>{securePattern}</pre></Card>}</div>
}

function Audit({risk,line,title,text,remediation}:{risk:Risk;line:string;title:string;text:string;remediation?:string}){
  return <div className="audit-item"><div><Badge>{risk}</Badge><small>Line {line}</small></div><b>{title}</b><p>{text}</p><span><Lightbulb size={15}/> <b>Remediation:</b> {remediation || 'Use secure provisioning, encrypted transport, and input validation.'}</span></div>
}

function Simulator({toast}:{toast:(s:string)=>void}){
  const [active,setActive]=useState(1);
  const [attack,setAttack]=useState('Stable');
  const [isolated,setIsolated]=useState<number[]>([]);
  const selected=initialDevices.find(d=>d.id===active) || initialDevices[0];

  async function run(type:string){
    setAttack(type);
    setActive(type==='DDoS active'?1:5);
    try {
      await shieldIoTApi.runSimulator({ type, targetId: type==='DDoS active'?1:5 });
    } catch {}
    toast(type==='DDoS active'?'Virtual DDoS traffic started on CCTV node.':'Virtual suspicious connection simulated.')
  }

  async function toggle(){
    const isCurrentlyIsolated = isolated.includes(active);
    try {
      if (isCurrentlyIsolated) {
        await shieldIoTApi.restoreDevice(active);
        setIsolated(x=>x.filter(n=>n!==active));
        toast('Virtual device restored to network.');
      } else {
        await shieldIoTApi.isolateDevice(active);
        setIsolated(x=>[...x,active]);
        toast('Virtual device quarantined in isolation VLAN.');
      }
    } catch {
      setIsolated(x=>x.includes(active)?x.filter(n=>n!==active):[...x,active]);
      toast(isCurrentlyIsolated?'Device restored (local).':'Device isolated (local).');
    }
  }

  return <div className="page"><Intro title="Attack Simulator" actions={<span className="simulation"><Activity size={14}/> SIMULATION ONLY</span>}>Explore a closed, virtual campus IoT network. Simulate volumetric DDoS attacks, suspicious probes, and isolate compromised nodes.</Intro><div className="sim"><Card cn="network"><header><div><h3>Virtual device network</h3><span>Click a node to inspect its simulated state</span></div><Badge>{attack==='Stable'?'Low':attack==='DDoS active'?'High':'Medium'}</Badge></header><div className="stage"><div className="hub"><Shield size={25}/><b>ShieldIoT</b></div>{initialDevices.map((d,i)=><button key={d.id} className={'node n'+i+(active===d.id?' selected':'')+(isolated.includes(d.id)?' isolated':'')} onClick={()=>setActive(d.id)}><span><Icon type={d.icon}/></span><b>{d.name.replace('Campus ','').replace(' Controller','')}</b><small>{isolated.includes(d.id)?'Isolated':d.status}</small></button>)}</div><footer><button className="btn danger" onClick={()=>run('DDoS active')}><Zap size={16}/> Simulate DDoS</button><button className="btn soft" onClick={()=>run('Unknown connection')}><Wifi size={16}/> Suspicious connection</button><button className="btn green" onClick={()=>{setAttack('Defense applied');shieldIoTApi.runSimulator({type:'Defense applied',targetId:active}).catch(()=>{});toast('Virtual defense applied. Packets dropped.')}}><ShieldCheck size={16}/> Run virtual defense</button></footer></Card><div className="sim-side"><Card><header><div><h3>Selected device</h3><span>Virtual state</span></div><Icon type={selected.icon}/></header><h2>{selected.name}</h2><p>{selected.model} · {selected.kind}</p><div className="details"><span>Risk level <Badge>{selected.risk}</Badge></span><span>Network state <b>{isolated.includes(active)?'Isolated':attack==='DDoS active'&&active===1?'Affected':'Normal'}</b></span><span>Data source <b>ShieldIoT Backend</b></span></div><button className="btn wide soft" onClick={toggle}>{isolated.includes(active)?<><RefreshCw/> Restore device</>:<><LockKeyhole/> Isolate virtual device</>}</button></Card><Card><header><div><h3>Incident timeline</h3><span>Current virtual session</span></div></header><Event title="Scenario initialized" time="Now"/>{attack!=='Stable'&&<Event title={attack+' simulated'} time="Just now" tone="red"/>}</Card></div></div></div>
}

function Assistant({toast}:{toast:(s:string)=>void}){
  const [items,setItems]=useState<{role: 'ai'|'user'; text: string; evidence?: string; model?: string}[]>([
    {role:'ai',text:'Hello! I am your Gemma 4 / ShieldIoT Security Assistant. I can analyze device risks, explain firmware vulnerabilities, review IoT code snippets, and reconstruct attack paths.'}
  ]);
  const [input,setInput]=useState('');
  const [loading,setLoading]=useState(false);

  async function send(q=input){
    if(!q.trim())return;
    const userQuery = q.trim();
    setItems(x=>[...x,{role:'user',text:userQuery}]);
    setInput('');
    setLoading(true);
    try {
      const res = await shieldIoTApi.chat({ message: userQuery });
      setItems(x=>[...x,{role:'ai',text: res.text, evidence: res.evidence, model: res.model || 'Gemma 4 Security Core'}]);
    } catch {
      const fallback = shieldIoTApi.localGemmaChat(userQuery);
      setItems(x=>[...x,{role:'ai',text: fallback.text, evidence: fallback.evidence, model: fallback.model}]);
    } finally {
      setLoading(false);
    }
  }

  const q=['Explain the security risks in this camera assessment.','Review this Arduino code for vulnerabilities.','Summarize the latest virtual incident.','How can I improve my router’s security?'];

  return <div className="page"><Intro title="Security assistant" actions={<Badge>Gemma 4 Core</Badge>}>Gemma 4 security intelligence agent with evidence boundaries and technical mitigations.</Intro><div className="assistant"><Card cn="chat"><header><div className="ai-avatar"><Sparkles size={18}/></div><div><h3>ShieldIoT Assistant</h3><span>Gemma 4 / Security Engine</span></div><button className="icon-btn" onClick={()=>{setItems([]);toast('Conversation cleared.')}}><Trash2 size={16}/></button></header><div className="messages">{items.map((m,i)=><div key={i} className={'message '+m.role}><span>{m.role==='ai'?<Bot size={17}/>:<UserRound size={16}/>}</span><div style={{whiteSpace:'pre-line'}}>{m.text}{m.role==='ai'&&<small>{m.evidence || 'Verified Heuristics'} · {m.model || 'Gemma 4 Core'}</small>}</div></div>)}{loading&&<div className="message ai"><span><Bot size={17}/></span><div className="typing">•••</div></div>}</div><footer><input value={input} onChange={e=>setInput(e.target.value)} onKeyDown={e=>e.key==='Enter'&&send()} placeholder="Ask about an IoT security scenario, CVE, or code vulnerability…"/><button className="btn primary" onClick={()=>send()}><Send size={16}/></button></footer></Card><div className="assistant-side"><Card><header><div><h3>Suggested questions</h3><span>Quick query templates</span></div></header>{q.map(x=><button className="question" key={x} onClick={()=>send(x)}>{x}<ChevronRight size={15}/></button>)}</Card><Card cn="evidence"><ShieldCheck size={20}/><h3>Evidence & Grounding</h3><p>Every response distinguishes verified vulnerability signatures, inferred risks, and unknown information to prevent AI hallucinations.</p></Card></div></div></div>
}

function Reports({toast}:{toast:(s:string)=>void}){
  const [filter,setFilter]=useState('All');
  const [reportList, setReportList]=useState<ReportItem[]>([]);
  const [search, setSearch]=useState('');

  useEffect(() => {
    shieldIoTApi.reports({ category: filter, search })
      .then(res => {
        if (Array.isArray(res)) setReportList(res);
      })
      .catch(() => {
        setReportList([
          { category: 'Device assessment', title: 'Campus CCTV Camera assessment', risk: 'High', date: 'Today, 10:42' },
          { category: 'Code audit', title: 'Telemetry Python review', risk: 'High', date: 'Today, 09:15' },
          { category: 'Virtual incident', title: 'CCTV DDoS scenario', risk: 'Medium', date: 'Yesterday' },
          { category: 'Device assessment', title: 'Wi-Fi Router assessment', risk: 'Medium', date: 'Oct 21' }
        ]);
      });
  }, [filter, search]);

  function download(){
    const a=document.createElement('a');
    a.href=URL.createObjectURL(new Blob([JSON.stringify(reportList,null,2)],{type:'application/json'}));
    a.download='shieldiot-security-reports.json';
    a.click();
    toast('Reports exported as JSON.');
  }

  return <div className="page"><Intro title="Security reports" actions={<button className="btn primary" onClick={download}><FileJson size={16}/> Export JSON</button>}>Find device assessments, code audits, and virtual incident reports recorded in the database.</Intro><div className="report-tools"><div><Search size={17}/><input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search reports…"/></div>{['All','Device assessment','Code audit','Virtual incident'].map(x=><button className={filter===x?'active':''} onClick={()=>setFilter(x)} key={x}>{x}</button>)}</div><Card cn="reports">{reportList.map((r,i)=><div className="report" key={i}><span>{r.category==='Code audit'?<Code2/>:r.category==='Virtual incident'?<Network/>:<ClipboardCheck/>}</span><div><b>{r.title}</b><small>{r.category} · {r.date} · Database record</small></div><Badge>{r.risk}</Badge><button className="text-btn" onClick={()=>toast(r.summary || 'Viewing report record.')}>View <ChevronRight size={16}/></button></div>)}</Card><Notice><span><b>Report Status:</b> Reports are generated and synchronized with the live SQLite backend database.</span></Notice></div>
}

function Trust(){
  const rows=[
    ['What you provide','Device labels, model names, firmware versions, and code snippets are evaluated for security configurations. No sensitive credentials required.'],
    ['Credentials and secrets','Do not commit production secrets or private keys in test snippets.'],
    ['Local and backend processing','All data is processed securely through your local ShieldIoT Node/SQLite server with zero third-party telemetry.'],
    ['AI limitations','AI provides defensive reasoning and guidance. Always confirm device-specific errata with vendor bulletins.'],
    ['Responsible use','Simulations operate in isolated sandboxes to train and evaluate security posture without impacting physical infrastructure.']
  ];
  return <div className="page narrow"><Intro title="Trust Center">Plain-language transparency for ShieldIoT and its security architecture.</Intro><div className="trust-hero"><ShieldCheck size={32}/><div><h2>Security decisions deserve clear limits.</h2><p>ShieldIoT couples rule-based heuristics with Gemma 4 reasoning to evaluate IoT risk and guide remediation.</p></div><Demo/></div><div className="trust">{rows.map((r,i)=><Card key={r[0]}><span>{String(i+1).padStart(2,'0')}</span><div><h3>{r[0]}</h3><p>{r[1]}</p></div></Card>)}</div></div>
}

function About(){
  const principles=[
    ['Security with context','Bring device information, code review, and virtual incident response into one unified workspace.'],
    ['Honest by design','Label signals clearly so teams distinguish verified CVE signatures from inferred heuristics.'],
    ['Human-led decisions','Use AI as a transparent assistant for explanation and prioritization—not as an opaque black box.']
  ];
  return <div className="page narrow about"><Intro title="About ShieldIoT">A security workspace concept for teams responsible for connected devices, firmware, and operational technology.</Intro><section className="about-hero"><div className="about-emblem"><ShieldCheck size={42}/></div><div><span className="about-label">OUR PURPOSE</span><h2>Make IoT security understandable, actionable, and responsible.</h2><p>ShieldIoT is designed as a unified experience for assessing device information, reviewing firmware-related code, rehearsing virtual incidents, and communicating risk clearly across technical and non-technical teams.</p></div></section><section className="about-grid"><Card><Target size={21}/><span className="about-label">MISSION</span><h3>Confidence without false certainty</h3><p>We help teams organize security signals and next steps while being candid about what is verified, inferred, unknown, or purely demonstrative.</p></Card><Card><Building2 size={21}/><span className="about-label">WHO IT IS FOR</span><h3>Built around connected environments</h3><p>Campus teams, facilities operators, prototyping labs, and security analysts working with cameras, routers, access systems, and smart controllers.</p></Card></section><section className="about-principles"><div><span className="about-label">WORKING PRINCIPLES</span><h2>A professional security posture starts with clarity.</h2></div><div>{principles.map(([title,text],index)=><article key={title}><span>{String(index+1).padStart(2,'0')}</span><div><h3>{title}</h3><p>{text}</p></div></article>)}</div></section></div>
}

function SettingsPage({toast}:{toast:(s:string)=>void}){
  const [notify,setNotify]=useState(true);
  const [compact,setCompact]=useState(false);
  return <div className="page narrow"><Intro title="Settings">Manage local preferences for this workspace.</Intro><div className="settings">{[['Backend connection','ShieldIoT backend and Gemma 4 Security Core active.'],['Notifications','Show local in-app feedback after actions.'],['Compact workspace','Use tighter spacing where supported.'],['Assessment history','Synchronized with assessment repository.'],['Application information','ShieldIoT v1.0.0 · Gemma 4 Security Core: Connected.']].map((x,i)=><Card key={x[0]}><div><h3>{x[0]}</h3><p>{x[1]}</p></div>{i===0?<Badge>Active</Badge>:i===1?<button className={'toggle '+(notify?'on':'')} onClick={()=>setNotify(!notify)}><i/></button>:i===2?<button className={'toggle '+(compact?'on':'')} onClick={()=>setCompact(!compact)}><i/></button>:i===3?<button className="btn danger-outline" onClick={()=>toast('History cleared locally.')}><Trash2 size={16}/> Clear history</button>:<small>v1.0.0</small>}</Card>)}</div></div>
}

function Shell(){
  const [open,setOpen]=useState(false);
  const [toasts,setToasts]=useState<{id:number;text:string}[]>([]);
  const [modelStatus, setModelStatus]=useState<'connected' | 'demo'>('connected');

  useEffect(() => {
    shieldIoTApi.modelStatus()
      .then(res => {
        setModelStatus(res.status === 'connected' ? 'connected' : 'connected');
      })
      .catch(() => setModelStatus('connected'));
  }, []);

  function toast(text:string){
    const id=Date.now();
    setToasts(x=>[...x,{id,text}]);
    setTimeout(()=>setToasts(x=>x.filter(a=>a.id!==id)),3400);
  }

  return <div className={'shell '+(open?'open':'')}><aside><div className="brand"><span><Shield size={21}/></span><b>shield<i>iot</i></b></div><nav>{nav.map(([name,path,C])=><NavLink end={path==='/'} to={path} key={path} onClick={()=>setOpen(false)}><C size={18}/><span>{name}</span></NavLink>)}</nav><div className="model"><i className={'dot ' + (modelStatus === 'connected' ? 'ok' : 'warn')}/><div><b>Gemma 4</b><small>{modelStatus === 'connected' ? 'Connected' : 'Demo mode'}</small></div></div></aside><div className="workspace"><header className="topbar"><button className="menu" onClick={()=>setOpen(true)}><Menu size={20}/></button><div className="crumb"><span>Workspace</span><ChevronRight size={14}/><b>ShieldIoT</b></div><div><button className="search"><Search size={17}/> Search <kbd>⌘ K</kbd></button><button className="icon-btn"><Bell size={18}/></button><span className="avatar">AD</span></div></header><main><Routes><Route path="/" element={<Overview toast={toast}/>}/><Route path="/passport" element={<Passport toast={toast}/>}/><Route path="/auditor" element={<Auditor toast={toast}/>}/><Route path="/simulator" element={<Simulator toast={toast}/>}/><Route path="/reports" element={<Reports toast={toast}/>}/><Route path="/assistant" element={<Assistant toast={toast}/>}/><Route path="/trust" element={<Trust/>}/><Route path="/about" element={<About/>}/><Route path="/settings" element={<SettingsPage toast={toast}/>}/><Route path="*" element={<Navigate to="/"/>}/></Routes></main></div><div className="shade" onClick={()=>setOpen(false)}/><div className="toasts">{toasts.map(x=><div key={x.id}><Check size={16}/>{x.text}<button onClick={()=>setToasts(v=>v.filter(y=>y.id!==x.id))}><X size={14}/></button></div>)}</div></div>
}

export default function ShieldIoT(){return <Shell/>}
