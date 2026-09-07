const csrf = document.querySelector('meta[name="csrf-token"]').content;
const state = {settings:null, doctor:null, status:null, serverOnline:false, busy:false, currentSession:'', initPreviewed:false, previewedShares:new Set()};
const $ = id => document.getElementById(id);

async function api(path, method='GET', body) {
  const options = {method, headers:{'X-CSRF-Token':csrf}};
  if (body !== undefined) { options.headers['Content-Type']='application/json'; options.body=JSON.stringify(body); }
  const response = await fetch(path, options);
  const data = await response.json().catch(()=>({}));
  if (!response.ok) throw new Error(data.error || response.statusText || '请求失败');
  return data;
}

function toast(message, error=false) {
  $('toastText').textContent = message;
  $('toastIcon').textContent = error ? '!' : '✓';
  $('toast').className = error ? 'show error' : 'show';
  clearTimeout(toast.timer); toast.timer=setTimeout(()=>$('toast').className='', 4200);
}

function humanError(error) {
  const text = String(error?.message || error);
  const known = [
    ['Administrator privileges are required','需要管理员权限，请以管理员身份重新启动 TrafficShare'],
    ['invalid username or password','用户名或密码不正确'],
    ['provider unavailable','当前没有可用的 Provider'],
    ['Provider is not reachable','Provider 与本机不在可直连的局域网'],
    ['conflict','当前设备已有活动连接，或资源发生冲突'],
    ['quota exhausted','共享额度已经用尽'],
    ['authentication required','请先登录'],
    ['invalid or expired token','登录已过期，请重新登录'],
    ['receiver account not found','没有找到接收方账号；请让同学先连接同一个控制服务器完成注册，再输入他的精确用户名']
  ];
  for (const [needle, translated] of known) if (text.includes(needle)) return translated;
  return text;
}

function formatBytes(value) {
  let n=Number(value||0); const units=['B','KB','MB','GB','TB']; let i=0;
  while (n>=1000 && i<units.length-1) { n/=1000; i++; }
  return `${n.toFixed(i===0?0:n>=100?0:n>=10?1:2)} ${units[i]}`;
}
function formatDate(value) { if(!value) return '—'; const d=new Date(value); return Number.isNaN(d.getTime())?'—':d.toLocaleString('zh-CN',{hour12:false}); }
function statusText(value) { return ({active:'使用中',stopped:'已停止',expired:'已到期',exhausted:'额度用尽',revoked:'已撤销',disconnected:'已断开',pending:'准备中'})[value] || value || '未知'; }
function setText(id, value) { const el=$(id); if(el) el.textContent=value ?? '—'; }

async function withOperation(button, title, details, task) {
  if(state.busy){toast('已有操作正在执行，请等待完成',true);return;}
  state.busy=true; const oldText=button.textContent, oldDisabled=button.disabled; button.disabled=true; button.textContent='处理中…';
  $('operationTitle').textContent=title; $('operationDetail').textContent=details[0]; $('operationProgress').className=''; $('operationOverlay').hidden=false; document.body.setAttribute('aria-busy','true');
  let index=0; const timer=setInterval(()=>{$('operationDetail').textContent=details[Math.min(++index,details.length-1)]},2600);
  try { const result=await task(); $('operationProgress').className='complete'; $('operationDetail').textContent='操作已完成，正在刷新状态…'; await new Promise(resolve=>setTimeout(resolve,380)); return result; }
  finally { clearInterval(timer); $('operationOverlay').hidden=true; document.body.removeAttribute('aria-busy'); state.busy=false; button.textContent=oldText; button.disabled=button.id==='disconnectButton'?!state.currentSession:oldDisabled; renderSteps(); }
}

function gotoPage(page) {
  document.querySelectorAll('.page').forEach(p=>p.classList.toggle('active',p.id===page));
  document.querySelectorAll('.nav-item').forEach(b=>b.classList.toggle('active',b.dataset.page===page));
  if (page==='provider') providerShares(); if(page==='consumer') shares(); if(page==='session') refreshStatus(); if(page==='diagnostics') doctor();
}
document.querySelectorAll('[data-page]').forEach(b=>b.addEventListener('click',()=>gotoPage(b.dataset.page)));
document.querySelectorAll('[data-goto]').forEach(b=>b.addEventListener('click',()=>gotoPage(b.dataset.goto)));
$('primaryAction').onclick=()=>gotoPage($('primaryAction').dataset.page||'account');

function applySettings(s) {
  state.settings=s;
  $('role').value=s.role; $('role').disabled=s.role_locked; $('serverURL').value=s.server_url; $('serverURL').disabled=s.embedded_server; $('deviceName').value=s.device_name||'';
  setText('roleHint',s.role_locked?'此启动器已锁定设备角色。':'角色或服务器变化后需要重新登录并注册。');
  setText('roleBadge',s.role==='provider'?'Provider · 提供网络':'Consumer · 使用网络'); $('roleBadge').className=`chip ${s.role}`;
  setText('deploymentMode',s.embedded_server?'本机控制服务器 + Provider':'独立 Agent · 可连接本地或云端服务器');
  setText('configPath',`配置文件：${s.config_path}`);
  document.querySelectorAll('.provider-only').forEach(el=>el.hidden=s.role!=='provider');
  document.querySelectorAll('.consumer-only').forEach(el=>el.hidden=s.role!=='consumer');
  setText('authState',s.authenticated?`已登录 · ${s.username}`:'未登录'); $('authState').className=`chip ${s.authenticated?'success':'neutral'}`;
  setText('accountUsername',s.username||'—'); setText('accountDeviceName',s.device_name||'使用 Windows 计算机名'); setText('accountDeviceID',s.device_id||'尚未注册'); setText('accountRole',s.role==='provider'?'Provider':'Consumer');
  setText('metricIdentity',s.authenticated?s.username:'未登录'); setText('metricDevice',s.device_id?`设备 ${s.device_id.slice(0,8)}…`:'尚未注册设备'); setText('metricServerURL',s.server_url);
  $('deviceButton').disabled=!s.authenticated;
  renderSteps();
}

async function loadSettings() { const s=await api('/api/settings'); applySettings(s); return s; }

async function checkServer(showToast=false) {
  try { await api('/api/control-health'); state.serverOnline=true; $('serverHealth').className='health online'; $('serverHealth').innerHTML='<i></i><span>服务器在线</span>'; setText('metricServer','在线'); renderSteps(); if(showToast)toast('控制服务器连接正常'); return true; }
  catch(e) { state.serverOnline=false; $('serverHealth').className='health offline'; $('serverHealth').innerHTML='<i></i><span>服务器离线</span>'; setText('metricServer','离线'); renderSteps(); if(showToast)toast(humanError(e),true); return false; }
}

async function doctor(showToast=false) {
  try {
    const d=await api('/api/doctor'); state.doctor=d; $('doctorOutput').textContent=JSON.stringify(d,null,2);
    const checks=[['管理员权限',d.administrator,'网络改动需要管理员权限'],['WireGuard',Boolean(d.wireguard_exe&&d.wg_exe),'需要安装 WireGuard for Windows'],['活动网络',Boolean(d.default_adapter?.ipv4),d.default_adapter?.name||'未检测到'],['Windows NAT',Boolean(d.get_net_nat_available&&d.new_net_nat_available),'系统需要 NetNat 支持']];
    const root=$('doctorCards'); root.replaceChildren(...checks.map(([name,ok,note])=>{const row=document.createElement('div');row.className=`check ${ok?'ok':'bad'}`;row.innerHTML=`<i>${ok?'✓':'!'}</i><div><strong></strong><span></span></div>`;row.querySelector('strong').textContent=name;row.querySelector('span').textContent=note;return row;}));
    setText('metricNetwork',d.default_adapter?.ipv4?'可用':'异常'); setText('metricLAN',d.default_adapter?.ipv4?`${d.default_adapter.name} · ${d.default_adapter.ipv4}`:'未检测到 IPv4 出口');
    if(showToast)toast('诊断完成'); renderSteps(); return d;
  } catch(e) { if(showToast)toast(humanError(e),true); throw e; }
}

function activeSessionFromStatus(v) {
  const items=Array.isArray(v?.sessions)?v.sessions:[];
  return items.find(x=>!x.state?.completed && x.state?.role==='consumer') || items.find(x=>!x.state?.completed) || null;
}
function renderSession(v) {
  state.status=v; const item=activeSessionFromStatus(v);
  if(!item) { state.currentSession=''; $('sessionCard').className='session-card idle'; setText('sessionHeadline','当前没有活动会话'); setText('sessionDescription','选择一项授权流量并预览后即可连接。'); $('disconnectButton').disabled=true; setText('sessionTunnel','—');setText('sessionRX','0 B');setText('sessionTX','0 B');setText('sessionRemaining','—');setText('sessionExpiry','—');setText('metricSession','未连接');setText('metricTraffic','0 B'); $('sessionOutput').textContent=JSON.stringify(v,null,2); return; }
  const server=item.server||{}, wg=item.wireguard||{}, snapshot=item.state||{}; state.currentSession=snapshot.session_id||server.session?.id||'';
  $('sessionCard').className='session-card connected'; setText('sessionHeadline',snapshot.role==='provider'?'Provider 网关正在运行':'已通过 Provider 连接'); setText('sessionDescription',`会话 ${state.currentSession}`); $('disconnectButton').disabled=!state.currentSession;
  setText('sessionTunnel',v.tunnel_name||'TrafficShare-Tunnel'); setText('sessionRX',formatBytes(wg.rx)); setText('sessionTX',formatBytes(wg.tx)); setText('sessionRemaining',server.remaining_bytes!==undefined?formatBytes(server.remaining_bytes):'—'); setText('sessionExpiry',server.expires_at?`到期 ${formatDate(server.expires_at)}`:'本机网关会话');
  setText('metricSession','已连接'); setText('metricTraffic',formatBytes(Number(wg.rx||0)+Number(wg.tx||0))); $('sessionOutput').textContent=JSON.stringify(v,null,2); renderSteps();
}
async function refreshStatus(showToast=false) { try { const v=await api('/api/status'); renderSession(v); if(showToast)toast('状态已刷新'); return v; } catch(e){ if(showToast)toast(humanError(e),true); } }

function renderSteps() {
  const s=state.settings||{}; const steps=[];
  steps.push({done:state.serverOnline,title:'连接控制服务器',text:state.serverOnline?'服务器连接正常':'填写或检查服务器地址',page:'settings'});
  steps.push({done:s.authenticated,title:'登录账户',text:s.authenticated?`已登录 ${s.username}`:'注册或登录控制服务器',page:'account'});
  steps.push({done:Boolean(s.device_id),title:'注册设备',text:s.device_id?'设备已就绪':'自动登记 LAN IP 与 WireGuard 公钥',page:'account'});
  if(s.role==='provider')steps.push({done:Boolean(state.status?.sessions?.some(x=>x.state?.role==='provider'&&!x.state?.completed)),title:'初始化 Provider 网关',text:'创建安全隧道、转发与 NAT',page:'provider'});
  else steps.push({done:Boolean(state.currentSession),title:'连接授权流量',text:'先预览网络改动，再建立连接',page:'consumer'});
  $('nextSteps').replaceChildren(...steps.map((step,index)=>{const b=document.createElement('button');b.className=`step ${step.done?'done':''}`;b.innerHTML=`<i>${step.done?'✓':index+1}</i><span><strong></strong><small></small></span><em>›</em>`;b.querySelector('strong').textContent=step.title;b.querySelector('small').textContent=step.text;b.onclick=()=>gotoPage(step.page);return b;}));
  const completed=steps.filter(x=>x.done).length, next=steps.find(x=>!x.done);
  setText('setupProgress',`${completed} / ${steps.length}`);
  setText('heroKicker',s.role==='provider'?'PROVIDER · 提供网络':'CONSUMER · 使用网络');
  setText('heroTitle',s.role==='provider'?'让这台电脑成为同学可信的网络出口':'通过同学授权的 Provider 安全联网');
  setText('heroText',next?`下一步：${next.title}。${next.text}。`:(s.role==='provider'?'网关已经就绪，现在可以创建或管理流量授权。':'连接已经建立，可在“当前连接”查看流量和安全断开。'));
  $('primaryAction').dataset.page=next?.page||(s.role==='provider'?'provider':'session');
  $('primaryAction').textContent=next?`下一步：${next.title}`:(s.role==='provider'?'管理流量授权':'查看当前连接');
  const ready=Boolean(s.authenticated&&s.device_id);
  $('previewInit').disabled=!ready;
  $('applyInit').disabled=!ready||!state.initPreviewed;
  $('shareButton').disabled=!ready;
}

$('saveSettings').onclick=async()=>{try{const s=await api('/api/settings','POST',{role:$('role').value,server_url:$('serverURL').value,device_name:$('deviceName').value});applySettings(s);await checkServer();toast('设置已保存')}catch(e){toast(humanError(e),true)}};
$('testServer').onclick=()=>checkServer(true);

async function login(register) { try { await api('/api/login','POST',{username:$('username').value.trim(),password:$('password').value,register}); $('password').value=''; await loadSettings(); toast(register?'注册并登录成功':'登录成功'); await refreshStatus(); } catch(e){toast(humanError(e),true)} }
$('loginButton').onclick=()=>login(false); $('registerButton').onclick=()=>login(true);
$('deviceButton').onclick=async()=>{try{const d=await api('/api/device','POST',{});await loadSettings();toast(`设备 ${d.device_name} 已注册`)}catch(e){toast(humanError(e),true)}};

function renderPlan(target, preview) {
  const actions=preview?.plan?.actions||[]; const root=$(target); root.className='result'; root.replaceChildren();
  if(!actions.length){root.textContent='没有需要执行的网络改动';return;}
  actions.forEach((a,i)=>{const row=document.createElement('div');row.className='plan-row';row.innerHTML=`<i>${i+1}</i><div><strong></strong><span></span></div>`;row.querySelector('strong').textContent=a.description;row.querySelector('span').textContent=a.resource||'';root.append(row)});
}
$('previewInit').onclick=async()=>{try{const v=await api('/api/provider/init','POST',{apply:false});renderPlan('initSummary',v);state.initPreviewed=true;$('applyInit').disabled=false;toast('预览完成，尚未修改网络')}catch(e){toast(humanError(e),true)}};
$('applyInit').onclick=async()=>{if(!state.initPreviewed||!confirm('将以管理员权限创建 WireGuard、转发、NAT 与防火墙规则。确认继续？'))return;try{await withOperation($('applyInit'),'正在初始化 Provider 网关',['正在准备 WireGuard 配置…','正在启动安全隧道…','正在启用 IPv4 转发与 NAT…','正在应用最小范围防火墙规则…'],async()=>{const v=await api('/api/provider/init','POST',{apply:true});renderPlan('initSummary',v);state.initPreviewed=false;$('providerState').textContent='网关运行中';$('providerState').className='chip success';await refreshStatus()});toast('Provider 网关初始化完成')}catch(e){toast(humanError(e),true)}};
$('shareButton').onclick=async()=>{try{const quota=Number($('quota').value),hours=Number($('hours').value);if(!(quota>0)||!(hours>0))throw new Error('额度和有效期必须大于 0');await api('/api/share','POST',{receiver:$('receiver').value.trim(),quota_bytes:Math.round(quota*1e9),hours});$('receiver').value='';toast('私有共享已创建');await providerShares()}catch(e){toast(humanError(e),true)}};

function progress(used,total){return Math.min(100,Math.max(0,total?used/total*100:0));}
async function providerShares(){if(state.settings?.role!=='provider'||!state.settings?.authenticated)return;try{const v=await api('/api/provider/shares');const root=$('providerShares');root.replaceChildren();if(!(v.shares||[]).length){root.innerHTML='<div class="empty-state">还没有创建共享</div>';return;}v.shares.forEach(s=>{const row=document.createElement('div');row.className='share-row';const used=Number(s.used_bytes||0),total=Number(s.quota_bytes||0);row.innerHTML='<div class="share-main"><div class="share-title"><span class="status-dot"></span><strong></strong><span class="status-pill"></span></div><div class="progress"><i></i></div><div class="share-meta"><span class="usage"></span><span class="expiry"></span></div></div><button class="danger subtle">停止</button>';row.querySelector('.share-title strong').textContent=`共享 ${s.id.slice(0,8)}…`;row.querySelector('.status-pill').textContent=statusText(s.status);row.querySelector('.status-pill').classList.add(s.status);row.querySelector('.progress i').style.width=`${progress(used,total)}%`;row.querySelector('.usage').textContent=`已用 ${formatBytes(used)} / ${formatBytes(total)}`;row.querySelector('.expiry').textContent=`到期 ${formatDate(s.expires_at)}`;const stop=row.querySelector('button');stop.disabled=s.status!=='active';stop.onclick=async()=>{if(confirm('停止此共享并撤销相关会话？')){try{await api('/api/share/stop','POST',{share_id:s.id});toast('共享已停止');providerShares()}catch(e){toast(humanError(e),true)}}};root.append(row)});}catch(e){toast(humanError(e),true)}}
$('providerSharesButton').onclick=providerShares;

async function shares(){if(state.settings?.role!=='consumer'||!state.settings?.authenticated)return;try{const v=await api('/api/shares');const root=$('shareList');root.replaceChildren();if(!(v.shares||[]).length){root.innerHTML='<div class="empty-state panel">当前没有授权给你的可用流量</div>';return;}v.shares.forEach(s=>{const card=document.createElement('article');card.className='offer panel';const remaining=Math.max(0,Number(s.quota_bytes)-Number(s.used_bytes));card.innerHTML='<div class="offer-top"><div class="provider-avatar">P</div><div><span>Provider</span><h3></h3></div><span class="online"></span></div><div class="offer-quota"><strong></strong><span>剩余可用流量</span></div><div class="progress"><i></i></div><div class="offer-meta"><span class="used"></span><span class="expires"></span></div><div class="actions"><button class="secondary preview">预览改动</button><button class="primary connect" disabled>连接</button></div>';card.querySelector('h3').textContent=s.provider_username;card.querySelector('.online').textContent=s.provider_online?'● 在线':'● 离线';card.querySelector('.online').classList.toggle('offline',!s.provider_online);card.querySelector('.offer-quota strong').textContent=formatBytes(remaining);card.querySelector('.progress i').style.width=`${progress(s.used_bytes,s.quota_bytes)}%`;card.querySelector('.used').textContent=`已用 ${formatBytes(s.used_bytes)}`;card.querySelector('.expires').textContent=`${formatDate(s.expires_at)} 到期`;const preview=card.querySelector('.preview'),connectButton=card.querySelector('.connect');preview.onclick=async()=>{const ok=await connect(s.id,false);if(ok){state.previewedShares.add(s.id);connectButton.disabled=!s.provider_online;preview.textContent='✓ 已预览'}};connectButton.onclick=()=>connect(s.id,true);root.append(card)});}catch(e){toast(humanError(e),true)}}
$('refreshShares').onclick=shares;

async function connect(shareID,apply){if(apply&&!state.previewedShares.has(shareID)){toast('请先预览网络改动',true);return false;}if(apply&&!confirm('连接将修改本机路由、防火墙和 WireGuard 配置。确认继续？'))return false;try{const v=await api('/api/connect','POST',{share_id:shareID,apply});$('sessionOutput').textContent=JSON.stringify(v,null,2);if(apply){state.currentSession=v.session.id;toast('连接成功，IPv4 流量正在通过 Provider');gotoPage('session');await refreshStatus();}else{toast('预览完成，未修改网络；现在可以点击“连接”');}return true;}catch(e){toast(humanError(e),true);return false;}}

$('statusButton').onclick=()=>refreshStatus(true);
$('disconnectButton').onclick=async()=>{if(!state.currentSession||!confirm('断开隧道并恢复原始网络？'))return;try{await withOperation($('disconnectButton'),'正在安全断开',['正在停止 WireGuard 隧道…','正在恢复原始路由和 DNS…','正在清理 TrafficShare 防火墙与 NAT…','正在确认网络恢复…'],async()=>{await api('/api/disconnect','POST',{session_id:state.currentSession,apply:true});state.currentSession='';await refreshStatus()});toast('已断开，原始网络已恢复')}catch(e){toast(humanError(e),true)}};
$('doctorButton').onclick=()=>doctor(true);
$('logsButton').onclick=async()=>{try{const v=await api('/api/logs');const lines=String(v.logs||'暂无日志').trim().split(/\r?\n/);$('logsOutput').textContent=lines.slice(-250).join('\n');toast('日志已刷新')}catch(e){toast(humanError(e),true)}};
$('refreshAll').onclick=()=>refreshAll(true);

async function refreshAll(showToast=false){await Promise.allSettled([loadSettings(),checkServer(),doctor(),refreshStatus()]);if(state.settings?.role==='provider')providerShares();else shares();if(showToast)toast('界面已刷新');}
async function boot(){try{await loadSettings();await Promise.allSettled([checkServer(),doctor(),refreshStatus()]);if(state.settings.role==='provider')providerShares();else shares();renderSteps();}catch(e){toast(humanError(e),true)}setInterval(()=>{if(!state.busy){checkServer();refreshStatus()}},10000)}
boot();
