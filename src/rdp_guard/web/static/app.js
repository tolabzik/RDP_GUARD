"use strict";
const $ = id => document.getElementById(id);
let csrf = "", view = "dashboard", loading = false, filters = {}, offset = 0;
const titles = {dashboard:"Обзор защиты", events:"События аутентификации", blocks:"Блокировки", whitelist:"Белый список", settings:"Настройки защиты", system:"Система и диагностика"};
const fmt = value => value ? new Date(value * 1000).toLocaleString("ru-RU") : "—";
const number = value => Number(value || 0).toLocaleString("ru-RU");
function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else if (key === "class") node.className = value;
    else if (key === "checked" || key === "disabled") node[key] = value;
    else node.setAttribute(key, value);
  }
  for (const child of children.flat()) if (child !== null && child !== undefined) node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  return node;
}
const button = (text, action, cls="quiet") => el("button", {type:"button", class:cls, onclick: () => Promise.resolve().then(action).catch(notice)}, text);
function notice(error) { $("notice").hidden = false; $("notice").textContent = error.message || String(error); }
async function api(op, args={}) {
  const response = await fetch("/api/rpc", {method:"POST", headers:{"Content-Type":"application/json", "X-CSRF-Token":csrf}, body:JSON.stringify({op,args})});
  const data = await response.json();
  if (response.status === 401) { location.assign("/login"); throw new Error("Сессия завершена"); }
  if (!response.ok) throw new Error(data.error || "Ошибка службы");
  return data;
}
function badge(text, kind="") { return el("span", {class:`badge ${kind}`}, text); }
function panel(title, content, actions=[]) {
  return el("section", {class:"panel"}, el("div", {class:"panel-head"}, el("h2", {}, title), el("div", {class:"actions"}, actions)), content);
}
function table(headers, rows) {
  if (!rows.length) return el("div", {class:"empty"}, "Записей пока нет");
  return el("div", {class:"table-wrap"}, el("table", {}, el("thead", {}, el("tr", {}, headers.map(h => el("th", {}, h)))),
    el("tbody", {}, rows.map(row => el("tr", {}, row.map(value => el("td", {}, value)))))));
}
function field(name, label, type="text", value="", attrs={}) {
  const input = type === "textarea" ? el("textarea", {name,...attrs}, value) : el("input", {name,type,value,...attrs});
  return el("label", {class:type === "checkbox" ? "check" : ""}, type === "checkbox" ? input : label, type === "checkbox" ? label : input);
}
function modal(title, content, submit) {
  $("modal-title").textContent = title;
  $("modal-body").replaceChildren(...content);
  $("modal-error").textContent = "";
  $("modal-form").onsubmit = async event => {
    event.preventDefault();
    const btn = event.target.querySelector("button[type=submit]"); btn.disabled = true;
    try { await submit(new FormData(event.target)); $("modal").close(); await render(); }
    catch (error) { $("modal-error").textContent = error.message; }
    finally { btn.disabled = false; }
  };
  $("modal").showModal();
}
function confirmAction(title, message, action) { modal(title, [el("p", {class:"muted"}, message)], action); }
function download(name, data) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data,null,2)], {type:"application/json"}));
  const a = el("a", {href:url,download:name}); document.body.append(a); a.click(); a.remove(); URL.revokeObjectURL(url);
}
function listImport(kind) {
  modal("Импорт списка", [el("p", {class:"muted"}, 'JSON-массив: [{"network":"203.0.113.7","comment":"Описание"}]. Записи добавляются к существующим. Весь список проверяется до сохранения.'),
    field("entries","Записи","textarea","",{required:"required"})], async data => api("import-lists",{kind,entries:JSON.parse(data.get("entries"))}));
}
function addNetwork(kind, initial="") {
  modal(kind === "whitelist" ? "Добавить доверенный адрес" : "Добавить постоянную блокировку", [
    field("network","IP или CIDR","text",initial,{required:"required",placeholder:"203.0.113.7 или 203.0.113.0/24"}),
    field("comment","Комментарий","text","",{maxlength:"500"}),
    el("p",{class:"muted"},kind === "whitelist" ? "Пересекающиеся блокировки будут сняты полностью." : "Правило ограничивается RDP-портом. В Monitor Only адрес сохраняется без применения правила.")
  ], async data => api(kind === "whitelist" ? "whitelist-add" : "block",Object.fromEntries(data)));
}
function eventTable(events) {
  return table(["Время","Источник / пользователь","Категория","Причина","Обработка"],events.map(e => [fmt(e.timestamp),
    el("div",{},el("div",{class:"mono"},e.ip || "Без IP"),el("small",{class:"muted"},e.username || "—")),
    el("div",{},badge(e.category,e.category === "RDP-confirmed" ? "good" : ""),el("div",{class:"muted"},e.event_id === 140 ? "RdpCoreTS · 140" : `${e.event_id} · LogonType ${e.logon_type ?? "—"}`)),
    el("div",{},e.reason,el("div",{class:"mono muted"},e.substatus || e.status)),badge(e.disposition === "no-source-ip" ? "Нет IP для блокировки" : e.disposition,["admin-protected","no-source-ip"].includes(e.disposition) ? "warn" : "") ]));
}
function graph(histogram, now) {
  const buckets = Array.from({length:12},(_,i)=>({time:Math.floor(now/300)*300-(11-i)*300,count:0}));
  for (const bucket of buckets) bucket.count = histogram.find(h => h.time === bucket.time)?.count || 0;
  const maximum = Math.max(1,...buckets.map(b=>b.count));
  const points = buckets.map((b,i)=>`${i*1000/11},${140-b.count/maximum*120}`).join(" ");
  const svg = document.createElementNS("http://www.w3.org/2000/svg","svg");
  svg.setAttribute("viewBox","0 0 1000 160"); svg.setAttribute("class","chart"); svg.setAttribute("preserveAspectRatio","none");
  svg.setAttribute("role","img"); svg.setAttribute("aria-label",`Записи об отказах за час; максимум ${maximum} за 5 минут`);
  const shape = (tag,attrs) => { const n=document.createElementNS(svg.namespaceURI,tag); for(const [k,v] of Object.entries(attrs)) n.setAttribute(k,v); svg.append(n); };
  for(const y of [20,60,100,140]) shape("line",{x1:0,x2:1000,y1:y,y2:y,class:"chart-grid"});
  shape("polygon",{points:`0,160 ${points} 1000,160`,class:"chart-fill"});
  shape("polyline",{points,class:"chart-line"});
  return el("div",{},svg,el("div",{class:"chart-labels"},el("span",{},"60 минут назад"),el("span",{},"Интервал: 5 минут"),el("span",{},"Сейчас")));
}
async function activate() {
  const pre = await api("preflight");
  const checks = el("div",{},Object.entries(pre.checks).map(([k,v])=>el("div",{class:"status-row"},k,badge(v ? "OK" : "НЕ ПРОЙДЕНО",v ? "good" : "bad"))));
  const sessions = pre.sessions.length ? table(["Администратор Windows", "IP подключения на сервере", "Белый список"],pre.sessions.map(s=>[
    `${s.domain ? s.domain+"\\" : ""}${s.username}`,el("div",{},el("span",{class:"mono"},s.ip),
      el("small",{class:"muted"},`Адрес клиента: ${s.client_reported_ip || "не сообщён"} · ${s.ip_source || "—"}`)),
    badge(s.whitelisted ? "В списке" : "Нет в списке",s.whitelisted ? "good" : "warn")])) :
    el("p",{class:"muted"},pre.checks.session_inventory ?
      "Активных административных RDP-сессий не найдено. Для проверки подключитесь по RDP под администратором Windows." :
      pre.session_error || "Не удалось проверить административные RDP-сессии. Подробности — в разделе «Система».");
  modal("Проверка перед включением ACTIVE",[checks,
    el("h3",{},"Административные RDP-сессии"),sessions,
    el("p",{class:"muted"},"Белый список проверяется по адресу подключения из серверного журнала, сопоставленному с текущей сессией. Локальный адрес клиента за NAT показан только для справки."),
    el("p",{class:"muted"},`Расчёт: ${pre.dry_run.length} решений. После включения нужно повторно подключиться по RDP и подтвердить подключение. Иначе собственные правила будут сняты автоматически.`),
    field("backup_access","Резервный доступ проверен и доступен","checkbox","yes",{required:"required"}),
    field("confirmation","Введите ENABLE RDP GUARD","text","",{required:"required"})],async data=>{
      if(!pre.ready) throw new Error("Сначала устраните ошибки проверки");
      return api("activate",{confirmation:data.get("confirmation"),backup_access:data.get("backup_access")==="yes"});
    });
}
async function dashboard() {
  const [s,events]=await Promise.all([api("status"),api("events")]);
  $("version").textContent=s.version;
  const active=s.mode==="ACTIVE";
  const modeActions = active ? [button("Monitor Only",()=>confirmAction("Перейти в наблюдение","Все собственные блокировки будут сняты; история сохранится.",()=>api("monitor-only")))] : [button("Включить защиту",activate,"primary")];
  const content=[el("section",{class:"banner"},el("div",{},el("h2",{},badge(active ? "ACTIVE" : "MONITOR ONLY",active ? "good" : "warn"),"  ",active ? "Защита включена" : "Наблюдение без блокировок"),
    el("p",{},active ? "Блокировки ограничены входящим трафиком на RDP-порт." : "События собираются, решения рассчитываются. Правила блокировки не создаются.")),el("div",{class:"actions"},modeActions))];
  if(s.lease?.deadline) content.push(el("section",{class:"banner"},el("div",{},el("h2",{},"Ожидается повторное RDP-подключение"),
    el("p",{},`Автоматический откат: ${fmt(s.lease.deadline)}`)),button("Подключение проверено",()=>confirmAction("Подтвердить подключение","После включения защиты закройте окно RDP на своём компьютере, не завершая сеанс Windows, и подключитесь снова с адреса из белого списка под Windows-администратором. Затем вернитесь сюда и нажмите «Подтвердить» до автоматического отката. Обновление страницы не считается переподключением.",()=>api("confirm-active")),"primary")));
  if(s.last_error) content.push(el("div",{class:"banner"},badge("ОШИБКА","bad"),s.last_error));
  content.push(el("div",{class:"toolbar"},badge(s.platform?.firewall ? "Windows Firewall · OK" : "Windows Firewall · требуется проверка",s.platform?.firewall ? "good" : "warn"),
    badge(s.collectors.Security?.healthy ? "Security · подписка активна" : "Security · требуется проверка",s.collectors.Security?.healthy ? "good" : "warn"),
    badge(s.collectors["Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"]?.healthy ? "RdpCoreTS · подписка активна" : "RdpCoreTS · требуется проверка",s.collectors["Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"]?.healthy ? "good" : "warn")));
  const applied=s.blocks.find(b=>b.status==="applied")?.n || 0;
  content.push(el("div",{class:"cards"},[
    ["Записей об отказах · 24 ч",number(s.counters.day.n),`${number(s.counters.hour.n)} за час · ${number(s.counters.minute.n)} за последнюю минуту`],
    ["Уникальных IP отказов · 24 ч",number(s.counters.day.unique_ips),`${number(s.counters.day.n-s.counters.day.with_ip)} записей без IP за сутки`],
    ["Применённых блокировок",number(applied),`${number(s.blocks.reduce((n,b)=>n+b.n,0))} действующих решений`],
    ["Доверенных сетей",number(s.whitelist_count),"Адреса и сети из белого списка"]
  ].map(([label,value,hint])=>el("article",{class:"card"},el("div",{class:"label"},label),el("div",{class:"value"},value),el("div",{class:"hint"},hint)))));
  content.push(panel("Записи об отказах за последний час",el("div",{},graph(s.histogram,s.now),
    el("p",{class:"muted"},"Security 4625 и RdpCoreTS 140, включая записи без IP. Одна попытка может попасть в оба журнала. Порог блокировки считается отдельно по каждому журналу для одного IP.")),[badge("Все категории")]));
  content.push(panel("Последние события",eventTable(events.slice(0,8)),[button("Все события →",()=>selectView("events"))]));
  return content;
}
async function eventsView() {
  const events=await api("events",{...filters,offset});
  const form=el("form",{class:"toolbar"});
  form.append(field("ip","IP","text",filters.ip || ""),field("username","Пользователь","text",filters.username || ""));
  for(const [name,label,options] of [["category","Категория",["RDP-confirmed","Network-auth","RDP-context","Other"]],["disposition","Обработка",["observed","proposed","pending","unconfirmed","no-source-ip","whitelisted","admin-protected","historical"]]]) {
    const select=el("select",{name},el("option",{value:""},"Все"),options.map(o=>el("option",{value:o},o === "no-source-ip" ? "Нет IP для блокировки" : o))); select.value=filters[name] || ""; form.append(el("label",{},label,select));
  }
  form.append(field("since","С","datetime-local",filters.since ? localTime(filters.since) : ""),field("until","По","datetime-local",filters.until ? localTime(filters.until) : ""));
  form.append(el("button",{type:"submit",class:"primary"},"Применить"));
  form.onsubmit=event=>{event.preventDefault();filters=Object.fromEntries(new FormData(form));for(const key of ["since","until"]) if(filters[key]) filters[key]=new Date(filters[key]).getTime()/1000;else delete filters[key];offset=0;render();};
  return [panel("Журнал событий",el("div",{},form,eventTable(events),el("div",{class:"pager"},button("← Назад",()=>{offset=Math.max(0,offset-100);return render();}),badge(`${offset+1}–${offset+events.length}`),button("Далее →",()=>{if(events.length===100)offset+=100;return render();}))))];
}
function localTime(seconds) { const d=new Date(seconds*1000); return new Date(d-d.getTimezoneOffset()*60000).toISOString().slice(0,16); }
async function blocksView() {
  const rows=await api("list-blocks");
  const actionsFor=b=>el("div",{class:"actions"},
    button("Снять",()=>confirmAction("Снять блокировку",b.network,()=>api("unblock",{network:b.network}))),
    button("Продлить",()=>modal("Продлить блокировку",[field("seconds","Новый срок, секунд","number","3600",{min:"60",max:"2592000",required:"required"})],data=>api("extend",{network:b.network,seconds:Number(data.get("seconds"))}))),
    button("Навсегда",()=>confirmAction("Постоянный blacklist",b.network,()=>api("make-permanent",{network:b.network}))),
    button("В whitelist",()=>addNetwork("whitelist",b.network)),
    button("События",()=>{filters={ip:b.network.split("/")[0]};offset=0;return selectView("events");}),
    button("История",async()=>{const all=await api("list-blocks",{history:true});modal(`История ${b.network}`,[table(["Создана","Завершена","Статус"],all.filter(r=>r.network===b.network).map(r=>[fmt(r.created),fmt(r.ended),r.status]))],async()=>{});})
  );
  return [panel("Действующие решения",table(["Адрес","Причина / попытки","Срок","Firewall","Действия"],rows.map(b=>[
    el("div",{},el("div",{class:"mono"},b.network),el("small",{class:"muted"},`${b.kind} · нарушение ${b.strikes}`)),
    el("div",{},b.reason,el("div",{class:"muted"},`${b.attempts} попыток · ${fmt(b.created)}`)),
    b.expires ? el("div",{},fmt(b.expires),el("small",{class:"muted"},`${Math.max(0,Math.ceil((b.expires-Date.now()/1000)/60))} мин. осталось`)) : "Постоянно",
    el("div",{},badge(b.status,b.status==="applied" ? "good" : b.status==="error" ? "bad" : "warn"),el("small",{},b.error)),actionsFor(b)])),[
      button("Импорт",()=>listImport("blacklist")),button("Экспорт",async()=>download("rdpguard-blacklist.json",rows.filter(r=>r.kind==="static").map(r=>({network:r.network,comment:r.reason})))),button("+ Блокировка",()=>addNetwork("blacklist"),"primary")])];
}
async function whitelistView() {
  const rows=await api("list-whitelist");
  return [el("div",{class:"banner"},el("p",{},"Whitelist имеет приоритет над всеми блокировками. Loopback 127.0.0.0/8 и ::1 защищены постоянно. Добавьте административный IP явно, даже если текущая сессия уже защищена.")),
    panel("Доверенные адреса и сети",table(["Адрес / сеть","Комментарий","Добавлено","Действия"],rows.map(r=>[el("span",{class:"mono"},r.network),r.comment,
      el("div",{},fmt(r.created),el("small",{class:"muted"},r.author)),el("div",{class:"actions"},
      button("Комментарий",()=>modal("Изменить комментарий",[field("comment","Комментарий","text",r.comment,{maxlength:"500"})],data=>api("whitelist-add",{network:r.network,comment:data.get("comment")}))),
      button("Удалить",()=>confirmAction("Удалить доверенный адрес",r.network,()=>api("whitelist-remove",{network:r.network}))))])),[
        button("Импорт",()=>listImport("whitelist")),button("Экспорт",()=>download("rdpguard-whitelist.json",rows)),button("+ Доверенный адрес",()=>addNetwork("whitelist"),"primary")])];
}
async function settingsView() {
  const s=await api("settings");
  const labels={threshold:"Порог неудачных входов",window_seconds:"Окно обнаружения, секунд",rdp_port:"RDP-порт для правил",max_blocks_per_minute:"Лимит новых блокировок / минуту",max_block_entries:"Максимум адресов в блокировках",batch_size:"Адресов в одном правиле",firewall_interval_seconds:"Интервал сверки firewall, секунд",retention_days:"Хранение событий, дней",rollback_seconds:"Ожидание повторного RDP-входа, секунд"};
  const form=el("form",{class:"form-grid"});
  for(const [key,label] of Object.entries(labels))form.append(field(key,label,"number",s[key],{required:"required"}));
  form.append(field("ban_seconds","Сроки блокировок, секунд через запятую","text",s.ban_seconds.join(", "),{required:"required"}));
  form.append(el("div",{class:"wide"},field("include_network_auth","Учитывать Network-auth / LogonType 3","checkbox","yes",{checked:s.include_network_auth}),
    el("p",{class:"form-help"},"Тип 3 может относиться к SMB или другой службе. Включайте только после проверки доступных извне портов. Отказы RdpCoreTS 140 с IP учитываются автоматически и не требуют этой настройки.")));
  form.append(el("p",{class:"wide muted"},"Порог применяется к одному IP за указанное окно, отдельно для Security 4625 и RdpCoreTS 140. Записи из двух журналов не суммируются для блокировки. Без IP адрес заблокировать невозможно."));
  form.append(el("p",{class:"wide muted"},"Порт здесь используется только для правил RDP Guard. Настройки RDP самой Windows не меняются. Для смены порта нужен режим Monitor Only и совпадение с Windows."),
    el("div",{class:"wide"},el("button",{type:"submit",class:"primary"},"Сохранить настройки")));
  form.onsubmit=async event=>{event.preventDefault();try{const data=new FormData(form),settings={...s};for(const key of Object.keys(labels))settings[key]=Number(data.get(key));settings.ban_seconds=data.get("ban_seconds").split(",").map(n=>Number(n.trim()));settings.include_network_auth=data.get("include_network_auth")==="yes";
    const save=()=>api("update-settings",{settings,confirm_port:settings.rdp_port});
    if(settings.rdp_port!==s.rdp_port)confirmAction("Изменить порт правил",`Подтвердите порт ${settings.rdp_port}. Конфигурация RDP Windows не изменится.`,save);
    else{await save();notice("Настройки сохранены");}}catch(error){notice(error);}};
  return [panel("Параметры обнаружения и блокировки",form)];
}
async function systemView() {
  const [s,audit]=await Promise.all([api("health"),api("audit")]);
  const statuses=el("div",{},...Object.entries(s.platform).filter(([k])=>k!=="errors").map(([k,v])=>el("div",{class:"status-row"},k,badge(v ? "OK" : "ТРЕБУЕТ ПРОВЕРКИ",v ? "good" : "warn"))),
    ...Object.entries(s.collectors).map(([name,data])=>el("div",{class:"status-row"},el("span",{},name,el("small",{class:"muted"},data.error)),badge(data.healthy ? "Подписка активна" : "Ошибка",data.healthy ? "good" : "bad"))));
  return [panel("Состояние компонентов",el("div",{},el("p",{class:"muted"},`Версия ${s.version} · ${s.os} · Служба работает ${Math.floor(s.uptime/60)} мин. · ${s.mode}`),statuses,
    el("pre",{},JSON.stringify({integrity:s.integrity,last_error:s.last_error,errors:s.platform.errors},null,2))),[
      button("Экспорт диагностики",async()=>download("rdpguard-diagnostics.json",await api("diagnostics"))),button("Экспорт конфигурации",async()=>download("rdpguard-config.json",await api("export-config"))),
      button("Сверить firewall",()=>confirmAction("Сверка firewall","Будут обновлены только собственные правила RDP Guard в соответствии с текущим режимом.",()=>api("firewall-reconcile")))]),
    panel("Аварийное отключение",el("div",{},el("p",{class:"muted"},"Отключает автоматическое реагирование и снимает только собственные блокировки. История и настройки сохраняются. Независимая команда: rdpguard.exe emergency-disable."),
      button("Аварийно снять блокировки",()=>confirmAction("Emergency Disable","Подтвердите снятие всех собственных блокировок RDP Guard.",()=>api("emergency-disable")),"danger"))),
    panel("Аудит действий",table(["Время","Инициатор","Действие","Детали"],audit.map(a=>[fmt(a.timestamp),a.actor,a.action,el("span",{class:"mono"},a.detail)])))];
}
async function render() {
  if(loading)return; loading=true;
  const current=view;
  try {
    const content=await ({dashboard,events:eventsView,blocks:blocksView,whitelist:whitelistView,settings:settingsView,system:systemView}[view])();
    if(current===view){$("content").replaceChildren(...content);$("connection").textContent=`Обновлено ${new Date().toLocaleTimeString("ru-RU")}`;}
  } catch(error){notice(error);$("connection").textContent="Нет связи со службой";}
  finally{loading=false;if(current!==view)render();}
}
async function selectView(name) {view=name;$("title").textContent=titles[name];document.querySelectorAll("nav button").forEach(b=>b.classList.toggle("selected",b.dataset.view===name));$("notice").hidden=true;await render();}
$("refresh").onclick=render;
$("close-modal").onclick=$("cancel-modal").onclick=()=>$("modal").close();
$("theme").onclick=()=>{const theme=document.documentElement.dataset.theme==="dark" ? "light" : "dark";document.documentElement.dataset.theme=theme;localStorage.setItem("rdpguard-theme",theme);};
document.documentElement.dataset.theme=localStorage.getItem("rdpguard-theme") || "dark";
$("logout").onclick=async()=>{try{await api("logout");location.assign("/login");}catch(error){notice(error);}};
document.querySelectorAll("nav button").forEach(b=>b.onclick=()=>selectView(b.dataset.view));
(async()=>{try{const response=await fetch("/api/session");if(!response.ok){location.assign("/login");return;}csrf=(await response.json()).csrf;await render();setInterval(()=>{if((view==="dashboard" || view==="events") && !$("modal").open && !document.querySelector("input:focus,select:focus"))render();},5000);}catch(error){notice(error);}})();
