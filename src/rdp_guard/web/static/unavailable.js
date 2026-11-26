"use strict";
async function checkService() {
  try {
    const health = await (await fetch("/api/service-status")).json();
    const names = {1:"Остановлена",2:"Запускается",3:"Останавливается",4:"Процесс запущен"};
    const lines = [health.checked_at ? `Проверено: ${new Date(health.checked_at*1000).toLocaleString("ru-RU")}` : "Нет свежей проверки watchdog"];
    for (const [name,s] of Object.entries(health.services || {})) lines.push(`${name}: ${names[s.state] || "Неизвестно"}; код Windows: ${s.exit_code ?? "—"}`);
    document.getElementById("service-state").textContent=lines.join("\n");
    const response = await fetch("/api/session");
    if (response.ok) location.replace("/");
    else if (response.status===401) location.replace("/login");
  } catch (_) { document.getElementById("service-state").textContent="Панель ожидает восстановления связи"; }
}
checkService();setInterval(checkService,5000);
