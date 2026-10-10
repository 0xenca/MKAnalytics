'use strict';

/* ==========================================================================
   Utilidades
   ========================================================================== */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const pad = n => String(n).padStart(2, '0');
const fmtN = n => (n ?? 0).toLocaleString('es-ES');
const COLOR_OK = /^#[0-9a-f]{6}$/i;

function fmtTs(sec, withMs = false) {
  const d = new Date(sec * 1000);
  let s = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  if (withMs) s += '.' + String(d.getMilliseconds()).padStart(3, '0');
  return s;
}
function toLocalInput(sec) {
  const d = new Date(sec * 1000);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}
function fmtBytes(b) {
  if (b < 1024) return b + ' B';
  const u = ['KiB', 'MiB', 'GiB', 'TiB'];
  let i = -1;
  do { b /= 1024; i++; } while (b >= 1024 && i < u.length - 1);
  return b.toFixed(b < 10 ? 2 : 1) + ' ' + u[i];
}
function fmtDur(sec) {
  if (sec < 90) return Math.round(sec) + ' s';
  if (sec < 5400) return Math.round(sec / 60) + ' min';
  if (sec < 172800) return (sec / 3600).toFixed(1) + ' h';
  return (sec / 86400).toFixed(1) + ' d';
}
const debounce = (fn, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };

let toastTimer;
function toast(msg, err = false) {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'toast' + (err ? ' err' : '');
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, err ? 6000 : 2800);
}

async function api(path, opts = {}) {
  const { raw, ...fo } = opts;
  const o = { method: 'GET', ...fo, headers: { 'X-Requested-With': 'fetch', ...(fo.headers || {}) } };
  if (o.body && !(o.body instanceof FormData)) {
    o.headers['Content-Type'] = 'application/json';
    o.body = JSON.stringify(o.body);
  }
  const r = await fetch(path, o);
  if (!r.ok) {
    let m = r.statusText;
    try { m = (await r.json()).error || m; } catch (e) { /* sin cuerpo JSON */ }
    throw new Error(m);
  }
  if (raw) return r;
  return (r.headers.get('content-type') || '').includes('json') ? r.json() : r;
}
const post = (p, body) => api(p, { method: 'POST', body });

// Marca un botón como "esperando respuesta" (spinner + deshabilitado) mientras dura `fn`.
async function busyRun(btn, fn) {
  btn.classList.add('busy');
  btn.disabled = true;
  try { return await fn(); }
  finally { btn.classList.remove('busy'); btn.disabled = false; }
}

// Muestra "Cargando…" sobre `container` si `fn` tarda más de `delay` ms (evita parpadeos en cargas rápidas).
function withLoading(container, fn, { delay = 300, text = 'Cargando…' } = {}) {
  container._loadPending = (container._loadPending || 0) + 1;
  const timer = setTimeout(() => {
    if (!container._loadPending || container.querySelector(':scope > .load-overlay')) return;
    container.classList.add('loadwrap');
    const ov = document.createElement('div');
    ov.className = 'load-overlay';
    ov.textContent = text;
    container.appendChild(ov);
  }, delay);
  const finish = () => {
    clearTimeout(timer);
    container._loadPending = Math.max(0, (container._loadPending || 1) - 1);
    if (!container._loadPending) {
      const ov = container.querySelector(':scope > .load-overlay');
      if (ov) ov.remove();
      container.classList.remove('loadwrap');
    }
  };
  return (async () => fn())().then(r => { finish(); return r; }, e => { finish(); throw e; });
}

/* ==========================================================================
   Estado
   ========================================================================== */
const FIELD_OPTS = [
  ['any', 'Mensaje completo'], ['src_ip', 'IP origen'], ['dst_ip', 'IP destino'], ['ip', 'IP (origen o destino)'],
  ['src_port', 'Puerto origen'], ['dst_port', 'Puerto destino'], ['port', 'Puerto (cualquiera)'],
  ['src_mac', 'MAC origen'], ['proto', 'Protocolo'], ['proto_info', 'Flags / info proto'],
  ['in_if', 'Interfaz entrada'], ['out_if', 'Interfaz salida'], ['if', 'Interfaz (cualquiera)'],
  ['chain', 'Cadena'], ['prefix', 'Prefijo'], ['topics', 'Topics'], ['level', 'Nivel'],
  ['conn_state', 'Estado conexión'], ['conn_mark', 'Marca conexión'], ['nat', 'NAT'],
  ['len', 'Longitud'], ['scope', 'Sentido'], ['device', 'Dispositivo'],
];
const OP_OPTS = [
  ['contains', 'contiene'], ['not_contains', 'no contiene'], ['eq', 'es igual a'], ['ne', 'distinto de'],
  ['starts', 'empieza por'], ['ends', 'termina en'], ['regex', 'regex'], ['not_regex', 'no cumple regex'],
  ['cidr', 'dentro de red (CIDR)'], ['not_cidr', 'fuera de red (CIDR)'], ['in', 'en lista'], ['not_in', 'no en lista'],
  ['gt', '>'], ['gte', '≥'], ['lt', '<'], ['lte', '≤'], ['exists', 'existe'], ['not_exists', 'no existe'],
];
const OP_SYM = { contains: '~', not_contains: '!~', eq: '=', ne: '≠', starts: '^=', ends: '=$', regex: 'regex', not_regex: '!regex', cidr: '∈', not_cidr: '∉', in: 'en', not_in: 'no en', gt: '>', gte: '≥', lt: '<', lte: '≤', exists: 'existe', not_exists: 'no existe' };
const FIELD_LABEL = Object.fromEntries(FIELD_OPTS);

const DEFAULT_STATE = {
  q: '', conds: [], range: { type: 'quick', seconds: 3600, from: '', to: '' },
  showHidden: false, onlyHl: false, sort: 'ts', dir: 'desc', page: 1, size: 100, view: 'table',
  liveSec: 10,   // refresco automático de Logs/Analítica: 10, 30, 60 o 0 (desactivado)
};
const S = Object.assign({}, DEFAULT_STATE, {
  tab: 'logs', expanded: new Set(), lastId: null, statsId: null, lastStats: 0,
  status: null, config: null, seq: 0, seqStats: 0,
});
try {
  const saved = JSON.parse(localStorage.getItem('mtlogs.state.v1') || '{}');
  for (const k of Object.keys(DEFAULT_STATE)) if (k in saved) S[k] = saved[k];
} catch (e) { /* almacenamiento no disponible */ }
function persist() {
  try {
    const o = {};
    for (const k of Object.keys(DEFAULT_STATE)) o[k] = S[k];
    localStorage.setItem('mtlogs.state.v1', JSON.stringify(o));
  } catch (e) { /* ignorar */ }
}

function validCond(c) {
  return c && c.field && c.op && (['exists', 'not_exists'].includes(c.op) || String(c.value ?? '') !== '');
}
function filterBody(extra = {}) {
  const b = {
    q: S.q, conditions: S.conds.filter(validCond),
    show_hidden: S.showHidden, only_highlighted: S.onlyHl,
  };
  if (S.range.type === 'quick') { if (S.range.seconds) b.range_seconds = S.range.seconds; }
  else {
    if (S.range.from) b.from = new Date(S.range.from).getTime() / 1000;
    if (S.range.to) b.to = new Date(S.range.to).getTime() / 1000;
  }
  return { ...b, ...extra };
}

/* ==========================================================================
   Editor de condiciones (compartido: filtros y reglas)
   ========================================================================== */
function renderCondEditor(container, conds, onChange) {
  container.innerHTML = '';
  conds.forEach((c, i) => {
    const row = document.createElement('div');
    row.className = 'cond';
    row.innerHTML =
      `<select class="c-f" aria-label="Campo">${FIELD_OPTS.map(([v, l]) => `<option value="${v}" ${c.field === v ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select>` +
      `<select class="c-o" aria-label="Operador">${OP_OPTS.map(([v, l]) => `<option value="${v}" ${c.op === v ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select>` +
      `<input class="c-v" aria-label="Valor" placeholder="valor" value="${esc(c.value ?? '')}" spellcheck="false">` +
      `<button type="button" class="icon c-x" title="Quitar condición">✕</button>`;
    const val = $('.c-v', row);
    const sync = () => { val.style.display = ['exists', 'not_exists'].includes(c.op) ? 'none' : ''; };
    sync();
    $('.c-f', row).onchange = e => { c.field = e.target.value; onChange(); };
    $('.c-o', row).onchange = e => { c.op = e.target.value; sync(); onChange(); };
    val.oninput = e => { c.value = e.target.value; onChange(true); };
    $('.c-x', row).onclick = () => { conds.splice(i, 1); renderCondEditor(container, conds, onChange); onChange(); };
    container.appendChild(row);
  });
}

/* ==========================================================================
   Barra de filtros
   ========================================================================== */
function condLabel(c) {
  const neg = c.not ? 'NO ' : '';
  const v = ['exists', 'not_exists'].includes(c.op) ? '' : ' ' + c.value;
  return `${neg}${FIELD_LABEL[c.field] || c.field} ${OP_SYM[c.op] || c.op}${v}`;
}
function renderChips() {
  const box = $('#f-chips');
  box.innerHTML = '';
  S.conds.filter(validCond).forEach((c, i) => {
    const neg = c.not || ['ne', 'not_contains', 'not_regex', 'not_cidr', 'not_in', 'not_exists'].includes(c.op);
    const chip = document.createElement('span');
    chip.className = 'chip' + (neg ? ' neg' : '');
    chip.innerHTML = `${esc(condLabel(c))}<button title="Quitar filtro" aria-label="Quitar filtro">✕</button>`;
    chip.querySelector('button').onclick = () => {
      const idx = S.conds.indexOf(c);
      if (idx >= 0) S.conds.splice(idx, 1);
      renderFilters(); S.page = 1; reloadCurrent();
    };
    box.appendChild(chip);
  });
}
function renderFilters() {
  $('#f-q').value = S.q;
  $$('#f-ranges button').forEach(b => b.classList.toggle('active', S.range.type === 'quick' && +b.dataset.s === S.range.seconds));
  $('#f-from').value = S.range.type === 'custom' ? S.range.from : '';
  $('#f-to').value = S.range.type === 'custom' ? S.range.to : '';
  $('#f-hidden').checked = S.showHidden;
  $('#f-onlyhl').checked = S.onlyHl;
  renderCondEditor($('#f-conds'), S.conds, condChanged);
  renderChips();
  persist();
}
const reloadSoon = debounce(() => { S.page = 1; reloadCurrent(); }, 450);
function condChanged(typing) {
  renderChips(); persist();
  if (typing) reloadSoon(); else { S.page = 1; reloadCurrent(); }
}
function addCond(field, value, neg = false) {
  const op = neg ? 'ne' : 'eq';
  if (!S.conds.some(c => c.field === field && c.op === op && String(c.value) === String(value))) {
    S.conds.push({ field, op, value: String(value) });
  }
  S.page = 1;
  renderFilters();
  reloadCurrent();
}
function setRangeQuick(sec) {
  S.range = { type: 'quick', seconds: sec, from: '', to: '' };
  S.page = 1; renderFilters(); reloadCurrent();
}
function setRangeCustom(from, to) {
  S.range = { type: 'custom', seconds: 0, from, to };
  S.page = 1; renderFilters(); reloadCurrent();
}
function reloadCurrent() {
  if (S.tab === 'logs') loadLogs();
  else if (S.tab === 'analytics') loadStats();
}

function initFilters() {
  $('#f-q').addEventListener('input', e => { S.q = e.target.value; persist(); reloadSoon(); });
  $('#f-ranges').addEventListener('click', e => { const b = e.target.closest('button'); if (b) setRangeQuick(+b.dataset.s); });
  $('#f-adv-toggle').onclick = () => { const a = $('#f-adv'); a.hidden = !a.hidden; };
  $('#f-clear').onclick = () => {
    S.q = ''; S.conds = []; S.showHidden = false; S.onlyHl = false;
    S.range = { type: 'quick', seconds: 0, from: '', to: '' };
    S.page = 1; renderFilters(); reloadCurrent();
  };
  $('#f-add-cond').onclick = () => { S.conds.push({ field: 'any', op: 'contains', value: '' }); renderFilters(); };
  const dateChange = () => {
    const from = $('#f-from').value, to = $('#f-to').value;
    if (from || to) setRangeCustom(from, to); else setRangeQuick(0);
  };
  $('#f-from').step = 1; $('#f-to').step = 1;
  $('#f-from').onchange = dateChange; $('#f-to').onchange = dateChange;
  $('#f-hidden').onchange = e => { S.showHidden = e.target.checked; S.page = 1; persist(); reloadCurrent(); };
  $('#f-onlyhl').onchange = e => { S.onlyHl = e.target.checked; S.page = 1; persist(); reloadCurrent(); };

  $('#f-saved').onchange = e => {
    const s = (S.config?.searches || []).find(x => x.id === e.target.value);
    if (!s) return;
    S.q = s.q || '';
    S.conds = (s.conditions || []).map(c => ({ ...c }));
    S.range = s.range && s.range.type ? s.range : { type: 'quick', seconds: 0, from: '', to: '' };
    S.showHidden = !!s.show_hidden; S.onlyHl = !!s.only_highlighted;
    S.page = 1; renderFilters(); reloadCurrent();
  };
  $('#f-saved-del').onclick = async () => {
    const id = $('#f-saved').value;
    if (!id) return toast('Elige primero una búsqueda guardada', true);
    if (!confirm('¿Borrar esta búsqueda guardada?')) return;
    await api('/api/searches/' + id, { method: 'DELETE' });
    await loadConfig(); toast('Búsqueda borrada');
  };
  $('#f-saved-save').onclick = async () => {
    const name = prompt('Nombre de la búsqueda:');
    if (!name) return;
    try {
      await post('/api/searches', { name, q: S.q, conditions: S.conds.filter(validCond), range: S.range, show_hidden: S.showHidden, only_highlighted: S.onlyHl });
      await loadConfig(); toast('Búsqueda guardada');
    } catch (e) { toast(e.message, true); }
  };
}

async function loadConfig() {
  S.config = await api('/api/config');
  const sel = $('#f-saved');
  const cur = sel.value;
  sel.innerHTML = '<option value="">— elegir —</option>' +
    (S.config.searches || []).map(s => `<option value="${esc(s.id)}">${esc(s.name)}</option>`).join('');
  sel.value = cur && (S.config.searches || []).some(s => s.id === cur) ? cur : '';
}

/* ==========================================================================
   Vista de logs
   ========================================================================== */
const msgOf = e => (e.topics && e.raw.toLowerCase().startsWith(e.topics)) ? e.raw.slice(e.topics.length).trim() : e.raw;
const fcell = (f, v, text) => (v === undefined || v === null || v === '') ? '' :
  `<span class="f" data-f="${f}" data-v="${esc(v)}">${esc(text ?? v)}</span>`;

function rowHtml(e) {
  const hl = e.hl && COLOR_OK.test(e.hl.color || '');
  const open = S.expanded.has(e.id);
  const topics = e.topics ? e.topics.split(',').map(t => fcell('topics', t)).join(',') : '';
  const src = e.src_ip ? fcell('src_ip', e.src_ip) + (e.src_port != null ? ':' + fcell('src_port', e.src_port) : '') : '';
  const dst = e.dst_ip ? fcell('dst_ip', e.dst_ip) + (e.dst_port != null ? ':' + fcell('dst_port', e.dst_port) : '') : '';
  const proto = fcell('proto', e.proto) + (e.proto_info ? ' ' + fcell('proto_info', e.proto_info, `(${e.proto_info})`) : '');
  const parts = [];
  if (e.conn_mark) parts.push('mark:' + e.conn_mark);
  if (e.nat) parts.push('NAT ' + e.nat);
  if (!e.chain) parts.push(msgOf(e));
  const scopeCls = e.scope ? ' sc-' + e.scope : '';
  const tip = hl ? ` title="${esc('Resaltado por: ' + e.hl.names.join(', '))}"` : '';
  let html = `<tr class="entry${hl ? ' hl' : ''}${open ? ' expanded' : ''}" data-id="${e.id}"${hl ? ` style="background:${e.hl.color}"` : ''}${tip}>` +
    `<td>${esc(fmtTs(e.ts))}</td><td>${topics}</td><td>${fcell('prefix', e.prefix)}</td><td>${fcell('chain', e.chain)}</td>` +
    `<td>${fcell('in_if', e.in_if)}</td><td>${fcell('out_if', e.out_if)}</td><td>${proto}</td>` +
    `<td>${src}</td><td class="${scopeCls}">${dst}</td><td>${fcell('conn_state', e.conn_state)}</td>` +
    `<td>${e.len ?? ''}</td><td class="detail" title="${esc(parts.join(' '))}">${esc(parts.join(' '))}</td></tr>`;
  if (open) html += detailRowHtml(e);
  return html;
}

const DETAIL_FIELDS = ['topics', 'level', 'prefix', 'chain', 'in_if', 'out_if', 'proto', 'proto_info', 'src_ip', 'src_port', 'dst_ip', 'dst_port',
  'src_mac', 'conn_state', 'conn_mark', 'conn_nat_state', 'nat', 'len', 'scope', 'device'];
function detailRowHtml(e) {
  const rows = DETAIL_FIELDS.filter(f => e[f] !== undefined).map(f =>
    `<tr><td><input type="checkbox" class="pick" data-f="${f}" data-v="${esc(e[f])}" aria-label="Usar ${f} en una regla"></td>` +
    `<td>${f}</td><td><span class="f" data-f="${f}" data-v="${esc(e[f])}">${esc(e[f])}</span></td>` +
    `<td><button class="fa" data-op="eq" data-f="${f}" data-v="${esc(e[f])}" title="Filtrar: igual a">=</button> ` +
    `<button class="fa" data-op="ne" data-f="${f}" data-v="${esc(e[f])}" title="Filtrar: distinto de">≠</button></td></tr>`).join('');
  return `<tr class="detailrow" data-for="${e.id}"><td colspan="12"><div class="dgrid">` +
    `<div><h5>Campos interpretados (marca los que quieras usar en una regla)</h5><table class="dfields">${rows || '<tr><td>Sin campos interpretados</td></tr>'}</table></div>` +
    `<div><h5>Mensaje original · ${esc(fmtTs(e.ts, true))}${e.hl ? ' · resaltado por ' + esc(e.hl.names.join(', ')) : ''}</h5><div class="rawbox">${esc(e.raw)}</div>` +
    `<div class="dactions"><button class="copyraw" data-id="${e.id}">Copiar</button>` +
    `<button class="mkrule" data-act="highlight" data-id="${e.id}">Regla: resaltar…</button>` +
    `<button class="mkrule" data-act="exclude" data-id="${e.id}">Regla: excluir…</button></div></div></div></td></tr>`;
}

let currentRows = [];
function renderPager(box, page, pages) {
  box.innerHTML = `<button data-p="1" ${page <= 1 ? 'disabled' : ''} title="Primera">«</button>` +
    `<button data-p="${page - 1}" ${page <= 1 ? 'disabled' : ''}>‹</button><span>${page} / ${pages}</span>` +
    `<button data-p="${page + 1}" ${page >= pages ? 'disabled' : ''}>›</button>` +
    `<button data-p="${pages}" ${page >= pages ? 'disabled' : ''} title="Última">»</button>`;
}

async function loadLogs() {
  const seq = ++S.seq;
  const inp = $('#f-q');
  try {
    const d = await withLoading($('.tablewrap'), () => post('/api/logs', filterBody({ sort: S.sort, dir: S.dir, page: S.page, size: S.size })));
    if (seq !== S.seq) return;
    inp.classList.remove('bad');
    S.page = d.page;
    currentRows = d.entries;
    const present = new Set(d.entries.map(e => e.id));
    S.expanded = new Set([...S.expanded].filter(id => present.has(id)));
    updateLiveButton();
    const empty = $('#logs-empty');
    $('#logs-summary').textContent = `${fmtN(d.total)} coincidencias`;
    empty.hidden = d.entries.length > 0;
    if (!d.entries.length) {
      empty.textContent = 'No hay logs que coincidan. Amplía el rango de tiempo o quita filtros; si acabas de configurar el router, comprueba que llegan datagramas al puerto UDP (indicador superior).';
    }
    const raw = S.view === 'raw';
    $('#logtable').hidden = raw; $('#rawview').hidden = !raw;
    if (raw) {
      $('#rawview').innerHTML = d.entries.map(e => {
        const hl = e.hl && COLOR_OK.test(e.hl.color || '');
        return `<div class="rawline${hl ? ' hl' : ''}"${hl ? ` style="background:${e.hl.color}"` : ''}><span class="t">${esc(fmtTs(e.ts))}</span>${esc(e.raw)}</div>`;
      }).join('');
    } else {
      $('#logbody').innerHTML = d.entries.map(rowHtml).join('');
    }
    $$('#logtable th[data-sort]').forEach(th => {
      th.classList.remove('sorted-asc', 'sorted-desc');
      if (th.dataset.sort === S.sort) th.classList.add('sorted-' + S.dir);
    });
    renderPager($('#pager-top'), d.page, d.pages);
    renderPager($('#pager-bottom'), d.page, d.pages);
    S.lastId = S.status ? S.status.last_id : S.lastId;
  } catch (e) {
    if (seq !== S.seq) return;
    inp.classList.add('bad');
    $('#logs-empty').hidden = false;
    $('#logs-empty').textContent = 'Error en la búsqueda: ' + e.message;
  }
}

function initLogs() {
  $('#view-mode').addEventListener('click', e => {
    const b = e.target.closest('button'); if (!b) return;
    S.view = b.dataset.v; persist();
    $$('#view-mode button').forEach(x => x.classList.toggle('active', x === b));
    loadLogs();
  });
  $$('#view-mode button').forEach(x => x.classList.toggle('active', x.dataset.v === S.view));
  $('#pg-size').value = String(S.size);
  $('#pg-size').onchange = e => { S.size = +e.target.value; S.page = 1; persist(); loadLogs(); };
  $('#logtable thead').addEventListener('click', e => {
    const th = e.target.closest('th[data-sort]'); if (!th) return;
    const k = th.dataset.sort;
    if (S.sort === k) S.dir = S.dir === 'asc' ? 'desc' : 'asc'; else { S.sort = k; S.dir = k === 'ts' ? 'desc' : 'asc'; }
    S.page = 1; persist(); loadLogs();
  });
  const pagerClick = e => {
    const b = e.target.closest('button[data-p]'); if (!b || b.disabled) return;
    S.page = +b.dataset.p; loadLogs();
  };
  $('#pager-top').onclick = pagerClick; $('#pager-bottom').onclick = pagerClick;

  $('#logbody').addEventListener('click', e => {
    const fa = e.target.closest('button.fa');
    if (fa) return addCond(fa.dataset.f, fa.dataset.v, fa.dataset.op === 'ne');
    const copy = e.target.closest('button.copyraw');
    if (copy) {
      const r = currentRows.find(x => x.id === +copy.dataset.id);
      navigator.clipboard?.writeText(r ? r.raw : '').then(() => toast('Copiado'), () => toast('No se pudo copiar', true));
      return;
    }
    const mk = e.target.closest('button.mkrule');
    if (mk) {
      const scope = mk.closest('tr.detailrow');
      const picked = $$('input.pick:checked', scope).map(i => ({ field: i.dataset.f, op: 'eq', value: i.dataset.v }));
      const r = currentRows.find(x => x.id === +mk.dataset.id);
      if (!picked.length && r) picked.push({ field: 'any', op: 'contains', value: msgOf(r).slice(0, 120) });
      openRuleDlg({ name: '', action: mk.dataset.act, mode: 'drop', color: '#ffeb3b', match: 'all', conditions: picked });
      return;
    }
    const f = e.target.closest('.f');
    if (f) return addCond(f.dataset.f, f.dataset.v, e.shiftKey);
    if (e.target.closest('input, button, .rawbox')) return;
    const tr = e.target.closest('tr.entry');
    if (tr) {
      const id = +tr.dataset.id;
      if (S.expanded.has(id)) S.expanded.delete(id); else S.expanded.add(id);
      const next = tr.nextElementSibling;
      if (S.expanded.has(id)) {
        tr.classList.add('expanded');
        const r = currentRows.find(x => x.id === id);
        if (r) tr.insertAdjacentHTML('afterend', detailRowHtml(r));
      } else {
        tr.classList.remove('expanded');
        if (next && next.classList.contains('detailrow')) next.remove();
      }
      updateLiveButton();
    }
  });
}

/* ==========================================================================
   Analítica
   ========================================================================== */
const TOPS = [
  ['src_ip', 'Origen (IP)'], ['dst_ip', 'Destino (IP)'], ['dst_port', 'Puertos de destino'], ['flows', 'Flujos origen → destino'],
  ['proto', 'Protocolos'], ['flags', 'Flags TCP'], ['prefix', 'Prefijos de log'], ['chain', 'Cadenas'],
  ['in_if', 'Interfaz de entrada'], ['out_if', 'Interfaz de salida'], ['conn_state', 'Estado de conexión'],
  ['scope', 'Sentido (según IP)'], ['src_mac', 'MAC de origen'], ['topics', 'Topics'], ['device', 'Dispositivos'], ['rules', 'Reglas de resaltado'],
];
const TOP_FIELD = { src_ip: 'src_ip', dst_ip: 'dst_ip', dst_port: 'dst_port', proto: 'proto', flags: 'proto_info', prefix: 'prefix', chain: 'chain', in_if: 'in_if', out_if: 'out_if', conn_state: 'conn_state', scope: 'scope', src_mac: 'src_mac', topics: 'topics', device: 'device' };

function barsSvg(vals, opts = {}) {
  const W = 1000, H = 170, n = vals.length, max = Math.max(1, ...vals.map(v => v.n));
  const bw = W / n;
  let s = `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="${esc(opts.label || 'gráfico')}">`;
  vals.forEach((v, i) => {
    const h = v.n ? Math.max(2, (v.n / max) * (H - 6)) : 0;
    const x = i * bw;
    s += `<rect class="bar" x="${x + 0.5}" y="${H - h}" width="${Math.max(1, bw - 1)}" height="${h}" data-i="${i}"><title>${esc(v.tip)}</title></rect>`;
    if (v.h) { const hh = Math.max(2, (v.h / max) * (H - 6)); s += `<rect class="barhl" x="${x + 0.5}" y="${H - hh}" width="${Math.max(1, bw - 1)}" height="${hh}"/>`; }
  });
  return s + '</svg>';
}

async function loadStats() {
  const seq = ++S.seqStats;
  const body = filterBody();
  try {
    const d = await withLoading($('#an-body'), () => post('/api/stats', body), { text: 'Calculando estadísticas…' });
    if (seq !== S.seqStats) return;
    S.lastStats = Date.now();
    S.statsId = S.status ? S.status.last_id : null;
    renderStats(d);
  } catch (e) {
    if (seq !== S.seqStats) return;
    $('#an-body').innerHTML = `<div class="empty">Error: ${esc(e.message)}</div>`;
  }
}

function renderStats(d) {
  const box = $('#an-body');
  if (!d.total) {
    $('#an-summary').textContent = '';
    box.innerHTML = '<div class="empty">No hay logs en este filtro. Amplía el rango o quita filtros.</div>';
    return;
  }
  $('#an-summary').textContent = `${fmtN(d.total)} logs · ${fmtTs(d.first_ts)} → ${fmtTs(d.last_ts)}`;
  let delta = '';
  if (d.prev_total !== null && d.prev_total !== undefined) {
    if (d.prev_total === 0) delta = `<div class="d">periodo anterior: 0</div>`;
    else {
      const p = ((d.total - d.prev_total) / d.prev_total) * 100;
      delta = `<div class="d ${p > 0 ? 'up' : 'down'}">${p > 0 ? '▲' : '▼'} ${Math.abs(p).toFixed(0)}% vs periodo anterior (${fmtN(d.prev_total)})</div>`;
    }
  }
  const kpi = (v, l, extra = '') => `<div class="kpi"><div class="v">${v}</div><div class="l">${l}</div>${extra}</div>`;
  let h = `<div class="kpis">` +
    kpi(fmtN(d.total), 'logs', delta) +
    kpi(fmtN(d.unique_src), 'IP de origen distintas') + kpi(fmtN(d.unique_dst), 'IP de destino distintas') +
    kpi(fmtBytes(d.bytes), 'tráfico visto en los logs', `<div class="d muted">media ${d.avg_len} B/paquete</div>`) +
    kpi(d.rate_per_min, 'logs por minuto', `<div class="d muted">pico ${fmtN(d.peak.n)} en ${fmtDur(d.peak.bucket)}</div>`) +
    kpi(fmtN(d.highlighted), 'resaltados', `<div class="d muted">${d.total ? ((d.highlighted / d.total) * 100).toFixed(1) : 0}% del total</div>`) +
    `</div>`;

  const tlVals = d.timeline.map(x => ({ n: x.n, h: x.h, tip: `${fmtTs(x.t)} · ${fmtN(x.n)} logs${x.h ? ` (${x.h} resaltados)` : ''} · ${fmtBytes(x.b)}` }));
  const hrVals = d.hours.map((n, i) => ({ n, h: 0, tip: `${pad(i)}:00 · ${fmtN(n)} logs` }));
  h += `<div class="charts"><div class="card chart"><h4>Logs en el tiempo <small>cada barra = ${fmtDur(d.bucket)} · clic para acotar · amarillo = resaltados</small></h4>` +
    `<div id="ch-tl">${barsSvg(tlVals, { label: 'Logs en el tiempo' })}</div>` +
    `<div class="axis"><span>${fmtTs(d.timeline[0].t)}</span><span>máx ${fmtN(d.peak.n)}</span><span>${fmtTs(d.timeline[d.timeline.length - 1].t)}</span></div></div>` +
    `<div class="card chart"><h4>Por hora del día <small>hora del servidor</small></h4>${barsSvg(hrVals, { label: 'Logs por hora del día' })}` +
    `<div class="axis"><span>00h</span><span>12h</span><span>23h</span></div></div></div>`;

  h += `<div class="tops">`;
  for (const [key, title] of TOPS) {
    const rows = d.top[key] || [];
    if (!rows.length) continue;
    const max = rows[0].n;
    h += `<div class="card"><h4>${esc(title)}</h4>` + rows.map(r => {
      const tip = r.b !== undefined ? `${r.label || r.k} — ${fmtN(r.n)} logs, ${fmtBytes(r.b)}` : `${r.label || r.k} — ${fmtN(r.n)}`;
      const swatch = key === 'rules' ? '' : '';
      return `<div class="toprow" data-top="${key}" data-k="${esc(r.k)}" title="${esc(tip)}"><span class="lbl">${swatch}${esc(r.label || r.k)}</span>` +
        `<span class="bar"><i style="width:${(r.n / max) * 100}%"></i></span><span class="n">${fmtN(r.n)}</span></div>`;
    }).join('') + `<p class="note">${key === 'rules' ? 'Coincidencias por regla dentro del filtro actual.' : 'Clic: filtrar · Mayús+clic: excluir'}</p></div>`;
  }
  h += `</div>`;

  h += `<div class="card"><h4>Picos de actividad <small>&gt; media + 3σ</small></h4>`;
  if (d.spikes.length) {
    h += `<table><tr><th>Inicio</th><th>Logs</th><th></th></tr>` + d.spikes.map(s => `<tr><td class="mono">${esc(fmtTs(s.t))}</td><td>${fmtN(s.n)}</td><td><button class="small zoom" data-t="${s.t}" data-b="${d.bucket}">Acotar</button></td></tr>`).join('') + `</table>`;
  } else h += `<p class="note">Sin picos anómalos en el rango (o hay pocos intervalos para calcularlo).</p>`;
  h += `</div>`;
  if (d.capped) h += `<p class="note">Rango muy grande: los rankings de IP, MAC y flujos son aproximados (se alcanzó el tope de claves distintas).</p>`;
  box.innerHTML = h;
  box._stats = d;
}

function initAnalytics() {
  $('#an-refresh').onclick = loadStats;
  $('#an-body').addEventListener('click', e => {
    const d = $('#an-body')._stats;
    const row = e.target.closest('.toprow');
    if (row) {
      const key = row.dataset.top, k = row.dataset.k, neg = e.shiftKey;
      if (key === 'flows') {
        const [s, dd, p] = k.split('|');
        S.conds.push({ field: 'src_ip', op: 'eq', value: s }, { field: 'dst_ip', op: 'eq', value: dd });
        if (p) S.conds.push({ field: 'dst_port', op: 'eq', value: p });
        S.page = 1; renderFilters(); loadStats();
      } else if (key === 'rules') {
        toast('Las reglas se gestionan en la pestaña Reglas');
      } else addCond(TOP_FIELD[key], k, neg);
      return;
    }
    const f = e.target.closest('.f');
    if (f) return addCond(f.dataset.f, f.dataset.v, e.shiftKey);
    const z = e.target.closest('button.zoom');
    if (z) return setRangeCustom(toLocalInput(+z.dataset.t), toLocalInput(+z.dataset.t + +z.dataset.b));
    const bar = e.target.closest('#ch-tl rect.bar');
    if (bar && d) {
      const p = d.timeline[+bar.dataset.i];
      setRangeCustom(toLocalInput(p.t), toLocalInput(p.t + d.bucket));
    }
  });
}

/* ==========================================================================
   Reglas
   ========================================================================== */
const R = { id: null, conditions: [] };

async function loadRules() {
  const body = $('#rules-body');
  try {
    const rules = await withLoading(body, () => api('/api/rules?counts=1'));
    if (!rules.length) {
      body.innerHTML = '<div class="empty">Aún no hay reglas. Crea una con «Nueva regla», o abre un log en la tabla y usa «Regla: resaltar…» / «Regla: excluir…».</div>';
      return;
    }
    body.innerHTML = `<div class="tablewrap rules-table"><table><thead><tr><th>Activa</th><th>Nombre</th><th>Acción</th><th>Condiciones</th><th title="Últimas 24 horas">Coinciden (24 h)</th><th>Descartados</th><th></th></tr></thead><tbody>` +
      rules.map((r, i) => {
        const act = r.action === 'highlight'
          ? `<span class="badge hl"><span class="rulechip" style="background:${COLOR_OK.test(r.color) ? r.color : '#ffeb3b'}"></span>Resaltar</span>`
          : `<span class="badge ex">Excluir · ${r.mode === 'hide' ? 'ocultar' : 'no guardar'}</span>`;
        const conds = r.conditions.map(c => esc(condLabel(c))).join(r.match === 'any' ? '  <b>o</b>  ' : '  <b>y</b>  ');
        return `<tr class="${r.enabled ? '' : 'off'}" data-id="${esc(r.id)}"><td><label class="switch"><input type="checkbox" class="r-en" ${r.enabled ? 'checked' : ''} aria-label="Activar regla"><span></span></label></td>` +
          `<td>${esc(r.name)}</td><td>${act}</td><td class="conds">${conds}</td><td>${fmtN(r.matches ?? 0)}</td>` +
          `<td>${r.action === 'exclude' && r.mode !== 'hide' ? fmtN(r.hits || 0) : '—'}</td>` +
          `<td style="white-space:nowrap"><button class="small r-up" ${i === 0 ? 'disabled' : ''} title="Subir">↑</button> <button class="small r-down" ${i === rules.length - 1 ? 'disabled' : ''} title="Bajar">↓</button> ` +
          `<button class="small r-edit">Editar</button> <button class="small danger r-del">Borrar</button></td></tr>`;
      }).join('') + `</tbody></table></div>`;
    body._rules = rules;
  } catch (e) { body.innerHTML = `<div class="empty">Error: ${esc(e.message)}</div>`; }
}

function openRuleDlg(rule) {
  R.id = rule.id || null;
  R.conditions = (rule.conditions || []).map(c => ({ ...c }));
  if (!R.conditions.length) R.conditions.push({ field: 'any', op: 'contains', value: '' });
  $('#ruleTitle').textContent = R.id ? 'Editar regla' : 'Nueva regla';
  $('#r-name').value = rule.name || '';
  $('#r-action').value = rule.action || 'highlight';
  $('#r-mode').value = rule.mode || 'drop';
  $('#r-color').value = COLOR_OK.test(rule.color || '') ? rule.color : '#ffeb3b';
  $('#r-match').value = rule.match || 'all';
  $('#r-test').hidden = true;
  syncRuleAction();
  renderCondEditor($('#r-conds'), R.conditions, () => { $('#r-test').hidden = true; });
  $('#ruleDlg').showModal();
}
function syncRuleAction() {
  const ex = $('#r-action').value === 'exclude';
  $('#r-mode-wrap').hidden = !ex; $('#r-color-wrap').hidden = ex;
}
function ruleFromForm() {
  return {
    name: $('#r-name').value, action: $('#r-action').value, mode: $('#r-mode').value, color: $('#r-color').value,
    match: $('#r-match').value, conditions: R.conditions.filter(validCond), enabled: true,
  };
}
function initRules() {
  $('#rule-new').onclick = () => openRuleDlg({ action: 'highlight', color: '#ffeb3b', match: 'all' });
  $('#r-action').onchange = syncRuleAction;
  $('#r-add-cond').onclick = () => { R.conditions.push({ field: 'any', op: 'contains', value: '' }); renderCondEditor($('#r-conds'), R.conditions, () => { $('#r-test').hidden = true; }); };
  $('#r-cancel').onclick = () => $('#ruleDlg').close();
  $('#r-test-btn').onclick = async () => {
    const box = $('#r-test'); box.hidden = false; box.textContent = 'Probando…';
    try {
      const t = await post('/api/rules/test', ruleFromForm());
      box.innerHTML = `<b>${fmtN(t.count)}</b> de ${fmtN(t.of)} logs de las últimas 24 h coinciden.` +
        t.sample.map(e => `<div class="s">${esc(fmtTs(e.ts))}  ${esc(e.raw)}</div>`).join('');
    } catch (e) { box.textContent = 'Error: ' + e.message; }
  };
  $('#ruleForm').onsubmit = async ev => {
    ev.preventDefault();
    try {
      const body = ruleFromForm();
      if (R.id) {
        const prev = ($('#rules-body')._rules || []).find(r => r.id === R.id);
        if (prev) body.enabled = prev.enabled;
        await api('/api/rules/' + R.id, { method: 'PUT', body });
      } else await post('/api/rules', body);
      $('#ruleDlg').close();
      toast('Regla guardada');
      if (S.tab === 'rules') loadRules(); else reloadCurrent();
    } catch (e) { toast(e.message, true); }
  };
  $('#rules-body').addEventListener('click', async e => {
    const tr = e.target.closest('tr[data-id]'); if (!tr) return;
    const id = tr.dataset.id;
    const rule = ($('#rules-body')._rules || []).find(r => r.id === id);
    try {
      if (e.target.closest('.r-edit')) openRuleDlg(rule);
      else if (e.target.closest('.r-del')) {
        if (confirm(`¿Borrar la regla «${rule.name}»?`)) { await api('/api/rules/' + id, { method: 'DELETE' }); loadRules(); }
      } else if (e.target.closest('.r-up')) { await post(`/api/rules/${id}/move`, { dir: 'up' }); loadRules(); }
      else if (e.target.closest('.r-down')) { await post(`/api/rules/${id}/move`, { dir: 'down' }); loadRules(); }
    } catch (err) { toast(err.message, true); }
  });
  $('#rules-body').addEventListener('change', async e => {
    const cb = e.target.closest('.r-en'); if (!cb) return;
    const id = cb.closest('tr').dataset.id;
    const rule = $('#rules-body')._rules.find(r => r.id === id);
    try { await api('/api/rules/' + id, { method: 'PUT', body: { ...rule, enabled: cb.checked } }); loadRules(); }
    catch (err) { toast(err.message, true); cb.checked = !cb.checked; }
  });
}

/* ==========================================================================
   Ajustes (Guardado/almacenamiento)
   ========================================================================== */
async function downloadExport(fmt, all) {
  try {
    const r = await api('/api/export', { method: 'POST', raw: true, body: { ...filterBody(), format: fmt, all } });
    const blob = await r.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `mikrotik-logs-${all ? 'todo' : 'filtro'}-${Date.now()}.${fmt}`;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 4000);
  } catch (e) { toast(e.message, true); }
}

async function loadStorage() {
  const box = $('#st-body');
  try {
    const [st, cfg, segs] = await withLoading(box, () => Promise.all([api('/api/status'), api('/api/config'), api('/api/segments')]));
    S.status = st; S.config = cfg;
    const s = cfg.settings, d = st.disk, sg = st.storage, g = st.guard || {};
    const num = (id, label, hint, val, min, max) =>
      `<label><span>${label}<small>${hint}</small></span><input type="number" id="s-${id}" value="${val}" min="${min}" max="${max}"></label>`;
    const sel = (id, label, hint, val, opts) =>
      `<label><span>${label}<small>${hint}</small></span><select id="s-${id}">` +
      opts.map(([v, t]) => `<option value="${v}" ${String(val) === String(v) ? 'selected' : ''}>${t}</option>`).join('') + `</select></label>`;

    // --- disco
    let disk = '<p class="note">No se pudo leer el uso de disco.</p>';
    if (d) {
      const used = 100 - d.free_pct, min = s.min_free_percent;
      const bad = g.low_disk || g.write_error;
      const cls = bad ? 'bad' : (d.free_pct < (min ? min + 5 : 10) ? 'warn' : '');
      let est = 'Estimación de llenado disponible con al menos 6 h de datos.';
      if (sg.growth_per_day !== undefined) {
        est = `Crecimiento ≈ <b>${fmtBytes(sg.growth_per_day)}/día</b> (comprimido). ` +
          (sg.days_left === null || sg.days_left === undefined ? '' :
            sg.days_left <= 0 ? `<b>El disco ya está en o por debajo del ${min ? 'mínimo libre' : 'límite'}.</b>` :
            `Al ritmo actual el disco ${min ? 'llegaría al mínimo libre' : 'se llenaría'} ` +
            (sg.days_left > 3650 ? '<b>en más de 10 años</b>' : `en ≈ <b>${sg.days_left >= 10 ? Math.round(sg.days_left) : sg.days_left} días</b>`) +
            ` <span class="muted">(supone que el resto del disco no crece)</span>.`);
      }
      let guard = min
        ? `Protección activa: mínimo <b>${min}%</b> libre → ${s.low_disk_action === 'pause' ? 'pausar la captura' : 'borrar los segmentos más antiguos (y pausar si aun así no basta)'}.`
        : '<b>Protección desactivada</b>: nada impide que los logs llenen el disco.';
      disk = `<div class="diskbar ${cls}" title="${fmtN(used)}% usado"><i style="width:${used}%"></i>${min ? `<b style="left:${100 - min}%" title="Mínimo libre ${min}%"></b>` : ''}</div>` +
        `<table class="kv"><tr><td>Libre</td><td><b>${fmtBytes(d.free)}</b> de ${fmtBytes(d.total)} (${d.free_pct}%)</td></tr>` +
        `<tr><td>Logs en disco</td><td><b>${fmtBytes(sg.logs_bytes)}</b> · ${fmtN(sg.segments)} segmentos rotados (${fmtBytes(sg.rotated_bytes)}) + activo ${fmtBytes(sg.cur_bytes)}</td></tr>` +
        `<tr><td>Previsión</td><td>${est}</td></tr>` +
        `<tr><td>Protección</td><td>${guard}</td></tr>` +
        (g.low_disk ? `<tr><td>Estado</td><td style="color:var(--danger)"><b>Captura pausada por poco espacio libre.</b> Libera espacio o baja el mínimo.</td></tr>` : '') +
        (g.write_error ? `<tr><td>Error</td><td style="color:var(--danger)">${esc(g.write_error)} — captura pausada; se reintenta sola.</td></tr>` : '') +
        (g.note ? `<tr><td>Última acción</td><td>${esc(g.note)}${g.freed_bytes ? ` · total liberado ${fmtBytes(g.freed_bytes)}` : ''}</td></tr>` : '') +
        `</table>`;
    }

    // --- segmentos
    const shown = segs.slice(0, 60);
    const segTable = `<table class="btable"><tr><th>Archivo</th><th>Desde</th><th>Hasta</th><th>Logs</th><th>Tamaño</th><th></th></tr>` +
      `<tr><td class="mono">current.ndjson <span class="badge hl">activo</span></td><td colspan="2" class="muted">en curso (se rota a ${s.rotate_size_mb} MB${s.rotate_hours ? ` o ${s.rotate_hours} h` : ''})</td><td>${fmtN(sg.cur_entries)}</td><td>${fmtBytes(sg.cur_bytes)}</td><td></td></tr>` +
      shown.map(x => `<tr><td class="mono">${esc(x.name)}</td><td>${esc(fmtTs(x.first))}</td><td>${esc(fmtTs(x.last))}</td><td>${fmtN(x.count)}</td><td>${fmtBytes(x.size)}${x.gz ? '' : ' <span class="muted">(sin comprimir)</span>'}</td>` +
        `<td class="btnrow" style="margin:0"><a href="/api/segments/${encodeURIComponent(x.name)}" download><button class="small">Descargar</button></a>` +
        `<button class="small danger" data-act="seg-del" data-name="${esc(x.name)}">Borrar</button></td></tr>`).join('') + `</table>` +
      (segs.length > shown.length ? `<p class="note">Mostrando los ${shown.length} más recientes de ${fmtN(segs.length)}.</p>` : '') +
      (!segs.length ? '<p class="note">Aún no ha rotado ningún segmento.</p>' : '');

    box.innerHTML =
      `<div class="card" style="grid-column:1/-1"><h4>Disco <small>${esc(st.logs_dir)}</small></h4>${disk}` +
      `<div class="btnrow"><button data-act="save" class="primary">Volcar a disco ahora</button><button data-act="rotate">Rotar ahora</button></div></div>` +

      `<div class="card form"><h4>Rotación y espacio</h4>` +
      num('rotate_size_mb', 'Rotar al llegar a (MB)', 'Tamaño del segmento activo. La RAM usada es ≈ 3× este valor', s.rotate_size_mb, 1, 4096) +
      num('rotate_hours', 'Rotar cada (horas)', '0 = solo por tamaño', s.rotate_hours, 0, 8760) +
      sel('compress_rotated', 'Comprimir rotados', 'gzip: ahorra mucho disco; consultar histórico es algo más lento', s.compress_rotated, [['true', 'Sí'], ['false', 'No']]) +
      num('min_free_percent', 'Espacio libre mínimo (%)', '0 = sin protección de disco', s.min_free_percent, 0, 50) +
      sel('low_disk_action', 'Si queda menos: acción', 'Borrar = segmentos rotados más antiguos, primero los más viejos. Nunca se toca el activo', s.low_disk_action, [['delete_oldest', 'Borrar antiguos'], ['pause', 'Pausar captura']]) +
      num('retention_days', 'Retención (días)', '0 = sin límite por antigüedad (se borran segmentos enteros)', s.retention_days, 0, 36500) +
      num('autosave_seconds', 'Volcado a disco (s)', 'Cada cuánto se fuerza la escritura (fsync)', s.autosave_seconds, 1, 300) +
      `<p class="note">No hay tope de número de logs ni backups: el único límite es el disco. Rotar solo cierra el segmento activo y abre otro.</p>` +
      `<div class="btnrow"><button data-act="settings" class="primary">Guardar ajustes</button></div></div>` +

      `<div class="card"><h4>Estado</h4><table class="kv">` +
      `<tr><td>Logs totales</td><td>${fmtN(st.entries)} ${st.first_ts ? `(${esc(fmtTs(st.first_ts))} → ${esc(fmtTs(st.last_ts))})` : ''}</td></tr>` +
      `<tr><td>Último volcado</td><td>${st.last_saved ? esc(fmtTs(st.last_saved)) : 'nunca'}${st.dirty ? ` · <b>${fmtN(st.unsaved)} en búfer aún sin volcar</b>` : ''}</td></tr>` +
      `<tr><td>Recibidos</td><td>${fmtN(st.counters.received)} · guardados ${fmtN(st.counters.stored)} · descartados por regla ${fmtN(st.counters.dropped_rule)} · ilegibles ${fmtN(st.counters.invalid)}</td></tr>` +
      `<tr><td>En búfer</td><td><b>${fmtN(st.unsaved)}</b> log(s) escritos pero aún sin fsync a disco</td></tr>` +
      `<tr><td>No capturados</td><td>en pausa manual ${fmtN(st.counters.paused)} · por disco ${fmtN(st.counters.paused_disk)}</td></tr>` +
      `<tr><td>Rotaciones</td><td>${fmtN(st.counters.rotations)} desde el arranque</td></tr>` +
      (st.last_save_error ? `<tr><td>Error</td><td style="color:var(--danger)">${esc(st.last_save_error)}</td></tr>` : '') +
      `</table></div>` +

      `<div class="card"><h4>Exportar e importar</h4>` +
      `<div class="btnrow"><button data-act="export" data-fmt="json" data-all="0">Filtro actual · JSON</button><button data-act="export" data-fmt="csv" data-all="0">Filtro actual · CSV</button></div>` +
      `<div class="btnrow"><button data-act="export" data-fmt="json" data-all="1">Todo · JSON</button><button data-act="export" data-fmt="csv" data-all="1">Todo · CSV</button></div>` +
      `<p class="note">Se genera en streaming (sirve para históricos grandes). El JSON exportado se puede volver a importar. Los CSV escapan celdas que empiezan por = + - @.</p><hr style="border:0;border-top:1px solid var(--line);margin:12px 0">` +
      `<div class="btnrow"><input type="file" id="imp-file" accept=".json,.gz,application/json"><select id="imp-mode"><option value="merge">Fusionar (sin duplicados)</option><option value="replace">Reemplazar todo (irreversible)</option></select><button data-act="import">Importar</button></div></div>` +

      `<div class="card"><h4>Mantenimiento</h4><p class="note" style="margin-top:0">Los borrados son <b>irreversibles</b>: no se crean backups.</p>` +
      `<div class="btnrow"><label class="muted">Borrar logs con más de <input id="pg-days" type="number" min="1" value="7" style="width:70px"> días</label><button data-act="purge-old" class="danger">Borrar antiguos</button></div>` +
      `<div class="btnrow"><button data-act="purge-filter" class="danger">Borrar los que coinciden con el filtro actual</button><button data-act="purge-all" class="danger">Vaciar todo</button></div></div>` +

      `<div class="card" style="grid-column:1/-1"><h4>Segmentos <small>rotados, del más reciente al más antiguo</small></h4>${segTable}</div>`;
  } catch (e) { box.innerHTML = `<div class="empty">Error: ${esc(e.message)}</div>`; }
}

function initStorage() {
  $('#st-body').addEventListener('click', async e => {
    const b = e.target.closest('button[data-act]'); if (!b) return;
    const act = b.dataset.act;
    try { await busyRun(b, () => runStorageAction(act, b)); }
    catch (err) { toast(err.message, true); }
  });
}

async function runStorageAction(act, b) {
      if (act === 'save') { await saveNow(); loadStorage(); }
      else if (act === 'rotate') { const r = await post('/api/rotate'); toast('Rotado: ' + r.name); loadStorage(); }
      else if (act === 'seg-del') {
        const name = b.dataset.name;
        if (!confirm(`¿Borrar definitivamente el segmento «${name}»? No hay backup: es irreversible.`)) return;
        const r = await api('/api/segments/' + encodeURIComponent(name), { method: 'DELETE' });
        toast(`Segmento borrado (${fmtN(r.deleted)} logs)`); loadStorage();
      }
      else if (act === 'settings') {
        const body = {};
        for (const k of ['rotate_size_mb', 'rotate_hours', 'min_free_percent', 'retention_days', 'autosave_seconds', 'low_disk_action']) body[k] = $('#s-' + k).value;
        body.compress_rotated = $('#s-compress_rotated').value === 'true';
        const mf = +body.min_free_percent, ret = +body.retention_days;
        if (ret > 0 && !confirm(`Con retención de ${ret} días se borrarán definitivamente los segmentos más viejos. ¿Continuar?`)) return;
        if (mf === 0 && !confirm('Sin espacio libre mínimo, nada impide que los logs llenen el disco. ¿Continuar?')) return;
        await api('/api/config', { method: 'PUT', body }); toast('Ajustes guardados'); loadStorage();
      }
      else if (act === 'export') await downloadExport(b.dataset.fmt, b.dataset.all === '1');
      else if (act === 'import') {
        const f = $('#imp-file').files[0];
        if (!f) return toast('Elige un archivo .json o .json.gz', true);
        const mode = $('#imp-mode').value;
        if (mode === 'replace' && !confirm('Se BORRARÁN todos los logs actuales y se cargarán los del archivo. No hay backup: es irreversible. ¿Continuar?')) return;
        const fd = new FormData(); fd.append('file', f); fd.append('mode', mode);
        const r = await api('/api/import', { method: 'POST', body: fd });
        toast(`Importados ${fmtN(r.added)} · duplicados omitidos ${fmtN(r.skipped)}`);
        loadStorage();
      }
      else if (act === 'purge-old') {
        const days = +$('#pg-days').value;
        if (!(days > 0)) return toast('Indica un número de días', true);
        if (!confirm(`¿Borrar definitivamente los logs con más de ${days} días?`)) return;
        const r = await post('/api/purge', { mode: 'older', days }); toast(`Borrados ${fmtN(r.deleted)}`); loadStorage();
      }
      else if (act === 'purge-filter') {
        if (!confirm('¿Borrar definitivamente todos los logs que coinciden con el filtro actual (incluye los ocultos por reglas)? En históricos grandes puede tardar.')) return;
        const r = await post('/api/purge', { mode: 'filter', filter: filterBody() }); toast(`Borrados ${fmtN(r.deleted)}`); loadStorage();
      }
      else if (act === 'purge-all') {
        if (!confirm('¿Vaciar TODOS los logs? Es irreversible: no hay backups.')) return;
        const r = await post('/api/purge', { mode: 'all' }); toast(`Borrados ${fmtN(r.deleted)}`); loadStorage();
      }
}

async function saveNow() {
  const r = await post('/api/save');
  if (r.ok) toast('Volcado a disco'); else toast('Error al escribir: ' + r.error, true);
  pollStatus();
}

/* ==========================================================================
   Estado del servidor, cabecera y arranque
   ========================================================================== */
function updateLiveButton() {
  const sel = $('#live-interval');
  if (sel.value !== String(S.liveSec)) sel.value = String(S.liveSec);
  const dot = $('#live-dot');
  const paused = S.liveSec > 0 && S.expanded.size > 0;
  dot.classList.toggle('on', S.liveSec > 0 && !paused);
  dot.classList.toggle('paused', paused);
  const opt = sel.options[sel.selectedIndex];
  dot.closest('.live-picker').title = paused
    ? 'En vivo en pausa: hay filas abiertas en la tabla'
    : (S.liveSec > 0 ? `Actualiza Logs/Analítica automáticamente (${opt ? opt.textContent : ''})` : 'Actualización automática desactivada: usa «Actualizar» o cambia de página para refrescar');
}

function renderStatus(s) {
  const L = s.listener || {};
  const pl = $('#pill-listener');
  pl.textContent = L.running ? `UDP :${L.port} escuchando` : `UDP :${L.port ?? '?'} sin escuchar`;
  pl.className = 'pill ' + (L.running ? 'ok' : 'bad');
  pl.title = L.error || 'Receptor syslog UDP';
  $('#pill-count').textContent = `${fmtN(s.entries)} logs`;
  $('#pill-rate').textContent = `${s.rate}/s`;
  const ps = $('#pill-save');
  const g = s.guard || {};
  if (g.write_error) { ps.textContent = 'error de escritura'; ps.className = 'pill bad'; ps.title = g.write_error; }
  else if (g.low_disk) { ps.textContent = 'captura pausada por disco'; ps.className = 'pill bad'; ps.title = g.note || ''; }
  else if (s.last_save_error) { ps.textContent = 'error al guardar'; ps.className = 'pill bad'; ps.title = s.last_save_error; }
  else if (s.dirty) { ps.textContent = `en búfer (${fmtN(s.unsaved)})`; ps.className = 'pill warn'; ps.title = `${fmtN(s.unsaved)} log(s) recientes aún sin volcar a disco (se vuelcan solos cada pocos segundos)`; }
  else { ps.textContent = s.last_saved ? 'en disco ' + fmtTs(s.last_saved).slice(11) : 'sin datos nuevos'; ps.className = 'pill ok'; ps.title = ''; }
  const pd = $('#pill-disk');
  if (s.disk) {
    const min = S.config ? S.config.settings.min_free_percent : 0;
    pd.textContent = `disco ${s.disk.free_pct}% libre`;
    pd.className = 'pill ' + (g.low_disk || g.write_error ? 'bad' : (s.disk.free_pct < (min ? min + 5 : 10) ? 'warn' : 'ok'));
    pd.title = `${fmtBytes(s.disk.free)} libres de ${fmtBytes(s.disk.total)}. Logs: ${fmtBytes(s.storage.logs_bytes)}`;
  }
  const cap = $('#btn-capture');
  const diskPaused = !!(g.low_disk || g.write_error);
  cap.classList.toggle('on', s.capture_enabled && !diskPaused); cap.classList.toggle('off', !s.capture_enabled || diskPaused);
  cap.textContent = diskPaused ? 'Pausada por disco' : (s.capture_enabled ? 'Capturando' : 'Captura en pausa');
  const bn = $('#banner');
  const msgs = [];
  if (L.error) msgs.push(`No se pudo abrir el puerto UDP ${L.port}: ${L.error}`);
  if (s.warning) msgs.push(s.warning);
  if (g.low_disk) msgs.push('Captura pausada: queda poco espacio libre en el disco de logs (Ajustes → Disco).');
  if (g.write_error) msgs.push('No se puede escribir en disco: ' + g.write_error);
  bn.hidden = !msgs.length; bn.textContent = msgs.join(' · ');
  bn.className = 'banner' + (L.error || g.low_disk || g.write_error ? ' err' : '');
}

let offline = false;
async function pollStatus() {
  try {
    const s = await api('/api/status');
    if (offline) { offline = false; toast('Conexión con el servidor recuperada'); }
    S.status = s;
    renderStatus(s);
  } catch (e) {
    if (!offline) { offline = true; toast('Sin conexión con el servidor', true); }
  }
}

// Refresco automático de Logs/Analítica según S.liveSec (10/30/60 s, o 0 = desactivado).
let liveTimer = null;
function scheduleLive() {
  if (liveTimer) { clearTimeout(liveTimer); liveTimer = null; }
  if (!S.liveSec) return;
  liveTimer = setTimeout(liveTick, S.liveSec * 1000);
}
function liveTick() {
  if (S.liveSec && !S.expanded.size) {
    if (S.tab === 'logs' && S.page === 1) loadLogs();
    else if (S.tab === 'analytics') loadStats();
  }
  scheduleLive();
}

function showTab(t) {
  S.tab = t;
  $$('.tabs button').forEach(b => b.classList.toggle('active', b.dataset.tab === t));
  $$('.tab').forEach(x => x.classList.toggle('active', x.id === 'tab-' + t));
  $('#filterbar').classList.toggle('hidden', !(t === 'logs' || t === 'analytics'));
  if (t === 'logs') loadLogs();
  else if (t === 'analytics') loadStats();
  else if (t === 'rules') loadRules();
  else if (t === 'storage') loadStorage();
}

async function init() {
  $$('.tabs button').forEach(b => b.onclick = () => showTab(b.dataset.tab));
  initFilters(); initLogs(); initAnalytics(); initRules(); initStorage();
  $('#live-interval').onchange = e => { S.liveSec = +e.target.value; persist(); updateLiveButton(); scheduleLive(); };
  $('#btn-save').onclick = e => busyRun(e.currentTarget, () => saveNow()).catch(err => toast(err.message, true));
  $('#btn-capture').onclick = e => busyRun(e.currentTarget, async () => {
    try {
      const cur = S.status ? S.status.capture_enabled : true;
      await api('/api/config', { method: 'PUT', body: { capture_enabled: !cur } });
      toast(cur ? 'Captura en pausa: los logs nuevos se ignoran' : 'Captura reanudada');
      pollStatus();
    } catch (e) { toast(e.message, true); }
  });
  renderFilters(); updateLiveButton();
  try { await loadConfig(); } catch (e) { toast(e.message, true); }
  await pollStatus();
  showTab('logs');
  setInterval(pollStatus, 2000);
  scheduleLive();
}
init();
