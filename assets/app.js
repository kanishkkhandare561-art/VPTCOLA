/* Constitutional Law notes — private, encrypted study site.
   The notes live in data/c.bin (AES-256-GCM). The key is wrapped with a key derived from the password
   (PBKDF2-SHA256) in data/key.json. Everything is decrypted in the browser; nothing is sent anywhere. */
'use strict';
(() => {
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const b64e = u8 => { let s = ''; u8.forEach(b => { s += String.fromCharCode(b); }); return btoa(s); };
  const enc = new TextEncoder();
  const today = () => Math.floor(Date.now() / 864e5);

  /* ---------------- local storage (per device, never leaves the browser) ---------------- */
  const store = {
    get(k, d) { try { const v = localStorage.getItem('cln.' + k); return v == null ? d : JSON.parse(v); } catch (e) { return d; } },
    set(k, v) { try { localStorage.setItem('cln.' + k, JSON.stringify(v)); } catch (e) { /* storage full or blocked */ } },
    del(k) { try { localStorage.removeItem('cln.' + k); } catch (e) { /* ignore */ } },
  };
  const raw = {
    get(k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* ignore */ } },
  };

  /* ---------------- crypto ---------------- */
  let KEY = null;
  let DB = null;
  const IK = 'https://indiankanoon.org';

  async function fetchBytes(path) {
    const r = await fetch(path, { cache: 'no-cache' });
    if (!r.ok) throw new Error(`Could not load ${path} (${r.status})`);
    return new Uint8Array(await r.arrayBuffer());
  }
  async function unseal(buf) {
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0, 12) }, KEY, buf.slice(12)));
  }
  async function gunzip(u8) {
    const s = new Blob([u8]).stream().pipeThrough(new DecompressionStream('gzip'));
    return new Uint8Array(await new Response(s).arrayBuffer());
  }
  async function keyFile() {
    const r = await fetch('data/key.json', { cache: 'no-cache' });
    if (!r.ok) throw new Error('The key file is missing (data/key.json).');
    return r.json();
  }
  async function kekFrom(pw, kf, usage) {
    const base = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: b64d(kf.salt), iterations: kf.iter, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, usage);
  }
  async function unwrapWith(pw, kf) {
    const kek = await kekFrom(pw, kf, ['decrypt']);
    try {
      return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64d(kf.iv), additionalData: enc.encode(kf.aad) }, kek, b64d(kf.wrapped)));
    } catch (e) { return null; }
  }
  async function useKey(rawKey) { KEY = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt']); }

  async function loadDB() {
    const plain = await gunzip(await unseal(await fetchBytes('data/c.bin')));
    DB = JSON.parse(new TextDecoder().decode(plain));
    indexDB();
  }

  /* ---------------- lock screen ---------------- */
  async function tryRemembered() {
    const k = raw.get('cln.k') || (() => { try { return sessionStorage.getItem('cln.k'); } catch (e) { return null; } })();
    if (!k) return false;
    try { await useKey(b64d(k)); await loadDB(); return true; } catch (e) { forget(); return false; }
  }
  function forget() { try { localStorage.removeItem('cln.k'); sessionStorage.removeItem('cln.k'); } catch (e) { /* ignore */ } KEY = null; }

  $('#lock-form').addEventListener('submit', async ev => {
    ev.preventDefault();
    const btn = $('#unlock'), err = $('#lock-err'), pw = $('#pw').value;
    if (!window.crypto?.subtle || !window.DecompressionStream) { err.textContent = 'This browser is too old to open the notes. Use a current Chrome, Edge, Firefox or Safari.'; return; }
    btn.disabled = true; btn.textContent = 'Opening…'; err.textContent = '';
    try {
      const kf = await keyFile();
      const rk = await unwrapWith(pw, kf);
      if (!rk) { err.textContent = 'That password is not right. Check it and try again.'; return; }
      await useKey(rk);
      await loadDB();
      const b = b64e(rk);
      if ($('#remember').checked) raw.set('cln.k', b); else { try { sessionStorage.setItem('cln.k', b); } catch (e) { /* ignore */ } }
      $('#pw').value = '';
      start();
    } catch (e) {
      err.textContent = e.message || 'The notes could not be opened.';
    } finally { btn.disabled = false; btn.textContent = 'Open notes'; }
  });

  /* ---------------- data indexes ---------------- */
  const M = { ch: {}, sec: {}, secs: [], cases: {}, qa: {}, art: {}, fix: {}, src: {}, fixWhere: {}, topics: [] };
  function indexDB() {
    for (const doc of ['exam', 'day']) {
      DB[doc].forEach((ch, i) => {
        ch.doc = doc; ch.idx = i;
        M.ch[doc + '/' + ch.id] = ch;
        ch.sections.forEach(s => {
          s.doc = doc; s.ch = ch.id;
          s.key = `${doc}/${ch.id}/${s.id}`;
          M.sec[s.key] = s; M.secs.push(s);
          const re = /data-fix="([\w-]+)"/g; let m;
          while ((m = re.exec(s.html))) (M.fixWhere[m[1]] ||= new Set()).add(s.key);
        });
      });
    }
    DB.cases.forEach(c => { M.cases[c.k] = c; });
    DB.qa.forEach(q => { M.qa[q.id] = q; });
    DB.articles.forEach(a => { M.art[a.n] = a; });
    DB.corrections.forEach(c => { M.fix[c.id] = c; });
    DB.sources.forEach(s => { M.src[s.id] = s; });
    const t = new Set(); DB.cases.forEach(c => c.topics.forEach(x => t.add(x)));
    M.topics = [...t].sort();
  }
  const chapterLabel = ch => ch.doc === 'exam'
    ? (ch.num ? `Lecture ${ch.num}` : (ch.kind === 'toolkit' ? 'Revision' : 'Start here'))
    : (ch.id === 'D0' ? 'Reference' : ch.id === 'WS' ? 'Handout' : ch.id === 'Dintro' ? 'Start here' : `Day ${ch.num}`);
  const secHref = (key, extra = '') => `#/read/${key}${extra}`;
  const caseUrl = c => c.url || `${IK}/search/?formInput=${encodeURIComponent(`title: "${c.name.split(' v. ')[0]}"`)}`;
  const caseSrcName = c => c.src === 'justia' ? 'Justia' : 'Indian Kanoon';

  /* ---------------- user state ---------------- */
  const S = {
    rev: store.get('rev', {}), bm: store.get('bm', []), notes: store.get('notes', {}), fc: store.get('fc', {}),
    steps: store.get('steps', {}), recent: store.get('recent', []), last: store.get('last', null),
    save(k) { store.set(k, this[k]); },
  };

  /* ---------------- shell ---------------- */
  const NAV = [
    ['Read', [['#/', 'Home'], ['#/read/exam/L1', 'Exam-ready notes', () => 'Oct'], ['#/read/day/D1', 'Day-wise class notes', () => 'Jul–Oct'], ['#/fixes', 'Corrections', () => DB.corrections.length]]],
    ['Find', [['#/search', 'Search everything'], ['#/cases', 'Case finder', () => DB.cases.length], ['#/articles', 'Constitution text', () => DB.articles.length], ['#/kanoon', 'Indian Kanoon search']]],
    ['Practise', [['#/solve', 'Problem frameworks'], ['#/flash', 'Flashcards'], ['#/quiz', 'Case quiz'], ['#/timeline', 'Timeline']]],
    ['Yours', [['#/sources', 'Lecture files', () => DB.sources.length], ['#/saved', 'Saved and progress'], ['#/settings', 'Settings']]],
  ];
  function drawNav(active) {
    $('#nav').innerHTML = NAV.map(([g, items]) => `<div class="navgroup">${g}</div>` + items.map(([h, l, cnt]) =>
      `<a href="${h}" ${active === h ? 'aria-current="page"' : ''}><span>${l}</span>${cnt ? `<span class="count">${cnt()}</span>` : ''}</a>`).join('')).join('');
  }
  function start() {
    $('#lock').hidden = true; $('#app').hidden = false;
    window.addEventListener('hashchange', route);
    route();
    setTimeout(() => (window.requestIdleCallback || setTimeout)(() => buildIndex()), 1500);
  }
  $('#menu-btn').addEventListener('click', () => document.body.classList.toggle('menu'));
  document.addEventListener('click', e => { if (document.body.classList.contains('menu') && !e.target.closest('#rail') && !e.target.closest('#menu-btn')) document.body.classList.remove('menu'); });

  function toast(msg) {
    const t = document.createElement('div'); t.className = 'toast'; t.textContent = msg; t.setAttribute('role', 'status');
    document.body.appendChild(t); setTimeout(() => t.remove(), 2200);
  }

  /* ---------------- router ---------------- */
  const view = () => $('#view');
  let cleanup = [];
  function route() {
    cleanup.forEach(f => f()); cleanup = [];
    hidePop();
    document.body.classList.remove('menu');
    const h = location.hash.slice(1) || '/';
    const [path, qs] = h.split('?');
    const q = new URLSearchParams(qs || '');
    const p = path.split('/').filter(Boolean).map(decodeURIComponent);
    const r = p[0] || '';
    let active = '#/' + r;
    try {
      if (!r) homeView();
      else if (r === 'read') { readerView(p[1], p[2], p[3], q); active = p[1] === 'exam' ? '#/read/exam/L1' : '#/read/day/D1'; }
      else if (r === 'cases') casesView(q);
      else if (r === 'case') { caseView(p[1]); active = '#/cases'; }
      else if (r === 'articles' || r === 'article') { articlesView(p[1] || '14'); active = '#/articles'; }
      else if (r === 'search') searchView(q);
      else if (r === 'kanoon') kanoonView(q);
      else if (r === 'flash') flashView(q);
      else if (r === 'quiz') quizView();
      else if (r === 'timeline') timelineView(q);
      else if (r === 'solve') { solveView(p[1]); active = '#/solve'; }
      else if (r === 'sources' || r === 'source') { sourcesView(p[1], q); active = '#/sources'; }
      else if (r === 'fixes') fixesView();
      else if (r === 'saved') savedView();
      else if (r === 'settings') settingsView();
      else notFound();
    } catch (e) { console.error(e); view().innerHTML = `<div class="wrap narrow"><h1 class="page">Something went wrong</h1><p class="lede">${esc(e.message)}</p><p><a href="#/">Go to the home page</a></p></div>`; }
    drawNav(active);
    const h1 = $('#view h1'); $('#top-title').textContent = h1 ? h1.textContent : 'Constitutional Law';
    document.title = (h1 ? h1.textContent + ' — ' : '') + 'Constitutional Law Notes';
    afterRender(view());
  }
  function notFound() { view().innerHTML = `<div class="wrap narrow"><h1 class="page">Page not found</h1><p class="lede">That address does not match anything in the notes.</p><p><a href="#/">Go to the home page</a></p></div>`; }

  function afterRender(root) {
    $$('span.ik', root).forEach(s => {
      const c = s.dataset.k && M.cases[s.dataset.k];
      const href = c ? caseUrl(c) : `${IK}/search/?formInput=${encodeURIComponent(s.dataset.q || '')}`;
      s.outerHTML = `<a class="ikbtn" href="${esc(href)}" target="_blank" rel="noopener noreferrer">${c ? caseSrcName(c) : 'Search Indian Kanoon'}</a>`;
    });
    $$('a[href^="http"]', root).forEach(a => { a.target = '_blank'; a.rel = 'noopener noreferrer'; });
  }

  /* ---------------- popovers (case references and corrections) ---------------- */
  const pop = $('#pop');
  function showPop(target, html) {
    pop.innerHTML = `<button class="x" aria-label="Close">×</button>${html}`;
    pop.hidden = false;
    afterRender(pop);
    const r = target.getBoundingClientRect(), w = Math.min(420, innerWidth - 24);
    let left = Math.min(Math.max(12, r.left), innerWidth - w - 12);
    pop.style.left = left + 'px';
    const ph = pop.offsetHeight;
    pop.style.top = (r.bottom + 8 + ph > innerHeight && r.top - ph - 8 > 0 ? r.top - ph - 8 : r.bottom + 8) + 'px';
    $('.x', pop).focus({ preventScroll: true });
  }
  function hidePop() { pop.hidden = true; }
  pop.addEventListener('click', e => { if (e.target.closest('.x')) hidePop(); if (e.target.closest('a[href^="#"]')) hidePop(); });
  document.addEventListener('keydown', e => { if (e.key === 'Escape') hidePop(); });
  window.addEventListener('scroll', () => { if (!pop.hidden && innerWidth > 640) hidePop(); }, { passive: true });

  function casePop(c) {
    const fixes = DB.corrections.filter(x => x.src.some(u => u === c.url));
    return `<h3>${esc(c.name)}</h3><p class="muted">${esc(c.date)}${c.court === 'HC' ? ', High Court' : c.court === 'US' ? ', US Supreme Court' : ', Supreme Court'}</p>
      <p>${esc(c.holding)}</p>${fixes.length ? `<p><b style="color:var(--madder)">Correction:</b> ${fixes.map(f => esc(f.title)).join('; ')}</p>` : ''}
      <div class="row"><a class="btn small" href="${esc(caseUrl(c))}" target="_blank" rel="noopener noreferrer">Open on ${caseSrcName(c)}</a><a class="btn small ghost" href="#/case/${c.k}">Case page</a></div>`;
  }
  function fixPop(f) {
    return `<h3>${esc(f.title)}</h3><p><b>The notes say:</b> ${esc(f.wrong)}</p><p><b>Correct:</b> ${esc(f.right)}</p>
      <div class="row">${f.src.map((u, i) => `<a class="btn small ghost" href="${esc(u)}">Source ${f.src.length > 1 ? i + 1 : ''}</a>`).join('')}<a class="btn small ghost" href="#/fixes">All corrections</a></div>`;
  }
  document.addEventListener('click', e => {
    const a = e.target.closest('a.cref');
    const m = e.target.closest('mark.fix');
    if (m && (!a || m.contains(a))) {
      const f = M.fix[m.dataset.fix];
      if (f) { e.preventDefault(); const c = a && M.cases[a.dataset.k]; showPop(m, fixPop(f) + (c ? `<hr class="rule" style="margin:12px 0">${casePop(c)}` : '')); return; }
    }
    if (a && !e.ctrlKey && !e.metaKey && !e.shiftKey) {
      const c = M.cases[a.dataset.k]; if (!c) return;
      e.preventDefault(); showPop(a, casePop(c)); return;
    }
    if (!pop.hidden && !e.target.closest('#pop')) hidePop();
  });
  document.addEventListener('keydown', e => {
    if (e.key === 'Enter' && e.target.matches && e.target.matches('mark.fix')) { const f = M.fix[e.target.dataset.fix]; if (f) showPop(e.target, fixPop(f)); }
  });

  /* ---------------- home ---------------- */
  function progressOf(ch) {
    const n = ch.sections.length, d = ch.sections.filter(s => S.rev[s.key]).length;
    return { n, d };
  }
  function sylItem(ch) {
    const p = progressOf(ch);
    const sub = ch.doc === 'exam' ? (ch.tag ? `Source: ${esc(ch.tag)}` : '') : esc(ch.date || '');
    const no = ch.doc === 'exam' ? (ch.num || '—') : (ch.id === 'D0' ? 'Ref' : ch.id === 'WS' ? 'W' : ch.num);
    return `<li><a href="#/read/${ch.doc}/${ch.id}"><span class="no">${esc(no)}</span><span class="nm">${esc(ch.title)}${sub ? `<small>${sub}</small>` : ''}</span>
      <span class="prog ${p.d === p.n && p.n ? 'done' : ''}">${p.d ? `${p.d}/${p.n} revised` : `${p.n} parts`}</span></a></li>`;
  }
  function homeView() {
    const last = S.last && M.sec[S.last];
    const exam = DB.exam.filter(c => c.kind !== 'front');
    const day = DB.day.filter(c => c.id !== 'Dintro');
    const revised = Object.keys(S.rev).length;
    view().innerHTML = `<div class="wrap">
      <h1 class="page">Constitutional Law</h1>
      <p class="lede">Every lecture from 15 July to 19 October 2026 in one place: ${DB.exam.filter(c => c.kind === 'lecture').length} exam-ready lectures, ${day.length - 2} day-wise sessions, ${DB.cases.length} cases with judgment links, and ${DB.articles.length} Articles of the Constitution. ${revised ? `You have marked ${revised} of ${M.secs.length} parts as revised.` : ''}</p>
      <form class="home-search" id="hs" role="search"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>
        <label class="sr" for="hq">Search the notes</label><input id="hq" type="search" placeholder="Search notes, cases, Articles and lecture PDFs — e.g. eclipse, Romesh Thappar, 19(2)"></form>
      ${last ? `<a class="continue" href="${secHref(last.key)}"><span><span class="muted">Continue reading</span><br><b>${esc(last.title)}</b> <span class="muted">— ${esc(chapterLabel(M.ch[last.doc + '/' + last.ch]))}</span></span></a>` : ''}
      <div class="course">
        <section><h2 class="block">Exam-ready notes, October</h2><p class="muted" style="margin-top:-6px">Art 19, property, FR v DPSP and Art 21 — with case cards, class questions and solved homework.</p><ol class="syl">${exam.map(sylItem).join('')}</ol></section>
        <section><h2 class="block">Day-wise class notes, July to October</h2><p class="muted" style="margin-top:-6px">Rule of law, basic structure, Arts 13–16 and Art 19(1)(a), session by session.</p><ol class="syl">${day.map(sylItem).join('')}</ol></section>
      </div>
      <h2 class="block">Study tools</h2>
      <div class="tools">
        <a href="#/cases"><b>Case finder</b><span>Filter ${DB.cases.length} cases by topic and year; open the judgment.</span></a>
        <a href="#/kanoon"><b>Indian Kanoon search</b><span>Build an exact search — title, judge, citation, court, years.</span></a>
        <a href="#/articles"><b>Constitution text</b><span>Bare text of Arts 12–51A, 300A, 358–368 with the cases on each.</span></a>
        <a href="#/solve"><b>Problem frameworks</b><span>Step-by-step tests for Art 13, 14, 19, 21, amendments, reservation.</span></a>
        <a href="#/flash"><b>Flashcards</b><span>Cases, holdings, class questions and Articles, with spaced repetition.</span></a>
        <a href="#/quiz"><b>Case quiz</b><span>Ten questions: match the holding to the case.</span></a>
        <a href="#/timeline"><b>Timeline</b><span>Amendments and the cases that provoked them, year by year.</span></a>
        <a href="#/fixes"><b>Corrections</b><span>${DB.corrections.length} errors found in the notes and how to fix them.</span></a>
        <a href="#/sources"><b>Lecture files</b><span>All ${DB.sources.length} original PDFs and Word files, searchable by page.</span></a>
      </div></div>`;
    $('#hs').addEventListener('submit', e => { e.preventDefault(); location.hash = '#/search?q=' + encodeURIComponent($('#hq').value.trim()); });
  }

  /* ---------------- reader ---------------- */
  function readerView(doc, chId, secId, q) {
    const ch = M.ch[doc + '/' + chId];
    if (!ch) return notFound();
    const list = DB[doc];
    const prev = list[ch.idx - 1], next = list[ch.idx + 1];
    const kicker = ch.doc === 'exam'
      ? (ch.num ? `Exam-ready notes, lecture ${ch.num}${ch.tag ? ` (${esc(ch.tag)})` : ''}` : 'Exam-ready notes')
      : (ch.id === 'D0' ? 'Day-wise notes, reference' : ch.id === 'WS' ? 'Day-wise notes, handout' : ch.id === 'Dintro' ? 'Day-wise notes' : `Day ${ch.num}, ${esc(ch.date)}`);
    const hasQA = ch.sections.some(s => s.html.includes('class="qa-a"'));
    view().innerHTML = `<div class="chap-head"><div class="chap-kicker">${kicker}</div><h1>${esc(ch.title)}</h1>${ch.trail ? `<p class="trail">${esc(ch.trail)}</p>` : ''}
      <div class="row" style="margin-top:10px">${hasQA ? '<button class="mini" id="selftest" aria-pressed="false">Self-test: hide answers</button>' : ''}<button class="mini" id="print">Print this chapter</button>
      <button class="mini" id="markall">Mark all parts revised</button></div></div>
      <div class="reader">
        <nav class="toc" aria-label="In this chapter"><b>In this chapter</b>${ch.sections.map(s => `<a href="${secHref(s.key)}" data-t="${s.key}">${esc(s.title)}</a>`).join('')}</nav>
        ${ch.sections.map(s => `<div class="sec"><div class="margin" id="s-${esc(s.id)}" data-key="${s.key}"><h2>${esc(s.title)}</h2>
          <div class="acts"><button class="mini" data-act="rev" aria-pressed="${!!S.rev[s.key]}">${S.rev[s.key] ? 'Revised' : 'Mark revised'}</button>
          <button class="mini" data-act="bm" aria-pressed="${S.bm.includes(s.key)}">${S.bm.includes(s.key) ? 'Saved' : 'Save'}</button>
          <button class="mini" data-act="note" aria-pressed="${!!S.notes[s.key]}">My note</button></div></div>
          <div class="body" data-key="${s.key}">${s.html}<div class="mynote" ${S.notes[s.key] ? '' : 'hidden'}><label class="muted" for="n-${esc(s.id)}">My note on this part (kept on this device)</label><textarea id="n-${esc(s.id)}">${esc(S.notes[s.key] || '')}</textarea></div></div></div>`).join('')}
        <nav class="chapnav" aria-label="Chapters">${prev ? `<a href="#/read/${doc}/${prev.id}"><small>Previous</small>${esc(prev.title)}</a>` : '<span></span>'}${next ? `<a href="#/read/${doc}/${next.id}" style="text-align:right"><small>Next</small>${esc(next.title)}</a>` : ''}</nav>
      </div>`;
    const root = view();
    root.addEventListener('click', e => {
      const b = e.target.closest('button[data-act]'); if (!b) return;
      const key = b.closest('.margin').dataset.key;
      if (b.dataset.act === 'rev') {
        if (S.rev[key]) delete S.rev[key]; else S.rev[key] = today();
        S.save('rev'); b.setAttribute('aria-pressed', !!S.rev[key]); b.textContent = S.rev[key] ? 'Revised' : 'Mark revised';
      } else if (b.dataset.act === 'bm') {
        const i = S.bm.indexOf(key); if (i >= 0) S.bm.splice(i, 1); else S.bm.unshift(key);
        S.save('bm'); b.setAttribute('aria-pressed', S.bm.includes(key)); b.textContent = S.bm.includes(key) ? 'Saved' : 'Save';
      } else if (b.dataset.act === 'note') {
        const box = $(`.body[data-key="${CSS.escape(key)}"] .mynote`, root); box.hidden = !box.hidden; if (!box.hidden) $('textarea', box).focus();
      }
    });
    let t;
    root.addEventListener('input', e => {
      if (!e.target.matches('.mynote textarea')) return;
      const key = e.target.closest('.body').dataset.key;
      clearTimeout(t); t = setTimeout(() => { if (e.target.value.trim()) S.notes[key] = e.target.value; else delete S.notes[key]; S.save('notes'); }, 400);
    });
    $('#print').addEventListener('click', () => { $$('details.qa-a', root).forEach(d => { d.open = true; }); print(); });
    $('#markall').addEventListener('click', () => { ch.sections.forEach(s => { S.rev[s.key] ||= today(); }); S.save('rev'); route(); toast('All parts marked as revised'); });
    const st = $('#selftest');
    if (st) st.addEventListener('click', () => {
      const on = st.getAttribute('aria-pressed') !== 'true';
      st.setAttribute('aria-pressed', on); st.textContent = on ? 'Self-test on: answers hidden' : 'Self-test: hide answers';
      $$('details.qa-a', root).forEach(d => { d.open = !on; });
    });
    // table of contents highlight + remember position
    const io = new IntersectionObserver(ents => {
      ents.forEach(en => {
        if (!en.isIntersecting) return;
        const key = en.target.dataset.key;
        $$('.toc a', root).forEach(a => a.classList.toggle('on', a.dataset.t === key));
        S.last = key; S.save('last');
      });
    }, { rootMargin: '0px 0px -70% 0px' });
    $$('.margin', root).forEach(m => io.observe(m));
    cleanup.push(() => io.disconnect());
    // scroll to the section / element and highlight search terms
    requestAnimationFrame(() => {
      let target = secId ? $(`#s-${CSS.escape(secId)}`, root) : null;
      const hl = q.get('hl'); if (hl) target = document.getElementById(hl) || target;
      const fx = q.get('fix'); if (fx) { const m = $(`.body[data-key="${CSS.escape(`${doc}/${chId}/${secId}`)}"] mark[data-fix="${CSS.escape(fx)}"]`, root); if (m) { target = m; setTimeout(() => showPop(m, fixPop(M.fix[fx])), 300); } }
      const term = q.get('q');
      if (term && secId) {
        const body = $(`.body[data-key="${CSS.escape(`${doc}/${chId}/${secId}`)}"]`, root);
        const first = body && highlight(body, term);
        if (first) target = first;
      }
      if (target) target.scrollIntoView({ block: 'start' }); else window.scrollTo(0, 0);
    });
  }
  function terms(q) { return q.toLowerCase().replace(/["“”]/g, ' ').split(/[\s,;]+/).filter(w => w.length > 1 && !STOP.has(w)); }
  const STOP = new Set(['the', 'of', 'and', 'in', 'to', 'a', 'v', 'vs', 'is', 'on', 'for', 'by', 'an', 'or', 'as', 'at', 'be', 'it', 'its', 'art', 'article']);
  function highlight(root, q) {
    const ts = terms(q); if (!ts.length) return null;
    const re = new RegExp(`(${ts.map(w => w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})`, 'gi');
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    const nodes = []; let n; while ((n = walker.nextNode())) if (re.test(n.nodeValue) && !n.parentElement.closest('textarea')) nodes.push(n);
    let first = null;
    nodes.slice(0, 60).forEach(node => {
      const span = document.createElement('span');
      span.innerHTML = esc(node.nodeValue).replace(re, '<mark class="hit" style="background:var(--turmeric-soft)">$1</mark>');
      node.replaceWith(span); first ||= span;
    });
    return first;
  }

  /* ---------------- search ---------------- */
  let MS = null, building = null;
  function buildIndex() {
    if (MS || building) return building;
    building = (async () => {
      const docs = [];
      M.secs.forEach(s => docs.push({ id: 'n:' + s.key, type: 'Notes', title: s.title, text: s.text }));
      DB.cases.forEach(c => docs.push({ id: 'c:' + c.k, type: 'Cases', title: c.name, text: `${c.holding} ${c.topics.join(' ')} ${c.year}` }));
      DB.qa.forEach(qa => docs.push({ id: 'q:' + qa.id, type: 'Questions', title: strip(qa.q).slice(0, 160), text: strip(qa.q) + ' ' + strip(qa.a) }));
      DB.articles.forEach(a => docs.push({ id: 'a:' + a.n, type: 'Articles', title: `${a.label} ${a.title}`, text: a.text + ' ' + a.note }));
      DB.pages.forEach((p, i) => docs.push({ id: 'p:' + i, type: 'Lecture PDFs', title: M.src[p.s].title, text: p.t }));
      const ms = new MiniSearch({ fields: ['title', 'text'], storeFields: ['type', 'title'],
        searchOptions: { boost: { title: 3 }, prefix: true, fuzzy: 0.15, combineWith: 'AND' } });
      await ms.addAllAsync(docs, { chunkSize: 200 });
      MS = ms; return ms;
    })();
    return building;
  }
  const strip = h => String(h || '').replace(/<[^>]+>/g, ' ').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/\s+/g, ' ').trim();
  function docText(id) {
    const [t, ...r] = id.split(':'); const k = r.join(':');
    if (t === 'n') return M.sec[k].text;
    if (t === 'c') return M.cases[k].holding;
    if (t === 'q') return strip(M.qa[k].q) + ' — ' + strip(M.qa[k].a);
    if (t === 'a') return M.art[k].text;
    if (t === 'p') return DB.pages[+k].t;
    return '';
  }
  function docLink(id, q) {
    const [t, ...r] = id.split(':'); const k = r.join(':');
    const qq = '&q=' + encodeURIComponent(q);
    if (t === 'n') return secHref(k, '?' + qq.slice(1));
    if (t === 'c') return '#/case/' + k;
    if (t === 'q') { const x = M.qa[k]; const sec = M.sec[`${x.src}/${x.ch}/${x.sec}`]; return sec ? secHref(sec.key, `?hl=${encodeURIComponent(x.id)}`) : '#/search'; }
    if (t === 'a') return '#/article/' + k;
    if (t === 'p') { const p = DB.pages[+k]; return `#/source/${p.s}?p=${p.p}`; }
    return '#/';
  }
  function docWhere(id) {
    const [t, ...r] = id.split(':'); const k = r.join(':');
    if (t === 'n') { const s = M.sec[k]; const ch = M.ch[s.doc + '/' + s.ch]; return `${s.doc === 'exam' ? 'Exam-ready notes' : 'Day-wise notes'} — ${chapterLabel(ch)}: ${ch.title}`; }
    if (t === 'c') { const c = M.cases[k]; return `Case, ${c.date}`; }
    if (t === 'q') { const x = M.qa[k]; const ch = M.ch[x.src + '/' + x.ch]; return `${x.kind === 'homework' ? 'Homework' : 'Question asked in class'} — ${ch ? chapterLabel(ch) + ': ' + ch.title : ''}`; }
    if (t === 'a') return 'Constitution of India';
    if (t === 'p') { const p = DB.pages[+k]; return `${M.src[p.s].date}, page ${p.p}`; }
    return '';
  }
  function snippet(text, q) {
    const ts = terms(q); const lo = text.toLowerCase();
    let pos = -1; for (const w of ts) { const i = lo.indexOf(w); if (i >= 0 && (pos < 0 || i < pos)) pos = i; }
    const s = Math.max(0, pos - 90), e = Math.min(text.length, (pos < 0 ? 0 : pos) + 210);
    let out = esc((s ? '…' : '') + text.slice(s, e) + (e < text.length ? '…' : ''));
    if (ts.length) out = out.replace(new RegExp(`(${ts.map(w => esc(w).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})`, 'gi'), '<mark>$1</mark>');
    return out;
  }
  const TYPES = ['All', 'Notes', 'Cases', 'Questions', 'Articles', 'Lecture PDFs'];
  function searchView(q) {
    const query = q.get('q') || '', type = q.get('t') || 'All';
    view().innerHTML = `<div class="wrap"><h1 class="page">Search</h1>
      <form class="home-search" id="sf" role="search"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>
      <label class="sr" for="sq">Search</label><input id="sq" type="search" value="${esc(query)}" placeholder="Words, case names, Article numbers…" autofocus></form>
      <div class="chips" id="tf" role="group" aria-label="Show">${TYPES.map(t => `<button class="chip" aria-pressed="${t === type}" data-t="${t}">${t}</button>`).join('')}</div>
      <div id="res" style="margin-top:18px"></div></div>`;
    const go = (qq, tt) => { location.hash = `#/search?q=${encodeURIComponent(qq)}${tt && tt !== 'All' ? '&t=' + encodeURIComponent(tt) : ''}`; };
    $('#sf').addEventListener('submit', e => { e.preventDefault(); go($('#sq').value.trim(), type); });
    $('#tf').addEventListener('click', e => { const b = e.target.closest('button'); if (b) go($('#sq').value.trim(), b.dataset.t); });
    const res = $('#res');
    if (!query) { res.innerHTML = '<p class="muted">Type at least one word. Searches the notes, the case list, class questions, the Constitution text and every page of the lecture PDFs. Prefixes work: "proportion" finds proportionality.</p>'; return; }
    res.innerHTML = '<p class="muted">Building the search index — this takes a moment the first time.</p>';
    buildIndex().then(ms => {
      let hits = ms.search(query);
      if (!hits.length) hits = ms.search(query, { combineWith: 'OR' });
      const counts = {}; hits.forEach(h => { counts[h.type] = (counts[h.type] || 0) + 1; });
      $$('#tf .chip').forEach(b => { const t = b.dataset.t; b.textContent = t === 'All' ? `All ${hits.length}` : `${t} ${counts[t] || 0}`; });
      if (type !== 'All') hits = hits.filter(h => h.type === type);
      const shown = hits.slice(0, 80);
      res.innerHTML = hits.length ? `<p class="count-line">${hits.length} result${hits.length === 1 ? '' : 's'}${hits.length > 80 ? ', showing the best 80' : ''}.</p>` + shown.map(h =>
        `<div class="result"><a class="t" href="${docLink(h.id, query)}">${esc(h.title)}</a><div class="where">${esc(docWhere(h.id))}</div><p>${snippet(docText(h.id), query)}</p></div>`).join('')
        : `<p>Nothing matches "${esc(query)}". Try fewer words, a case name, or an Article number like 19(2). You can also <a href="#/kanoon?q=${encodeURIComponent(query)}">search Indian Kanoon</a>.</p>`;
    }).catch(err => { res.innerHTML = `<p class="err">Search could not start: ${esc(err.message)}</p>`; });
  }

  /* ---------------- cases ---------------- */
  let caseState = { topic: '', court: '', sort: 'year', text: '' };
  function casesView(q) {
    if (q.get('t')) caseState.topic = q.get('t');
    view().innerHTML = `<div class="wrap"><h1 class="page">Case finder</h1>
      <p class="lede">Every case in the notes, with the decision date checked on Indian Kanoon and a link to the full judgment. Green links inside the notes open these cards.</p>
      <div class="toolbar"><label class="sr" for="cf">Filter cases</label><input class="input" id="cf" type="search" placeholder="Filter by name or holding" value="${esc(caseState.text)}">
        <select class="select" id="cc" aria-label="Court"><option value="">All courts</option><option value="SC">Supreme Court of India</option><option value="HC">High Courts</option><option value="US">US Supreme Court</option></select>
        <select class="select" id="cs" aria-label="Sort"><option value="year">Oldest first</option><option value="-year">Newest first</option><option value="name">A to Z</option><option value="seen">Most mentioned</option></select></div>
      <div class="chips" id="ct" style="margin-bottom:14px"><button class="chip" data-t="" aria-pressed="${!caseState.topic}">All topics</button>${M.topics.map(t => `<button class="chip" data-t="${esc(t)}" aria-pressed="${caseState.topic === t}">${esc(t)}</button>`).join('')}</div>
      <p class="count-line" id="cn"></p><ul class="cases" id="cl"></ul></div>`;
    $('#cc').value = caseState.court; $('#cs').value = caseState.sort;
    const draw = () => {
      const t = caseState.text.toLowerCase();
      let list = DB.cases.filter(c => (!caseState.topic || c.topics.includes(caseState.topic)) && (!caseState.court || c.court === caseState.court)
        && (!t || c.name.toLowerCase().includes(t) || c.holding.toLowerCase().includes(t)));
      const s = caseState.sort;
      list.sort(s === 'name' ? (a, b) => a.name.localeCompare(b.name) : s === '-year' ? (a, b) => b.year - a.year : s === 'seen' ? (a, b) => b.seen.length - a.seen.length : (a, b) => a.year - b.year);
      $('#cn').textContent = `${list.length} case${list.length === 1 ? '' : 's'}`;
      $('#cl').innerHTML = list.map(c => `<li><a class="nm" href="#/case/${c.k}">${esc(c.name)}</a> <span class="yr">(${c.year})</span>
        <p>${esc(c.holding)}</p><div class="row">${c.topics.map(x => `<span class="pill">${esc(x)}</span>`).join('')}<span class="spacer"></span>
        ${DB.corrections.some(f => f.src.includes(c.url)) ? '<span class="pill madder">Correction</span>' : ''}
        <span class="muted" style="font-size:.88rem">${c.seen.length ? `In ${c.seen.length} part${c.seen.length === 1 ? '' : 's'} of the notes` : ''}</span>
        <a class="ikbtn" href="${esc(caseUrl(c))}">${caseSrcName(c)}</a></div></li>`).join('');
      afterRender($('#cl'));
    };
    $('#cf').addEventListener('input', e => { caseState.text = e.target.value; draw(); });
    $('#cc').addEventListener('change', e => { caseState.court = e.target.value; draw(); });
    $('#cs').addEventListener('change', e => { caseState.sort = e.target.value; draw(); });
    $('#ct').addEventListener('click', e => { const b = e.target.closest('.chip'); if (!b) return; caseState.topic = b.dataset.t; $$('#ct .chip').forEach(x => x.setAttribute('aria-pressed', x === b)); draw(); });
    draw();
  }
  function caseView(k) {
    const c = M.cases[k]; if (!c) return notFound();
    const fixes = DB.corrections.filter(f => f.src.includes(c.url));
    const cards = DB.cards.filter(x => x.reg === k);
    const seen = c.seen.map(w => M.sec[w]).filter(Boolean);
    const short = c.name.replace(/\s*\(.*?\)\s*$/, '').split(/ v\. /)[0].replace(/^(State of|Union of India|The)\s+/, '');
    const ikCite = `${IK}/search/?formInput=${encodeURIComponent(`"${c.name.replace(/\s*\(.*?\)\s*$/, '')}"`)}`;
    view().innerHTML = `<div class="wrap case-page"><p class="muted"><a href="#/cases">Case finder</a></p><h1 class="page">${esc(c.name)}</h1>
      <dl class="facts"><dt>Decided</dt><dd>${esc(c.date)}</dd><dt>Court</dt><dd>${c.court === 'HC' ? 'High Court' : c.court === 'US' ? 'Supreme Court of the United States' : 'Supreme Court of India'}</dd>
      <dt>Topics</dt><dd>${c.topics.map(t => `<a class="pill chakra" href="#/cases?t=${encodeURIComponent(t)}" style="text-decoration:none">${esc(t)}</a>`).join(' ')}</dd></dl>
      <p class="holding">${esc(c.holding)}</p>
      <div class="row" style="margin-bottom:24px"><a class="btn" href="${esc(caseUrl(c))}">Read the judgment on ${caseSrcName(c)}</a>
      ${c.court !== 'US' ? `<a class="btn ghost" href="${esc(ikCite)}">Judgments that cite it</a>` : ''}</div>
      ${fixes.map(f => `<div class="fixnote"><b>Correction — ${esc(f.title)}.</b> ${esc(f.right)}</div>`).join('')}
      ${cards.length ? `<h2 class="block">From your notes</h2>${cards.map(cardHTML).join('')}` : ''}
      <h2 class="block">Where it comes up</h2>${seen.length ? `<ul class="linklist">${seen.map(s => `<li><a href="${secHref(s.key, '?q=' + encodeURIComponent(short))}">${esc(s.title)}</a> <span class="muted">— ${esc(chapterLabel(M.ch[s.doc + '/' + s.ch]))}, ${esc(M.ch[s.doc + '/' + s.ch].title)}</span></li>`).join('')}</ul>` : '<p class="muted">Only in the case list.</p>'}
      </div>`;
  }
  function cardHTML(card) {
    const where = M.sec[`${card.source === 'exam' ? 'exam' : 'day'}/${card.chapter}/${card.section}`];
    return `<article class="box box-case" style="max-width:80ch;font:400 1rem/1.6 var(--serif)"><header class="case-h"><span class="tag">${card.source === 'exam' ? 'Exam-ready notes' : 'Day-wise notes'}</span><h4>${esc(card.name)}</h4>${where ? `<a class="ikbtn" style="border-color:var(--chakra);color:var(--chakra)" href="${secHref(where.key, '?hl=' + encodeURIComponent(card.id))}">Open in notes</a>` : ''}</header>
      ${card.sub ? `<p class="case-sub">${esc(card.sub)}</p>` : ''}${card.fields.map(f => `<div class="cf"><div class="cf-l">${esc(f.label)}</div><div class="cf-v">${f.html}</div></div>`).join('')}</article>`;
  }

  /* ---------------- Constitution text ---------------- */
  const ART_TOPICS = { '12': ['Art 12 State'], '13': ['Art 13'], '14': ['Art 14'], '15': ['Arts 15-16 & Reservation'], '16': ['Arts 15-16 & Reservation'],
    '19': ['Art 19(1)(a) Speech', 'Art 19 Other Freedoms', 'Art 19(1)(g) Trade'], '20': ['Arts 20 & 22'], '21': ['Art 21'], '22': ['Arts 20 & 22'],
    '31': ['Property'], '31A': ['Property'], '31C': ['FR v DPSP'], '37': ['FR v DPSP'], '39': ['FR v DPSP'], '300A': ['Property'], '368': ['Amendment & Basic Structure'], '359': ['Rule of Law'] };
  function articlesView(n) {
    const a = M.art[n] || M.art['14'];
    const parts = []; DB.articles.forEach(x => { if (!parts.includes(x.part)) parts.push(x.part); });
    const num = a.n === '0' ? null : a.n;
    const re = num ? new RegExp(`\\bArt(?:icle)?s?\\.?\\s*${num.replace(/[A-Z]/, m => m)}(?![\\dA-Z])`, 'i') : /Preamble/;
    const cases = DB.cases.filter(c => (ART_TOPICS[a.n] || []).some(t => c.topics.includes(t)) || (num && new RegExp(`Arts? ${num}(?![\\dA-Z])`).test(c.holding)));
    const mentions = M.secs.filter(s => re.test(s.text));
    const ikArt = `${IK}/search/?formInput=${encodeURIComponent(`title: "Article ${num} in Constitution of India"`)}`;
    const ikCases = `${IK}/search/?formInput=${encodeURIComponent(`"article ${num}" doctypes: supremecourt sortby: mostrecent`)}`;
    view().innerHTML = `<div class="wrap"><h1 class="page">${num ? `Article ${esc(num)}` : 'Preamble'} <span class="muted" style="font-weight:500">${num ? esc(a.title) : ''}</span></h1>
      <div class="art-grid"><nav class="art-list" aria-label="Articles">${parts.map(p => `<b>${esc(p)}</b>` + DB.articles.filter(x => x.part === p).map(x =>
        `<a href="#/article/${x.n}" class="${x.n === a.n ? 'on' : ''}">${x.n === '0' ? 'Preamble' : `${esc(x.n)}. ${esc(x.title)}`}</a>`).join('')).join('')}</nav>
      <div><p class="muted" style="margin-top:0">${esc(a.part)}</p><div class="bare">${esc(a.text)}</div>
      ${a.note ? `<div class="art-note">${esc(a.note)}</div>` : ''}
      <p class="muted" style="font-size:.9rem;max-width:76ch">Text from a public dataset of the Constitution, checked against the amendments affecting these Articles (up to the 106th Amendment, 2023). For citation in a submission use the official text on India Code.</p>
      ${num ? `<div class="row"><a class="btn small ghost" href="${esc(ikCases)}">Supreme Court judgments on Article ${esc(num)}</a><a class="btn small ghost" href="${esc(ikArt)}">Article ${esc(num)} on Indian Kanoon</a><a class="btn small ghost" href="https://www.indiacode.nic.in/handle/123456789/15240">Official text (India Code)</a></div>` : ''}
      ${cases.length ? `<h2 class="block">Cases on this Article (${cases.length})</h2><ul class="linklist">${cases.sort((x, y) => x.year - y.year).map(c => `<li><a class="cref" data-k="${c.k}" href="#/case/${c.k}">${esc(c.name)}</a> <span class="muted">(${c.year})</span></li>`).join('')}</ul>` : ''}
      <h2 class="block">Where your notes discuss it (${mentions.length})</h2>${mentions.length ? `<ul class="linklist">${mentions.slice(0, 60).map(s => `<li><a href="${secHref(s.key, '?q=' + encodeURIComponent(num ? 'Art ' + num : 'Preamble'))}">${esc(s.title)}</a> <span class="muted">— ${esc(chapterLabel(M.ch[s.doc + '/' + s.ch]))}</span></li>`).join('')}</ul>` : '<p class="muted">Not discussed directly.</p>'}
      </div></div></div>`;
    const on = $('.art-list a.on'); if (on && innerWidth > 900) on.scrollIntoView({ block: 'center' });
  }

  /* ---------------- Indian Kanoon search builder ---------------- */
  const COURTS = [['supremecourt', 'Supreme Court of India'], ['highcourts', 'All High Courts'], ['bombay', 'Bombay High Court (incl. Nagpur Bench)'], ['delhi', 'Delhi High Court'],
    ['chennai', 'Madras High Court'], ['kolkata', 'Calcutta High Court'], ['allahabad', 'Allahabad High Court'], ['karnataka', 'Karnataka High Court'], ['kerala', 'Kerala High Court'],
    ['judgments', 'All courts and tribunals'], ['laws', 'Central Acts and the Constitution'], ['', 'Everything on Indian Kanoon']];
  function kanoonView(q) {
    const recent = S.recent;
    view().innerHTML = `<div class="wrap"><h1 class="page">Indian Kanoon search</h1>
      <p class="lede">Fill in what you know; the search opens on indiankanoon.org in a new tab. Nothing typed here is stored except your recent searches on this device.</p>
      <form class="kform" id="kf">
        <label class="field full"><span>All of these words</span><input class="input" name="w" value="${esc(q.get('q') || '')}" placeholder="e.g. right to privacy surveillance"></label>
        <label class="field"><span>Exact phrase</span><input class="input" name="p" placeholder="e.g. procedure established by law"></label>
        <label class="field"><span>Case title contains</span><input class="input" name="t" placeholder="e.g. Maneka Gandhi"></label>
        <label class="field"><span>Citation</span><input class="input" name="c" placeholder="e.g. AIR 1978 SC 597"></label>
        <label class="field"><span>Judge who wrote it</span><input class="input" name="a" placeholder="e.g. Bhagwati"></label>
        <label class="field"><span>Judge on the bench</span><input class="input" name="b" placeholder="e.g. Krishna Iyer"></label>
        <label class="field"><span>Court or collection</span><select class="select" name="d" style="width:100%">${COURTS.map(([v, l]) => `<option value="${v}">${esc(l)}</option>`).join('')}</select></label>
        <label class="field"><span>From year</span><input class="input" name="f" inputmode="numeric" placeholder="1950"></label>
        <label class="field"><span>To year</span><input class="input" name="u" inputmode="numeric" placeholder="2026"></label>
        <label class="field"><span>Order results by</span><select class="select" name="s" style="width:100%"><option value="">Relevance</option><option value="mostrecent">Newest first</option><option value="leastrecent">Oldest first</option></select></label>
        <div class="field full"><span class="muted">Query sent to Indian Kanoon</span><div class="qprev" id="qp"></div></div>
        <div class="full row"><button class="btn" type="submit">Search Indian Kanoon</button><button class="btn ghost" type="reset">Clear</button></div>
      </form>
      ${recent.length ? `<h2 class="block">Recent searches</h2><ul class="linklist">${recent.map(r => `<li><a href="${IK}/search/?formInput=${encodeURIComponent(r)}">${esc(r)}</a></li>`).join('')}</ul>` : ''}
      <h2 class="block">Quick searches for this course</h2><div class="chips" id="qk">${[
        ['Basic structure', '"basic structure" doctypes: supremecourt'], ['Art 19(2) public order', '"public order" "19(2)" doctypes: supremecourt'],
        ['Proportionality', 'proportionality "least restrictive" doctypes: supremecourt'], ['Creamy layer', '"creamy layer" doctypes: supremecourt'],
        ['Art 300A', '"article 300A" acquisition doctypes: supremecourt sortby: mostrecent'], ['Hate speech', '"hate speech" doctypes: supremecourt'],
        ['Right to protest', '"right to protest" doctypes: supremecourt'], ['Doctrine of eclipse', '"doctrine of eclipse" doctypes: supremecourt'],
        ['Nagpur Bench, Art 19', '"article 19" doctypes: bombay sortby: mostrecent']].map(([l, v]) => `<a class="chip" style="text-decoration:none" href="${IK}/search/?formInput=${encodeURIComponent(v)}">${esc(l)}</a>`).join('')}</div>
      <h2 class="block">Search operators you can type yourself</h2>
      <div class="plain cheat tbl-wrap"><table><tr><th>Type</th><th>Finds</th></tr>
        <tr><td>title: "Romesh Thappar"</td><td>Words in the case title</td></tr>
        <tr><td>author: bhagwati</td><td>Judgments written by that judge</td></tr>
        <tr><td>bench: chandrachud</td><td>Judgments where the judge sat on the bench</td></tr>
        <tr><td>cite: "AIR 1978 SC 597"</td><td>Judgments with that citation</td></tr>
        <tr><td>doctypes: supremecourt</td><td>Only one court or collection (highcourts, bombay, delhi, laws …)</td></tr>
        <tr><td>fromdate: 1-1-1970 todate: 31-12-1980</td><td>Decided between those dates (day-month-year)</td></tr>
        <tr><td>sortby: mostrecent</td><td>Newest first (leastrecent for oldest first)</td></tr>
        <tr><td>privacy ANDD surveillance</td><td>Both words; ORR for either, NOTT to exclude</td></tr></table></div>
      <h2 class="block">Judgments linked from these notes</h2><p class="muted">Every case in the <a href="#/cases">case finder</a> opens its full judgment directly — ${DB.cases.filter(c => c.src).length} of ${DB.cases.length} have a checked link.</p></div>`;
    const f = $('#kf');
    const build = () => {
      const v = n => (f.elements[n].value || '').trim();
      const parts = [];
      if (v('w')) parts.push(v('w'));
      if (v('p')) parts.push(`"${v('p').replace(/"/g, '')}"`);
      if (v('t')) parts.push(`title: "${v('t').replace(/"/g, '')}"`);
      if (v('c')) parts.push(`cite: "${v('c').replace(/"/g, '')}"`);
      if (v('a')) parts.push(`author: ${v('a')}`);
      if (v('b')) parts.push(`bench: ${v('b')}`);
      if (v('d')) parts.push(`doctypes: ${v('d')}`);
      if (/^\d{4}$/.test(v('f'))) parts.push(`fromdate: 1-1-${v('f')}`);
      if (/^\d{4}$/.test(v('u'))) parts.push(`todate: 31-12-${v('u')}`);
      if (v('s')) parts.push(`sortby: ${v('s')}`);
      return parts.join(' ');
    };
    const upd = () => { $('#qp').textContent = build() || 'Type something above'; };
    f.addEventListener('input', upd); f.addEventListener('change', upd); f.addEventListener('reset', () => setTimeout(upd));
    f.addEventListener('submit', e => {
      e.preventDefault(); const qs = build(); if (!qs) { toast('Type at least one word or a title'); return; }
      S.recent = [qs, ...S.recent.filter(x => x !== qs)].slice(0, 8); S.save('recent');
      window.open(`${IK}/search/?formInput=${encodeURIComponent(qs)}`, '_blank', 'noopener,noreferrer');
    });
    upd();
  }

  /* ---------------- flashcards (Leitner boxes) ---------------- */
  const GAPS = [0, 1, 3, 7, 16, 35];
  function deckCards(deck) {
    if (deck === 'cases') return DB.cases.map(c => ({ id: c.k, side: 'Case', front: `${c.name} (${c.year})`, back: `<p>${esc(c.holding)}</p>` }));
    if (deck === 'holdings') return DB.cases.map(c => ({ id: c.k, side: 'Which case held this?', front: c.holding.replace(new RegExp(c.name.split(' v. ')[0].replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), '…'), back: `<p><b>${esc(c.name)}</b> (${c.year})</p>` }));
    if (deck === 'questions') return DB.qa.filter(x => x.kind === 'question' && x.a).map(x => ({ id: x.id, side: 'Question asked in class', frontHTML: x.q, back: x.a }));
    if (deck === 'articles') return DB.articles.filter(a => a.n !== '0' && !/^Rep\./.test(a.text) && !/Repealed|\[.*\] Rep\./.test(a.text)).map(a => ({ id: a.n, side: 'What does this Article provide?', front: `Article ${a.n}`, back: `<p><b>${esc(a.title)}</b></p><p>${esc(a.text.slice(0, 600))}${a.text.length > 600 ? '…' : ''}</p>` }));
    return [];
  }
  const DECKS = [['cases', 'Case → holding'], ['holdings', 'Holding → case'], ['questions', 'Class questions'], ['articles', 'Article number → content']];
  function flashView(q) {
    const deck = q.get('d') || 'cases';
    const all = deckCards(deck);
    const st = id => S.fc[deck + ':' + id] || { b: 0, d: 0 };
    const due = all.filter(c => st(c.id).d <= today());
    const fresh = due.filter(c => !S.fc[deck + ':' + c.id]);
    const seen = due.filter(c => S.fc[deck + ':' + c.id]).sort((a, b) => st(a.id).b - st(b.id).b);
    const queue = [...seen, ...shuffle(fresh).slice(0, 12)].slice(0, 25);
    const boxCounts = [0, 0, 0, 0, 0, 0]; all.forEach(c => { if (S.fc[deck + ':' + c.id]) boxCounts[st(c.id).b]++; });
    view().innerHTML = `<div class="wrap"><h1 class="page">Flashcards</h1>
      <p class="lede">Cards you know move to a later box and come back after longer gaps (1, 3, 7, 16, 35 days). Cards you miss return today.</p>
      <div class="chips">${DECKS.map(([k, l]) => `<a class="chip" style="text-decoration:none" href="#/flash?d=${k}" aria-pressed="${k === deck}">${l}</a>`).join('')}</div>
      <div class="boxes"><span>${all.length} cards</span><span>${all.length - boxCounts.reduce((a, b) => a + b, 0)} new</span>${boxCounts.map((n, i) => n ? `<span>Box ${i}: ${n}</span>` : '').join('')}</div>
      <div class="card-stage" id="stage"></div></div>`;
    let i = 0;
    const show = () => {
      const stage = $('#stage');
      if (i >= queue.length) {
        stage.innerHTML = `<div class="flash"><div class="front">${queue.length ? 'Session finished.' : 'Nothing is due in this deck today.'}</div><p class="muted">${queue.length ? `You went through ${queue.length} cards.` : 'Come back tomorrow, or pick another deck.'}</p><div class="rate"><a class="btn" href="#/flash?d=${deck}&r=${Date.now()}">Start another round</a></div></div>`; return;
      }
      const c = queue[i];
      stage.innerHTML = `<div class="flash"><div class="side">${esc(c.side)} — card ${i + 1} of ${queue.length}</div>
        <div class="front">${c.frontHTML || esc(c.front)}</div><div class="back" hidden>${c.back}</div>
        <div class="rate" id="rb"><button class="btn" data-r="show">Show answer</button></div></div>`;
      afterRender(stage);
    };
    $('#stage').addEventListener('click', e => {
      const b = e.target.closest('button[data-r]'); if (!b) return;
      if (b.dataset.r === 'show') {
        $('#stage .back').hidden = false;
        $('#rb').innerHTML = '<button class="btn ghost" data-r="0">Didn\'t know it</button><button class="btn ghost" data-r="1">Partly</button><button class="btn" data-r="2">Knew it</button>';
        $('#rb [data-r="2"]').focus(); return;
      }
      const c = queue[i], key = deck + ':' + c.id, s = st(c.id);
      const r = +b.dataset.r;
      const nb = r === 0 ? 0 : r === 1 ? Math.max(1, s.b) : Math.min(5, s.b + 1);
      S.fc[key] = { b: nb, d: today() + GAPS[nb] }; S.save('fc');
      if (r === 0) queue.push(c);
      i++; show();
    });
    show();
  }
  function shuffle(a) { a = a.slice(); for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; } return a; }

  /* ---------------- quiz ---------------- */
  function quizView() {
    const pool = DB.cases.filter(c => c.court !== 'US');
    const qs = shuffle(pool).slice(0, 10).map(c => {
      const same = pool.filter(x => x.k !== c.k && x.topics.some(t => c.topics.includes(t)));
      const others = shuffle(same.length >= 3 ? same : pool.filter(x => x.k !== c.k)).slice(0, 3);
      return { c, opts: shuffle([c, ...others]) };
    });
    let n = 0, score = 0;
    view().innerHTML = `<div class="wrap"><h1 class="page">Case quiz</h1><p class="lede">Ten holdings from the case list. Pick the case that decided each one.</p><div class="card-stage" id="qz"></div></div>`;
    const draw = () => {
      const box = $('#qz');
      if (n >= qs.length) { box.innerHTML = `<div class="flash"><div class="front">You scored ${score} out of ${qs.length}.</div><p class="muted">${score >= 8 ? 'Strong — try the flashcards for the ones you missed.' : 'Open the case pages for the ones you missed, then try again.'}</p><div class="rate"><a class="btn" href="#/quiz?${Date.now()}">New quiz</a><a class="btn ghost" href="#/flash?d=holdings">Practise holdings</a></div></div>`; return; }
      const { c, opts } = qs[n];
      const masked = c.holding.replace(new RegExp(c.name.split(' v. ')[0].replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), '…');
      box.innerHTML = `<div class="flash"><div class="side">Question ${n + 1} of ${qs.length}, score ${score}</div><div class="front">${esc(masked)}</div>
        <div class="opts">${opts.map(o => `<button class="opt" data-k="${o.k}">${esc(o.name)} <span class="muted">(${o.year})</span></button>`).join('')}</div><div id="after"></div></div>`;
    };
    $('#qz').addEventListener('click', e => {
      const b = e.target.closest('.opt'); if (b && !b.disabled) {
        const { c } = qs[n]; const ok = b.dataset.k === c.k; if (ok) score++;
        $$('#qz .opt').forEach(x => { x.disabled = true; if (x.dataset.k === c.k) x.classList.add('right'); else if (x === b) x.classList.add('wrong'); });
        $('#after').innerHTML = `<div class="rate"><button class="btn" id="nx">${n + 1 < qs.length ? 'Next question' : 'See score'}</button><a class="btn ghost" href="#/case/${c.k}">Case page</a></div>`;
        $('#nx').focus(); return;
      }
      if (e.target.closest('#nx')) { n++; draw(); }
    });
    draw();
  }

  /* ---------------- timeline ---------------- */
  function timelineView(q) {
    const show = q.get('s') || 'both', topic = q.get('t') || '';
    const items = [];
    if (show !== 'cases') DB.amendments.forEach(a => items.push({ y: a.year, am: a }));
    if (show !== 'amend') DB.cases.filter(c => !topic || c.topics.includes(topic)).forEach(c => items.push({ y: c.year, c }));
    items.sort((a, b) => a.y - b.y || (a.am ? -1 : 1));
    const link = (s, t) => `#/timeline?s=${s}${t ? '&t=' + encodeURIComponent(t) : ''}`;
    view().innerHTML = `<div class="wrap"><h1 class="page">Timeline</h1><p class="lede">Constitutional amendments (purple) beside the cases that provoked or tested them.</p>
      <div class="chips" style="margin-bottom:10px">${[['both', 'Amendments and cases'], ['amend', 'Amendments only'], ['cases', 'Cases only']].map(([k, l]) => `<a class="chip" style="text-decoration:none" href="${link(k, topic)}" aria-pressed="${k === show}">${l}</a>`).join('')}</div>
      ${show !== 'amend' ? `<div class="toolbar"><select class="select" id="tt" aria-label="Topic"><option value="">All topics</option>${M.topics.map(t => `<option ${t === topic ? 'selected' : ''}>${esc(t)}</option>`).join('')}</select></div>` : ''}
      <ol class="tl">${items.map(it => it.am
        ? `<li class="am"><span class="y">${it.y}</span><div><b>${ordinal(it.am.n)} Amendment</b><p>${esc(it.am.what)}</p><p class="muted">${esc(it.am.why)} ${it.am.cases.filter(k => M.cases[k]).map(k => `<a class="cref" data-k="${k}" href="#/case/${k}">${esc(M.cases[k].name.split(' v. ')[0])}</a>`).join(', ')}</p></div></li>`
        : `<li class="cs"><span class="y">${it.y}</span><div><a class="cref" data-k="${it.c.k}" href="#/case/${it.c.k}">${esc(it.c.name)}</a><p>${esc(it.c.holding)}</p></div></li>`).join('')}</ol></div>`;
    const tt = $('#tt'); if (tt) tt.addEventListener('change', () => { location.hash = link(show, tt.value); });
  }
  function ordinal(n) { const s = ['th', 'st', 'nd', 'rd'], v = n % 100; return n + (s[(v - 20) % 10] || s[v] || s[0]); }

  /* ---------------- problem frameworks ---------------- */
  function solveView(id) {
    if (!id) {
      view().innerHTML = `<div class="wrap"><h1 class="page">Problem frameworks</h1><p class="lede">For problem questions: work through the steps in order, citing the case for each step. Tick steps as you write them; your ticks and draft stay on this device.</p>
        <div class="solver-list">${DB.solvers.map(s => `<a href="#/solve/${s.id}"><b>${esc(s.title)}</b><span>${esc(s.use)}</span></a>`).join('')}</div></div>`;
      return;
    }
    const s = DB.solvers.find(x => x.id === id); if (!s) return notFound();
    const done = S.steps[id] || {};
    view().innerHTML = `<div class="wrap"><p class="muted"><a href="#/solve">Problem frameworks</a></p><h1 class="page">${esc(s.title)}</h1><p class="lede">Use when: ${esc(s.use)}</p>
      <ol class="steps">${s.steps.map(([t, txt, cases], i) => `<li><div><h3>${esc(t)}</h3><p>${esc(txt)}</p>${cases.length ? `<p style="font:400 .95rem var(--sans)">Cite: ${cases.filter(k => M.cases[k]).map(k => `<a class="cref" data-k="${k}" href="#/case/${k}">${esc(M.cases[k].name)}</a> (${M.cases[k].year})`).join('; ')}</p>` : ''}
        <label><input type="checkbox" data-i="${i}" ${done[i] ? 'checked' : ''}> Covered in my answer</label></div></li>`).join('')}</ol>
      <h2 class="block">Draft</h2><textarea class="input" id="draft" style="min-height:220px;max-width:820px;font:400 1.02rem/1.6 var(--serif)" placeholder="Write your answer here — it is saved on this device as you type.">${esc(done.draft || '')}</textarea>
      <div class="row" style="margin-top:10px"><button class="btn ghost small" id="clr">Clear ticks and draft</button></div></div>`;
    view().addEventListener('change', e => { if (e.target.matches('input[data-i]')) { (S.steps[id] ||= {})[e.target.dataset.i] = e.target.checked; S.save('steps'); } });
    let t; $('#draft').addEventListener('input', e => { clearTimeout(t); t = setTimeout(() => { (S.steps[id] ||= {}).draft = e.target.value; S.save('steps'); }, 400); });
    $('#clr').addEventListener('click', () => { delete S.steps[id]; S.save('steps'); route(); });
  }

  /* ---------------- lecture files ---------------- */
  const blobs = {};
  async function sourceBlob(src) {
    if (blobs[src.id]) return blobs[src.id];
    const bytes = await unseal(await fetchBytes(`data/s/${src.id}.bin`));
    const type = src.kind === 'pdf' ? 'application/pdf' : 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
    blobs[src.id] = URL.createObjectURL(new Blob([bytes], { type }));
    return blobs[src.id];
  }
  function sourcesView(id, q) {
    if (id) return sourceView(id, q);
    const groups = []; DB.sources.forEach(s => { if (!groups.includes(s.group)) groups.push(s.group); });
    view().innerHTML = `<div class="wrap"><h1 class="page">Lecture files</h1><p class="lede">The original files, decrypted only in your browser. Every PDF page is also in the site search.</p>
      ${groups.map(g => `<h2 class="block">${esc(g)}</h2><ul class="src-list">${DB.sources.filter(s => s.group === g).map(s => `<li><div><a class="t" href="#/source/${s.id}">${esc(s.title)}</a><br><small>${esc(s.date)}; ${esc(s.topics)}; ${s.kind === 'pdf' ? `${s.pages} pages` : 'Word file'}, ${(s.size / 1e6).toFixed(1)} MB</small></div><a class="btn small ghost" href="#/source/${s.id}">${s.kind === 'pdf' ? 'Open' : 'Download'}</a></li>`).join('')}</ul>`).join('')}</div>`;
  }
  function sourceView(id, q) {
    const s = M.src[id]; if (!s) return notFound();
    const page = +q.get('p') || 1;
    view().innerHTML = `<div class="wrap"><p class="muted"><a href="#/sources">Lecture files</a></p><h1 class="page">${esc(s.title)}</h1><p class="lede">${esc(s.date)} — ${esc(s.topics)}</p>
      <div class="row" id="sa"><span class="muted">Decrypting…</span></div>
      ${s.kind === 'pdf' ? `<form class="toolbar" id="ps" style="margin-top:16px"><label class="sr" for="pq">Search this file</label><input class="input" id="pq" type="search" placeholder="Search inside this file"><button class="btn small ghost">Find pages</button></form><div id="pr"></div><div class="viewer" id="vw"></div>` : '<p class="muted" style="margin-top:14px">Word files cannot be shown in the browser; download it to open in Word or Google Docs.</p>'}</div>`;
    sourceBlob(s).then(url => {
      $('#sa').innerHTML = `<a class="btn" href="${url}${s.kind === 'pdf' ? `#page=${page}` : ''}" target="_blank" rel="noopener">${s.kind === 'pdf' ? 'Open in a new tab' : 'Open'}</a><a class="btn ghost" href="${url}" download="${esc(s.file)}">Download</a>`;
      if (s.kind === 'pdf') $('#vw').innerHTML = `<iframe title="${esc(s.title)}" src="${url}#page=${page}"></iframe>`;
    }).catch(e => { $('#sa').innerHTML = `<p class="err">The file could not be opened: ${esc(e.message)}</p>`; });
    const ps = $('#ps');
    if (ps) ps.addEventListener('submit', e => {
      e.preventDefault(); const term = $('#pq').value.trim().toLowerCase(); if (!term) return;
      const hits = DB.pages.filter(p => p.s === id && p.t.toLowerCase().includes(term));
      $('#pr').innerHTML = hits.length ? `<ul class="linklist" style="max-width:900px">${hits.map(p => `<li><a href="#/source/${id}?p=${p.p}">Page ${p.p}</a> <span class="snip">${snippet(p.t, term)}</span></li>`).join('')}</ul>` : '<p class="muted">Not found in this file.</p>';
    });
  }

  /* ---------------- corrections ---------------- */
  function fixesView() {
    const lvl = { error: ['Error', 'madder'], imprecise: ['Misleading', 'chakra'], minor: ['Detail', ''] };
    view().innerHTML = `<div class="wrap"><h1 class="page">Corrections</h1>
      <p class="lede">Found while checking the notes against the judgments on Indian Kanoon. In the notes the affected words are underlined in red — select them to see the fix. ${DB.corrections.filter(f => f.level === 'error').length} are real errors; the rest are dates, names or loose wording.</p>
      <ul class="fixes">${DB.corrections.map(f => {
        const where = [...(M.fixWhere[f.id] || [])].map(k => M.sec[k]).filter(Boolean);
        return `<li id="fix-${f.id}"><div class="row"><span class="pill ${lvl[f.level][1]}">${lvl[f.level][0]}</span><h3 style="margin:0">${esc(f.title)}</h3></div>
          <p class="w"><b>The notes say:</b> ${esc(f.wrong)}</p><p class="r">${esc(f.right)}</p>
          <div class="row">${f.src.map((u, i) => `<a class="ikbtn" href="${esc(u)}">Source${f.src.length > 1 ? ' ' + (i + 1) : ''}</a>`).join('')}
          ${where.map(s => `<a href="${secHref(s.key, '?fix=' + f.id)}" class="muted" style="font-size:.9rem">${esc(chapterLabel(M.ch[s.doc + '/' + s.ch]))}: ${esc(s.title)}</a>`).join(' ')}</div></li>`;
      }).join('')}</ul></div>`;
  }

  /* ---------------- saved & progress ---------------- */
  function savedView() {
    const bms = S.bm.map(k => M.sec[k]).filter(Boolean);
    const notes = Object.keys(S.notes).map(k => M.sec[k] && [M.sec[k], S.notes[k]]).filter(Boolean);
    const prog = ['exam', 'day'].map(doc => DB[doc].filter(c => c.sections.length).map(ch => ({ ch, ...progressOf(ch) })));
    view().innerHTML = `<div class="wrap"><h1 class="page">Saved and progress</h1><p class="lede">Everything here is stored only in this browser. Export a backup before clearing your browser data or switching devices.</p>
      <h2 class="block">Saved parts (${bms.length})</h2>${bms.length ? `<ul class="linklist">${bms.map(s => `<li><a href="${secHref(s.key)}">${esc(s.title)}</a> <span class="muted">— ${esc(chapterLabel(M.ch[s.doc + '/' + s.ch]))}, ${esc(M.ch[s.doc + '/' + s.ch].title)}</span></li>`).join('')}</ul>` : '<p class="muted">Use "Save" in the margin of any part of the notes.</p>'}
      <h2 class="block">My notes (${notes.length})</h2>${notes.length ? `<ul class="linklist">${notes.map(([s, t]) => `<li><a href="${secHref(s.key)}">${esc(s.title)}</a><br><span class="muted">${esc(t.slice(0, 200))}</span></li>`).join('')}</ul>` : '<p class="muted">Use "My note" in the margin to write your own points beside the notes.</p>'}
      <h2 class="block">Revision progress</h2><div class="course">${prog.map((list, i) => `<section><h3 style="margin:0 0 8px">${i ? 'Day-wise notes' : 'Exam-ready notes'}</h3><ol class="syl">${list.map(({ ch, n, d }) => `<li><a href="#/read/${ch.doc}/${ch.id}"><span class="no">${esc(chapterLabel(ch).replace(/^(Lecture|Day) /, ''))}</span><span class="nm">${esc(ch.title)}</span><span class="prog ${d === n ? 'done' : ''}">${d}/${n}</span></a></li>`).join('')}</ol></section>`).join('')}</div>
      <h2 class="block">Backup</h2><div class="row"><button class="btn ghost" id="exp">Export my data</button><label class="btn ghost" style="cursor:pointer">Import a backup<input type="file" id="imp" accept="application/json" hidden></label><button class="btn ghost" id="rst">Reset progress</button></div></div>`;
    $('#exp').addEventListener('click', () => {
      const data = { v: 1, rev: S.rev, bm: S.bm, notes: S.notes, fc: S.fc, steps: S.steps };
      const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([JSON.stringify(data, null, 1)], { type: 'application/json' }));
      a.download = `colaw-notes-backup-${new Date().toISOString().slice(0, 10)}.json`; a.click();
    });
    $('#imp').addEventListener('change', async e => {
      try { const d = JSON.parse(await e.target.files[0].text()); ['rev', 'bm', 'notes', 'fc', 'steps'].forEach(k => { if (d[k]) { S[k] = d[k]; S.save(k); } }); toast('Backup imported'); route(); } catch (err) { toast('That file is not a backup from this site'); }
    });
    $('#rst').addEventListener('click', () => { if (confirm('Clear revised ticks and flashcard progress on this device? Saved parts and your notes stay.')) { S.rev = {}; S.fc = {}; S.save('rev'); S.save('fc'); route(); } });
  }

  /* ---------------- settings ---------------- */
  function settingsView() {
    const theme = raw.get('cln.theme') || 'auto';
    const size = parseFloat(raw.get('cln.size') || '1.125');
    view().innerHTML = `<div class="wrap narrow"><h1 class="page">Settings</h1>
      <h2 class="block">Appearance</h2><div class="chips" id="th">${[['auto', 'Match device'], ['light', 'Light'], ['dark', 'Dark']].map(([k, l]) => `<button class="chip" data-t="${k}" aria-pressed="${k === theme}">${l}</button>`).join('')}</div>
      <label class="field" style="margin-top:18px;max-width:360px"><span>Reading text size</span><input type="range" id="fs" min="1" max="1.4" step="0.025" value="${size}" style="width:100%"></label>
      <h2 class="block">Privacy</h2>
      <p>The notes are encrypted with AES-256. The password never leaves this browser; without it the site shows only the lock screen.</p>
      <div class="row"><button class="btn ghost" id="lockn">Lock now</button><button class="btn ghost" id="forget">Lock and forget this device</button></div>
      <h2 class="block">Change the password</h2>
      <p class="muted">This makes a new key file. Upload it to GitHub at <b>docs/data/key.json</b> (replacing the old one); the new password works once GitHub Pages updates, usually within a minute.</p>
      <form id="cpw" style="max-width:420px"><label class="field"><span>Current password</span><input class="input" type="password" name="o" required autocomplete="current-password"></label>
        <label class="field"><span>New password (at least 10 characters)</span><input class="input" type="password" name="n" minlength="10" required autocomplete="new-password"></label>
        <label class="field"><span>Repeat the new password</span><input class="input" type="password" name="r" minlength="10" required autocomplete="new-password"></label>
        <button class="btn">Make the new key file</button><p class="err" id="cerr"></p></form>
      <h2 class="block">About</h2>
      <p class="muted">Built ${esc(DB.built)} from your Word notes, the day-wise PDF and ${DB.sources.length} lecture files. Case dates and links were checked on Indian Kanoon; ${DB.corrections.length} corrections are listed on the <a href="#/fixes">corrections page</a>. Constitution text: civictech-India/constitution-of-india dataset, with amendments checked. Fonts: Literata and Mukta (SIL Open Font License). Search: MiniSearch (MIT).</p></div>`;
    $('#th').addEventListener('click', e => {
      const b = e.target.closest('.chip'); if (!b) return; const t = b.dataset.t;
      raw.set('cln.theme', t); if (t === 'auto') delete document.documentElement.dataset.theme; else document.documentElement.dataset.theme = t;
      $$('#th .chip').forEach(x => x.setAttribute('aria-pressed', x === b));
    });
    $('#fs').addEventListener('input', e => { raw.set('cln.size', e.target.value); document.documentElement.style.setProperty('--read', e.target.value + 'rem'); });
    $('#lockn').addEventListener('click', () => { try { sessionStorage.removeItem('cln.k'); } catch (e) { /* ignore */ } location.reload(); });
    $('#forget').addEventListener('click', () => { forget(); location.hash = ''; location.reload(); });
    $('#cpw').addEventListener('submit', async e => {
      e.preventDefault(); const f = e.target, err = $('#cerr'); err.textContent = '';
      if (f.n.value !== f.r.value) { err.textContent = 'The new passwords do not match.'; return; }
      try {
        const kf = await keyFile(); const rk = await unwrapWith(f.o.value, kf);
        if (!rk) { err.textContent = 'The current password is not right.'; return; }
        const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
        const nk = { ...kf, salt: b64e(salt), iv: b64e(iv) };
        const kek = await kekFrom(f.n.value, nk, ['encrypt']);
        nk.wrapped = b64e(new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(kf.aad) }, kek, rk)));
        const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([JSON.stringify(nk, null, 1)], { type: 'application/json' }));
        a.download = 'key.json'; a.click(); f.reset(); toast('key.json downloaded — upload it to docs/data/ on GitHub');
      } catch (ex) { err.textContent = ex.message; }
    });
  }

  /* ---------------- boot ---------------- */
  (async () => {
    if (await tryRemembered()) start();
    else { $('#lock').hidden = false; $('#pw').focus(); }
  })();
})();
