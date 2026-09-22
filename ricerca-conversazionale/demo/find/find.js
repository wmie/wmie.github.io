// wmie AI Search · semantic find demo. One rAF loop, one deterministic timeline: the recorder's fake clock owns
// every millisecond, so two takes are identical frame by frame.
const params = new URLSearchParams(location.search)
const SRC = params.get('src') ?? './content.json'
const SPEED = Number(params.get('speed')) || 1

const $ = (id) => document.getElementById(id)
const viewport = $('viewport'), body = $('body'), toc = $('toc'), rail = document.querySelector('.rail')
const thumb = $('thumb'), ticksBox = $('ticks'), panel = $('panel'), typed = $('typed'), ph = $('ph')
const caret = $('caret'), count = $('count'), meta = $('meta'), keys = $('keys'), go = $('go'), ms = $('ms')
const nextBtn = $('next'), prevBtn = $('prev'), field = $('field')

const data = await fetch(SRC).then((r) => r.json())

// ── page ──
document.title = `${data.pageTitle} — ${data.brand}`
const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;')
const html = [`<p class="crumb">Legale</p><h1>${esc(data.pageTitle)}</h1><p class="updated">${esc(data.updated)}</p>`]
for (const p of data.intro ?? []) html.push(`<p class="lede">${esc(p)}</p>`)
for (const s of data.sections) {
  html.push(`<section id="${s.id}"><h2>${esc(s.heading)}</h2>`)
  s.paragraphs.forEach((p, i) => html.push(`<p data-p="${s.id}:${i}">${esc(p)}</p>`))
  html.push('</section>')
}
body.innerHTML = html.join('')
toc.insertAdjacentHTML(
  'beforeend',
  data.sections.map((s) => `<a data-toc="${s.id}">${esc(s.heading)}</a>`).join(''),
)

// ── hits: wrap each key sentence, once per paragraph, marks shared by whichever query points at them ──
const queries = data.queries.map((q, qi) => ({
  ...q,
  hits: q.hits.map((h, hi) => ({ ...h, id: `q${qi}h${hi}` })),
}))
const byParagraph = new Map()
for (const q of queries)
  for (const h of q.hits) {
    const key = `${h.section}:${h.paragraph}`
    ;(byParagraph.get(key) ?? byParagraph.set(key, []).get(key)).push(h)
  }
const missing = []
for (const [key, hits] of byParagraph) {
  const el = body.querySelector(`[data-p="${key}"]`)
  if (!el) { missing.push(key); continue }
  const text = el.textContent
  const spans = []
  for (const h of hits) {
    const at = text.indexOf(h.sentence)
    if (at < 0) { missing.push(`${key} · ${h.sentence.slice(0, 40)}…`); continue }
    spans.push({ at, end: at + h.sentence.length, h })
  }
  spans.sort((a, b) => a.at - b.at)
  let out = '', cursor = 0
  for (const s of spans) {
    if (s.at < cursor) continue
    out += esc(text.slice(cursor, s.at)) + `<mark class="hit" id="${s.h.id}">${esc(text.slice(s.at, s.end))}</mark>`
    cursor = s.end
  }
  el.innerHTML = out + esc(text.slice(cursor))
}
if (missing.length) console.error('hit non trovati:', missing)

for (const q of queries)
  for (const h of q.hits) {
    h.mark = document.getElementById(h.id)
    h.para = h.mark?.closest('p')
    h.tick = Object.assign(document.createElement('i'), { className: 'tick' })
    ticksBox.append(h.tick)
    h.top = h.mark ? h.mark.getBoundingClientRect().top + viewport.scrollTop : 0
  }

function placeTicks() {
  const total = viewport.scrollHeight, railH = rail.clientHeight
  for (const q of queries) for (const h of q.hits) h.tick.style.top = `${(h.top / total) * railH}px`
}

// ── scrolling (manual easing: CSS smooth scroll is not frame-deterministic) ──
let scroll = { from: 0, to: 0, at: -1, dur: 0 }
const maxScroll = () => viewport.scrollHeight - viewport.clientHeight
const easeInOut = (u) => (u < 0.5 ? 4 * u * u * u : 1 - Math.pow(-2 * u + 2, 3) / 2)
function scrollTo(y, dur, t) {
  scroll = { from: viewport.scrollTop, to: Math.max(0, Math.min(maxScroll(), y)), at: t, dur }
}
function scrollToMark(mark, dur, t, frac = 0.42) {
  const top = mark.getBoundingClientRect().top + viewport.scrollTop
  scrollTo(top - viewport.clientHeight * frac, dur, t)
}
function paintScroll(t) {
  if (scroll.at >= 0) {
    const u = scroll.dur ? Math.min(1, (t - scroll.at) / scroll.dur) : 1
    viewport.scrollTop = scroll.from + (scroll.to - scroll.from) * easeInOut(u)
    if (u >= 1) scroll.at = -1
  }
  const h = viewport.clientHeight, total = viewport.scrollHeight
  const railH = rail.clientHeight
  const th = Math.max(34, (h / total) * railH)
  thumb.style.height = `${th}px`
  thumb.style.top = `${(viewport.scrollTop / (total - h)) * (railH - th)}px`
  // active section in the table of contents
  const y = viewport.scrollTop + 120
  let on = data.sections[0].id
  for (const s of data.sections) { const el = document.getElementById(s.id); if (el && el.offsetTop <= y) on = s.id }
  for (const a of toc.querySelectorAll('a')) a.classList.toggle('is-on', a.dataset.toc === on)
}

// ── panel state ──
let shown = []      // hits revealed so far, in page order
let current = -1
function setCurrent(i, t, dur = 0.62) {
  current = i
  shown.forEach((h, k) => {
    h.mark?.classList.toggle('is-on', k === i)
    h.tick.classList.toggle('is-on', k === i)
  })
  count.innerHTML = `<b>${i + 1}</b> di <b>${shown.length}</b> connessioni`
  if (shown[i]?.mark) scrollToMark(shown[i].mark, dur, t)
}
function reveal(hit, t) {
  hit.mark?.classList.add('is-in')
  hit.para?.classList.add('is-ctx')
  hit.tick.classList.add('is-in')
  shown.push(hit)
  shown.sort((a, b) => a.top - b.top)
  count.innerHTML = `<b>${shown.length}</b> connession${shown.length === 1 ? 'e' : 'i'}`
}
function clearHits() {
  for (const h of shown) { h.mark?.classList.remove('is-in', 'is-on'); h.para?.classList.remove('is-ctx'); h.tick.classList.remove('is-in', 'is-on') }
  shown = []; current = -1
  count.textContent = 'Nessuna connessione'
  meta.innerHTML = ''
  ms.textContent = ''
}

// ── deterministic human typing ──
const rng = (seed) => () => ((seed = (seed * 1664525 + 1013904223) >>> 0) / 2 ** 32)
const rand = rng(20260920)
function schedule(text, start) {
  const out = []
  let t = start
  for (let i = 0; i < text.length; i++) {
    const c = text[i], prev = text[i - 1]
    let dt = 0.052 + rand() * 0.055
    if (prev === ' ') dt += 0.035
    if (c === ' ') dt += 0.02
    if (prev === ',') dt += 0.13
    if (i === 0) dt = 0.1
    out.push({ at: (t += dt * SPEED), n: i + 1 })
  }
  return out
}

// ── timeline ──
// Two framings: NEAR on the panel, so the question is legible in a phone-sized feed, and WIDE on the
// page, where the lit sentence and the panel sit together. The pull-back from one to the other is the reveal.
const steps = []
const cues = []   // pointer cues, resolved by the recorder against live element boxes
const zooms = []  // punch-ins, same idea
const add = (at, fn) => steps.push({ at, fn, done: false })
const cue = (t, target, opts = {}) => cues.push({ t, target, ...opts })
const zoom = (t, target, scale, dur) => zooms.push({ t, target, scale, dur })
// The page and the panel are typeset large enough to read as they are, so the camera barely moves:
// one slow push in after the panel opens, one pull out at the end. Nothing else.
const HOLD = 1.26

let t = 0.4
add(t, (tt) => scrollTo(820, 1.5, tt))                        // a look at the page, as a reader would
cue(0.5, 'read')                                              // the pointer drifts over the text, then rests
t = 1.95
add(t - 0.35, () => keys.classList.add('is-on'))              // ⌘F: the shortcut everyone already uses
add(t + 0.45, () => keys.classList.remove('is-on'))
cue(t - 0.02, 'extOn')                                        // the toolbar button answers
cue(t + 0.42, 'extOff')
add(t + 0.08, () => panel.classList.add('is-open'))
zoom(t + 0.3, 'page', HOLD, 1.35)                             // one slow push in, then the framing is kept
t += 1.05

queries.forEach((q, qi) => {
  if (qi > 0) {
    add(t - 0.5, () => typed.classList.add('is-sel'))
    add(t - 0.08, () => { typed.classList.remove('is-sel'); typed.textContent = ''; ph.style.opacity = '0'; clearHits() })
    t += 0.3
  }
  add(t - 0.2, () => { ph.style.opacity = '0'; meta.innerHTML = 'lettura della pagina…'; ms.textContent = '' })
  const plan = schedule(q.text, t)
  for (const k of plan) add(k.at, (tt) => { typed.textContent = q.text.slice(0, k.n); lastType = tt })
  const end = plan[plan.length - 1].at

  // a hit appears as soon as the word that makes it make sense has been typed
  const words = q.text.split(/\s+/)
  const endOf = (word) => {
    const i = words.findIndex((w) => w.replace(/[^\p{L}\p{N}']/gu, '') === word.replace(/[^\p{L}\p{N}']/gu, ''))
    const chars = words.slice(0, i + 1).join(' ').length
    return plan[Math.min(plan.length - 1, Math.max(0, chars - 1))].at
  }
  const seen = new Map()
  const floor = plan[Math.floor(plan.length * 0.52)].at
  let lastReveal = t
  for (const h of q.hits) {
    const base = endOf(h.after)
    const k = seen.get(h.after) ?? 0
    seen.set(h.after, k + 1)
    // nothing surfaces until the question is halfway typed: two words in is not a search, it is a script
    const at = Math.max(base + 0.18, floor) + k * 0.16
    lastReveal = Math.max(lastReveal, at)
    add(at, (tt) => reveal(h, tt))
  }
  const settle = Math.max(end + 0.34, lastReveal + 0.36)

  add(end + 0.06, () => go.classList.add('is-hot'))
  add(end + 0.3, () => go.classList.remove('is-hot'))
  add(settle, (tt) => {
    meta.innerHTML = `${data.passages ?? 328} passaggi letti sulla pagina · ⌘F letterale: <em>0 risultati</em>`
    ms.textContent = `${q.ms ?? 780 + qi * 90} ms`
    const best = Math.max(0, shown.findIndex((h) => h.best))
    setCurrent(best, tt, 0.8)
  })

  t = settle + 3.0                                            // time to read the sentence that answers

  // stepping through the connections with the ↓ button
  const stops = Math.min(2, Math.max(0, q.hits.length - 1))
  for (let s = 0; s < stops; s++) {
    cue(t - 0.8, 'next', { dur: 0.55 })                       // travel, with a duration so it always lands in time…
    cue(t - 0.05, 'press')                                    // …then the click, on the frame the button reacts
    add(t, (tt) => {
      nextBtn.classList.add('is-press')
      setCurrent((current + 1) % shown.length, tt)
    })
    add(t + 0.18, () => nextBtn.classList.remove('is-press'))
    t += 1.6
  }
  t += 0.5
})

zoom(t, 'out', 1, 0.85)
t += 1.15
const DONE_AT = t
window.__demo = {
  get done() { return clock >= DONE_AT },
  duration: DONE_AT,
  cues,
  zooms,
  hotspot(name) {
    if (name === 'read') return { x: innerWidth * 0.42, y: innerHeight * 0.62, w: 0, h: 0 }
    // where the scroll always parks the current sentence: the WIDE framing centres on it
    // the one framing that is held: index, column and panel all inside, the tab strip just outside,
    // and the sentence the scroll parks at 42% lands in the middle of it
    if (name === 'page') return { x: innerWidth * 0.506, y: innerHeight * 0.438, w: 0, h: 0 }
    const el = { field, next: nextBtn, prev: prevBtn, go, panel, current: shown[current]?.mark }[name]
    if (!el) return null
    const r = el.getBoundingClientRect()
    return { x: r.x, y: r.y, w: r.width, h: r.height }
  },
}

// ── loop ──
let t0 = null, clock = 0, lastType = -9
await document.fonts.ready
placeTicks()
function frame(now) {
  if (t0 === null) t0 = now
  clock = (now - t0) / 1000
  for (const s of steps) if (!s.done && clock >= s.at) { s.done = true; s.fn(clock) }
  // caret: solid while the keys are moving, a calm blink when they are not
  caret.style.opacity = clock - lastType < 0.45 ? '1' : clock % 1.06 < 0.6 ? '1' : '0'
  paintScroll(clock)
  requestAnimationFrame(frame)
}
requestAnimationFrame(frame)
