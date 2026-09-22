// The page plays itself: one scripted take, driven only by setTimeout, so under the
// recorder's fake clock every run produces the same frames. It also publishes where the
// pointer should be a beat before each click (window.__faq.intent) and where the frame
// should push in (window.__faq.zoom), which is how record-faq.mjs choreographs the
// cursor and the Screen-Studio-style zoom without a hardcoded timeline.
import { FAQ, ASKED } from './content.js'

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const el = (tag, cls, text) => {
  const n = document.createElement(tag)
  if (cls) n.className = cls
  if (text != null) n.textContent = text
  return n
}

// Deterministic jitter for the typing rhythm.
let seed = 0x2f6e2b1
const rnd = () => (((seed = (seed * 1103515245 + 12345) & 0x7fffffff) >>> 8) % 1000) / 1000

const CHEV = '<svg class="chev" viewBox="0 0 12 12"><path d="M2.5 4.5L6 8l3.5-3.5"/></svg>'
const ARROW = '<svg viewBox="0 0 12 12"><path d="M6 10V2"/><path d="M2.5 5.5L6 2l3.5 3.5"/></svg>'
const LINKICON = '<svg viewBox="0 0 12 12"><path d="M4 8l4-4"/><path d="M4.5 3.5H8.5V7.5"/></svg>'

const list = document.getElementById('list')

// ── accordion rows ───────────────────────────────────────────────────────────
const items = FAQ.map(({ q, a }) => {
  const item = el('div', 'item')
  const head = el('div', 'item__head')
  head.append(el('div', 'item__q', q))
  head.insertAdjacentHTML('beforeend', CHEV)
  const body = el('div', 'item__body')
  const inner = el('div', 'item__bodyin')
  const ans = el('div', 'item__a')
  for (const p of a) ans.append(el('p', null, p))
  inner.append(ans)
  body.append(inner)
  item.append(head, body)
  list.append(item)
  return { item, head }
})

// ── the ask row ──────────────────────────────────────────────────────────────
const ask = el('div', 'ask')
const row = el('div', 'ask__row')
const field = el('div', 'ask__field')
const typed = el('span', 'ask__typed')
const caret = el('span', 'caret')
const ph = el('span', 'ask__ph', 'Chiedi qualsiasi altra cosa')
field.append(typed, caret, ph)
const send = el('div', 'send')
send.insertAdjacentHTML('beforeend', ARROW)
row.append(field, send)

const answer = el('div', 'answer')
const status = el('div', 'answer__status')
const statusText = el('span', null, 'Sto leggendo ')
const statusSrc = el('span', 'answer__src')
status.append(statusText, statusSrc)
const abody = el('div', 'answer__body')
answer.append(status, abody)
ask.append(row, answer)
list.append(ask)

// ── pointer intents, read by the recorder ────────────────────────────────────
const LEAD_MS = 950 // the cursor gets this long to arrive before the click lands
const QUICK_MS = 720 // short hop: the pointer starts out near the list
let intentId = 0
const aim = (node, click = true) => {
  const r = node.getBoundingClientRect()
  window.__faq.intent = { id: ++intentId, click, x: r.x + r.width / 2, y: r.y + r.height / 2 }
}

window.__faq = { intent: null, zoom: null, phase: 'idle', done: false }

let zoomId = 0
/** Frame this box of the page (iframe coordinates); null pulls back out. */
const pushIn = (box, dur) => { window.__faq.zoom = { id: ++zoomId, box, dur } }
/** The FAQ block alone: from the bottom of the header to the top of the CTA strip. */
const faqBox = () => {
  const top = document.querySelector('.topbar').getBoundingClientRect().bottom
  const bottom = document.querySelector('.tail').getBoundingClientRect().top
  const left = document.querySelector('.faq__side').getBoundingClientRect().left
  return { x: left, y: top, w: innerWidth - 2 * left, h: bottom - top }
}

// ── actions ──────────────────────────────────────────────────────────────────
let open = -1
async function toggle(i) {
  const was = open
  if (was >= 0 && was !== i) items[was].item.classList.remove('is-open')
  open = was === i ? -1 : i
  items[i].item.classList.toggle('is-open', open === i)
  items.forEach((it, k) => it.item.classList.toggle('is-dim', open >= 0 && k !== open))
}

async function type(text) {
  ph.style.display = 'none'
  for (let i = 0; i < text.length; i++) {
    typed.textContent = text.slice(0, i + 1)
    const c = text[i]
    let d = 52 + rnd() * 58
    if (c === ' ') d += 26
    if (rnd() > 0.9) d += 120 // the small hesitations a real hand makes
    ask.classList.toggle('is-ready', i > 2)
    await sleep(d)
  }
}

async function stream(entry) {
  ask.classList.remove('is-ready')
  ask.classList.add('is-busy')
  statusSrc.textContent = entry.source
  status.classList.add('is-on')
  window.__faq.phase = 'reading'
  await sleep(1350)
  status.classList.remove('is-on')
  window.__faq.phase = 'answering'

  const spans = []
  for (const p of entry.a) {
    const para = el('p')
    for (const word of p.split(' ')) {
      const w = el('span', 'w', word + ' ')
      para.append(w)
      spans.push(w)
    }
    abody.append(para)
  }
  const link = el('a', 'answer__link')
  link.href = '#'
  link.insertAdjacentHTML('beforeend', LINKICON)
  link.append(el('span', null, entry.link.label + ' · ' + entry.link.url))
  abody.append(link)

  await sleep(80)
  for (const w of spans) {
    w.classList.add('is-in')
    await sleep(34 + rnd() * 22)
  }
  await sleep(260)
  link.classList.add('is-in')
  ask.classList.remove('is-busy')
  window.__faq.phase = 'answered'
}

function clearAnswer() {
  abody.replaceChildren()
  typed.textContent = ''
  ph.style.display = ''
}

// ── the take ─────────────────────────────────────────────────────────────────
const SHORT = new URLSearchParams(location.search).get('short') === '1'

async function play() {
  await sleep(SHORT ? 500 : 900)

  if (SHORT) {
    // One canned row, flicked open and shut: enough to show these are real FAQs,
    // not long enough to invite reading. The stack row, not the pricing one.
    aim(items[3].head)
    await sleep(QUICK_MS)
    await toggle(3)
    await sleep(900)
    await toggle(3)
    await sleep(260)
  }

  // The frame pushes in on the FAQ block while the cursor is still travelling, so the
  // move and the zoom land together. The answer's room is reserved first: nothing below
  // the list may shift once the frame is tight.
  aim(field)
  ask.classList.add('is-live')
  await sleep(120)
  pushIn(faqBox(), 1450)
  await sleep(LEAD_MS - 120)
  ask.classList.add('is-focus')
  items.forEach((it) => it.item.classList.add('is-dim'))
  await sleep(560)

  const asked = SHORT ? ASKED.slice(1) : ASKED
  for (let i = 0; i < asked.length; i++) {
    if (i > 0) {
      clearAnswer()
      await sleep(640)
    }
    window.__faq.phase = 'typing'
    await type(asked[i].q)
    await sleep(420)
    await stream(asked[i])
    await sleep(i === asked.length - 1 ? 1600 : 1900)
  }

  ask.classList.remove('is-focus')
  pushIn(null, 1150)
  await sleep(1150)
  window.__faq.done = true
}

// Fonts decide the layout, so wait for them before the first measured click.
await document.fonts.ready
await new Promise((r) => requestAnimationFrame(r))
play()
