// Rebuilds /playground/ and sitemap.xml from the published items of the wmie.it Playground.
// The API only returns published items to anonymous readers, so a draft never lands here.
// Each card is a title, a short description and a link to the page on wmie.it: the full
// text stays there, so the two sites never compete for the same content.
import { writeFile } from 'node:fs/promises'

const SITE = 'https://wmie.it'
const OUT = 'https://wmie.github.io'
const STATIC = ['/', '/faq-infinite/', '/ricerca-conversazionale/', '/ricerca-film/', '/ricerca-semantica/']

const res = await fetch(`${SITE}/api/playground-items?limit=100&depth=1&sort=-publishedAt&locale=it`)
if (!res.ok) throw new Error(`Playground API ${res.status}`)
const { docs } = await res.json()
if (!docs.length) throw new Error('Playground API returned no items: refusing to publish an empty page')

const esc = (s = '') => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c])
const abs = (u) => (u ? (u.startsWith('http') ? u : SITE + u) : null)
const image = (doc) => {
  const img = [doc.coverPoster, doc.cover].find((m) => m && typeof m === 'object' && m.mimeType?.startsWith('image/'))
  return img ? abs(img.sizes?.medium?.url || img.url) : null
}
const date = (d) => new Date(d).toLocaleDateString('it-IT', { month: 'long', year: 'numeric' })
const tags = (doc) => (doc.tags || []).map((t) => (typeof t === 'object' ? t.title : null)).filter(Boolean)

const cards = docs.map((doc) => {
  const img = image(doc)
  const k = [date(doc.publishedAt), ...tags(doc).slice(0, 2)].join(' · ')
  return `    <a class="card" href="${SITE}/design/${esc(doc.slug)}">
      ${img ? `<img src="${esc(img)}" alt="${esc(doc.title)}" width="1200" height="675" loading="lazy">` : ''}
      <div class="card__in">
        <span class="card__k">${esc(k)}</span>
        <h2>${esc(doc.title)}</h2>
        <p>${esc(doc.description)}</p>
      </div>
    </a>`
}).join('\n')

const html = `<!doctype html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Esplorazioni di design · Playground wmie</title>
<meta name="description" content="Le esplorazioni di design, i mockup e i prototipi pubblicati nel Playground di wmie.it: ${docs.length} lavori, dal più recente.">
<link rel="canonical" href="${OUT}/playground/">
<meta property="og:title" content="Esplorazioni di design · Playground wmie">
<meta property="og:url" content="${OUT}/playground/">
${image(docs[0]) ? `<meta property="og:image" content="${esc(image(docs[0]))}">` : ''}
<link rel="icon" href="../favicon.svg" type="image/svg+xml">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;450;500&family=Inter+Tight:wght@600;650&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<link rel="stylesheet" href="../s.css">
</head>
<body>
<header class="top"><div class="wrap top__in">
  <a class="brand" href="../"><span class="brand__w">wmie<span>.</span></span><span class="brand__k">playground</span></a>
  <a class="top__go" href="${SITE}/design">wmie.it/design</a>
</div></header>
<main>
  <section class="hero"><div class="wrap">
    <p class="eyebrow">Dal Playground di wmie.it</p>
    <h1>Esplorazioni di design</h1>
    <p class="lead">Mockup, redesign e prototipi che abbiamo pubblicato nel <a href="${SITE}/design">Playground di wmie.it</a>. Qui c'è l'elenco; ogni lavoro si apre sulla sua pagina, con video e contesto.</p>
    <p>La lista si aggiorna da sola quando pubblichiamo qualcosa di nuovo. I prototipi animati stanno <a href="../">nell'indice</a>.</p>
  </div></section>
  <section><div class="wrap"><div class="grid">
${cards}
  </div></div></section>
</main>
<footer><div class="wrap">
  <p>wmie · Cagliari, Italia · <a href="${SITE}">wmie.it</a></p>
  <nav><a href="../">Prototipi</a><a href="${SITE}/design">Playground su wmie.it</a><a href="${SITE}/contacts">Contatti</a></nav>
</div></footer>
</body>
</html>
`
await writeFile('playground/index.html', html)

const today = new Date().toISOString().slice(0, 10)
const latest = docs[0].updatedAt?.slice(0, 10) || today
const urls = [...STATIC.map((p) => [p, today]), ['/playground/', latest]]
await writeFile('sitemap.xml', `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.map(([p, d]) => `  <url><loc>${OUT}${p}</loc><lastmod>${d}</lastmod></url>`).join('\n')}
</urlset>
`)
console.log(`playground: ${docs.length} item, ultimo ${docs[0].slug}`)
