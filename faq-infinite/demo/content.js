// Real wmie.it content. The Gruppo Collu answer comes from /case-studies/gruppo-collu
// (6.449 redirects, 13.835 products are printed there). The CMS answer is Enrico's own
// wording, approved 2026-09-20: it describes what wmie does, not a quote from the site.
// The five accordion answers are the opening sentences of the FAQPage structured data
// on https://www.wmie.it/ (fetched 2026-09-20), trimmed so a row fits the frame.
// Nothing here is invented.
export const FAQ = [
  {
    q: 'Cosa fate esattamente e per che tipo di aziende lavorate?',
    a: [
      'Progettiamo e costruiamo infrastrutture digitali complete: siti web, e-commerce, web app, integrazioni AI e architetture cloud su AWS.',
      'Non siamo un’agenzia creativa né un body rental: siamo un team stabile di designer, engineer e cloud architect che opera come reparto tech integrato nel vostro business.',
    ],
  },
  {
    q: 'Quanto tempo ci vuole per completare un progetto digitale?',
    a: [
      'Un progetto web va in produzione in 4-8 settimane, una web app in 8-14, un e-commerce su Shopify con integrazioni custom in 6-10.',
      'Ogni progetto segue cinque fasi: Discovery, Design, Build, Go-live, Growth.',
    ],
  },
  {
    q: 'Quanto costa un progetto digitale?',
    a: [
      'Un sito aziendale con design custom e CMS headless va da 8.000 a 25.000 euro. Un e-commerce su Shopify con integrazioni custom da 15.000 a 40.000.',
      'Preventivi senza Discovery sono stime al buio: vi diciamo il costo reale dopo aver capito cosa serve, di solito entro due settimane.',
    ],
  },
  {
    q: 'Quali tecnologie e piattaforme utilizzate per i progetti?',
    a: [
      'Stack enterprise-grade: CMS headless per i siti web, Shopify per gli e-commerce, React e Next.js per web app e dashboard custom.',
      'L’infrastruttura cloud gira su Cloudflare per CDN e protezione, con tempi di risposta sotto i 100 millisecondi e uptime al 99.9%.',
    ],
  },
  {
    q: 'Meglio WordPress, Shopify o un sito custom?',
    a: [
      'Ogni piattaforma ha il suo contesto. Su progetti con molte integrazioni o traffico alto WordPress tende a rallentare e la dipendenza dai plugin crea problemi di manutenzione.',
      'La piattaforma giusta dipende dagli obiettivi. Lo definiamo nella Discovery.',
    ],
  },
]

export const ASKED = [
  {
    q: 'potete collegare l\u2019ecommerce al gestionale?',
    source: 'wmie.it/case-studies/gruppo-collu',
    a: [
      'S\u00ec. Con Gruppo Collu abbiamo collegato lo store Shopify al gestionale Atelier: quando il catalogo si \u00e8 disallineato abbiamo rimesso in piedi 6.449 redirect e riportato 13.835 prodotti sui canali di vendita.',
      'Il lavoro vero \u00e8 tenere coerenti gestionale, piattaforma e campagne nel tempo.',
    ],
    link: { url: 'wmie.it/case-studies/gruppo-collu', label: 'Case study Gruppo Collu' },
  },
  {
    q: 'dopo posso aggiornare il sito da solo?',
    source: 'wmie.it/services/web-development',
    a: [
      'S\u00ec. Impostiamo il CMS su misura delle vostre esigenze, cos\u00ec il vostro team gestisce i contenuti in autonomia, senza passare dagli sviluppatori.',
      'Dove serve arriviamo a sistemi avanzati: landing page costruite in drag & drop, con componenti disegnati dai nostri designer.',
    ],
    link: { url: 'wmie.it/services/web-development', label: 'Web Development' },
  },
]
