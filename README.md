# wmie playground

Componenti di interfaccia sviluppati da [wmie](https://wmie.it), pubblicati su <https://wmie.github.io/>.
Ogni pagina mostra il componente in funzione e la sua scheda tecnica.

| Pagina | Componente | Pattern |
|---|---|---|
| [FAQ infinite](https://wmie.github.io/faq-infinite/) | `FaqAccordion` + `AskRow` | Retrieval-augmented generation (RAG) con citazione della fonte |
| [Ricerca sulle auto](https://wmie.github.io/ricerca-conversazionale/) | `NaturalLanguageSearchBar` + `ResultGrid` | Natural-language faceted search (query-to-filter parsing) |
| [Ricerca sui film](https://wmie.github.io/ricerca-film/) | `NaturalLanguageSearchBar` + `PhysicsResultPile` | Natural-language faceted search, reveal fisico (matter-js) |
| [Ricerca semantica](https://wmie.github.io/ricerca-semantica/) | `SemanticFindPanel` | Semantic in-page search, dense retrieval a livello di frase |
| [Esplorazioni di design](https://wmie.github.io/playground/) | — | Elenco sincronizzato con il Playground di wmie.it |

## Struttura

```
index.html              indice
<pagina>/index.html     il componente, la scheda tecnica, il contesto
<pagina>/demo/          il componente isolato, disegnato per una finestra 1664x936 e scalato via transform
playground/             generata da scripts/playground.mjs dall'API pubblica di wmie.it
media/                  registrazioni leggere e poster, mostrate sotto i 900px
```

Lo stato di ogni componente è indicato nella sua scheda tecnica.

## Crediti

- Foto delle auto: [Unsplash](https://unsplash.com), Unsplash License. Prezzi e chilometri indicativi.
- Locandine dei film: dei rispettivi studi e distributori. Titoli, anni e voti IMDb al momento della raccolta.
- Immagini degli immobili: [picsum.photos](https://picsum.photos).
- Il negozio "Ombralarga" della ricerca semantica è un esempio.

Fatto da [wmie](https://wmie.it), Cagliari.
