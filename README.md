# wmie playground

Prototipi di interfaccia pubblicati su <https://wmie.github.io/>.

Ogni pagina è un **concept**: i testi, i dati e le risposte stanno scritti dentro la demo.
Nessuna interroga un modello o un backend mentre gira, e tutte partono da sole. Servono a mostrare un
comportamento, non a essere un prodotto.

| Demo | Cosa mostra | Interattiva |
|---|---|---|
| [FAQ infinite](https://wmie.github.io/faq-infinite/) | Un accordion di FAQ con una riga in più dove il visitatore scrive la sua domanda | No, si recita da sola |
| [Ricerca conversazionale](https://wmie.github.io/ricerca-conversazionale/) | Una frase in italiano al posto di sei filtri, su un catalogo auto | No, si recita da sola; la ricerca sotto è vera sul catalogo di prova |
| [Ricerca sui film](https://wmie.github.io/ricerca-film/) | La stessa ricerca su un catalogo di film, con le locandine che salgono da un mucchio fisico | No, si recita da sola; la ricerca sotto è vera |
| [Ricerca semantica](https://wmie.github.io/ricerca-semantica/) | Le frasi di una pagina legale che rispondono a una domanda, senza parole in comune | No, si recita da sola |

## Struttura

```
index.html              indice
<demo>/index.html       la pagina che racconta la demo
<demo>/demo/            la demo, disegnata per una finestra 1664x936 e scalata via transform
media/                  registrazioni leggere e poster (fallback da telefono)
```

Questo repository contiene il sito pubblicato, non i sorgenti. La ricerca conversazionale
è il build di un progetto Vite + React + matter-js che teniamo separato.

## Crediti

- Foto delle auto: [Unsplash](https://unsplash.com), usate secondo la Unsplash License.
- Locandine dei film: dei rispettivi studi e distributori, usate a scopo dimostrativo. Titoli, anni e voti IMDb reali al momento della raccolta.
- Immagini degli immobili: [picsum.photos](https://picsum.photos), placeholder.
- Modelli, versioni, cavalli e autonomia delle auto sono reali; prezzi e chilometri sono
  verosimili e inventati. Il negozio "Ombralarga" della ricerca semantica non esiste, testo
  legale compreso.

Fatto da [wmie](https://wmie.it), Cagliari.
