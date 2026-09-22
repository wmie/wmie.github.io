// La demo è disegnata per una finestra 1664x936: la scaliamo invece di ridisegnarla.
const FRAME = { w: 1664, h: 936 }
const stage = document.querySelector('.stage')
if (stage) {
  const frame = stage.querySelector('iframe')
  const fit = () => {
    frame.style.transform = `scale(${stage.clientWidth / FRAME.w})`
  }
  new ResizeObserver(fit).observe(stage)
  fit()
  const replay = document.querySelector('.chrome__replay')
  if (replay) replay.addEventListener('click', () => { frame.src = frame.src })
}
