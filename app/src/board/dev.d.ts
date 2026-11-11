// The virtual board is for development and tests only (decided 2026-11-11): its seed lives
// unencrypted in the browser's storage, and the design keeps the phrase out of browsers
// (docs/notes/signer-app.md, decision 2). vite.config.ts sets this: true for the dev server and
// the tests, false for `vite build` unless VIRTUAL_BOARD=1 is set (to check the virtual board
// under the production CSP). Code under `if (__VIRTUAL_BOARD__)` is left out of the build, the
// virtual board's WebAssembly and worker with it.
declare const __VIRTUAL_BOARD__: boolean
