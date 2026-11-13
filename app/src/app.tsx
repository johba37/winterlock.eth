// The app's shell: storage, the device worker, this device's record, and a hash router.

import { createContext } from 'preact'
import { useContext, useEffect, useState } from 'preact/hooks'
import { link, useLink } from './board/link'
import { core } from './core/client'
import { short } from './lib/chain'
import { type BoardRecord, DB_NAME, type DeviceRecord, getBoard, getDevice, openDb } from './lib/db'
import type { Env } from './lib/flows'
import { resumeWc } from './lib/wc-state'
import { BoardDock, BoardHome, BoardInfo, BoardStart } from './screens/board'
import { Create, Install, Pair, Welcome } from './screens/onboarding'
import { Devices, Home, Join, Revoke, Settings } from './screens/member'
import { DappBar, DappsScreen } from './screens/dapps'
import { SafeScreen, Send, TxScreen } from './screens/safe'
import { Screen } from './ui'

export interface AppState {
  env: Env
  /** this browser's device key (without a board) */
  device: DeviceRecord | null
  /** the member's board (decision 7), if the app uses one */
  board: BoardRecord | null
  reload(): Promise<void>
}

const AppContext = createContext<AppState | null>(null)

export function useApp(): AppState {
  const s = useContext(AppContext)
  if (!s) throw new Error('no app state')
  return s
}

export function useDevice(): DeviceRecord {
  const d = useApp().device
  if (!d) throw new Error('no device')
  return d
}

export function useBoard(): BoardRecord {
  const b = useApp().board
  if (!b) throw new Error('no board')
  return b
}

/** The member, with a device key or a board: its owner and gas account. */
export function useMember(): DeviceRecord | BoardRecord {
  const a = useApp()
  const m = a.device ?? a.board
  if (!m) throw new Error('no member')
  return m
}

function route(): string {
  return decodeURIComponent(location.hash.replace(/^#/, '')) || '/'
}

export function App() {
  const [env, setEnv] = useState<Env | null>(null)
  const [device, setDevice] = useState<DeviceRecord | null | undefined>(undefined)
  const [board, setBoard] = useState<BoardRecord | null>(null)
  const linkState = useLink()
  const [path, setPath] = useState(route())
  const [fatal, setFatal] = useState<string | null>(null)

  useEffect(() => {
    const on = () => {
      setPath(route())
      window.scrollTo(0, 0)
    }
    addEventListener('hashchange', on)
    return () => removeEventListener('hashchange', on)
  }, [])

  useEffect(() => {
    ;(async () => {
      try {
        if (!globalThis.indexedDB) throw new Error('This browser has no IndexedDB (a private window?): the app can’t keep a device key here.')
        if (!navigator.locks) throw new Error('This browser has no Web Locks: update it to use the app.')
        const db = await openDb(indexedDB, DB_NAME, () => setFatal('A newer version of the app opened in another tab: reload this page to use it.'))
        const e = { db, core: core() }
        setEnv(e)
        const b = (await getBoard(db)) ?? null
        setBoard(b)
        const d = (await getDevice(db)) ?? null
        setDevice(d)
        // the member's board: the virtual one starts by itself, a USB one opens if this site may
        // use its port already (otherwise the board bar's Connect asks)
        if (__VIRTUAL_BOARD__ && b?.link === 'virtual') link.connectVirtual().catch(() => {})
        else if (b?.link === 'serial') link.connectGranted().catch(() => {})
        // a dapp session from before: reconnect, so its requests reach the app
        if (d || b) resumeWc(e, !!b).catch(() => {})
      } catch (err) {
        setFatal(short(err))
      }
    })()
  }, [])

  if (fatal)
    return (
      <Screen title="Winterlock">
        <p class="error">{fatal}</p>
      </Screen>
    )
  if (!env || device === undefined)
    return (
      <Screen title="Winterlock">
        <p class="muted">Opening…</p>
      </Screen>
    )

  const state: AppState = {
    env,
    device,
    board,
    reload: async () => {
      setBoard((await getBoard(env.db)) ?? null)
      setDevice((await getDevice(env.db)) ?? null)
    },
  }
  const dock = board !== null || linkState.phase !== 'none'
  return (
    <AppContext.Provider value={state}>
      <div class={dock ? 'with-dock' : ''}>
        {(device || board) && <DappBar />}
        {page(path, device, board)}
        {dock && <BoardDock />}
      </div>
    </AppContext.Provider>
  )
}

function page(path: string, device: DeviceRecord | null, board: BoardRecord | null) {
  const p = path.split('/').filter(Boolean)
  if (p[0] === 'install') return <Install />
  if (!device && !board) {
    if (p[0] === 'create') return <Create />
    if (p[0] === 'pair') return <Pair />
    if (p[0] === 'board') return <BoardStart />
    if (p[0] === 'settings') return <Settings />
    return <Welcome />
  }
  if (board) {
    // with a board: no device pairing or revoking, no messages; dapps send transactions only
    if (p[0] === 'join') return <Join />
    if (p[0] === 'board') return <BoardInfo />
    if (p[0] === 'settings') return <Settings />
    if (p[0] === 'safe' && p[1] && p[2]) return safePage(p)
    return <BoardHome />
  }
  if (p[0] === 'join') return <Join />
  if (p[0] === 'devices') return <Devices />
  if (p[0] === 'revoke' && p[1]) return <Revoke target={Number(p[1])} />
  if (p[0] === 'settings') return <Settings />
  if (p[0] === 'safe' && p[1] && p[2]) return safePage(p)
  return <Home />
}

function safePage(p: string[]) {
  const chain = Number(p[1])
  const safe = p[2] as `0x${string}`
  // keyed, so going from one transaction or Safe to another starts the screen afresh
  if (p[3] === 'tx' && p[4]) return <TxScreen key={`${chain}/${safe}/${p[4]}`} chain={chain} safe={safe} hash={p[4] as `0x${string}`} />
  if (p[3] === 'send') return <Send key={`${chain}/${safe}/send`} chain={chain} safe={safe} />
  if (p[3] === 'dapps') return <DappsScreen key={`${chain}/${safe}/dapps`} chain={chain} safe={safe} />
  return <SafeScreen key={`${chain}/${safe}`} chain={chain} safe={safe} />
}
