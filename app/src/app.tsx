// The app's shell: storage, the device worker, this device's record, and a hash router.

import { createContext } from 'preact'
import { useContext, useEffect, useState } from 'preact/hooks'
import { core } from './core/client'
import { short } from './lib/chain'
import { DB_NAME, type DeviceRecord, KEYS, getDevice, openDb } from './lib/db'
import type { Env } from './lib/flows'
import { resumeWc } from './lib/wc-state'
import { Create, EarlierKeys, Install, Pair, Welcome } from './screens/onboarding'
import { Devices, Home, Join, Revoke, Settings } from './screens/member'
import { DappBar, DappsScreen } from './screens/dapps'
import { SafeScreen, Send, TxScreen } from './screens/safe'
import { Screen } from './ui'

export interface AppState {
  env: Env
  device: DeviceRecord | null
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

function route(): string {
  return decodeURIComponent(location.hash.replace(/^#/, '')) || '/'
}

export function App() {
  const [env, setEnv] = useState<Env | null>(null)
  const [device, setDevice] = useState<DeviceRecord | null | undefined>(undefined)
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
        const d = (await getDevice(db)) ?? null
        setDevice(d)
        // a dapp session from before: reconnect, so its requests reach the app
        if (d?.keys === KEYS) resumeWc(e).catch(() => {})
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
    reload: async () => setDevice((await getDevice(env.db)) ?? null),
  }
  // a device from a build before ERC-8499: this build can't use its keys
  if (device && device.keys !== KEYS)
    return (
      <AppContext.Provider value={state}>
        <EarlierKeys device={device} />
      </AppContext.Provider>
    )
  return (
    <AppContext.Provider value={state}>
      {device && <DappBar />}
      {page(path, device)}
    </AppContext.Provider>
  )
}

function page(path: string, device: DeviceRecord | null) {
  const p = path.split('/').filter(Boolean)
  if (p[0] === 'install') return <Install />
  if (!device) {
    if (p[0] === 'create') return <Create />
    if (p[0] === 'pair') return <Pair />
    if (p[0] === 'settings') return <Settings />
    return <Welcome />
  }
  if (p[0] === 'join') return <Join />
  if (p[0] === 'devices') return <Devices />
  if (p[0] === 'revoke' && p[1]) return <Revoke target={Number(p[1])} />
  if (p[0] === 'settings') return <Settings />
  if (p[0] === 'safe' && p[1] && p[2]) {
    const chain = Number(p[1])
    const safe = p[2] as `0x${string}`
    if (p[3] === 'tx' && p[4]) return <TxScreen chain={chain} safe={safe} hash={p[4] as `0x${string}`} />
    if (p[3] === 'send') return <Send chain={chain} safe={safe} />
    if (p[3] === 'dapps') return <DappsScreen chain={chain} safe={safe} />
    return <SafeScreen chain={chain} safe={safe} />
  }
  return <Home />
}
