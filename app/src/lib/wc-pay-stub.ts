// Stands in for @walletconnect/pay in the app's build (vite.config.ts's alias). WalletKit creates a
// payments client when that package says it can run; the client talks to api.pay.walletconnect.com
// and carries its own WebAssembly. The app makes no payments, so this says it can't run.

export class WalletConnectPay {
  static isAvailable(): boolean {
    return false
  }
}

export default WalletConnectPay
