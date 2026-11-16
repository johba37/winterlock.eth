// The quantum exposure check for Safe accounts: who can sign for a Safe, and how its owners would
// stand against an attacker able to derive private keys from public keys. No DOM, no framework:
// chain reads through viem, Safe's Transaction Service through fetch, both injectable.

export { CHAINS, type Chain, type Token, chainById, chainByShortName } from './chains'
export { parseSafeInput, routeFor, type Parsed } from './input'
export { PASSKEY_FACTORIES, PASSKEY_SHARED_SIGNER, PROXY_CODE_HASHES, SINGLETONS, nameOf, officialSingleton } from './known'
export { EXPOSING_TYPES, allLimits, changesFor, classify, exposingCount, nestedClass, verdictOf, type VerdictInput } from './model'
export { CheckError, type CheckErrorCode, type CheckOptions, checkSafe } from './read'
export { SafeService, type ServiceOptions, type ServiceRead } from './service'
export * from './types'
export { WINTERLOCK_FACTORY, WINTERLOCK_IMPLEMENTATION, WINTERLOCK_VERSIONS, type WinterlockVersion, memberKeyOf, ownerAddress, winterlockOwnerOf } from './winterlock'
export * as explain from './explain'
