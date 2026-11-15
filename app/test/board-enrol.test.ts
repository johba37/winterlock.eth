// An enrolment that would only push the start nonce on is refused. The owner contract takes a new
// key tree only from a later start than the enrolled one's, and the board only from a later one
// than its own last tree's for the Safe: the first wired board (2026-11-15) enrolled a second tree
// right after the first, and the board then couldn't sign the Safe's next nonce.

import type { Address, Hex } from 'viem'
import { describe, expect, it } from 'vitest'
import type { BoardTree } from '../src/board/client'
import { needlessEnrolment } from '../src/lib/board-flows'
import type { OnchainTree } from '../src/lib/chain'
import { gapLine } from '../src/screens/board'

const SAFE = '0x00000000000000000000000000000000000000b0' as Address
const A = '0xaaaaaaaaaaaa0000000000000000000000000000000000a1' as Hex
const B = '0xbbbbbbbbbbbb0000000000000000000000000000000000b2' as Hex
const X = '0x5555555555550000000000000000000000000000000000c3' as Hex

const onBoard = (root: Hex, start: number): BoardTree => ({ chain: 11155111, safe: SAFE, start, height: 10, root, used: 0, certified: true })
const enrolled = (root: Hex, start: number): OnchainTree => ({ root, height: 10, start, generation: 0 })
const none: OnchainTree = { root: null, height: 0, start: 0, generation: 0 }

describe('a needless enrolment', () => {
  it('is refused right after the first: the enrolled tree is unused', () => {
    expect(needlessEnrolment(3, enrolled(A, 3), [onBoard(A, 3)])).toMatch(/enrolled \(nonces 3 to 514\).*nothing to enrol/)
  })

  it('is refused while a view behind the chain shows no owner contract: the board knows its tree', () => {
    expect(needlessEnrolment(3, none, [onBoard(A, 3)])).toMatch(/from nonce 3.*doesn’t show it enrolled.*start at nonce 4.*next nonce, 3/)
  })

  it('is refused after the double enrolment, naming the tree that counts', () => {
    expect(needlessEnrolment(3, enrolled(B, 4), [onBoard(A, 3), onBoard(B, 4)])).toMatch(/nonces 4 to 515/)
  })

  it('is allowed once the tree is in use (a fresh tree starts at the Safe’s nonce)', () => {
    expect(needlessEnrolment(420, enrolled(A, 3), [onBoard(A, 3)])).toBeNull()
  })

  it('is allowed for a recovered board, which doesn’t have the enrolled tree', () => {
    expect(needlessEnrolment(3, enrolled(X, 3), [])).toBeNull()
  })

  it('is allowed for the first tree', () => {
    expect(needlessEnrolment(0, none, [])).toBeNull()
  })
})

describe('the panel’s line when the Safe is below the tree', () => {
  it('names the nonce another owner has to execute', () => {
    expect(gapLine(3, { root: B, start: 4 })).toBe(
      'The Safe is at nonce 3, and your key tree starts at nonce 4: the board can’t sign nonce 3. Another owner has to execute a transaction at that nonce first (sending 0 ETH to the Safe itself will do); then the board signs from nonce 4.',
    )
    expect(gapLine(3, { root: B, start: 6 }, 'this device')).toMatch(/this device can’t sign nonces 3 to 5\. .*transactions at those nonces/)
  })

  it('says nothing once the Safe reaches the tree', () => {
    expect(gapLine(4, { root: B, start: 4 })).toBeNull()
    expect(gapLine(3, { root: null, start: 4 })).toBeNull()
  })
})
