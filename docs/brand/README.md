# Winterlock's look: Permanent Way

The idea: a hash sign is a stretch of track. Two rails, two sleepers leaning in the direction of travel, and one amber segment between the rails, the point a signature reveals. A hash chain is a line that only runs forward.

## Files

| File | Use |
|---|---|
| `mark.svg` | The mark, for sizes from 32 px up. It switches to dark colours with the viewer's setting. |
| `favicon.svg` | The simplified cut for 16–32 px, as used in the site's tab icon |
| `lockup.svg` | Mark and stencil wordmark, switching with the viewer's setting |
| `lockup-light.svg`, `lockup-dark.svg` | The same with fixed colours, for places that pick by theme (GitHub's README) |
| `stencil.py` | Draws stencil lettering as SVG: `python3 docs/brand/stencil.py "TURBULENT TIMES"` |

## Rules

- **Amber means one thing:** a point revealed, used once. Don't use it for decoration.
- **Always draw the `#` with its parts:** the stencil breaks, the forward lean and the lamp. Without them it's just a hash sign.
- **Use stencil lettering sparingly:** the wordmark and one-line headlines. It covers A–I, K–O, R–U, W, Y, space and full stop. Everything else is set in Atkinson Hyperlegible Next and Mono, already in `fonts/`.
- **Set numbers like car numbers:** nonces, chain points and key-log entries go in mono, for example `NONCE 007` or `CAR 12`.
- **The industrial details stay small:** a track rule under a kicker, rivets on a panel. Reading text sits on a plain background.

## Colours

| Token | Light | Dark | Role |
|---|---|---|---|
| `--bg` | `#E3E5E4` | `#111315` | background |
| `--surface` | `#F0F1EF` | `#1B1E21` | panels |
| `--frost` | `#B4BAB9` | `#34383C` | rules, rivets |
| `--ink` | `#131517` | `#EFEAE0` | text (14.5:1, 15.5:1) |
| `--slate` | `#4E5458` | `#A6A196` | secondary text (6.1:1, 7.2:1) |
| `--glacier` | `#19566E` | `#86C0D4` | links (6.4:1, 9.3:1) |
| `--lamp-ink` | `#864C00` | `#F2A73C` | amber text (5.4:1, 9.2:1) |
| `--lamp` | `#B36F05` | `#F2A73C` | amber fill, graphics only (3.2:1, 9.2:1) |
| `--breach` | `#A62C1B` | `#FF8266` | warnings (5.5:1, 7.7:1) |

Contrast is against the background. All of the marks and lettering are original, drawn from rectangles and polygons.
