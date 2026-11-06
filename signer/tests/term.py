"""A scripted member at the terminal, for the commands that ask (cli_recovery.ask): it reads the recovery phrase the
signer printed and answers the backup check, passphrase prompts and questions."""
import contextlib
import io
import re
from unittest import mock

from winterlock_signer import cli, cli_recovery, phrase, seedfile

PASSPHRASE = "test passphrase, not a real one"
FAST_SCRYPT = 1 << 12  # the tests' scrypt cost; the signer's own is 2^18


class Screen(io.StringIO):
    """The signer's stdout: a terminal (isatty) or not, keeping everything written to it. visible() is what's still
    on the screen: the output since the last clear (cli_recovery.CLEAR also clears the scrollback)."""

    def __init__(self, tty=False):
        super().__init__()
        self.tty = tty

    def isatty(self):
        return self.tty

    def visible(self):
        text = self.getvalue()
        i = text.rfind(cli_recovery.CLEAR)
        return text if i < 0 else text[i + len(cli_recovery.CLEAR):]


class Terminal:
    def __init__(self, passphrase=PASSPHRASE, phrase=None, situation=None, wrong_rounds=0, confirm="y", words=None,
                 tty=False, show_again="n"):
        self.passphrases = list(passphrase) if isinstance(passphrase, (list, tuple)) else [passphrase]
        self.words = words  # the phrase for a backup check, when the command doesn't print it
        self.phrase_text = phrase  # what to type at a "Recovery phrase" prompt
        self.situation = situation  # "1", "2" or "3"
        self.wrong_rounds = wrong_rounds  # answer this many backup-check rounds wrongly first
        self.word_prompts = 0
        self.confirm = confirm
        self.tty = tty  # stdout is a terminal
        self.show_again = show_again  # the answer to "Show the phrase again?"
        self.prompts = []
        self.on_screen = []  # what was visible at each prompt, as (prompt, text)
        self.buf = Screen(tty)

    def shown_phrase(self):
        """The phrase as the member wrote it down when it was shown"""
        if self.words:
            return self.words
        words = dict((int(n), w) for n, w in re.findall(r"(\d+)\. ([a-z]+)", self.buf.getvalue()))
        return [words[i] for i in range(1, 25)]

    def __call__(self, prompt, secret=False):
        self.prompts.append(prompt)
        self.on_screen.append((prompt, self.buf.visible()))
        if m := re.search(r"word #(\d+)", prompt):
            rnd, self.word_prompts = self.word_prompts // phrase.CHECK_WORDS, self.word_prompts + 1
            return "notaword" if rnd < self.wrong_rounds else self.shown_phrase()[int(m[1]) - 1]
        if "press Enter to hide them" in prompt:
            return ""
        if "Show the phrase again" in prompt:
            return self.show_again
        if "Recovery phrase" in prompt:
            return self.phrase_text
        if "Choose 1, 2 or 3" in prompt:
            return self.situation
        if "passphrase" in prompt.lower() or "Passphrase" in prompt:
            return self.passphrases.pop(0) if len(self.passphrases) > 1 else self.passphrases[0]
        if "[y/N]" in prompt:
            return self.confirm
        raise AssertionError(f"unexpected prompt: {prompt!r}")


def run(argv, term=None):
    """(exit code, output) of the signer's command line with `term` at the keyboard"""
    term = term or Terminal()
    term.buf = Screen(term.tty)
    with contextlib.redirect_stdout(term.buf), mock.patch.object(cli_recovery, "ask", term), \
            mock.patch.object(seedfile, "SCRYPT_N", FAST_SCRYPT):
        code = cli.main(argv)
    return code, term.buf.getvalue()
