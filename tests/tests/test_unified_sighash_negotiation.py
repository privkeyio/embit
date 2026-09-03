"""Hash type negotiation around the unified opt-in digest.

The digest itself is covered by the cross-implementation vectors in
test_unified_sighash.py. Every defect found in this feature so far has been in the
code around it: which type is asked for, which is signed, which is refused, and what
a streaming reader caches while doing it. Each test here corresponds to one such
defect and fails against the code that had it.
"""
import io
from unittest import TestCase

from embit import script
from embit.bip32 import HDKey
from embit.psbt import PSBT, PSBTError, DerivationPath, InputScope, sighash_types_agree
from embit.psbtview import PSBTView
from embit.transaction import (
    SIGHASH,
    Transaction,
    TransactionError,
    TransactionInput,
    TransactionOutput,
)

ROOT = HDKey.from_string(
    "tprv8ZgxMBicQKsPd9TeAdPADNnSyH9SSUUbTVeFszDE23Ki6TBB5nCefAdHkK8Fm3qMQR6sHwA5"
    "6zqRmKmxnHk37JkiFzvncDqoKmPWubu7hDF"
)
U = SIGHASH.UNIFIED
UNIFIED_ALL = SIGHASH.UNIFIED | SIGHASH.ALL


def _wallet(kind):
    if kind == "taproot":
        pub = ROOT.derive("m/86h/1h/0h/0/0").to_public()
        return pub, script.p2tr(pub), 86
    pub = ROOT.derive("m/84h/1h/0h/0/0").to_public()
    return pub, script.p2wpkh(pub), 84


def build(declared, nout=1, kind="segwit", values=None):
    """A PSBT this root can sign, one input per declared hash type."""
    pub, spk, purpose = _wallet(kind)
    values = values or [100000 + i for i in range(len(declared))]
    vin = [
        TransactionInput(bytes(30) + i.to_bytes(2, "big"), 0)
        for i in range(len(declared))
    ]
    psbt = PSBT(
        Transaction(vin=vin, vout=[TransactionOutput(50000, spk) for _ in range(nout)])
    )
    for i, sh in enumerate(declared):
        inp = psbt.inputs[i]
        inp.witness_utxo = TransactionOutput(values[i], spk)
        derivation = DerivationPath(
            ROOT.my_fingerprint, [purpose + 2**31, 1 + 2**31, 2**31, 0, 0]
        )
        if kind == "taproot":
            inp.taproot_bip32_derivations[pub.key] = ([], derivation)
        else:
            inp.bip32_derivations[pub.key] = derivation
        inp.sighash_type = sh
    return psbt


def hash_type_bytes(psbt):
    out = []
    for inp in psbt.inputs:
        for sig in inp.partial_sigs.values():
            out.append(bytes(sig)[-1])
        for sig in inp.taproot_sigs.values():
            out.append(bytes(sig)[-1] if len(bytes(sig)) == 65 else SIGHASH.DEFAULT)
    return out


class TestSighashTypesAgree(TestCase):
    """The predicate deciding whether a declared type is the one being asked for.

    Ported from SighashTypesAgree in the reference implementation, with embit's own
    DEFAULT/ALL equivalence preserved for callers who never opt in.
    """

    def test_default_and_all_are_the_same_request(self):
        # embit has always folded these, and narrowing that would change behaviour
        # for callers who never touch the opt-in
        self.assertTrue(sighash_types_agree(SIGHASH.DEFAULT, SIGHASH.ALL))
        self.assertTrue(sighash_types_agree(SIGHASH.ALL, SIGHASH.DEFAULT))

    def test_different_output_types_disagree(self):
        self.assertFalse(sighash_types_agree(SIGHASH.NONE, SIGHASH.ALL))
        self.assertFalse(sighash_types_agree(SIGHASH.ALL, SIGHASH.NONE))
        self.assertFalse(sighash_types_agree(U | SIGHASH.NONE, UNIFIED_ALL))

    def test_the_opt_in_may_be_asked_for_over_a_legacy_declaration(self):
        # what every wallet predating the fork writes
        self.assertTrue(sighash_types_agree(SIGHASH.ALL, UNIFIED_ALL))
        self.assertTrue(sighash_types_agree(UNIFIED_ALL, SIGHASH.ALL))

    def test_a_bare_opt_in_is_not_default_or_all(self):
        """0x20 names no output type. Stripping the bit leaves zero, which is
        SIGHASH_DEFAULT's value but a different type carrying its own message, so it
        must not be folded in. The reference refuses to sign it."""
        self.assertFalse(sighash_types_agree(U, SIGHASH.ALL))
        self.assertFalse(sighash_types_agree(SIGHASH.ALL, U))
        self.assertFalse(sighash_types_agree(U, SIGHASH.DEFAULT))
        self.assertTrue(sighash_types_agree(U, U))

    def test_anyonecanpay_is_part_of_the_comparison(self):
        acp = SIGHASH.ANYONECANPAY
        self.assertTrue(sighash_types_agree(UNIFIED_ALL | acp, UNIFIED_ALL | acp))
        self.assertFalse(sighash_types_agree(UNIFIED_ALL | acp, UNIFIED_ALL))


class TestWhatGetsSigned(TestCase):
    def test_a_bare_opt_in_is_not_signed(self):
        """0x20 produced a signature whose hash type byte no verifier accepts."""
        for requested in (SIGHASH.DEFAULT, SIGHASH.ALL, UNIFIED_ALL):
            psbt = build([U])
            self.assertEqual(psbt.sign_with(ROOT, sighash=requested), 0)

    def test_the_opt_in_signs(self):
        psbt = build([UNIFIED_ALL, UNIFIED_ALL])
        self.assertEqual(psbt.sign_with(ROOT, sighash=UNIFIED_ALL), 2)
        self.assertEqual(hash_type_bytes(psbt), [UNIFIED_ALL, UNIFIED_ALL])

    def test_the_caller_gets_the_type_it_asked_for(self):
        """A PSBT declaring the legacy type, signed by a caller opting in."""
        psbt = build([SIGHASH.ALL])
        self.assertEqual(psbt.sign_with(ROOT, sighash=UNIFIED_ALL), 1)
        self.assertEqual(hash_type_bytes(psbt), [UNIFIED_ALL])

    def test_an_untouched_default_leaves_the_psbt_its_own_type(self):
        psbt = build([UNIFIED_ALL])
        self.assertEqual(psbt.sign_with(ROOT), 1)
        self.assertEqual(hash_type_bytes(psbt), [UNIFIED_ALL])


class TestSighashSingleWithNoOutput(TestCase):
    """SIGHASH_SINGLE commits to the output at the input's index. Where there is
    none the digest cannot be built, so that input is skipped as an unsignable one
    is, rather than discarding the signatures already made for the others."""

    def test_the_other_inputs_are_still_signed(self):
        for kind in ("segwit", "taproot"):
            psbt = build([UNIFIED_ALL, U | SIGHASH.SINGLE], nout=1, kind=kind)
            self.assertEqual(psbt.sign_with(ROOT, sighash=None), 1, kind)

    def test_the_streaming_reader_agrees(self):
        for kind in ("segwit", "taproot"):
            raw = build([UNIFIED_ALL, U | SIGHASH.SINGLE], nout=1, kind=kind).serialize()
            view = PSBTView.view(io.BytesIO(raw), compress=False)
            self.assertEqual(view.sign_with(ROOT, io.BytesIO(), sighash=None), 1, kind)

    def test_an_invalid_hash_type_is_still_an_error(self):
        """Skipping must be a check on this one condition, not a catch: an
        undefined type raises the same exception and must not be swallowed."""
        psbt = build([SIGHASH.ALL, 0x05])
        self.assertRaises(TransactionError, psbt.sign_with, ROOT, sighash=None)


class TestPrevoutIndex(TestCase):
    """The index selecting from the previous transaction comes off the wire."""

    def _psbt_with_bad_index(self, vout):
        pub, spk, _ = _wallet("segwit")
        prev = Transaction(
            vin=[TransactionInput(bytes(32), 0)], vout=[TransactionOutput(100000, spk)]
        )
        psbt = build([UNIFIED_ALL, UNIFIED_ALL])
        psbt.inputs[1].witness_utxo = None
        psbt.inputs[1].non_witness_utxo = prev
        psbt.inputs[1].vout = vout
        return psbt

    def test_an_index_past_the_end_is_reported_not_raised(self):
        psbt = self._psbt_with_bad_index(5)
        self.assertRaises(PSBTError, psbt.sighash, 0, sighash=UNIFIED_ALL)
        self.assertRaises(PSBTError, psbt.sign_with, ROOT, sighash=UNIFIED_ALL)

    def test_a_missing_index_is_reported_not_raised(self):
        psbt = self._psbt_with_bad_index(None)
        self.assertRaises(PSBTError, psbt.sighash, 0, sighash=UNIFIED_ALL)


class TestStreamingReaderCache(TestCase):
    """PSBTView caches the spent outputs it reads, because the unified digest needs
    every one of them and re-reading is quadratic. A cache on a streaming reader is
    where a stale or borrowed value silently produces a wrong digest."""

    def test_a_caller_supplied_utxo_does_not_leak_into_siblings(self):
        """Signing one input with a utxo supplied out of band must not hand that
        value to any other input as its sibling amount."""
        psbt = build([UNIFIED_ALL, UNIFIED_ALL], values=[100000, 200000])
        raw = psbt.serialize()
        supplied = InputScope()
        pub, spk, _ = _wallet("segwit")
        supplied.witness_utxo = TransactionOutput(999999, spk)

        view = PSBTView.view(io.BytesIO(raw), compress=False)
        view.sign_input(0, ROOT, io.BytesIO(), sighash=UNIFIED_ALL, extra_scope_data=supplied)

        self.assertEqual(view.sighash(1, sighash=UNIFIED_ALL),
                         psbt.sighash(1, sighash=UNIFIED_ALL))

    def test_a_reused_view_still_honours_a_supplied_utxo(self):
        """The digest memo was keyed on nothing, so the first call's answer came
        back for every later one."""
        psbt = build([UNIFIED_ALL, UNIFIED_ALL], values=[100000, 200000])
        raw = psbt.serialize()
        pub, spk, _ = _wallet("segwit")

        view = PSBTView.view(io.BytesIO(raw), compress=False)
        view.sighash(0, sighash=UNIFIED_ALL)
        scope = view.input(1)
        scope.witness_utxo = TransactionOutput(777777, spk)
        reused = view.sighash(1, sighash=UNIFIED_ALL, input_scope=scope)

        fresh = PSBTView.view(io.BytesIO(raw), compress=False).sighash(
            1, sighash=UNIFIED_ALL, input_scope=scope
        )
        self.assertEqual(reused, fresh)
        self.assertEqual(reused, build([UNIFIED_ALL, UNIFIED_ALL],
                                       values=[100000, 777777]).sighash(1, sighash=UNIFIED_ALL))

    def test_signing_works_when_the_utxo_is_supplied_out_of_band(self):
        """PSBTView exists for signers that know more than the PSBT carries."""
        pub, spk, _ = _wallet("segwit")
        psbt = build([UNIFIED_ALL])
        psbt.inputs[0].witness_utxo = None
        raw = psbt.serialize()
        supplied = InputScope()
        supplied.witness_utxo = TransactionOutput(100000, spk)

        view = PSBTView.view(io.BytesIO(raw), compress=False)
        self.assertEqual(
            view.sign_input(0, ROOT, io.BytesIO(), sighash=UNIFIED_ALL,
                            extra_scope_data=supplied),
            1,
        )

    def test_caching_does_not_change_any_digest(self):
        """Signing several inputs on one view must equal a fresh view per input."""
        for kind in ("segwit", "taproot"):
            for declared in (UNIFIED_ALL, U | SIGHASH.NONE, UNIFIED_ALL | SIGHASH.ANYONECANPAY):
                psbt = build([declared] * 3, nout=3, kind=kind)
                raw = psbt.serialize()
                shared = PSBTView.view(io.BytesIO(raw), compress=False)
                for i in range(3):
                    fresh = PSBTView.view(io.BytesIO(raw), compress=False)
                    self.assertEqual(
                        shared.sighash(i, sighash=declared),
                        fresh.sighash(i, sighash=declared),
                        f"{kind} 0x{declared:02x} input {i}",
                    )


class TestClassesAgree(TestCase):
    """PSBT and PSBTView must produce the same digest. A defect in one and not the
    other is how a signer and its verifier come to disagree."""

    def test_digests_match_across_hash_types_and_shapes(self):
        types = [
            UNIFIED_ALL,
            U | SIGHASH.NONE,
            U | SIGHASH.SINGLE,
            UNIFIED_ALL | SIGHASH.ANYONECANPAY,
            SIGHASH.ALL,
        ]
        for kind in ("segwit", "taproot"):
            for n in (1, 2, 3):
                for nout in (1, 3):
                    for declared in types:
                        psbt = build([declared] * n, nout=nout, kind=kind)
                        raw = psbt.serialize()
                        for i in range(n):
                            view = PSBTView.view(io.BytesIO(raw), compress=False)
                            try:
                                expected = psbt.sighash(i, sighash=declared)
                            except (PSBTError, TransactionError) as e:
                                self.assertRaises(
                                    type(e), view.sighash, i, sighash=declared
                                )
                                continue
                            self.assertEqual(
                                expected,
                                view.sighash(i, sighash=declared),
                                f"{kind} n={n} nout={nout} 0x{declared:02x} input {i}",
                            )
