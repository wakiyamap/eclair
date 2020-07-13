/*
 * Copyright 2019 ACINQ SAS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fr.acinq.eclair.transactions

import fr.acinq.bitcoin.Crypto.ripemd160
import fr.acinq.bitcoin.SigHash.SIGHASH_ALL
import fr.acinq.bitcoin.{ByteVector => ByteVectorAcinq, _}
import fr.acinq.eclair.transactions.Scripts._
import org.scalatest.funsuite.AnyFunSuite

import scala.jdk.CollectionConverters._
import fr.acinq.eclair.KotlinUtils._

class ClaimSentHtlcSpec extends AnyFunSuite {
  implicit def bytearray2bytevector32(input: Array[Byte]): ByteVector32 = new ByteVector32(input)

  object Alice {
    val (commitKey, true) = pair2tuple(PrivateKey.fromBase58("cVuzKWCszfvjkoJyUasvsrRdECriz8hSd1BDinRNzytwnXmX7m1g", Base58.Prefix.SecretKeyTestnet))
    val (finalKey, true) = pair2tuple(PrivateKey.fromBase58("cRUfvpbRtMSqCFD1ADdvgPn5HfRLYuHCFYAr2noWnaRDNger2AoA", Base58.Prefix.SecretKeyTestnet))
    val commitPubKey = commitKey.publicKey
    val finalPubKey = finalKey.publicKey
    val R = Crypto.sha256("this is Alice's R".getBytes("UTF-8"))
    val Rhash: ByteVector32 = Crypto.sha256(R)
    val H = Crypto.hash160(Rhash)
    val revokeCommit = Crypto.sha256("Alice revocation R".getBytes("UTF-8"))
    val revokeCommitRHash = Crypto.sha256(revokeCommit)
    val revokeCommitH = Crypto.sha256(revokeCommit)
  }

  object Bob {
    val (commitKey, true) = pair2tuple(PrivateKey.fromBase58("cSupnaiBh6jgTcQf9QANCB5fZtXojxkJQczq5kwfSBeULjNd5Ypo", Base58.Prefix.SecretKeyTestnet))
    val (finalKey, true) = pair2tuple(PrivateKey.fromBase58("cQLk5fMydgVwJjygt9ta8GcUU4GXLumNiXJCQviibs2LE5vyMXey", Base58.Prefix.SecretKeyTestnet))
    val commitPubKey = commitKey.publicKey
    val finalPubKey = finalKey.publicKey
    val R = new ByteVector32(Crypto.sha256("this is Bob's R".getBytes("UTF-8")))
    val Rhash = Crypto.sha256(R)
    val H = Crypto.hash160(Rhash)
    val revokeCommit = Crypto.sha256("Bob revocation R".getBytes("UTF-8"))
    val revokeCommitRHash = Crypto.sha256(revokeCommit)
    val revokeCommitH = Crypto.sha256(revokeCommit)
  }

  def scriptPubKeyHtlcSend(ourkey: PublicKey, theirkey: PublicKey, abstimeout: Long, reltimeout: Long, rhash: ByteVector32, commit_revoke: ByteVectorAcinq): Seq[ScriptElt] = {
    // values lesser than 16 should be encoded using OP_0..OP_16 instead of OP_PUSHDATA
    require(abstimeout > 16, s"abstimeout=$abstimeout must be greater than 16")
    List(
      // @formatter:offOP_SIZE.INSTANCE, encodeNumber(32), OP_EQUALVERIFY.INSTANCE,
    OP_HASH160.INSTANCE, OP_DUP.INSTANCE,
    new OP_PUSHDATA(ripemd160(rhash)), OP_EQUAL.INSTANCE,
    OP_SWAP.INSTANCE, new OP_PUSHDATA(ripemd160(commit_revoke)), OP_EQUAL.INSTANCE, OP_ADD.INSTANCE,
    OP_IF.INSTANCE,
      new OP_PUSHDATA(theirkey),
    OP_ELSE.INSTANCE,
      encodeNumber(abstimeout), OP_CHECKLOCKTIMEVERIFY.INSTANCE, encodeNumber(reltimeout), OP_CHECKSEQUENCEVERIFY.INSTANCE, OP_2DROP.INSTANCE, new OP_PUSHDATA(ourkey),
    OP_ENDIF.INSTANCE,
    OP_CHECKSIG.INSTANCE
    // @formatter:on
    )
  }

  val abstimeout = 3000
  val reltimeout = 2000
  val htlcScript = scriptPubKeyHtlcSend(Alice.finalPubKey, Bob.finalPubKey, abstimeout, reltimeout, Alice.revokeCommitRHash, Alice.Rhash)
  val redeemScript = Script.write(htlcScript)

  // this tx sends money to our HTLC
  val tx = new Transaction(
    2,
    new TxIn(new OutPoint(ByteVector32.Zeroes, 0), 0xffffffffL) :: Nil,
    new TxOut(10 sat, Script.pay2wsh(htlcScript)) :: Nil,
    0)

  // this tx tries to spend the previous tx
  val tx1 = new Transaction(
    2,
    new TxIn(new OutPoint(tx, 0), 0xffffffff) :: Nil,
    new TxOut(10 sat, OP_DUP.INSTANCE :: OP_HASH160.INSTANCE :: new OP_PUSHDATA(Alice.finalPubKey.hash160) :: OP_EQUALVERIFY.INSTANCE :: OP_CHECKSIG.INSTANCE :: Nil) :: Nil,
    0)

  test("Alice can spend this HTLC after a delay") {
    val tx2 = new Transaction(
      2,
      new TxIn(new OutPoint(tx, 0), reltimeout + 1) :: Nil,
      new TxOut(10 sat, OP_DUP.INSTANCE :: OP_HASH160.INSTANCE :: new OP_PUSHDATA(Alice.finalPubKey.hash160) :: OP_EQUALVERIFY.INSTANCE :: OP_CHECKSIG.INSTANCE :: Nil) :: Nil,
      abstimeout + 1)

    val sig = Transaction.signInput(tx2, 0, redeemScript, SIGHASH_ALL, tx.txOut(0).amount, 1, Alice.finalKey)
    val witness = new ScriptWitness().push(sig).push(ByteVector32.Zeroes).push(redeemScript)
    val tx3 = tx2.updateWitness(0, witness)

    Transaction.correctlySpends(tx3, Seq(tx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
  }

  test("Alice cannot spend this HTLC before its absolute timeout") {
    val tx2 = new Transaction(
      2,
      new TxIn(new OutPoint(tx, 0), reltimeout + 1) :: Nil,
       new TxOut(10 sat, OP_DUP.INSTANCE :: OP_HASH160.INSTANCE :: new OP_PUSHDATA(Alice.finalPubKey.hash160) :: OP_EQUALVERIFY.INSTANCE :: OP_CHECKSIG.INSTANCE :: Nil) :: Nil,
      abstimeout - 1)

    val sig = Transaction.signInput(tx2, 0, redeemScript, SIGHASH_ALL, tx.txOut(0).amount, 1, Alice.finalKey)
    val witness = new ScriptWitness().push(sig).push(ByteVector32.Zeroes).push(redeemScript)
    val tx3 = tx2.updateWitness(0, witness)

    val e = intercept[RuntimeException] {
      Transaction.correctlySpends(tx3, Seq(tx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    }
    assert(e.getMessage === "unsatisfied CLTV lock time")
  }

  test("Alice cannot spend this HTLC before its relative timeout") {
    val tx2 = new Transaction(
      2,
      new TxIn(new OutPoint(tx, 0), reltimeout - 1) :: Nil,
      new TxOut(10 sat, OP_DUP.INSTANCE :: OP_HASH160.INSTANCE :: new OP_PUSHDATA(Alice.finalPubKey.hash160) :: OP_EQUALVERIFY.INSTANCE :: OP_CHECKSIG.INSTANCE :: Nil) :: Nil,
      abstimeout + 1)

    val sig = Transaction.signInput(tx2, 0, redeemScript, SIGHASH_ALL, tx.txOut(0).amount, 1, Alice.finalKey)
    val witness = new ScriptWitness().push(sig).push(ByteVector32.Zeroes).push(redeemScript)
    val tx3 = tx2.updateWitness(0, witness)

    val e = intercept[RuntimeException] {
      Transaction.correctlySpends(tx3, Seq(tx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    }
    assert(e.getMessage === "unsatisfied CSV lock time")
  }

  test("Bob can spend this HTLC if he knows the payment hash") {
    val sig = Transaction.signInput(tx1, 0, redeemScript, SIGHASH_ALL, tx.txOut(0).amount, 1, Bob.finalKey)
    val witness = new ScriptWitness().push(sig).push(Alice.R).push(redeemScript)
    val tx2 = tx1.updateWitness(0, witness)
    Transaction.correctlySpends(tx2, Seq(tx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
  }

  test("Bob can spend this HTLC if he knows the revocation hash") {
    val sig = Transaction.signInput(tx1, 0, redeemScript, SIGHASH_ALL, tx.txOut(0).amount, 1, Bob.finalKey)
    val witness = new ScriptWitness().push(sig).push(Alice.revokeCommit).push(redeemScript)
    val tx2 = tx1.updateWitness(0, witness)
    Transaction.correctlySpends(tx2, Seq(tx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
  }
}
