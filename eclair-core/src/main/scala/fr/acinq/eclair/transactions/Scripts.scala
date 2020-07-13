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

import fr.acinq.bitcoin
import fr.acinq.bitcoin.Script._
import fr.acinq.bitcoin.{ByteVector32, ByteVector64, Crypto, LexicographicalOrdering, OP_0, OP_1, OP_1NEGATE, OP_2, OP_CHECKLOCKTIMEVERIFY, OP_CHECKMULTISIG, OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_DROP, OP_DUP, OP_ELSE, OP_ENDIF, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160, OP_IF, OP_NOTIF, OP_PUSHDATA, OP_SIZE, OP_SWAP, PublicKey, Satoshi, Script, ScriptElt, ScriptEltMapping, ScriptWitness, Transaction, TxIn, ByteVector => ByteVectorAcinq}
import fr.acinq.eclair.{CltvExpiry, CltvExpiryDelta, KotlinUtils, LongToBtcAmount}

import scala.collection.JavaConverters._
import KotlinUtils._

/**
 * Created by PM on 02/12/2016.
 */
object Scripts {
  def der(sig: ByteVector64): ByteVectorAcinq = Crypto.compact2der(sig).concat(1.toByte)

  def multiSig2of2(pubkey1: PublicKey, pubkey2: PublicKey): Seq[ScriptElt] =
    if (LexicographicalOrdering.isLessThan(pubkey1, pubkey2)) {
      Script.createMultiSigMofN(2, Seq(pubkey1, pubkey2))
    } else {
      Script.createMultiSigMofN(2, Seq(pubkey2, pubkey1))
    }

  /**
   * @return a script witness that matches the msig 2-of-2 pubkey script for pubkey1 and pubkey2
   */
  def witness2of2(sig1: ByteVector64, sig2: ByteVector64, pubkey1: PublicKey, pubkey2: PublicKey): ScriptWitness =
    if (LexicographicalOrdering.isLessThan(pubkey1, pubkey2)) {
      new ScriptWitness(List(ByteVectorAcinq.empty, der(sig1), der(sig2), new ByteVectorAcinq(write(multiSig2of2(pubkey1, pubkey2)))).asJava)
    } else {
      new ScriptWitness(List(ByteVectorAcinq.empty, der(sig2), der(sig1), new ByteVectorAcinq(write(multiSig2of2(pubkey1, pubkey2)))).asJava)
    }


  /**
   * minimal encoding of a number into a script element:
   * - OP_0 to OP_16 if 0 <= n <= 16
   * - OP_PUSHDATA(encodeNumber(n)) otherwise
   *
   * @param n input number
   * @return a script element that represents n
   */
  def encodeNumber(n: Long): ScriptElt = n match {
    case 0 => OP_0.INSTANCE
    case -1 => OP_1NEGATE.INSTANCE
    case x if x >= 1 && x <= 16 => ScriptEltMapping.code2elt.asScala((ScriptEltMapping.elt2code.asScala(OP_1.INSTANCE) + x - 1).toInt)
    case _ => new OP_PUSHDATA(Script.encodeNumber(n))
  }

  def applyFees(amount_us: Satoshi, amount_them: Satoshi, fee: Satoshi) = {
    val (amount_us1: Satoshi, amount_them1: Satoshi) = (amount_us, amount_them) match {
      case (us, them) if us >= fee / 2 && them >= fee / 2 => ((us minus fee) div 2, (them minus fee) div 2)
      case (us, them) if us < fee / 2 => (0 sat, (them minus fee plus us).max(0 sat))
      case (us, them) if them < fee / 2 => ((us minus fee plus them).max(0 sat), 0 sat)
    }
    (amount_us1, amount_them1)
  }

  /**
   * This function interprets the locktime for the given transaction, and returns the block height before which this tx cannot be published.
   * By convention in bitcoin, depending of the value of locktime it might be a number of blocks or a number of seconds since epoch.
   * This function does not support the case when the locktime is a number of seconds that is not way in the past.
   * NB: We use this property in lightning to store data in this field.
   *
   * @return the block height before which this tx cannot be published.
   */
  def cltvTimeout(tx: Transaction): Long =
    if (tx.lockTime <= LockTimeThreshold) {
      // locktime is a number of blocks
      tx.lockTime
    }
    else {
      // locktime is a unix epoch timestamp
      require(tx.lockTime <= 0x20FFFFFF, "locktime should be lesser than 0x20FFFFFF")
      // since locktime is very well in the past (0x20FFFFFF is in 1987), it is equivalent to no locktime at all
      0
    }

  /**
   * @return the number of confirmations of the tx parent before which it can be published
   */
  def csvTimeout(tx: Transaction): Long = {
    def sequenceToBlockHeight(sequence: Long): Long = {
      if ((sequence & TxIn.SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0) 0
      else {
        require((sequence & TxIn.SEQUENCE_LOCKTIME_TYPE_FLAG) == 0, "CSV timeout must use block heights, not block times")
        sequence & TxIn.SEQUENCE_LOCKTIME_MASK
      }
    }

    if (tx.version < 2) 0
    else tx.txIn.map(_.sequence).map(sequenceToBlockHeight).max
  }

  def toLocalDelayed(revocationPubkey: PublicKey, toSelfDelay: CltvExpiryDelta, localDelayedPaymentPubkey: PublicKey) = {
    List(
      // @formatter:off
    OP_IF.INSTANCE,
      new OP_PUSHDATA(revocationPubkey),
    OP_ELSE.INSTANCE,
      encodeNumber(toSelfDelay.toInt), OP_CHECKSEQUENCEVERIFY.INSTANCE, OP_DROP.INSTANCE,
      new OP_PUSHDATA(localDelayedPaymentPubkey),
    OP_ENDIF.INSTANCE,
    OP_CHECKSIG.INSTANCE
    // @formatter:on
    )
  }

  /**
   * This witness script spends a [[toLocalDelayed]] output using a local sig after a delay
   */
  def witnessToLocalDelayedAfterDelay(localSig: ByteVector64, toLocalDelayedScript: ByteVectorAcinq): ScriptWitness =
    new ScriptWitness((der(localSig) :: fr.acinq.bitcoin.ByteVector.empty :: toLocalDelayedScript :: Nil).asJava)

  def witnessToLocalDelayedAfterDelay(localSig: ByteVector64, toLocalDelayedScript: Array[Byte]): ScriptWitness =
    witnessToLocalDelayedAfterDelay(localSig, new ByteVectorAcinq(toLocalDelayedScript))

  /**
   * This witness script spends (steals) a [[toLocalDelayed]] output using a revocation key as a punishment
   * for having published a revoked transaction
   */
  def witnessToLocalDelayedWithRevocationSig(revocationSig: ByteVector64, toLocalScript: ByteVectorAcinq): ScriptWitness =
    new ScriptWitness((der(revocationSig) :: new fr.acinq.bitcoin.ByteVector("01") :: toLocalScript :: Nil).asJava)

  def witnessToLocalDelayedWithRevocationSig(revocationSig: ByteVector64, toLocalScript: Array[Byte]): ScriptWitness = witnessToLocalDelayedWithRevocationSig(revocationSig, new ByteVectorAcinq(toLocalScript))

  def htlcOffered(localHtlcPubkey: PublicKey, remoteHtlcPubkey: PublicKey, revocationPubKey: PublicKey, paymentHash: Array[Byte]): Seq[ScriptElt] = {
    List(
      // @formatter:off
    // To you with revocation key
      OP_DUP.INSTANCE, OP_HASH160.INSTANCE, new OP_PUSHDATA(revocationPubKey.hash160), OP_EQUAL.INSTANCE,
      OP_IF.INSTANCE,
        OP_CHECKSIG.INSTANCE,
      OP_ELSE.INSTANCE,
        new OP_PUSHDATA(remoteHtlcPubkey), OP_SWAP.INSTANCE, OP_SIZE.INSTANCE, encodeNumber(32),  OP_EQUAL.INSTANCE,
        OP_NOTIF.INSTANCE,
          // To me via HTLC-timeout transaction (timelocked).
          OP_DROP.INSTANCE, OP_2.INSTANCE, OP_SWAP.INSTANCE, new OP_PUSHDATA(localHtlcPubkey), OP_2.INSTANCE, OP_CHECKMULTISIG.INSTANCE,
        OP_ELSE.INSTANCE,
          OP_HASH160.INSTANCE, new OP_PUSHDATA(paymentHash),  OP_EQUALVERIFY.INSTANCE,
          OP_CHECKSIG.INSTANCE,
        OP_ENDIF.INSTANCE,
      OP_ENDIF.INSTANCE
    // @formatter:on
    )
  }

  /**
   * This is the witness script of the 2nd-stage HTLC Success transaction (consumes htlcOffered script from commit tx)
   */
  def witnessHtlcSuccess(localSig: ByteVector64, remoteSig: ByteVector64, paymentPreimage: ByteVector32, htlcOfferedScript: ByteVectorAcinq): ScriptWitness =
    new ScriptWitness((fr.acinq.bitcoin.ByteVector.empty :: der(remoteSig) :: der(localSig) :: paymentPreimage :: htlcOfferedScript :: Nil).asJava)

  def witnessHtlcSuccess(localSig: ByteVector64, remoteSig: ByteVector64, paymentPreimage: ByteVector32, htlcOfferedScript: Array[Byte]): ScriptWitness =
    witnessHtlcSuccess(localSig, remoteSig, paymentPreimage,  new ByteVectorAcinq(htlcOfferedScript))

  /** Extract the payment preimage from a 2nd-stage HTLC Success transaction's witness script */
  def extractPreimageFromHtlcSuccess: PartialFunction[ScriptWitness, ByteVector32] = {
    case witness: ScriptWitness if witness.stack.size() == 5 && witness.stack.get(0).isEmpty && witness.stack.get(3).size() == 32 => new ByteVector32(witness.stack.get(3).toByteArray)
  }

  /**
   * If remote publishes its commit tx where there was a remote->local htlc, then local uses this script to
   * claim its funds using a payment preimage (consumes htlcOffered script from commit tx)
   */
  def witnessClaimHtlcSuccessFromCommitTx(localSig: ByteVector64, paymentPreimage: ByteVector32, htlcOffered: ByteVectorAcinq): ScriptWitness =
    new ScriptWitness((der(localSig) :: paymentPreimage :: htlcOffered :: Nil).asJava)

  def witnessClaimHtlcSuccessFromCommitTx(localSig: ByteVector64, paymentPreimage: ByteVector32, htlcOffered: Array[Byte]): ScriptWitness =
    witnessClaimHtlcSuccessFromCommitTx(localSig, paymentPreimage, new ByteVectorAcinq(htlcOffered))

  /** Extract the payment preimage from from a fulfilled offered htlc. */
  def extractPreimageFromClaimHtlcSuccess: PartialFunction[ScriptWitness, ByteVector32] = {
    case witness: ScriptWitness if witness.stack.size() == 3 && witness.stack.get(1).size() == 32 => new ByteVector32(witness.stack.get(1))
  }

  def htlcReceived(localHtlcPubkey: PublicKey, remoteHtlcPubkey: PublicKey, revocationPubKey: PublicKey, paymentHash: Array[Byte], lockTime: CltvExpiry): List[ScriptElt] = {
    List(
      // @formatter:off
      OP_DUP.INSTANCE, OP_HASH160.INSTANCE, (new OP_PUSHDATA(revocationPubKey.hash160)), OP_EQUAL.INSTANCE,
      OP_IF.INSTANCE,
        OP_CHECKSIG.INSTANCE,
      OP_ELSE.INSTANCE,
        (new OP_PUSHDATA(remoteHtlcPubkey)), OP_SWAP.INSTANCE, OP_SIZE.INSTANCE, encodeNumber(32), OP_EQUAL.INSTANCE,
        OP_IF.INSTANCE,
        // To me via HTLC-success transaction.
          OP_HASH160.INSTANCE, (new OP_PUSHDATA(paymentHash)), OP_EQUALVERIFY.INSTANCE,
          OP_2.INSTANCE, OP_SWAP.INSTANCE, (new OP_PUSHDATA(localHtlcPubkey)), OP_2.INSTANCE, OP_CHECKMULTISIG.INSTANCE,
        OP_ELSE.INSTANCE,
        // To you after timeout.
          OP_DROP.INSTANCE, encodeNumber(lockTime.toLong), OP_CHECKLOCKTIMEVERIFY.INSTANCE, OP_DROP.INSTANCE,
          OP_CHECKSIG.INSTANCE,
        OP_ENDIF.INSTANCE,
      OP_ENDIF.INSTANCE
    // @formatter:on
    )
  }

  /**
   * This is the witness script of the 2nd-stage HTLC Timeout transaction (consumes htlcOffered script from commit tx)
   */
  def witnessHtlcTimeout(localSig: ByteVector64, remoteSig: ByteVector64, htlcOfferedScript: ByteVectorAcinq): ScriptWitness =
    new ScriptWitness((ByteVectorAcinq.empty :: der(remoteSig) :: der(localSig) :: ByteVectorAcinq.empty :: htlcOfferedScript :: Nil).asJava)

  def witnessHtlcTimeout(localSig: ByteVector64, remoteSig: ByteVector64, htlcOfferedScript: Array[Byte]): ScriptWitness =
    witnessHtlcTimeout(localSig, remoteSig, new ByteVectorAcinq(htlcOfferedScript))

  /** Extract the payment hash from a 2nd-stage HTLC Timeout transaction's witness script */
  def extractPaymentHashFromHtlcTimeout: PartialFunction[ScriptWitness, ByteVectorAcinq] = {
    case witness: ScriptWitness if witness.stack.size() == 5 && witness.stack.get(0).isEmpty && witness.stack.get(3).isEmpty =>
      witness.stack.get(4).slice(109, 109 + 20)
  }

  /**
   * If remote publishes its commit tx where there was a local->remote htlc, then local uses this script to
   * claim its funds after timeout (consumes htlcReceived script from commit tx)
   */
  def witnessClaimHtlcTimeoutFromCommitTx(localSig: ByteVector64, htlcReceivedScript: ByteVectorAcinq): ScriptWitness =
    new ScriptWitness((der(localSig) :: fr.acinq.bitcoin.ByteVector.empty :: htlcReceivedScript :: Nil).asJava)

  def witnessClaimHtlcTimeoutFromCommitTx(localSig: ByteVector64, htlcReceivedScript: Array[Byte]): ScriptWitness =
    witnessClaimHtlcTimeoutFromCommitTx(localSig, new ByteVectorAcinq(htlcReceivedScript))

  /** Extract the payment hash from a timed-out received htlc. */
  def extractPaymentHashFromClaimHtlcTimeout: PartialFunction[ScriptWitness, ByteVectorAcinq] = {
    case witness: ScriptWitness if witness.stack.get(1).isEmpty =>
      witness.stack.get(2).slice(69, 69 + 20)
  }

  /**
   * This witness script spends (steals) a [[htlcOffered]] or [[htlcReceived]] output using a revocation key as a punishment
   * for having published a revoked transaction
   */

  def witnessHtlcWithRevocationSig(revocationSig: ByteVector64, revocationPubkey: PublicKey, htlcScript: ByteVectorAcinq): ScriptWitness =
    new ScriptWitness((der(revocationSig) :: revocationPubkey.value :: htlcScript :: Nil).asJava)

  def witnessHtlcWithRevocationSig(revocationSig: ByteVector64, revocationPubkey: PublicKey, htlcScript: Array[Byte]): ScriptWitness =
    witnessHtlcWithRevocationSig(revocationSig, revocationPubkey, new ByteVectorAcinq(htlcScript))

}