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

package fr.acinq.eclair.blockchain

import fr.acinq.bitcoin.{PrivateKey, PublicKey}
import fr.acinq.bitcoin.{Base58, ByteVector32, Crypto, OutPoint, Satoshi, Transaction, TxIn, TxOut}
import fr.acinq.eclair.LongToBtcAmount
import scodec.bits._

import scala.concurrent.Future
import scala.collection.JavaConverters._
import fr.acinq.eclair.KotlinUtils._

/**
 * Created by PM on 06/07/2017.
 */
class TestWallet extends EclairWallet {
  implicit def bytevector2bytevarray(input: ByteVector) : Array[Byte] = input.toArray

  var rolledback = Set.empty[Transaction]

  override def getBalance: Future[OnChainBalance] = Future.successful(OnChainBalance(1105 sat, 561 sat))

  override def getReceiveAddress: Future[String] = Future.successful("bcrt1qwcv8naajwn8fjhu8z59q9e6ucrqr068rlcenux")

  override def getReceivePubkey(receiveAddress: Option[String] = None): Future[PublicKey] = Future.successful(PublicKey.fromHex("028feba10d0eafd0fad8fe20e6d9206e6bd30242826de05c63f459a00aced24b12"))

  override def makeFundingTx(pubkeyScript: Array[Byte], amount: Satoshi, feeRatePerKw: Long): Future[MakeFundingTxResponse] =
    Future.successful(TestWallet.makeDummyFundingTx(pubkeyScript, amount, feeRatePerKw))

  override def commit(tx: Transaction): Future[Boolean] = Future.successful(true)

  override def rollback(tx: Transaction): Future[Boolean] = {
    rolledback = rolledback + tx
    Future.successful(true)
  }

  override def doubleSpent(tx: Transaction): Future[Boolean] = Future.successful(false)
}

object TestWallet {

  def makeDummyFundingTx(pubkeyScript: Array[Byte], amount: Satoshi, feeRatePerKw: Long): MakeFundingTxResponse = {
    val fundingTx = new Transaction(2,
      new TxIn(new OutPoint(new ByteVector32("0101010101010101010101010101010101010101010101010101010101010101"), 42), TxIn.SEQUENCE_FINAL) :: Nil,
      new TxOut(amount, pubkeyScript) :: Nil,
      0)
    MakeFundingTxResponse(fundingTx, 0, 420 sat)
  }

}