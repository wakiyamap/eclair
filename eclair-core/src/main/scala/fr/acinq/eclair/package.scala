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

package fr.acinq

import java.security.SecureRandom

import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin._
import scodec.Attempt
import scodec.bits.{BitVector, ByteVector}
import fr.acinq.eclair.KotlinUtils._
import scala.util.{Failure, Success, Try}

package object eclair {

  /**
   * We are using 'new SecureRandom()' instead of 'SecureRandom.getInstanceStrong()' because the latter can hang on Linux
   * See http://bugs.java.com/view_bug.do?bug_id=6521844 and https://tersesystems.com/2015/12/17/the-right-way-to-use-securerandom/
   */
  val secureRandom = new SecureRandom()

  def randomBytes(length: Int): Array[Byte] = {
    val buffer = new Array[Byte](length)
    secureRandom.nextBytes(buffer)
    buffer
  }

  def randomBytes32: ByteVector32 = new ByteVector32(randomBytes(32))

  def randomBytes64: ByteVector64 = new ByteVector64(randomBytes(64))

  def randomKey: PrivateKey = new PrivateKey(randomBytes32)

  def toLongId(fundingTxHash1: ByteVector32, fundingOutputIndex: Int): ByteVector32 = {
    val fundingTxHash = ByteVector.view(fundingTxHash1.toByteArray)
    require(fundingOutputIndex < 65536, "fundingOutputIndex must not be greater than FFFF")
    require(fundingTxHash.size == 32, "fundingTxHash must be of length 32B")
    val channelId = fundingTxHash.take(30) :+ (fundingTxHash(30) ^ (fundingOutputIndex >> 8)).toByte :+ (fundingTxHash(31) ^ fundingOutputIndex).toByte
    new ByteVector32(channelId.toArray)
  }

  def serializationResult(attempt: Attempt[BitVector]): ByteVector = attempt match {
    case Attempt.Successful(bin) => bin.toByteVector
    case Attempt.Failure(cause) => throw new RuntimeException(s"serialization error: $cause")
  }

  /**
   * Converts fee rate in satoshi-per-bytes to fee rate in satoshi-per-kw
   *
   * @param feeratePerByte fee rate in satoshi-per-bytes
   * @return fee rate in satoshi-per-kw
   */
  def feerateByte2Kw(feeratePerByte: Long): Long = feerateKB2Kw(feeratePerByte * 1000)

  /**
   * Converts fee rate in satoshi-per-kw to fee rate in satoshi-per-byte
   *
   * @param feeratePerKw fee rate in satoshi-per-kw
   * @return fee rate in satoshi-per-byte
   */
  def feerateKw2Byte(feeratePerKw: Long): Long = feeratePerKw / 250

  /**
   * why 253 and not 250 since feerate-per-kw is feerate-per-kb / 250 and the minimum relay fee rate is 1000 satoshi/Kb ?
   *
   * because bitcoin core uses neither the actual tx size in bytes or the tx weight to check fees, but a "virtual size"
   * which is (3 * weight) / 4 ...
   * so we want :
   * fee > 1000 * virtual size
   * feerate-per-kw * weight > 1000 * (3 * weight / 4)
   * feerate_per-kw > 250 + 3000 / (4 * weight)
   * with a conservative minimum weight of 400, we get a minimum feerate_per-kw of 253
   *
   * see https://github.com/ElementsProject/lightning/pull/1251
   **/
  val MinimumFeeratePerKw = 253

  /**
   * minimum relay fee rate, in satoshi per kilo
   * bitcoin core uses virtual size and not the actual size in bytes, see above
   **/
  val MinimumRelayFeeRate = 1000

  /**
   * Converts fee rate in satoshi-per-kilobytes to fee rate in satoshi-per-kw
   *
   * @param feeratePerKB fee rate in satoshi-per-kilobytes
   * @return fee rate in satoshi-per-kw
   */
  def feerateKB2Kw(feeratePerKB: Long): Long = Math.max(feeratePerKB / 4, MinimumFeeratePerKw)

  /**
   * Converts fee rate in satoshi-per-kw to fee rate in satoshi-per-kilobyte
   *
   * @param feeratePerKw fee rate in satoshi-per-kw
   * @return fee rate in satoshi-per-kilobyte
   */
  def feerateKw2KB(feeratePerKw: Long): Long = feeratePerKw * 4

  def isPay2PubkeyHash(address: String): Boolean = address.startsWith("1") || address.startsWith("m") || address.startsWith("n")

  /**
   * Tests whether the binary data is composed solely of printable ASCII characters (see BOLT 1)
   *
   * @param data to check
   */
  def isAsciiPrintable(data: ByteVector): Boolean = data.toArray.forall(ch => ch >= 32 && ch < 127)

  /**
   * @param baseFee         fixed fee
   * @param proportionalFee proportional fee (millionths)
   * @param paymentAmount   payment amount in millisatoshi
   * @return the fee that a node should be paid to forward an HTLC of 'paymentAmount' millisatoshis
   */
  def nodeFee(baseFee: MilliSatoshi, proportionalFee: Long, paymentAmount: MilliSatoshi): MilliSatoshi = baseFee + (paymentAmount * proportionalFee) / 1000000

  /**
   * @param address   base58 of bech32 address
   * @param chainHash hash of the chain we're on, which will be checked against the input address
   * @return the public key script that matches the input address.
   */
  def addressToPublicKeyScript(address: String, chainHash: ByteVector32): Seq[ScriptElt] = {
    import scala.jdk.CollectionConverters._

    Try(Base58Check.decode(address)) match {
      case Success(pair) if pair.getFirst == Base58.Prefix.PubkeyAddressTestnet && (chainHash == Block.TestnetGenesisBlock.hash || chainHash == Block.RegtestGenesisBlock.hash) =>
        Script.pay2pkh(pair.getSecond)
      case Success(pair) if pair.getFirst == Base58.Prefix.PubkeyAddress && chainHash == Block.LivenetGenesisBlock.hash =>
        Script.pay2pkh(pair.getSecond)
      case Success(pair) if pair.getFirst == Base58.Prefix.ScriptAddressTestnet && (chainHash == Block.TestnetGenesisBlock.hash || chainHash == Block.RegtestGenesisBlock.hash) =>
        Seq(OP_HASH160.INSTANCE, new OP_PUSHDATA(pair.getSecond), OP_EQUAL.INSTANCE)
      case Success(pair) if pair.getFirst == Base58.Prefix.ScriptAddress && chainHash == Block.LivenetGenesisBlock.hash =>
        Seq(OP_HASH160.INSTANCE, new OP_PUSHDATA(pair.getSecond), OP_EQUAL.INSTANCE)
      case Failure(base58error) =>
        Try(Bech32.decodeWitnessAddress(address)) match {
          case Success(triple) if triple.getSecond != 0.toByte => throw new IllegalArgumentException(s"invalid version ${triple.getSecond} in bech32 address")
          case Success(triple) if triple.getThird.size != 20 && triple.getThird.size != 32 => throw new IllegalArgumentException("hash length in bech32 address must be either 20 or 32 bytes")
          case Success(triple) if triple.getFirst == "bc" && chainHash == Block.LivenetGenesisBlock.hash => List(OP_0.INSTANCE,  new OP_PUSHDATA(triple.getThird))
          case Success(triple) if triple.getFirst == "tb" && chainHash == Block.TestnetGenesisBlock.hash => List(OP_0.INSTANCE,  new OP_PUSHDATA(triple.getThird))
          case Success(triple) if triple.getFirst == "bcrt" && chainHash == Block.RegtestGenesisBlock.hash => List(OP_0.INSTANCE,  new OP_PUSHDATA(triple.getThird))
          case Success(_) => throw new IllegalArgumentException("bech32 address does not match our blockchain")
          case Failure(bech32error) => throw new IllegalArgumentException(s"$address is neither a valid Base58 address ($base58error) nor a valid Bech32 address ($bech32error)")
        }
    }
  }

  implicit class LongToBtcAmount(l: Long) {
    // @formatter:off
    def msat: MilliSatoshi = MilliSatoshi(l)
    def mbtc: MilliBtc = MilliBtc(l)
    def btc: Btc = Btc(l)
    // @formatter:on
  }

  implicit class IntToBtcAmount(l: Int) {
    // @formatter:off
    def msat: MilliSatoshi = MilliSatoshi(l)
    def mbtc: MilliBtc = MilliBtc(l)
    def btc: Btc = Btc(l)
    // @formatter:on
  }

  // We implement Numeric to take advantage of operations such as sum, sort or min/max on iterables.
  implicit object NumericMilliSatoshi extends Numeric[MilliSatoshi] {
    // @formatter:off
    override def plus(x: MilliSatoshi, y: MilliSatoshi): MilliSatoshi = x + y
    override def minus(x: MilliSatoshi, y: MilliSatoshi): MilliSatoshi = x - y
    override def times(x: MilliSatoshi, y: MilliSatoshi): MilliSatoshi = MilliSatoshi(x.toLong * y.toLong)
    override def negate(x: MilliSatoshi): MilliSatoshi = -x
    override def fromInt(x: Int): MilliSatoshi = MilliSatoshi(x)
    override def toInt(x: MilliSatoshi): Int = x.toLong.toInt
    override def toLong(x: MilliSatoshi): Long = x.toLong
    override def toFloat(x: MilliSatoshi): Float = x.toLong
    override def toDouble(x: MilliSatoshi): Double = x.toLong
    override def compare(x: MilliSatoshi, y: MilliSatoshi): Int = x.compare(y)
    override def parseString(str: String): Option[MilliSatoshi] = ???
    // @formatter:on
  }

  implicit class ToMilliSatoshiConversion(amount: BtcAmount) {
    // @formatter:off
    def toMilliSatoshi: MilliSatoshi = MilliSatoshi.toMilliSatoshi(amount)
    def +(other: MilliSatoshi): MilliSatoshi = amount.toMilliSatoshi + other
    def -(other: MilliSatoshi): MilliSatoshi = amount.toMilliSatoshi - other
    // @formatter:on
  }

  /**
   * Apparently .getClass.getSimpleName can crash java 8 with a "Malformed class name" error
   */
  def getSimpleClassName(o: Any): String = o.getClass.getName.split("\\$").last

}