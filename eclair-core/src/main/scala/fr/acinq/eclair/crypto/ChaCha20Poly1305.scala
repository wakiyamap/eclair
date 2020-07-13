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

package fr.acinq.eclair.crypto

import java.nio.ByteOrder
import java.util

import fr.acinq.bitcoin.{BtcSerializer, ByteVector32, Protocol}
import fr.acinq.eclair.crypto.ChaCha20Poly1305.{DecryptionError, EncryptionError, InvalidCounter}
import grizzled.slf4j.Logger
import grizzled.slf4j.Logging
import org.spongycastle.crypto.engines.ChaCha7539Engine
import org.spongycastle.crypto.params.{KeyParameter, ParametersWithIV}
import org.spongycastle.util.encoders.Hex
import scodec.bits.ByteVector

/**
  * Poly1305 authenticator
  * see https://tools.ietf.org/html/rfc7539#section-2.5
  */
object Poly1305 {
  /**
    *
    * @param key   input key
    * @param datas input data
    * @return a 16 byte authentication tag
    */
  def mac(key: Array[Byte], datas: Array[Byte]*): Array[Byte] = {
    val out = new Array[Byte](16)
    val poly = new org.spongycastle.crypto.macs.Poly1305()
    poly.init(new KeyParameter(key))
    datas.foreach(data => poly.update(data, 0, data.length.toInt))
    poly.doFinal(out, 0)
    out
  }

  def mac(key: ByteVector, datas: ByteVector*): ByteVector = {
    ByteVector.view(mac(key.toArray, datas.map(_.toArray): _*))
  }
}

/**
  * ChaCha20 block cipher
  * see https://tools.ietf.org/html/rfc7539#section-2.5
  */
object ChaCha20 {
  // Whenever key rotation happens, we start with a nonce value of 0 and increment it for each message.
  val ZeroNonce = Array[Byte](12)

  def encrypt(plaintext: Array[Byte], key: Array[Byte], nonce: Array[Byte], counter: Int): Array[Byte] = {
    val engine = new ChaCha7539Engine()
    engine.init(true, new ParametersWithIV(new KeyParameter(key), nonce))
    val ciphertext: Array[Byte] = new Array[Byte](plaintext.length.toInt)
    counter match {
      case 0 => ()
      case 1 =>
        // skip 1 block == set counter to 1 instead of 0
        val dummy = new Array[Byte](64)
        engine.processBytes(new Array[Byte](64), 0, 64, dummy, 0)
      case _ => throw InvalidCounter()
    }
    val len = engine.processBytes(plaintext.toArray, 0, plaintext.length.toInt, ciphertext, 0)
    if (len != plaintext.length) throw EncryptionError()
    ciphertext
  }

  def encrypt(plaintext: ByteVector, key: ByteVector, nonce: ByteVector, counter: Int = 0): ByteVector = {
    ByteVector.view(encrypt(plaintext.toArray, key.toArray, nonce.toArray, counter))
  }

  def decrypt(ciphertext: Array[Byte], key: Array[Byte], nonce: Array[Byte], counter: Int): Array[Byte] = {
    val engine = new ChaCha7539Engine
    engine.init(false, new ParametersWithIV(new KeyParameter(key), nonce))
    val plaintext: Array[Byte] = new Array[Byte](ciphertext.length.toInt)
    counter match {
      case 0 => ()
      case 1 =>
        // skip 1 block == set counter to 1 instead of 0
        val dummy = new Array[Byte](64)
        engine.processBytes(new Array[Byte](64), 0, 64, dummy, 0)
      case _ => throw InvalidCounter()
    }
    val len = engine.processBytes(ciphertext, 0, ciphertext.length.toInt, plaintext, 0)
    if (len != ciphertext.length) throw DecryptionError()
    plaintext
  }

  def decrypt(ciphertext: ByteVector, key: ByteVector, nonce: ByteVector, counter: Int = 0): ByteVector = {
    ByteVector.view(decrypt(ciphertext.toArray, key.toArray, nonce.toArray, counter))
  }
}

/**
  * ChaCha20Poly1305 AEAD (Authenticated Encryption with Additional Data) algorithm
  * see https://tools.ietf.org/html/rfc7539#section-2.5
  *
  * This what we should be using (see BOLT #8)
  */
object ChaCha20Poly1305 extends Logging {

  abstract class ChaCha20Poly1305Error(msg: String) extends RuntimeException(msg)
  case class InvalidMac() extends ChaCha20Poly1305Error("invalid mac")
  case class DecryptionError() extends ChaCha20Poly1305Error("decryption error")
  case class EncryptionError() extends ChaCha20Poly1305Error("encryption error")
  case class InvalidCounter() extends ChaCha20Poly1305Error("chacha20 counter must be 0 or 1")

  // This logger is used to dump encryption keys to enable traffic analysis by the lightning-dissector.
  // See https://github.com/nayutaco/lightning-dissector for more details.
  // It is disabled by default (in the logback.xml configuration file).
  val keyLogger = Logger("keylog")
  private val Zeroes = new Array[Byte](32)

  /**
    *
    * @param key       32 bytes encryption key
    * @param nonce     12 bytes nonce
    * @param plaintext plain text
    * @param aad       additional authentication data. can be empty
    * @return a (ciphertext, mac) tuple
    */
  def encrypt(key: Array[Byte], nonce: Array[Byte], plaintext: Array[Byte], aad: Array[Byte]): (Array[Byte], Array[Byte]) = {
    val polykey = ChaCha20.encrypt(Zeroes, key, nonce, 0)
    val ciphertext = ChaCha20.encrypt(plaintext, key, nonce, 1)
    val tag = Poly1305.mac(polykey, aad, pad16(aad), ciphertext, pad16(ciphertext), BtcSerializer.writeUInt64(aad.length), BtcSerializer.writeUInt64(ciphertext.length))

    logger.debug(s"encrypt($key, $nonce, $aad, $plaintext) = ($ciphertext, $tag)")
    if (util.Arrays.equals(nonce, ChaCha20.ZeroNonce)) {
      keyLogger.debug(s"${Hex.toHexString(tag)} ${Hex.toHexString(key)}")
    }

    (ciphertext, tag)
  }

  def encrypt(key: ByteVector, nonce: ByteVector, plaintext: ByteVector, aad: ByteVector): (ByteVector, ByteVector) = {
    val (ciphertext, tag) = encrypt(key.toArray, nonce.toArray, plaintext.toArray, aad.toArray)
    (ByteVector.view(ciphertext), ByteVector.view(tag))
  }

  /**
    *
    * @param key        32 bytes decryption key
    * @param nonce      12 bytes nonce
    * @param ciphertext ciphertext
    * @param aad        additional authentication data. can be empty
    * @param mac        authentication mac
    * @return the decrypted plaintext if the mac is valid.
    */
  def decrypt(key: Array[Byte], nonce: Array[Byte], ciphertext: Array[Byte], aad: Array[Byte], mac: Array[Byte]): Array[Byte] = {
    val polykey = ChaCha20.encrypt(Zeroes, key, nonce, 0)
    val tag = Poly1305.mac(polykey, aad, pad16(aad), ciphertext, pad16(ciphertext), BtcSerializer.writeUInt64(aad.length), BtcSerializer.writeUInt64(ciphertext.length))
    if (util.Arrays.compare(tag, mac) != 0) throw InvalidMac()
    val plaintext = ChaCha20.decrypt(ciphertext, key, nonce, 1)

    logger.debug(s"decrypt($key, $nonce, $aad, $ciphertext, $mac) = $plaintext")
    if (util.Arrays.equals(nonce, ChaCha20.ZeroNonce)) {
      keyLogger.debug(s"${Hex.toHexString(tag)} ${Hex.toHexString(key)}")
    }

    plaintext
  }

  def decrypt(key: ByteVector, nonce: ByteVector, ciphertext: ByteVector, aad: ByteVector, mac: ByteVector): ByteVector = {
    ByteVector.view(decrypt(key.toArray, nonce.toArray, ciphertext.toArray, aad.toArray, mac.toArray))
  }

  def pad16(data: Array[Byte]): Array[Byte] =
    if (data.size % 16 == 0) Array.emptyByteArray
    else new Array[Byte](16 - (data.size % 16))

  def pad16(data: ByteVector): ByteVector =
    if (data.size % 16 == 0)
      ByteVector.empty
    else
      ByteVector.fill(16 - (data.size % 16))(0)
}

