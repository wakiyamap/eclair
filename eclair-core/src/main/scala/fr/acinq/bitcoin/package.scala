package fr.acinq

package object bitcoin {
  implicit object NumericPimpSatoshi extends Numeric[PimpSatoshi] {
    // @formatter:off
    override def compare(x: PimpSatoshi, y: PimpSatoshi): Int = x.compare(y)
    override def minus(x: PimpSatoshi, y: PimpSatoshi): PimpSatoshi = x - y
    override def negate(x: PimpSatoshi): PimpSatoshi = -x
    override def plus(x: PimpSatoshi, y: PimpSatoshi): PimpSatoshi = x + y
    override def times(x: PimpSatoshi, y: PimpSatoshi): PimpSatoshi = x * y.toLong
    override def toDouble(x: PimpSatoshi): Double = x.toLong
    override def toFloat(x: PimpSatoshi): Float = x.toLong
    override def toInt(x: PimpSatoshi): Int = x.toLong.toInt
    override def toLong(x: PimpSatoshi): Long = x.toLong
    override def fromInt(x: Int): PimpSatoshi = PimpSatoshi(x)
    override def parseString(str: String): Option[PimpSatoshi] = ???
    // @formatter:on
  }

//  implicit final class PimpSatoshiLong(private val n: Long) extends AnyVal {
//    def sat = PimpSatoshi(n)
//  }

  implicit final class MilliBtcDouble(private val n: Double) extends AnyVal {
    def millibtc = MilliBtc(n)
  }

  implicit final class BtcDouble(private val n: Double) extends AnyVal {
    def btc = Btc(n)
  }

  // @formatter:off
  implicit def satoshi2pimmysatoshi(input: Satoshi): PimpSatoshi = PimpSatoshi(input.toLong)
  implicit def pimpmysatoshi2satoshi(input: PimpSatoshi): Satoshi = new Satoshi(input.toLong)
  implicit def PimpSatoshi2btc(input: PimpSatoshi): Btc = input.toBtc
  implicit def btc2PimpSatoshi(input: Btc): PimpSatoshi = input.toSatoshi
  implicit def PimpSatoshi2millibtc(input: PimpSatoshi): MilliBtc = input.toMilliBtc
  implicit def millibtc2PimpSatoshi(input: MilliBtc): PimpSatoshi = input.toSatoshi
  implicit def btc2millibtc(input: Btc): MilliBtc = input.toMilliBtc
  implicit def millibtc2btc(input: MilliBtc): Btc = input.toBtc
  // @formatter:on
}
