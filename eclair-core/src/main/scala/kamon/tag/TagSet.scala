package kamon.tag

trait TagSet {
  def withTag(t: String, v: Any) = this
}
object TagSet extends TagSet {
  def Empty: TagSet = this
  def of(t: String, s: String) = this
}
