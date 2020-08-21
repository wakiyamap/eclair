/*
 * Copyright 2020 ACINQ SAS
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

package fr.acinq.eclair

import org.scalatest.funsuite.AnyFunSuite

class TypeErasureSpec extends AnyFunSuite {

  test("type erasure") {

    sealed trait Shape
    case class Circle() extends Shape
    case class Square() extends Shape

    case class Container[T <: Shape](o: T)


    def edges(o: Any): Int =  o match {
      case _: Container[Circle] => 0
      case _: Container[Square] => 4
      case _ => -1
    }

    assert(edges(Container(Square())) == 4)
  }

}
