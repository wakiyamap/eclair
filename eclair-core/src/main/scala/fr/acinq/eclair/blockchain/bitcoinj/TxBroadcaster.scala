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

package fr.acinq.eclair.blockchain.bitcoinj

import java.util.concurrent.Executors

import com.google.common.util.concurrent.{FutureCallback, Futures, ListenableFuture, MoreExecutors}
import fr.acinq.bitcoin.{Block, ByteVector32}
import grizzled.slf4j.Logging
import org.bitcoinj.core._
import org.bitcoinj.core.listeners.PreMessageReceivedEventListener
import org.bitcoinj.net.discovery.DnsDiscovery
import org.bitcoinj.params.{MainNetParams, RegTestParams, TestNet3Params}
import org.bitcoinj.utils.{ContextPropagatingThreadFactory, Threading}

import scala.concurrent.{ExecutionContext, Future, Promise}
import scala.util.{Failure, Success}

class TxBroadcaster(chain: ByteVector32) extends Logging {

  import ScalaConversions._

  implicit val ec = ExecutionContext.fromExecutorService(Executors.newCachedThreadPool(new ContextPropagatingThreadFactory("bitcoinj-broadcast")))

  private val params = chain match {
    case Block.RegtestGenesisBlock.hash => RegTestParams.get()
    case Block.TestnetGenesisBlock.hash => TestNet3Params.get()
    case Block.LivenetGenesisBlock.hash => MainNetParams.get()
  }
  val peerGroup = new PeerGroup(params, null)
  peerGroup.setMaxConnections(2)
  peerGroup.addPeerDiscovery(new DnsDiscovery(params))
  peerGroup.start()

  def broadcast(tx: fr.acinq.bitcoin.Transaction): Future[Boolean] = {

    val promise = Promise[Boolean]()

    for {
      _ <- peerGroup.waitForPeers(peerGroup.getMinBroadcastConnections).asScala
      bitcoinjTx = new Transaction(params, fr.acinq.bitcoin.Transaction.write(tx).toArray)
      rejectionListener = new PreMessageReceivedEventListener() {
        override def onPreMessageReceived(peer: Peer, m: Message): Message = {
          m match {
            case rejectMessage: RejectMessage if bitcoinjTx.getTxId == rejectMessage.getRejectedObjectHash =>
              // the tx got rejected: we know for sure that the tx won't be published on the network
              logger.warn(rejectMessage)
              promise.trySuccess(false)
            case _ => ()
          }
          m
        }
      }
    } yield {
      peerGroup.addPreMessageReceivedEventListener(Threading.SAME_THREAD, rejectionListener)

      val broadcast = peerGroup.broadcastTransaction(bitcoinjTx)

      broadcast.future().asScala onComplete {
        case Success(_) => promise.trySuccess(true)
        case Failure(t) => promise.tryFailure(t)
      }

      promise.future onComplete {
        case _ => peerGroup.removePreMessageReceivedEventListener(rejectionListener)
      }
    }

    promise.future
  }
}


object ScalaConversions {

  implicit class ListenableFutureToScalaFuture[T](lfuture: ListenableFuture[T]) {
    def asScala: Future[T] = {
      val promise = Promise[T]()
      Futures.addCallback(lfuture, new FutureCallback[T] {
        override def onFailure(t: Throwable): Unit = promise failure t

        override def onSuccess(result: T): Unit = promise success result
      }, MoreExecutors.directExecutor)
      promise.future
    }
  }

}