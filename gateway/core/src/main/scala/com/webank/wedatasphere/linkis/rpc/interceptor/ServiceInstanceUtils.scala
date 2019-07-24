/*
 * Copyright 2019 WeBank
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webank.wedatasphere.linkis.rpc.interceptor

import java.util.concurrent.TimeUnit

import com.webank.wedatasphere.linkis.rpc.RPCSpringBeanCache

import scala.concurrent.duration.Duration

/**
  * created by cooperyang on 2019/1/9.
  */
object ServiceInstanceUtils {

  def getRPCServerLoader: RPCServerLoader = RPCSpringBeanCache.getRPCServerLoader
  def refreshServiceInstances(): Unit = getRPCServerLoader match {
    case loader: AbstractRPCServerLoader => loader.refreshAllServers()
    case _ =>
  }
  def serviceRefreshMaxWaitTime(): Duration = getRPCServerLoader match {
    case loader: AbstractRPCServerLoader => loader.refreshMaxWaitTime
    case _ => Duration(5, TimeUnit.SECONDS)
  }
}
