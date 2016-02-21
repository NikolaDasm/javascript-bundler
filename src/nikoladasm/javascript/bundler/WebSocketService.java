/*
 *  JavaScript Bundler
 *  Copyright (C) 2016  Nikolay Platov
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package nikoladasm.javascript.bundler;

import java.util.concurrent.ConcurrentLinkedQueue;

import org.slf4j.Logger;

import nikoladasm.aspark.ASpark;
import nikoladasm.aspark.WebSocketContext;
import nikoladasm.aspark.WebSocketHandler;

import static nikoladasm.aspark.ASpark.*;

public class WebSocketService {
	
	private final Logger LOG;

	private WebSocketHandler wsHandler = new WebSocketHandler() {
		
		@Override
		public void onConnect(WebSocketContext wctx) {
			LOG.debug("WebSocket connect");
			registerWebSocket(wctx);
		}
		
		@Override
		public void onClose(WebSocketContext wctx, int statusCode, String reason) {
			LOG.debug("WebSocket close");
			unregisterWebSocket(wctx);
		}
	};

	private ConcurrentLinkedQueue<WebSocketContext> webSockets =
		new ConcurrentLinkedQueue<>();
	private String ipAddress;
	private int port;
	private String staticFileLocation;
	
	public WebSocketService(String ipAddress, int port, String staticFileLocation, Logger LOG) {
		this.ipAddress = ipAddress;
		this.port = port;
		this.staticFileLocation = staticFileLocation;
		this.LOG = LOG;
	}
	
	public void start() {
		ipAddress(ipAddress);
		port(port);
		externalStaticFileLocation(staticFileLocation);
		webSocket("/modules", wsHandler);
		init();
		awaitInitialization();
	}
	
	public void stop() {
		ASpark.stop();
	}
	
	public void send(String msg) {
		webSockets.forEach(wctx -> wctx.send(msg));
	}
	
	private void registerWebSocket(WebSocketContext wctx) {
		webSockets.add(wctx);
	}
	
	private void unregisterWebSocket(WebSocketContext wctx) {
		webSockets.remove(wctx);
	}
}
