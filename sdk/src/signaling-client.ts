// Copyright (c) 2024-2026 Soumya Debnath. All Rights Reserved.
// Licensed under the Business Source License 1.1 (BSL 1.1).
// See LICENSE file for details. Production use requires a paid license.
// Contact: soumyadebnath1661@gmail.com

import { EventEmitter } from './events';
import { SignalingMessage } from './types';

interface SignalingEvents {
  open: void;
  message: SignalingMessage;
  close: void;
  error: Event;
}

export class SignalingClient extends EventEmitter<SignalingEvents> {
  private ws: WebSocket | null = null;
  private url: string;
  private connectPromise: Promise<void> | null = null;

  constructor(url: string) {
    super();
    this.url = url;
  }

  /**
   * Opens the WebSocket. Idempotent: repeat calls return the in-flight or
   * already-resolved promise instead of replacing this.ws and orphaning the
   * previous socket.
   */
  connect(): Promise<void> {
    if (this.connectPromise) return this.connectPromise;

    this.connectPromise = new Promise<void>((resolve, reject) => {
      let settled = false;
      this.ws = new WebSocket(this.url);

      this.ws.onopen = () => {
        settled = true;
        this.emit('open', undefined);
        resolve();
      };

      this.ws.onmessage = (event) => {
        try {
          const message: SignalingMessage = JSON.parse(event.data);
          this.emit('message', message);
        } catch (err) {
          console.error('Error parsing signaling message:', err);
        }
      };

      this.ws.onclose = () => {
        this.emit('close', undefined);
        if (!settled) {
          settled = true;
          reject(new Error(`PeerVault: signaling connection to ${this.url} closed before opening`));
        }
      };

      this.ws.onerror = (error) => {
        this.emit('error', error);
        if (!settled) {
          settled = true;
          reject(new Error(`PeerVault: could not connect to the signaling relay at ${this.url}`));
        }
      };
    });

    // A failed connect must not poison later attempts.
    this.connectPromise.catch(() => {
      this.connectPromise = null;
    });

    return this.connectPromise;
  }

  /** True when the socket is open and send() will actually transmit. */
  get isOpen(): boolean {
    return !!this.ws && this.ws.readyState === WebSocket.OPEN;
  }

  /**
   * Sends a signaling message. Returns false if the socket is not open, so callers
   * can detect a dropped message instead of silently losing it.
   */
  send(message: SignalingMessage): boolean {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
      return true;
    }
    return false;
  }

  close(): void {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.connectPromise = null;
  }
}
