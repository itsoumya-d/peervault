// Copyright (c) 2024-2026 Soumya Debnath. All Rights Reserved.
// Licensed under the Business Source License 1.1 (BSL 1.1).
// See LICENSE file for details. Production use requires a paid license.
// Contact: soumyadebnath1661@gmail.com

import { EventEmitter } from './events';
import { SignalingClient } from './signaling-client';
import { SignalingMessage } from './types';

interface PeerEvents {
  datachannel_open: RTCDataChannel;
  error: Error;
}

export interface PeerConnectionOptions {
  /**
   * ICE servers for the underlying RTCPeerConnection. Defaults to three public
   * STUN servers and NO TURN server, which means symmetric and carrier-grade NAT
   * cannot be traversed. Supply a TURN server here for reliable connectivity.
   */
  iceServers?: RTCIceServer[];
}

export const DEFAULT_ICE_SERVERS: RTCIceServer[] = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun1.l.google.com:19302' },
  { urls: 'stun:stun.cloudflare.com:3478' },
];

export class PeerConnection extends EventEmitter<PeerEvents> {
  private pc: RTCPeerConnection;
  private dc: RTCDataChannel | null = null;
  private signaling: SignalingClient;
  private isSender: boolean;
  private iceFailureReported = false;

  constructor(signaling: SignalingClient, isSender: boolean, options?: PeerConnectionOptions) {
    super();
    this.signaling = signaling;
    this.isSender = isSender;

    this.pc = new RTCPeerConnection({
      iceServers: options?.iceServers ?? DEFAULT_ICE_SERVERS,
    });

    this.pc.onicecandidate = (event) => {
      if (event.candidate) {
        this.signaling.send({
          type: 'signal',
          payload: { candidate: event.candidate },
        });
      }
    };

    // Without these handlers a failed ICE negotiation produced no event at all:
    // the connection simply never opened and every pending promise hung forever.
    this.pc.oniceconnectionstatechange = () => this.checkIceState();
    this.pc.onconnectionstatechange = () => this.checkIceState();

    if (this.isSender) {
      // DataChannel must be ordered and reliable for file transfer
      this.dc = this.pc.createDataChannel('peervault_transfer', {
        ordered: true,
      });
      this.setupDataChannel(this.dc);
    } else {
      this.pc.ondatachannel = (event) => {
        this.dc = event.channel;
        this.setupDataChannel(this.dc);
      };
    }

    this.signaling.on('message', this.handleSignalingMessage.bind(this));
  }

  private checkIceState() {
    const ice = this.pc.iceConnectionState;
    const conn = this.pc.connectionState;
    if (this.iceFailureReported) return;
    if (ice === 'failed' || conn === 'failed') {
      this.iceFailureReported = true;
      this.emit(
        'error',
        new Error(
          `PeerVault: ICE negotiation failed (iceConnectionState=${ice}, connectionState=${conn}). ` +
            'No TURN server is configured, so peers behind symmetric or carrier-grade NAT ' +
            'cannot establish a direct connection. Pass iceServers with a TURN entry to fix this.'
        )
      );
    }
  }

  /** Current ICE/connection state, useful for diagnostics. */
  get state(): { ice: RTCIceConnectionState; connection: RTCPeerConnectionState } {
    return { ice: this.pc.iceConnectionState, connection: this.pc.connectionState };
  }

  private setupDataChannel(dc: RTCDataChannel) {
    dc.binaryType = 'arraybuffer';
    dc.onopen = () => {
      this.emit('datachannel_open', dc);
    };
    dc.onerror = (event) => {
      const err = (event as RTCErrorEvent).error;
      this.emit('error', err instanceof Error ? err : new Error('DataChannel error'));
    };
  }

  private async handleSignalingMessage(msg: SignalingMessage) {
    if (msg.type !== 'signal') return;

    try {
      const payload = msg.payload;
      if (!payload || typeof payload !== 'object') return;

      if (payload.sdp) {
        await this.pc.setRemoteDescription(new RTCSessionDescription(payload.sdp));

        if (payload.sdp.type === 'offer') {
          const answer = await this.pc.createAnswer();
          await this.pc.setLocalDescription(answer);
          this.signaling.send({
            type: 'signal',
            payload: { sdp: this.pc.localDescription },
          });
        }
      } else if (payload.candidate) {
        await this.pc.addIceCandidate(new RTCIceCandidate(payload.candidate));
      }
    } catch (err: unknown) {
      this.emit('error', err instanceof Error ? err : new Error('PeerVault: signaling error'));
    }
  }

  async initiateConnection() {
    if (!this.isSender) return;

    try {
      const offer = await this.pc.createOffer();
      await this.pc.setLocalDescription(offer);
      this.signaling.send({
        type: 'signal',
        payload: { sdp: this.pc.localDescription },
      });
    } catch (err: unknown) {
      this.emit('error', err instanceof Error ? err : new Error('PeerVault: failed to create offer'));
    }
  }

  close() {
    if (this.dc) this.dc.close();
    this.pc.close();
  }
}
