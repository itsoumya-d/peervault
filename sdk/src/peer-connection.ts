// Copyright (c) 2024-2026 Soumya Debnath. All Rights Reserved.
// Licensed under the Business Source License 1.1 (BSL 1.1).
// See LICENSE file for details. Production use requires a paid license.
// Contact: soumyadebnath1661@gmail.com | +91 7031648617

import { EventEmitter } from './events';
import { SignalingClient } from './signaling-client';
import { SignalingMessage } from './types';

interface PeerEvents {
  datachannel_open: RTCDataChannel;
  error: Error;
}

export class PeerConnection extends EventEmitter<PeerEvents> {
  private pc: RTCPeerConnection;
  private dc: RTCDataChannel | null = null;
  private signaling: SignalingClient;
  private isSender: boolean;

  constructor(signaling: SignalingClient, isSender: boolean) {
    super();
    this.signaling = signaling;
    this.isSender = isSender;

    this.pc = new RTCPeerConnection({
      iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' },
        { urls: 'stun:stun.cloudflare.com:3478' }
      ]
    });

    this.pc.onicecandidate = (event) => {
      if (event.candidate) {
        this.signaling.send({
          type: 'signal',
          payload: { candidate: event.candidate }
        });
      }
    };

    if (this.isSender) {
      // DataChannel must be ordered and reliable for file transfer
      this.dc = this.pc.createDataChannel('peervault_transfer', {
        ordered: true
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

  private setupDataChannel(dc: RTCDataChannel) {
    dc.binaryType = 'arraybuffer';
    dc.onopen = () => {
      this.emit('datachannel_open', dc);
    };
    dc.onerror = (error) => {
      this.emit('error', new Error('DataChannel error: ' + error));
    };
  }

  private async handleSignalingMessage(msg: SignalingMessage) {
    if (msg.type !== 'signal') return;

    try {
      const payload = msg.payload;

      if (payload.sdp) {
        await this.pc.setRemoteDescription(new RTCSessionDescription(payload.sdp));

        if (payload.sdp.type === 'offer') {
          const answer = await this.pc.createAnswer();
          await this.pc.setLocalDescription(answer);
          this.signaling.send({
            type: 'signal',
            payload: { sdp: this.pc.localDescription }
          });
        }
      } else if (payload.candidate) {
        await this.pc.addIceCandidate(new RTCIceCandidate(payload.candidate));
      }
    } catch (err: any) {
      this.emit('error', err);
    }
  }

  async initiateConnection() {
    if (!this.isSender) return;

    try {
      const offer = await this.pc.createOffer();
      await this.pc.setLocalDescription(offer);
      this.signaling.send({
        type: 'signal',
        payload: { sdp: this.pc.localDescription }
      });
    } catch (err: any) {
      this.emit('error', err);
    }
  }

  close() {
    if (this.dc) this.dc.close();
    this.pc.close();
  }
}
