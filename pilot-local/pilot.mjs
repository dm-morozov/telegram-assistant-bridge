// Synthetic domain model only. No Telegram, HTTP, JWT, persistence or model client.
export class SyntheticPilot {
  #verify; #issuer; #audience; #owner; #chats; #clock; #messages = new Map(); #drafts = new Map(); #sequence = 0;
  constructor({ verifyAccessToken, issuer, audience, owner, chats = [], clock = Date.now }) {
    if (!Array.isArray(chats) || chats.length > 10) throw new Error('Explicit bounded chat selection required');
    if (verifyAccessToken !== undefined && (typeof verifyAccessToken !== 'function' || typeof owner !== 'string' || !owner || !/^https:\/\//.test(issuer ?? '') || !/^https:\/\//.test(audience ?? ''))) throw new Error('Explicit verifier identity configuration required');
    if (new Set(chats.map(chat => chat.id)).size !== chats.length) throw new Error('Duplicate chat selection');
    this.#chats = new Map(chats.map(chat => {
      if (!/^synthetic-[a-z0-9-]+$/.test(chat.id) || !Number.isFinite(chat.activatedAt) || !Number.isFinite(chat.consentUntil) || chat.participantsConsented !== true) throw new Error('Synthetic chat and explicit participant consent required');
      return [chat.id, Object.freeze({ ...chat })];
    }));
    this.#verify = verifyAccessToken; this.#issuer = issuer; this.#audience = audience; this.#owner = owner; this.#clock = clock;
  }
  #purge() {
    const now = this.#clock();
    for (const [key, message] of this.#messages) {
      const chat = this.#chats.get(message.chatId);
      if (!chat || chat.consentUntil <= now || message.expiresAt <= now) this.#messages.delete(key);
    }
    for (const [id, draft] of this.#drafts) if (!this.#messages.has(draft.sourceKey) || draft.expiresAt <= now) this.#drafts.delete(id);
  }
  async #authorize(token, chatId, scope) {
    this.#purge();
    if (typeof this.#verify !== 'function') throw new Error('OAuth verifier not configured');
    // This callback MUST be a real cryptographic verifier in a future protected adapter.
    // Tests inject a fixture verifier; this class is not a JWT implementation.
    const principal = await this.#verify(token);
    this.#purge();
    if (!principal || principal.issuer !== this.#issuer || principal.audience !== this.#audience || principal.subject !== this.#owner || !Number.isFinite(principal.expiresAt) || principal.expiresAt <= this.#clock() || !Array.isArray(principal.scopes) || !principal.scopes.includes(scope)) throw new Error('Access denied');
    const chat = this.#chats.get(chatId);
    if (!chat || chat.consentUntil <= this.#clock()) throw new Error('Chat access denied');
    return chat;
  }
  ingestSynthetic(event) {
    this.#purge();
    if (event?.source !== 'synthetic') throw new Error('Real Telegram adapter is disabled');
    const chat = this.#chats.get(event.chatId);
    if (!chat || chat.consentUntil <= this.#clock()) return false;
    if (!/^msg-[a-z0-9-]+$/.test(event.id ?? '') || !['new', 'edit', 'delete'].includes(event.type)) return false;
    const key = `${event.chatId}/${event.id}`;
    if (event.type === 'delete') { this.#messages.delete(key); this.#purge(); return true; }
    if (event.direction !== 'incoming' || !Number.isFinite(event.receivedAt) || event.receivedAt <= chat.activatedAt || event.receivedAt > this.#clock() || this.#clock() - event.receivedAt >= 3600000 || typeof event.text !== 'string' || event.text.length > 2000) return false;
    if (event.type === 'edit' && !this.#messages.has(key)) return false;
    if (event.type === 'new' && this.#messages.has(key)) return false;
    if (event.type === 'edit') {
      const original = this.#messages.get(key);
      this.#messages.set(key, { ...original, text: event.text });
      // An edited source invalidates any prior draft; never silently approve a stale response.
      for (const [id, draft] of this.#drafts) if (draft.sourceKey === key) this.#drafts.delete(id);
      return true;
    }
    if (this.#messages.size >= 100) this.#messages.delete(this.#messages.keys().next().value);
    this.#messages.set(key, { id: event.id, chatId: event.chatId, receivedAt: event.receivedAt, text: event.text, trust: 'untrusted-chat-content', expiresAt: Math.min(event.receivedAt + 3600000, chat.consentUntil) });
    this.#purge(); return true;
  }
  async listNewMessages(token, chatId, limit = 10) {
    await this.#authorize(token, chatId, 'messages:read');
    if (!Number.isInteger(limit) || limit < 1 || limit > 20) throw new Error('Limit must be 1..20');
    return [...this.#messages.values()].filter(message => message.chatId === chatId).slice(-limit).map(({ expiresAt, ...message }) => ({ ...message }));
  }
  async createLocalDraft(token, chatId, messageId, userText) {
    await this.#authorize(token, chatId, 'messages:read');
    await this.#authorize(token, chatId, 'drafts:create');
    const key = `${chatId}/${messageId}`;
    const message = this.#messages.get(key);
    if (!message || typeof userText !== 'string' || userText.length < 1 || userText.length > 2000) throw new Error('Invalid draft/source');
    if (this.#drafts.size >= 20) throw new Error('Draft capacity reached');
    const draft = { id: `draft-${++this.#sequence}`, chatId, messageId, text: userText, sourceKey: key, expiresAt: message.expiresAt, status: 'local-review-only', sent: false };
    this.#drafts.set(draft.id, draft);
    const { sourceKey, ...result } = draft; return { ...result };
  }
  async getLocalDraft(token, chatId, draftId) {
    await this.#authorize(token, chatId, 'messages:read');
    await this.#authorize(token, chatId, 'drafts:create');
    const draft = this.#drafts.get(draftId);
    if (!draft || draft.chatId !== chatId) throw new Error('Draft unavailable');
    const { sourceKey, ...result } = draft; return { ...result };
  }
  diagnostics() { return Object.freeze({ messages: this.#messages.size, drafts: this.#drafts.size }); }
  collectGarbage() { this.#purge(); return Object.freeze({ messages: this.#messages.size, drafts: this.#drafts.size }); }
  clear() { this.#messages.clear(); this.#drafts.clear(); this.#chats.clear(); }
  revokeChat(chatId) { this.#chats.delete(chatId); this.#purge(); }
}
export function connectRealTelegram() { throw new Error('Disabled: separate credentials, chat scope, participant consent and OAuth approval required'); }
export function exposeProtectedMcp() { throw new Error('Disabled: production OAuth verification and protected transport not implemented'); }
