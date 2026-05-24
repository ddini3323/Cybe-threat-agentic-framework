/* CTI Assistant — floating chat widget */
(function () {
  'use strict';

  /* ── Styles ─────────────────────────────────────────────────────── */
  const CSS = `
#cti-chat-btn {
  position: fixed; bottom: 24px; right: 24px; z-index: 9998;
  width: 52px; height: 52px; border-radius: 50%;
  background: #00d4ff; border: none; cursor: pointer;
  box-shadow: 0 4px 16px rgba(0,212,255,.45);
  display: flex; align-items: center; justify-content: center;
  font-size: 22px; transition: transform .2s, box-shadow .2s;
}
#cti-chat-btn:hover {
  transform: scale(1.1);
  box-shadow: 0 6px 22px rgba(0,212,255,.65);
}
#cti-chat-panel {
  position: fixed; bottom: 88px; right: 24px; z-index: 9999;
  width: 370px; max-height: 560px;
  display: flex; flex-direction: column;
  background: #0d1117; border: 1px solid #00d4ff44;
  border-radius: 12px; box-shadow: 0 8px 32px rgba(0,0,0,.7);
  font-family: 'Segoe UI', system-ui, sans-serif; font-size: 13px;
  color: #c9d1d9; overflow: hidden;
  transform: scale(0); transform-origin: bottom right;
  transition: transform .2s cubic-bezier(.34,1.56,.64,1), opacity .2s;
  opacity: 0; pointer-events: none;
}
#cti-chat-panel.open {
  transform: scale(1); opacity: 1; pointer-events: all;
}
#cti-chat-header {
  padding: 12px 14px; background: #161b22;
  border-bottom: 1px solid #30363d;
  display: flex; align-items: center; justify-content: space-between;
  flex-shrink: 0;
}
#cti-chat-header span { font-weight: 700; color: #00d4ff; letter-spacing: .5px; }
#cti-chat-header small { color: #8b949e; font-size: 11px; }
#cti-chat-close {
  background: none; border: none; color: #8b949e; cursor: pointer;
  font-size: 16px; padding: 0 4px; line-height: 1;
}
#cti-chat-close:hover { color: #fff; }
#cti-chat-msgs {
  flex: 1; overflow-y: auto; padding: 12px;
  display: flex; flex-direction: column; gap: 10px;
  scroll-behavior: smooth;
}
#cti-chat-msgs::-webkit-scrollbar { width: 4px; }
#cti-chat-msgs::-webkit-scrollbar-track { background: transparent; }
#cti-chat-msgs::-webkit-scrollbar-thumb { background: #30363d; border-radius: 2px; }
.cti-msg { max-width: 88%; line-height: 1.55; word-break: break-word; }
.cti-msg.user {
  align-self: flex-end;
  background: #1a3a4a; color: #cae8ff;
  padding: 8px 12px; border-radius: 12px 12px 4px 12px;
}
.cti-msg.bot {
  align-self: flex-start;
  background: #161b22; color: #c9d1d9;
  padding: 8px 12px; border-radius: 4px 12px 12px 12px;
  border: 1px solid #30363d; white-space: pre-wrap;
}
.cti-msg.bot strong { color: #00d4ff; }
.cti-msg.bot code {
  background: #0d1117; color: #58a6ff;
  padding: 1px 5px; border-radius: 4px; font-family: monospace;
}
.cti-typing { color: #8b949e; font-style: italic; font-size: 12px; }
#cti-chat-footer {
  padding: 10px 12px; border-top: 1px solid #30363d;
  display: flex; gap: 8px; flex-shrink: 0; background: #161b22;
}
#cti-chat-input {
  flex: 1; background: #0d1117; border: 1px solid #30363d;
  border-radius: 8px; color: #c9d1d9; padding: 8px 10px;
  font-size: 13px; outline: none; resize: none;
  max-height: 80px; font-family: inherit;
}
#cti-chat-input:focus { border-color: #00d4ff66; }
#cti-chat-send {
  background: #00d4ff22; border: 1px solid #00d4ff55;
  color: #00d4ff; border-radius: 8px; padding: 0 14px;
  cursor: pointer; font-size: 16px; transition: background .15s;
  flex-shrink: 0;
}
#cti-chat-send:hover { background: #00d4ff44; }
#cti-chat-send:disabled { opacity: .4; cursor: not-allowed; }
.cti-quick-btns {
  display: flex; flex-wrap: wrap; gap: 5px; padding: 0 12px 8px;
}
.cti-quick-btn {
  background: #161b22; border: 1px solid #30363d;
  color: #8b949e; border-radius: 20px;
  padding: 3px 10px; font-size: 11px; cursor: pointer;
  transition: border-color .15s, color .15s;
}
.cti-quick-btn:hover { border-color: #00d4ff55; color: #00d4ff; }
`;

  /* ── HTML ────────────────────────────────────────────────────────── */
  const QUICK = [
    "What's in the queue?",
    "What's running?",
    "What's complete?",
    "Show patterns",
    "Show mitigations",
    "My last submission",
    "Help",
  ];

  function buildUI() {
    const style = document.createElement('style');
    style.textContent = CSS;
    document.head.appendChild(style);

    // Floating button
    const btn = document.createElement('button');
    btn.id = 'cti-chat-btn';
    btn.title = 'CTI Assistant';
    btn.textContent = '🛡';
    document.body.appendChild(btn);

    // Panel
    const panel = document.createElement('div');
    panel.id = 'cti-chat-panel';
    panel.innerHTML = `
      <div id="cti-chat-header">
        <span>🛡 CTI Assistant</span>
        <small>Ask about any threat or stage</small>
        <button id="cti-chat-close" title="Close">✕</button>
      </div>
      <div id="cti-chat-msgs"></div>
      <div class="cti-quick-btns" id="cti-quick-btns"></div>
      <div id="cti-chat-footer">
        <textarea id="cti-chat-input" rows="1"
          placeholder="Ask about a threat ID, queue status, patterns…"></textarea>
        <button id="cti-chat-send" title="Send">➤</button>
      </div>`;
    document.body.appendChild(panel);

    // Quick buttons
    const qc = document.getElementById('cti-quick-btns');
    QUICK.forEach(q => {
      const b = document.createElement('button');
      b.className = 'cti-quick-btn';
      b.textContent = q;
      b.addEventListener('click', () => sendMessage(q));
      qc.appendChild(b);
    });

    // Toggle
    btn.addEventListener('click', toggle);
    document.getElementById('cti-chat-close').addEventListener('click', close);

    // Send on button or Enter (Shift+Enter = newline)
    document.getElementById('cti-chat-send').addEventListener('click', () => {
      const v = document.getElementById('cti-chat-input').value.trim();
      if (v) sendMessage(v);
    });
    document.getElementById('cti-chat-input').addEventListener('keydown', e => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        const v = e.target.value.trim();
        if (v) sendMessage(v);
      }
    });

    // Auto-grow textarea
    document.getElementById('cti-chat-input').addEventListener('input', function () {
      this.style.height = 'auto';
      this.style.height = Math.min(this.scrollHeight, 80) + 'px';
    });
  }

  /* ── State ───────────────────────────────────────────────────────── */
  let open = false;
  let busy = false;
  const history = [];

  function toggle() { open ? close() : openPanel(); }

  function openPanel() {
    open = true;
    document.getElementById('cti-chat-panel').classList.add('open');
    if (!history.length) {
      addBotMsg(
        'Hi! I\'m your CTI Assistant.\n\n' +
        'Ask me about any submitted threat by its ID, check the queue, ' +
        'pipeline status, patterns, or mitigations.\n\n' +
        'Try one of the quick buttons below or type your question.'
      );
    }
    setTimeout(() => document.getElementById('cti-chat-input').focus(), 200);
  }

  function close() {
    open = false;
    document.getElementById('cti-chat-panel').classList.remove('open');
  }

  /* ── Messaging ───────────────────────────────────────────────────── */
  function addUserMsg(text) {
    const div = document.createElement('div');
    div.className = 'cti-msg user';
    div.textContent = text;
    document.getElementById('cti-chat-msgs').appendChild(div);
    scrollBottom();
  }

  function addBotMsg(text) {
    const div = document.createElement('div');
    div.className = 'cti-msg bot';
    // Render simple markdown: **bold**, `code`
    div.innerHTML = renderMd(text);
    document.getElementById('cti-chat-msgs').appendChild(div);
    scrollBottom();
    return div;
  }

  function addTyping() {
    const div = document.createElement('div');
    div.className = 'cti-msg bot cti-typing';
    div.id = 'cti-typing';
    div.textContent = 'Thinking…';
    document.getElementById('cti-chat-msgs').appendChild(div);
    scrollBottom();
  }

  function removeTyping() {
    const t = document.getElementById('cti-typing');
    if (t) t.remove();
  }

  function scrollBottom() {
    const msgs = document.getElementById('cti-chat-msgs');
    msgs.scrollTop = msgs.scrollHeight;
  }

  function renderMd(text) {
    return text
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      .replace(/\n/g, '<br>');
  }

  async function sendMessage(text) {
    if (busy) return;
    busy = true;

    const input = document.getElementById('cti-chat-input');
    input.value = '';
    input.style.height = 'auto';
    document.getElementById('cti-chat-send').disabled = true;

    addUserMsg(text);
    addTyping();

    history.push({ role: 'user', content: text });

    try {
      const res = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: text, history: history.slice(-6) }),
      });
      removeTyping();
      if (res.ok) {
        const data = await res.json();
        const reply = data.reply || 'No response received.';
        history.push({ role: 'assistant', content: reply });
        addBotMsg(reply);
      } else {
        addBotMsg('Error ' + res.status + ': Could not reach the CTI backend.');
      }
    } catch (err) {
      removeTyping();
      addBotMsg('Network error — make sure the CTI system is running.');
    }

    busy = false;
    document.getElementById('cti-chat-send').disabled = false;
    input.focus();
  }

  /* ── Init ────────────────────────────────────────────────────────── */
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', buildUI);
  } else {
    buildUI();
  }
})();
