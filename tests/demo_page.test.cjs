const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const html = readFileSync(join(__dirname, '../service/static/demo.html'), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];

// Minimal DOM adapter: reject HTML parsing sinks while allowing literal text.
// These tests exercise the page's actual script without browser dependencies.
class Element {
  constructor() {
    this.children = [];
    this.value = '';
    this.textContent = '';
    this.disabled = false;
  }
  appendChild(child) { this.children.push(child); return child; }
  replaceChildren(...children) { this.children = children; }
  reportValidity() { return true; }
  set innerHTML(value) { throw new Error('Unexpected HTML parsing sink: ' + value); }
}

function page() {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, new Element());
    return elements.get(id);
  };
  const replies = new Map();
  const requests = [];
  const context = vm.createContext({
    document: { getElementById: element, createElement: () => new Element() },
    setInterval() {},
    fetch: async (url, options) => {
      requests.push({ url, options });
      assert(replies.has(url), 'Unexpected request: ' + url);
      const reply = replies.get(url);
      return { ok: reply.ok !== false, statusText: 'Failed', json: async () => reply.body };
    },
  });
  vm.runInContext(script, context);
  element('adminToken').value = 'test-admin-token';
  element('requestText').value = 'wire transfer of $500 to Alice Chen (Acct ...4471)';
  element('expiryMinutes').value = '15';
  return { element, replies, requests, run: (code) => vm.runInContext(code, context) };
}

test('approval messages and server errors render as literal text', async () => {
  const { element, replies, run } = page();
  const malicious = '<img src=x onerror=alert(document.cookie)>';
  replies.set('/v1/admin/approvals/TEST', { body: { message: malicious, status: malicious } });
  await run("tracked.push('TEST'); renderApprovals()");
  const row = element('approvals').children[0];
  assert.equal(row.children[0].textContent, malicious);
  assert.equal(row.children[1].textContent, malicious);
  assert.equal(row.children[1].className, 'status error');

  replies.set('/v1/devices', { ok: false, body: { detail: malicious } });
  await run('refreshDevices()');
  assert(element('devices').children[0].textContent.includes(malicious));
  assert(element('createApproval').disabled);

  replies.set('/v1/admin/approvals/TEST', { ok: false, body: { detail: malicious } });
  await run('renderApprovals()');
  assert(element('approvals').children[0].children[0].textContent.includes(malicious));
});

test('requests require an approved device and include the selected expiry', async () => {
  const { element, replies, requests, run } = page();
  replies.set('/v1/devices', { body: [
    { device_id: 'pending-device', status: 'pending_manual_approval' },
    { device_id: 'active-device', status: 'approved' },
  ] });
  await run('refreshDevices()');
  const rows = element('devices').children;
  assert.deepEqual(rows[0].children.map((child) => child.textContent), ['Approve enrollment']);
  assert.deepEqual(rows[1].children.map((child) => child.textContent), ['Select']);
  assert(element('createApproval').disabled);
  await run('createApproval()');
  assert(!requests.some((request) => request.url === '/v1/approvals'));

  rows[1].children[0].onclick();
  await new Promise(setImmediate);
  replies.set('/v1/approvals', { body: { ref: 'TEST' } });
  replies.set('/v1/admin/approvals/TEST', { body: { message: 'test request', status: 'pending' } });
  await run('createApproval()');
  const request = requests.find((item) => item.url === '/v1/approvals');
  const payload = JSON.parse(request.options.body);
  assert.equal(payload.device_id, 'active-device');
  assert.equal(payload.ttl_seconds, 900);
});

test('request submission failures are visible and allow retry', async () => {
  const { element, replies, run } = page();
  const message = '<svg onload=alert(1)>';
  replies.set('/v1/approvals', { ok: false, body: { detail: message } });
  await run("selectedDeviceId = 'active-device'; createApproval()");
  assert(element('error').textContent.includes(message));
  assert.equal(element('createApproval').disabled, false);
});
