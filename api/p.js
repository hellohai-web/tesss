'use strict';
// The (encrypted) page is only sent to a visitor who passed password + key on this device.
const h = require('./_h.js');
module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  try {
    const sec = h.secret();
    if (!sec || req.method !== 'GET') { res.statusCode = 401; return res.end(); }
    const s = await h.checkSession(req, sec);
    if (!s.ok) { res.statusCode = 401; return res.end(); }
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.statusCode = 200;
    res.end(require('./_p.js'));
  } catch (e) { res.statusCode = 500; res.end(); }
};
